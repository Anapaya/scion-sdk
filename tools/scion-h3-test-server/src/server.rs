// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The HTTP/3 server inside the topology, and its restart.

use std::{io::Write, sync::Arc};

use axum::Router;
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA212, PsSetup},
};
use scion_quic::{quic::config::QuicConfig, reexport::squiche, socket::GenericScionUdpSocket};
use scion_stack::{ScionStack, ScionStackBuilder};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{Args, app};

/// The name in the server certificate, and therefore the host a client must use.
pub const SERVER_NAME: &str = "localhost";

type BoxError = Box<dyn std::error::Error>;

/// An HTTP/3 server on a SCION socket, which can be stopped and started again at the same address.
///
/// The stack and the socket outlive every serve task. Rebuilding either would give the client a
/// different address to reach, which is the opposite of what a reconnect test wants to see, and a
/// socket cannot be handed back promptly anyway: the endpoint's per-connection tasks hold it until
/// their connections time out. Only the endpoint reading the socket is replaced, which is what the
/// client sees: every connection it holds becomes one nothing on the other side knows about.
pub struct Http3Server {
    // Kept because the socket was bound from it and works only while it is alive.
    _stack: ScionStack,
    socket: Arc<dyn GenericScionUdpSocket>,
    bind_addr: ScionSocketIpAddr,
    router: Router,
    max_streams: u64,
    alpn: Vec<u8>,
    // Files, because squiche loads a server's own certificate chain and private key from paths and
    // from nothing else, and reads them again during every handshake. `QuicConfig::ca_certs_pem`
    // is not the counterpart: it configures trust anchors, which is what a client verifies
    // against, and the client side of these tests does use it. Loading an identity from memory
    // needs a squiche addition mirroring `load_verify_locations_from_memory`.
    cert_file: NamedTempFile,
    key_file: NamedTempFile,
    /// Cancelled when the process shuts down. Each serve task gets a child of it, so a restart can
    /// stop one incarnation without stopping the process.
    shutdown: CancellationToken,
    serving: Mutex<Option<Serving>>,
    ca_pem: String,
    wrong_ca_pem: String,
}

/// One incarnation of the serve task.
struct Serving {
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl Http3Server {
    /// Builds a stack in [IA212], binds a socket, and serves on it.
    pub async fn start(
        ps: &PsSetup,
        args: &Args,
        counters: Arc<app::Counters>,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>, BoxError> {
        // The bound address rather than the advertised one. This process runs on the host, where
        // the advertised IP exists for the benefit of whatever reaches the topology from outside;
        // see the note on `--advertise-ip` in the crate documentation.
        let endhost_api_id = *ps
            .endhost_apis
            .get(&IA212)
            .expect("an endhost API for IA212");
        let endhost_api = pocketscion::util::addr_to_http_url(
            ps.runtime
                .endhost_api_addr(endhost_api_id)
                .expect("a bound endhost API for IA212"),
        );

        let stack = ScionStackBuilder::new()
            .with_endhost_api(endhost_api)
            .with_auth_token(dev_auth_token())
            .build()
            .await?;

        let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
        let ca_pem = cert.cert.pem();
        let cert_file = write_temp_file(ca_pem.as_bytes())?;
        let key_file = write_temp_file(cert.signing_key.serialize_pem().as_bytes())?;

        // A second authority for the same name, which signs nothing this server ever presents. A
        // client pinned to it has to reject the handshake, and it fails on trust rather than on the
        // name, which a certificate for some other host would not distinguish.
        let wrong_ca_pem = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?
            .cert
            .pem();

        let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(stack.bind(None).await?);
        let bind_addr = socket.local_addr();

        let server = Arc::new(Self {
            _stack: stack,
            socket,
            bind_addr,
            router: app::router(counters),
            max_streams: args.max_streams,
            alpn: args.alpn.as_bytes().to_vec(),
            cert_file,
            key_file,
            shutdown,
            serving: Mutex::new(None),
            ca_pem,
            wrong_ca_pem,
        });
        *server.serving.lock().await = Some(server.spawn_serve()?);

        Ok(server)
    }

    /// The port clients address the server on.
    pub fn port(&self) -> u16 {
        self.bind_addr.port()
    }

    /// The server's SCION address, without a port.
    pub fn target(&self) -> String {
        self.bind_addr.host().to_string()
    }

    /// The authority that signed the certificate the server presents.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// An authority that signed nothing, for a client that should fail to verify.
    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }

    /// Throws away every connection and serves again at the same address, with the same
    /// certificate.
    ///
    /// The address a client reaches the server at is unchanged, which is what makes this a
    /// reconnect rather than a redirect: nothing tells the client anything, and it has to establish
    /// a new connection to the same place by itself. Returns once the new endpoint is serving, so a
    /// caller that has been told the restart is done can send a request straight away.
    pub async fn restart(&self) -> Result<(), BoxError> {
        let mut serving = self.serving.lock().await;
        if let Some(previous) = serving.take() {
            previous.token.cancel();
            // Awaited, not merely cancelled: two endpoints reading the same socket would take each
            // other's datagrams, and which of them got a handshake would be a coin toss.
            let _ = previous.task.await;
        }
        *serving = Some(self.spawn_serve()?);
        Ok(())
    }

    fn spawn_serve(&self) -> Result<Serving, BoxError> {
        let quic = self.quic_config()?;
        let router = self.router.clone();
        let socket = self.socket.clone();
        let token = self.shutdown.child_token();
        let task = tokio::spawn({
            let token = token.clone();
            async move {
                let served = scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
                    socket, router, quic, token,
                )
                .await;
                if let Err(error) = served {
                    tracing::error!(%error, "The HTTP/3 server stopped");
                }
            }
        });
        Ok(Serving { token, task })
    }

    fn quic_config(&self) -> Result<squiche::Config, BoxError> {
        let mut quic = QuicConfig::builder().verify_peer(false).build();
        quic.initial_max_streams_bidi = self.max_streams;
        quic.application_protos = vec![self.alpn.clone()];
        let mut quic = quic.to_quiche_config()?;
        quic.load_cert_chain_from_pem_file(path_str(&self.cert_file))?;
        quic.load_priv_key_from_pem_file(path_str(&self.key_file))?;
        Ok(quic)
    }
}

fn write_temp_file(contents: &[u8]) -> std::io::Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    file.as_file_mut().write_all(contents)?;
    file.as_file_mut().flush()?;
    Ok(file)
}

fn path_str(file: &NamedTempFile) -> &str {
    file.path().to_str().expect("a UTF-8 temporary path")
}
