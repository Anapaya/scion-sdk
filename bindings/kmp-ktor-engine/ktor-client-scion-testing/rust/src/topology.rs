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

//! A PocketSCION topology with an HTTP/3 server in AS 2-ff00:0:212.
//!
//! The client attaches to AS 1-ff00:0:132.
//!
//! A server of the user can attach to AS 2-ff00:0:212 beside the built-in one,
//! through [`Topology::server_endhost_api_url`].
//!
//! The server presents a certificate for `localhost`, `web_gateway::HTTP1_HOST`
//! and `web_gateway::TLS_HOST`, signed by a new CA on every start.

mod test_api;
mod web_gateway;

use std::{collections::HashMap, io::Write, net::SocketAddr, sync::Arc};

use axum::extract::Request;
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use scion_quic::{quic::config::QuicConfig, reexport::squiche, socket::GenericScionUdpSocket};
use scion_stack::{ScionStack, ScionStackBuilder};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

use crate::topology::{test_api::TestApi, web_gateway::WebGateway};

/// The host that a client addresses the server by.
const SERVER_NAME: &str = "localhost";

type BoxError = Box<dyn std::error::Error>;

/// What a topology starts with.
pub struct Options {
    /// How the client and the server enter the network. Each AS gets a router
    /// that they reach over UDP, or a SNAP.
    pub underlay: UnderlayType,
    /// `CONNECT` authorities, as `host` or `host:port`, to TCP backends. The
    /// module doc of `web_gateway` has the match rules.
    pub gateway_backends: HashMap<String, SocketAddr>,
}

/// A running topology and server. Dropping it stops both.
pub struct Topology {
    // Dropping either one stops the topology or the socket of the server.
    _ps: PsSetup,
    _stack: ScionStack,
    shutdown: CancellationToken,
    endhost_api_url: String,
    server_endhost_api_url: String,
    port: u16,
    target: String,
    ca_pem: String,
    wrong_ca_pem: String,
}

impl Topology {
    /// Starts the topology and serves the test API and the gateway in it.
    pub async fn start(options: Options) -> Result<Self, BoxError> {
        // Discovery speaks TLS through rustls, which needs a provider.
        scion_sdk_utils::rustls::select_ring_crypto_provider();

        // Start the network.
        let ps = minimal_topology(options.underlay).await;
        let endhost_api_url = ps
            .endhost_api(IA132)
            .ok_or("no endhost API for IA132")?
            .to_string();

        // Bind the socket of the server.
        let server_endhost_api = pocketscion::util::addr_to_http_url(
            ps.runtime
                .endhost_api_addr(
                    *ps.endhost_apis
                        .get(&IA212)
                        .ok_or("no endhost API for IA212")?,
                )
                .ok_or("the endhost API for IA212 is not bound")?,
        );
        let server_endhost_api_url = server_endhost_api.to_string();
        let stack = ScionStackBuilder::new()
            .with_endhost_api(server_endhost_api)
            .with_auth_token(dev_auth_token())
            .build()
            .await?;
        let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(stack.bind(None).await?);
        let bind_addr = socket.local_addr();

        // Route the test API and the gateway.
        let identity = Identity::generate()?;
        let gateway = Arc::new(WebGateway::new(
            TestApi::router(),
            identity.rustls_config()?,
            &options.gateway_backends,
        ));
        let router = TestApi::router().fallback(move |request: Request| {
            let gateway = gateway.clone();
            async move { gateway.answer(request).await }
        });

        // Configure QUIC for HTTP/3.
        let mut quic = QuicConfig::builder().verify_peer(false).build();
        quic.application_protos = vec![b"h3".to_vec()];
        let mut quic: squiche::Config = quic.to_quiche_config()?;

        // squiche loads the identity of the server from files only. It reads
        // them once, here.
        let cert_file = temp_file(identity.leaf.cert.pem().as_bytes())?;
        let key_file = temp_file(identity.leaf.signing_key.serialize_pem().as_bytes())?;
        quic.load_cert_chain_from_pem_file(path_str(&cert_file))?;
        quic.load_priv_key_from_pem_file(path_str(&key_file))?;

        // Serve until shutdown.
        let shutdown = CancellationToken::new();
        let token = shutdown.child_token();
        tokio::spawn(async move {
            let served = scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
                socket, router, quic, token,
            )
            .await;
            if let Err(error) = served {
                tracing::error!(%error, "the HTTP/3 server stopped");
            }
        });

        return Ok(Topology {
            _ps: ps,
            _stack: stack,
            shutdown,
            endhost_api_url,
            server_endhost_api_url,
            port: bind_addr.port(),
            target: bind_addr.host().to_string(),
            ca_pem: identity.ca_pem,
            wrong_ca_pem: identity.wrong_ca_pem,
        });

        fn temp_file(contents: &[u8]) -> std::io::Result<NamedTempFile> {
            let mut file = NamedTempFile::new()?;
            file.as_file_mut().write_all(contents)?;
            file.as_file_mut().flush()?;
            Ok(file)
        }

        fn path_str(file: &NamedTempFile) -> &str {
            file.path().to_str().expect("a UTF-8 temporary path")
        }
    }

    /// Where a client discovers its connectivity.
    pub fn endhost_api_url(&self) -> &str {
        &self.endhost_api_url
    }

    /// Where a server in AS 2-ff00:0:212 discovers its connectivity.
    pub fn server_endhost_api_url(&self) -> &str {
        &self.server_endhost_api_url
    }

    /// The bearer token that the endhost API and the SNAP control plane accept.
    pub fn auth_token(&self) -> String {
        dev_auth_token()
    }

    /// `https://localhost:<port>`.
    pub fn base_url(&self) -> String {
        format!("https://{SERVER_NAME}:{}", self.port)
    }

    /// The port of the built-in server, and of the gateway in it.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The SCION address of the built-in server, without a port. A server of
    /// the user in AS 2-ff00:0:212 on this host gets the same address. The topology has no
    /// TSAR records, so a client sets this as a DNS override.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The CA that signed the certificate of the server.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// A CA that signs nothing here, for a client that must fail to verify.
    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The certificates of the server.
struct Identity {
    leaf: rcgen::CertifiedKey<rcgen::KeyPair>,
    ca_pem: String,
    wrong_ca_pem: String,
}

impl Identity {
    fn generate() -> Result<Self, rcgen::Error> {
        // A CA signs the leaf. Android installs a user CA only if the
        // certificate is a CA.
        let mut ca_params = rcgen::CertificateParams::new(Vec::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ktor-scion-testing CA");
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate()?)?;

        // Issue the leaf for every test host.
        let leaf_key = rcgen::KeyPair::generate()?;
        let mut leaf_params = rcgen::CertificateParams::new(vec![
            SERVER_NAME.to_string(),
            web_gateway::HTTP1_HOST.to_string(),
            web_gateway::TLS_HOST.to_string(),
        ])?;
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = rcgen::CertifiedKey {
            cert: leaf_params.signed_by(&leaf_key, &ca)?,
            signing_key: leaf_key,
        };

        // A certificate for the same name, so that a client pinned to it
        // fails on trust, not on the name.
        let wrong_ca_pem = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?
            .cert
            .pem();

        Ok(Identity {
            leaf,
            ca_pem: ca.pem(),
            wrong_ca_pem,
        })
    }

    /// The same identity for the TLS server inside the `https.invalid`
    /// tunnel, so that a client verifies both against one CA.
    fn rustls_config(&self) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![self.leaf.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.leaf.signing_key.serialize_der()).into(),
        )?;
        Ok(Arc::new(config))
    }
}
