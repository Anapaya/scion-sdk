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

//! Shared setup for the PocketSCION end-to-end tests: an axum-over-HTTP/3
//! server in one AS of a minimal topology.

#![allow(dead_code)]

use std::{io::Write, sync::Arc, time::Duration};

use axum::{
    Router,
    routing::{get, post},
};
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use scion_http3::{Config, scion_quic::quic::config::QuicConfig};
use scion_stack::ScionStackBuilder;
use sciparse::address::{ip_addr::ScionIpAddr, ip_socket_addr::ScionSocketIpAddr};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

/// The server name in the test URLs and the server certificate.
pub const SERVER_NAME: &str = "localhost";

/// A PocketSCION network with an HTTP/3 server running in AS 2-ff00:0:212.
pub struct E2eSetup {
    /// The running topology (dropping it stops the simulation).
    pub ps: PsSetup,
    /// The server's SCION address, including its (ephemeral) port.
    pub server_addr: ScionSocketIpAddr,
    /// The self-signed certificate the server presents, for `ca_certs_file`.
    pub cert_file: NamedTempFile,
    shutdown: CancellationToken,
}

impl E2eSetup {
    /// The server's address without the port, as resolution would return it.
    pub fn server_ip(&self) -> ScionIpAddr {
        self.server_addr.host()
    }

    /// A URL for `path` on the test server.
    pub fn url(&self, path: &str) -> String {
        format!("https://{SERVER_NAME}:{}{path}", self.server_addr.port())
    }

    /// A client [`Config`] for the topology: endhost API of AS 1-ff00:0:132,
    /// dev auth token, and trust in the server's certificate.
    pub fn client_config(&self) -> Config {
        Config::new(self.ps.endhost_api(IA132).expect("endhost API for IA132"))
            .with_auth_token(dev_auth_token())
            .with_quic_config(
                QuicConfig::builder()
                    .ca_certs_file(self.cert_file.path().to_str().expect("UTF-8 path"))
                    .build(),
            )
    }
}

impl Drop for E2eSetup {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Starts a minimal UDP-underlay topology and serves the test router over
/// HTTP/3 in AS 2-ff00:0:212.
pub async fn e2e_setup() -> E2eSetup {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let ps = minimal_topology(UnderlayType::Udp).await;

    let server_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).expect("endhost API for IA212"))
        .with_auth_token(dev_auth_token())
        .build()
        .await
        .expect("building server stack");
    let server_socket = Arc::new(
        server_stack
            .bind(None)
            .await
            .expect("binding server socket"),
    );
    let server_addr = server_socket.local_addr();

    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    cert_file
        .as_file_mut()
        .write_all(cert.cert.pem().as_bytes())
        .unwrap();
    key_file
        .as_file_mut()
        .write_all(cert.signing_key.serialize_pem().as_bytes())
        .unwrap();

    let mut server_config = QuicConfig::builder()
        .build()
        .to_quiche_config()
        .expect("building quiche server config");
    server_config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .unwrap();
    server_config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .unwrap();

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        let router = test_router();
        async move {
            // The stack must outlive the server: sockets bound from it stay
            // functional only while it is alive.
            let _stack = server_stack;
            let _key_file = key_file;
            let _ = scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
                server_socket,
                router,
                server_config,
                shutdown,
            )
            .await;
        }
    });

    E2eSetup {
        ps,
        server_addr,
        cert_file,
        shutdown,
    }
}

fn test_router() -> Router {
    Router::new()
        .route("/hello", get(|| async { "world" }))
        .route("/echo", post(|body: String| async move { body }))
        .route(
            "/slow",
            get(|| {
                async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    "slow"
                }
            }),
        )
}
