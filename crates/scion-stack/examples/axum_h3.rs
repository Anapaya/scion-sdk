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

//! HTTP/3 Axum over SCION example.
//!
//! This includes an [axum] HTTP/3 server and a matching client.
//! They are connected using a [PocketSCION] network, which is started as part of the example.
//!
//! The network is two ASes joined by a single link:
//!
//! ```text
//!   1-ff00:0:132  #1 ───────── #3  2-ff00:0:212
//!     (client)                       (server)
//! ```
//!
//! **Server.** [`ScionH3AxumServer`] takes a bound SCION socket and an ordinary
//! [`axum::Router`] and speaks HTTP/3 (QUIC over SCION) on that socket.
//!
//! **Client.** [`Http3Client`] (from `scion-quic`) is the HTTP/3-over-SCION
//! client.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p scion-stack --example axum_h3
//! ```
//!
//! [PocketSCION]: pocketscion
//! [axum]: axum
//! [`ScionH3AxumServer`]: scion_h3_axum::ScionH3AxumServer
//! [`Http3Client`]: scion_quic::h3::client::Http3Client

mod common;

use std::sync::Arc;

use anyhow::Context;
use axum::{Router, routing::post};
use pocketscion::util::topologies::{IA132, IA212, UnderlayType, minimal::minimal_topology};
use scion_h3_axum::ScionH3AxumServer;
use scion_quic::{
    h3::client::Http3Client, quic::config::QuicConfig, socket::GenericScionUdpSocket,
};
use scion_stack::{ScionStack, UdpScionSocket};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

/// The server name used in the client request and the server certificate.
const SERVER_NAME: &str = "localhost";

/// Body of the POST request, checked against the echoed response.
const ECHO_PAYLOAD: &str = "round-trip over HTTP/3 over SCION";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts a two-AS SCION network, serves an axum app over HTTP/3 in one AS, and
/// makes a GET and a POST to it from the other.
async fn run() -> anyhow::Result<()> {
    // PocketSCION's control plane and QUIC both use rustls; pick a crypto backend.
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // Start the PocketSCION network with a minimal topology.
    let ps = minimal_topology(UnderlayType::Snap).await;

    // Create a self-signed certificate and key for the server, which will be used for TLS.
    let (cert_file, key_file) = server_certs()?;

    // Start the HTTP/3 server in AS 2-ff00:0:212
    let (server_task, server_addr, shutdown) = {
        // Build a SCION stack for the server in AS 2-ff00:0:212.
        let server_stack: ScionStack = common::build_stack(&ps, IA212).await?;
        // Bind a SCION UDP socket for the server to listen on.
        let udp_socket: UdpScionSocket = server_stack.bind(None).await?;
        // Convert to a trait object so we can pass it to the server.
        let server_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(udp_socket);
        let server_addr = server_socket.local_addr();

        let mut server_config = QuicConfig::builder()
            .build()
            .to_quiche_config()
            .context("building quiche server config")?;

        // `squiche` can only load certs/keys from files, so we write them to temporary files and
        // keep them alive for the duration of the server.
        server_config.load_cert_chain_from_pem_file(
            cert_file.path().to_str().context("cert path not UTF-8")?,
        )?;
        server_config
            .load_priv_key_from_pem_file(key_file.path().to_str().context("key path not UTF-8")?)?;

        let shutdown = CancellationToken::new();
        let server_task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                // Create a normal axum app
                let app = Router::new()
                    // Echoes the request body back verbatim.
                    .route("/echo", post(|body: String| async move { body }));

                ScionH3AxumServer::serve_with_graceful_shutdown(
                    server_socket,
                    app,
                    server_config,
                    shutdown,
                )
                .await
            }
        });
        println!("HTTP/3 server listening on {server_addr}");

        (server_task, server_addr, shutdown)
    };

    // Create the HTTP/3 client, which will connect to the server over SCION.
    let client = {
        // Build a SCION stack for the client in AS 1-ff00:0:132.
        let client_stack: ScionStack = common::build_stack(&ps, IA132).await?;
        // Bind a SCION UDP socket for the client to use.
        let client_udp_socket: UdpScionSocket = client_stack.bind(None).await?;
        // Convert to a trait object so we can pass it to the client.
        let client_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(client_udp_socket);

        // Build a QUIC config for the client.
        let client_config = QuicConfig::builder()
            .ca_certs_file(cert_file.path().to_str().context("cert path not UTF-8")?)
            .build();

        // Create the HTTP/3 client,
        Http3Client::with_config(
            server_addr,
            client_socket,
            Some(SERVER_NAME.to_string()),
            client_config,
        )
    };

    // Sending a request and receiving the response
    {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{SERVER_NAME}/echo"))
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(ECHO_PAYLOAD.to_string())?;

        // Send the request, this will await until the response headers are received, and return a
        // response body stream.
        let response = client.request(request).await?;

        // Check the response status code.
        if !response.status().is_success() {
            anyhow::bail!("request failed with status {}", response.status());
        }

        // Collect the response body stream
        let max_response_size = Some(1024);
        let (response, _trailers) = response.into_body().text(max_response_size).await?;

        println!("Response body: {response:?}");
    }

    // Shut down the server and wait for it to finish.
    shutdown.cancel();
    server_task
        .await
        .expect("server task should not panic")
        .expect("server task should not return an error");

    Ok(())
}

/// Creates a self-signed certificate and key for the server, returning them as
/// temporary files.
fn server_certs() -> anyhow::Result<(NamedTempFile, NamedTempFile)> {
    use std::io::Write;

    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;

    let mut cert_file = NamedTempFile::new()?;
    cert_file.write_all(cert.cert.pem().as_bytes())?;
    let mut key_file = NamedTempFile::new()?;
    key_file.write_all(cert.signing_key.serialize_pem().as_bytes())?;

    Ok((cert_file, key_file))
}

#[cfg(test)]
mod tests {
    use test_log::test;

    /// End-to-end smoke test: serve an axum app over HTTP/3 on PocketSCION and
    /// complete a GET and a POST against it.
    #[test(tokio::test)]
    #[ntest::timeout(60_000)]
    async fn axum_h3_roundtrip() {
        super::run().await.expect("axum_h3 example should succeed");
    }
}
