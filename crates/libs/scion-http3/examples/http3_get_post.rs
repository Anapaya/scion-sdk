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

//! URL-driven HTTP/3 over SCION: GET and POST with [`scion_http3::Client`].
//!
//! The example starts a local two-AS PocketSCION network, serves an axum app
//! over HTTP/3 in one AS, and talks to it from the other.
//!
//! ```text
//!                        +--------------------------+
//!   Client (this file)   |  PocketSCION simulation  |   Server (axum)
//!   1-ff00:0:132  ------ |  two ASes, one link      | ------  2-ff00:0:212
//!                        +--------------------------+
//! ```
//!
//! Run it with:
//!
//! ```text
//! cargo run -p scion-http3 --example http3_get_post
//! ```

use std::{io::Write, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    routing::{get, post},
};
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use scion_h3_axum::ScionH3AxumServer;
use scion_http3::{Client, Config, Request, scion_quic::quic::config::QuicConfig};
use scion_stack::{ScionStackBuilder, resolver::txt::ScionTxtDnsResolver};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

/// The server name: certificate identity, SNI, and the host in every URL.
const SERVER_NAME: &str = "localhost";
/// Cap on a collected response body; a larger one fails rather than buffering
/// unboundedly. The responses here are a few bytes.
const MAX_BODY_SIZE: usize = 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts the network and the server, then issues a GET and a POST by URL.
async fn run() -> anyhow::Result<()> {
    // PocketSCION's control plane uses rustls; pick a crypto backend.
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // Start the PocketSCION network with a minimal two-AS topology.
    let ps = minimal_topology(UnderlayType::Udp).await;

    // Serve an axum app over HTTP/3 in AS 2-ff00:0:212.
    let (server_addr, cert_file, shutdown) = start_server(&ps).await?;
    println!("HTTP/3 server listening on {server_addr}");

    // Build the client: the endhost API is how it discovers SCION connectivity.
    let config = Config::new(ps.endhost_api(IA132).context("no endhost API")?)
        .with_auth_token(dev_auth_token())
        // Trust the server's self-signed certificate.
        .with_quic_config(
            QuicConfig::builder()
                .ca_certs_file(cert_file.path().to_str().context("cert path")?)
                .build(),
        )
        // The local simulation has no DNS, so map the server name to its SCION address.
        .with_resolver(Arc::new(
            ScionTxtDnsResolver::new()?.with_override(SERVER_NAME, vec![server_addr.host()]),
        ));
    let client = Client::new(config);

    // GET by URL.
    let url = format!("https://{SERVER_NAME}:{}/hello", server_addr.port());
    let response = client.get(&url).await?;
    let (body, _trailers) = response.text(Some(MAX_BODY_SIZE)).await?;
    println!("GET {url} -> {body:?}");
    anyhow::ensure!(body == "world", "unexpected GET body: {body:?}");

    // POST with headers and a body, via the request builder.
    let url = format!("https://{SERVER_NAME}:{}/echo", server_addr.port());
    let sent = "round-trip over HTTP/3 over SCION";
    let request = Request::post(&url)
        .header("content-type", "text/plain; charset=utf-8")
        .body(sent)
        .request_timeout(Duration::from_secs(10))
        .build()?;
    let response = client.request(request).await?;
    let (body, _trailers) = response.text(Some(MAX_BODY_SIZE)).await?;
    println!("POST {url} -> {body:?}");
    anyhow::ensure!(body == sent, "echo mismatch: sent {sent:?}, got {body:?}");

    client.close().await;

    shutdown.cancel();
    Ok(())
}

/// Builds a stack in AS 2-ff00:0:212, binds a socket, and serves an axum
/// router over HTTP/3 on it with a fresh self-signed certificate.
async fn start_server(
    ps: &PsSetup,
) -> anyhow::Result<(ScionSocketIpAddr, NamedTempFile, CancellationToken)> {
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).context("no endhost API")?)
        .with_auth_token(dev_auth_token())
        .build()
        .await?;
    let socket = Arc::new(stack.bind(None).await?);
    let server_addr = socket.local_addr();

    // squiche loads certificates from files, so write the generated
    // certificate and key to temporary files kept alive by the server task.
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let mut cert_file = NamedTempFile::new()?;
    let mut key_file = NamedTempFile::new()?;
    cert_file
        .as_file_mut()
        .write_all(cert.cert.pem().as_bytes())?;
    key_file
        .as_file_mut()
        .write_all(cert.signing_key.serialize_pem().as_bytes())?;

    let mut server_config = QuicConfig::builder().build().to_quiche_config()?;
    server_config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().context("cert path")?)
        .map_err(|e| anyhow::anyhow!("loading certificate: {e}"))?;
    server_config
        .load_priv_key_from_pem_file(key_file.path().to_str().context("key path")?)
        .map_err(|e| anyhow::anyhow!("loading key: {e}"))?;

    let app = Router::new()
        .route("/hello", get(|| async { "world" }))
        .route("/echo", post(|body: String| async move { body }));

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let _stack = stack;
            let _key_file = key_file;
            let _ = ScionH3AxumServer::serve_with_graceful_shutdown(
                socket,
                app,
                server_config,
                shutdown,
            )
            .await;
        }
    });

    Ok((server_addr, cert_file, shutdown))
}

#[cfg(test)]
mod tests {
    use test_log::test;

    /// Runs the whole example end-to-end as part of `cargo test`.
    #[test(tokio::test)]
    #[ntest::timeout(120_000)]
    async fn example_runs() {
        super::run().await.unwrap();
    }
}
