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
//! The client authenticates with an Anapaya AA API key. It exchanges the key
//! for a SNAP token on the first request and renews the token itself.
//!
//! The example starts a local two-AS PocketSCION network, serves an axum app
//! over HTTP/3 in one AS, and talks to it from the other. It also serves a
//! stand-in AA, because a local network has none. A real deployment points
//! `aa_url` at the Anapaya AA instead, and changes nothing else.
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

use std::{io::Write, net::SocketAddr, sync::Arc, time::Duration};

use anapaya_aa_protobuf::proto::anapaya::aa::v1::{
    AuthenticateByKeyRequest, AuthenticateByKeyResponse,
};
use anyhow::Context;
use axum::{
    Router,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_connect_rpc::{
    error::{CrpcError, CrpcErrorCode},
    extractor::ConnectRpc,
};
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use scion_h3_axum::ScionH3AxumServer;
use scion_http3::{ApiKeyAuth, Client, Config, Request, scion_quic::quic::config::QuicConfig};
use scion_stack::{ScionStackBuilder, resolver::txt::ScionTxtDnsResolver};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use url::Url;

/// The server name: certificate identity, SNI, and the host in every URL.
const SERVER_NAME: &str = "localhost";
/// Cap on a collected response body; a larger one fails rather than buffering
/// unboundedly. The responses here are a few bytes.
const MAX_BODY_SIZE: usize = 1024;
/// The key the stand-in AA accepts. A real key comes from your subscription.
const API_KEY: &str = "example-api-key";
/// What the AA records for this device, and puts in the token it returns.
const DEVICE_ID: &str = "example-device";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts the network, the server and the AA, then issues a GET and a POST by
/// URL.
async fn run() -> anyhow::Result<()> {
    // PocketSCION's control plane uses rustls; pick a crypto backend.
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // Start the PocketSCION network with a minimal two-AS topology.
    let ps = minimal_topology(UnderlayType::Udp).await;
    let shutdown = CancellationToken::new();

    // Serve an axum app over HTTP/3 in AS 2-ff00:0:212.
    let (server_addr, cert_file) = start_server(&ps, shutdown.clone()).await?;
    println!("HTTP/3 server listening on {server_addr}");

    let aa_url = start_aa(shutdown.clone()).await?;
    println!("Stand-in AA listening on {aa_url}");

    let endhost_api = ps.endhost_api(IA132).context("no endhost API")?;

    // ANCHOR: api-key
    // The endhost API is where the client discovers SCION connectivity. The
    // client exchanges the API key for a SNAP token at the AA on the first
    // request, and renews the token for as long as it lives.
    //
    // The stand-in AA below serves plain HTTP, which the client permits only
    // when it is told to. A deployment reaches the Anapaya AA over HTTPS and
    // drops that call.
    let config = Config::new(endhost_api)
        .with_api_key(ApiKeyAuth::new(API_KEY, aa_url, DEVICE_ID).allow_insecure_http());
    // ANCHOR_END: api-key

    let config = config
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

    // GET by URL. This request performs the key exchange; a refused key fails
    // it as `Error::StackBuild`, and `is_retryable` is then false.
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

/// Serves the AA route on the loopback address and answers with the token that
/// PocketSCION accepts. The Anapaya AA serves the same route over HTTPS.
async fn start_aa(shutdown: CancellationToken) -> anyhow::Result<Url> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let url = format!("http://{}", listener.local_addr()?).parse()?;
    let app = Router::new().route(
        "/anapaya.aa.v1.AuthService/AuthenticateByKey",
        post(authenticate),
    );

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await;
    });

    Ok(url)
}

async fn authenticate(ConnectRpc(request): ConnectRpc<AuthenticateByKeyRequest>) -> Response {
    if request.api_key != API_KEY {
        return CrpcError::new(
            CrpcErrorCode::Unauthenticated,
            "unknown API key".to_string(),
        )
        .into_response();
    }
    ConnectRpc(AuthenticateByKeyResponse {
        snap_token: dev_auth_token(),
        ..Default::default()
    })
    .into_response()
}

/// Builds a stack in AS 2-ff00:0:212, binds a socket, and serves an axum
/// router over HTTP/3 on it with a fresh self-signed certificate.
///
/// The stack takes the development token directly, because it stands in for
/// the peer this example talks to rather than for an application you write.
async fn start_server(
    ps: &PsSetup,
    shutdown: CancellationToken,
) -> anyhow::Result<(ScionSocketIpAddr, NamedTempFile)> {
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

    tokio::spawn({
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

    Ok((server_addr, cert_file))
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
