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

//! Integration tests for trust anchors supplied to [`QuicConfig`] in memory
//! ([`QuicConfigBuilder::ca_certs_pem`]), the path Android clients use for
//! anchors held by the system key store.
//!
//! Each test runs an HTTP/3 server over an in-memory SCION socket pair and
//! connects an [`Http3Client`] with `verify_peer(true)`, so the certificate
//! chain is verified for real.

mod common;

use std::{
    convert::Infallible,
    io::Write,
    net::Ipv4Addr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame};
use scion_quic::{
    h3::{
        client::{EstablishError, Http3Client, RequestError},
        server::{H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    },
    quic::{
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::GenericScionUdpSocket,
};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

use crate::common::{MockScionSocket, generate_server_config_with_cert, test_metrics};

/// The name in the server certificate, and the SNI the client sends.
const SERVER_NAME: &str = "localhost";

fn client_addr() -> ScionSocketIpAddr {
    ScionSocketIpAddr::new(
        "1-ff00:0:0".parse().unwrap(),
        Ipv4Addr::new(10, 1, 1, 1).into(),
        40001,
    )
}

fn server_addr() -> ScionSocketIpAddr {
    ScionSocketIpAddr::new(
        "2-ff00:0:0".parse().unwrap(),
        Ipv4Addr::new(10, 2, 1, 1).into(),
        40002,
    )
}

/// A response body yielding a single buffer.
struct OnceBody(Option<Bytes>);

impl Body for OnceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
    }
}

/// Answers every request with `200 OK` and a fixed body.
#[derive(Clone)]
struct OkService;

impl HttpService for OkService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, _req: http::Request<H3RequestBody>) -> http::Response<OnceBody> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(OnceBody(Some(Bytes::from_static(b"hello"))))
            .unwrap()
    }
}

/// A running HTTP/3 server. Dropping it stops the endpoint driver.
struct TestServer {
    /// The PEM-encoded self-signed certificate the server presents. This is the
    /// only anchor that verifies its chain.
    cert_pem: String,
    cancel: CancellationToken,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Spawns a server serving [`OkService`], and returns it with the client-side
/// half of the socket pair connected to it.
fn spawn_server() -> (TestServer, Arc<MockScionSocket>) {
    let (client_socket, server_socket) = MockScionSocket::pair(8192, client_addr(), server_addr());
    let server_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(server_socket);
    let scion_addr = server_socket.local_addr();

    let (config, cert_pem, cert, key) = generate_server_config_with_cert();
    let endpoint = QuicScionServerEndpoint::new([3u8; 32], config, scion_addr, test_metrics());

    let driver = QuicScionEndpointDriver::with_config(
        endpoint,
        server_socket,
        |_handle: ConnectionHandle<Http3Server<OkService>>| {},
        Http3ServerConfig::new(OkService),
    );

    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        // Keep the certificate/key temp files alive for the server's lifetime.
        let _keep_alive = (cert, key);
        let _ = driver.run(cancel_task).await;
    });

    (TestServer { cert_pem, cancel }, Arc::new(client_socket))
}

/// A client that verifies the server certificate against `config`'s anchors.
fn make_client(socket: Arc<MockScionSocket>, config: QuicConfig) -> Http3Client {
    Http3Client::with_config(server_addr(), socket, Some(SERVER_NAME.to_string()), config)
}

/// Issues `GET /` and returns the response status.
async fn get(client: &Http3Client) -> Result<http::StatusCode, RequestError> {
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{SERVER_NAME}/"))
        .body(OnceBody(None))
        .unwrap();
    Ok(client.request(req).await?.status())
}

/// A self-signed certificate for `SERVER_NAME` that no server in these tests
/// presents: an anchor that verifies nothing.
///
/// Its subject differs from the one the test servers use, so a store holding
/// both anchors can tell them apart by subject.
fn unrelated_cert_pem() -> String {
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, "unrelated test anchor");
    params.distinguished_name = name;

    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().pem()
}

/// The handshake succeeds with `verify_peer(true)` when the only trust anchor
/// is handed to the config in memory: no file backs the anchor.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn in_memory_anchor_verifies_server() {
    let (server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .ca_certs_pem(server.cert_pem.clone().into_bytes())
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// An in-memory anchor that did not sign the server's certificate fails the
/// handshake instead of being waved through.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn non_matching_in_memory_anchor_rejects_server() {
    let (_server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .ca_certs_pem(unrelated_cert_pem().into_bytes())
            .build(),
    );

    let err = get(&client).await.expect_err("handshake should fail");
    assert!(
        matches!(
            err,
            RequestError::Establish(EstablishError::Handshake | EstablishError::Quic(_))
        ),
        "unexpected error: {err:?}"
    );
}

/// The in-memory bundle adds to the file-based anchors rather than replacing
/// them: a chain anchored in either source verifies.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn in_memory_anchor_adds_to_file_anchor() {
    let (server, socket) = spawn_server();

    // The file holds an anchor that verifies nothing, so the handshake can only
    // succeed through the in-memory bundle.
    let mut unrelated_file = NamedTempFile::new().unwrap();
    unrelated_file
        .as_file_mut()
        .write_all(unrelated_cert_pem().as_bytes())
        .unwrap();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .ca_certs_file(unrelated_file.path().to_str().unwrap())
            .ca_certs_pem(server.cert_pem.clone().into_bytes())
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// A bundle without a certificate is rejected where the config is turned into a
/// `squiche::Config`, not silently ignored.
#[test]
fn malformed_in_memory_bundle_is_rejected() {
    let config = QuicConfig::builder()
        .verify_peer(true)
        .ca_certs_pem(b"not a pem bundle".to_vec())
        .build();

    assert!(config.to_quiche_config().is_err());
}
