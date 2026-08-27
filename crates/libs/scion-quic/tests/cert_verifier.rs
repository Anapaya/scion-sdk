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

//! Integration tests for the caller-supplied certificate verifier
//! ([`QuicConfigBuilder::with_cert_verifier`]).
//!
//! Each test runs an HTTP/3 server over an in-memory SCION socket pair and
//! connects an [`Http3Client`], so the verifier runs inside a real handshake.

mod common;

use std::{
    convert::Infallible,
    io::Write,
    net::Ipv4Addr,
    panic,
    pin::Pin,
    sync::{Arc, Mutex},
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
        cert_verifier::{CertRejected, CertVerifier, PeerCertificates},
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::GenericScionUdpSocket,
};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

use crate::common::{MockScionSocket, test_metrics};

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
///
/// The server presents a leaf certificate together with the CA that issued it.
struct TestServer {
    /// The leaf, which a verifier sees first.
    leaf_der: Vec<u8>,
    /// The certificate the leaf chains up to, which a verifier sees second.
    ca_der: Vec<u8>,
    /// The CA in PEM form: the one anchor that verifies the server's chain.
    ca_pem: String,
    /// Kept alive because the server reads them while it runs.
    _files: (NamedTempFile, NamedTempFile),
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
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test chain ca");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

    // The leaf comes first in the file, which is the order the server sends.
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file
        .as_file_mut()
        .write_all(format!("{}{}", leaf.pem(), ca.pem()).as_bytes())
        .unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file
        .as_file_mut()
        .write_all(leaf_key.serialize_pem().as_bytes())
        .unwrap();

    let mut config = QuicConfig::builder()
        .verify_peer(false)
        .build()
        .to_quiche_config()
        .unwrap();
    config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .unwrap();

    let (client_socket, server_socket) = MockScionSocket::pair(8192, client_addr(), server_addr());
    let server_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(server_socket);
    let scion_addr = server_socket.local_addr();

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
        let _ = driver.run(cancel_task).await;
    });

    (
        TestServer {
            leaf_der: leaf.der().to_vec(),
            ca_der: ca.der().to_vec(),
            ca_pem: ca.pem(),
            _files: (cert_file, key_file),
            cancel,
        },
        Arc::new(client_socket),
    )
}

/// A client that verifies the server certificate the way `config` says.
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

/// Asserts that `err` is a verifier rejection carrying `reason`, and that the
/// message a caller prints names it.
fn assert_rejected_with(err: &RequestError, reason: &str) {
    let RequestError::Establish(EstablishError::CertificateRejected(rejected)) = err else {
        panic!("unexpected error: {err:?}");
    };

    assert_eq!(rejected.message(), reason);
    assert!(
        err.to_string().contains(reason),
        "the printed error does not name the reason: {err}"
    );
}

/// The handshake succeeds with `verify_peer(true)` on a verifier's verdict
/// alone: no CA file, directory, or in-memory bundle is configured, so nothing
/// else could have accepted the self-signed chain.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn verifier_accepts_chain_with_no_ca_source() {
    let (_server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(|_: &PeerCertificates<'_>| Ok(()))
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// The premise of the two tests below: with no verifier, the CA alone verifies
/// the server's chain. Without this, a rejection in
/// `verifier_rejects_chain_that_the_anchors_accept` would prove nothing,
/// because a verifier rejects before an anchor is ever consulted.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn anchors_alone_verify_the_chain() {
    let (server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .ca_certs_pem(server.ca_pem.clone().into_bytes())
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// A verifier replaces anchor-based validation rather than adding to it: a
/// chain that the configured anchor verifies still fails when the verifier
/// rejects it, and the failure names the verifier's reason.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn verifier_rejects_chain_that_the_anchors_accept() {
    let (server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            // Without the verifier this anchor alone verifies the chain, as
            // `anchors_alone_verify_the_chain` shows.
            .ca_certs_pem(server.ca_pem.clone().into_bytes())
            .with_cert_verifier(|_: &PeerCertificates<'_>| {
                Err(CertRejected::new("not the pinned server"))
            })
            .build(),
    );

    let err = get(&client).await.expect_err("handshake should fail");
    assert_rejected_with(&err, "not the pinned server");
}

/// The other direction of the same rule: anchors that verify nothing do not
/// stop a verifier from accepting the chain.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn verifier_accepts_chain_that_the_anchors_reject() {
    let (_server, socket) = spawn_server();

    let unrelated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .unwrap()
        .cert
        .pem();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .ca_certs_pem(unrelated.into_bytes())
            .with_cert_verifier(|_: &PeerCertificates<'_>| Ok(()))
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// The verifier receives the chain the server sent, leaf first and DER encoded,
/// together with the name the connection was opened with.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn verifier_sees_the_chain_and_the_server_name() {
    let (server, socket) = spawn_server();

    let seen = Arc::new(Mutex::new(None));
    let recorder = Arc::clone(&seen);

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(move |peer: &PeerCertificates<'_>| {
                let chain = peer.chain().iter().map(|c| c.to_vec()).collect::<Vec<_>>();
                *recorder.lock().unwrap() = Some((chain, peer.server_name().map(str::to_string)));

                Ok(())
            })
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);

    let (chain, server_name) = seen.lock().unwrap().take().expect("verifier ran");

    assert_eq!(server_name.as_deref(), Some(SERVER_NAME));
    assert_eq!(chain, vec![server.leaf_der.clone(), server.ca_der.clone()]);
}

/// A verifier that carries state is a plain trait implementation, which is how
/// a platform verifier is written.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn a_trait_implementation_works_as_a_verifier() {
    /// Accepts exactly one leaf certificate.
    struct PinnedLeaf(Vec<u8>);

    impl CertVerifier for PinnedLeaf {
        fn verify(&self, peer: &PeerCertificates<'_>) -> Result<(), CertRejected> {
            match peer.chain().first() {
                Some(leaf) if *leaf == self.0.as_slice() => Ok(()),
                _ => Err(CertRejected::new("the leaf is not the pinned one")),
            }
        }
    }

    let (pinned, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(PinnedLeaf(pinned.leaf_der.clone()))
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);

    // A second server has a certificate of its own, which the same verifier
    // refuses. Each server owns its socket pair, so the two do not share a
    // connection.
    let (_other, other_socket) = spawn_server();

    let client = make_client(
        other_socket,
        QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(PinnedLeaf(pinned.leaf_der.clone()))
            .build(),
    );

    let err = get(&client).await.expect_err("handshake should fail");
    assert_rejected_with(&err, "the leaf is not the pinned one");
}

/// A panic inside a verifier rejects the connection instead of unwinding into
/// the TLS library, and the caller is told what happened.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn a_panicking_verifier_rejects_the_connection() {
    let (_server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(|_: &PeerCertificates<'_>| -> Result<(), CertRejected> {
                panic!("verifier is broken")
            })
            .build(),
    );

    // The hook is global, so it is restored before the assertions run.
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let err = get(&client).await.expect_err("handshake should fail");
    panic::set_hook(hook);

    assert_rejected_with(&err, "the certificate verifier panicked");
}

/// `verify_peer` still decides whether a verdict is fatal: without it a
/// rejection is ignored, exactly as a failed built-in check is.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn a_rejection_is_not_fatal_without_verify_peer() {
    let (_server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .verify_peer(false)
            .with_cert_verifier(|_: &PeerCertificates<'_>| {
                Err(CertRejected::new("rejected, but not enforced"))
            })
            .build(),
    );

    assert_eq!(get(&client).await.expect("request"), http::StatusCode::OK);
}

/// The setters compose in either order, so a caller cannot lose verification by
/// configuring the two the other way round.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn the_verifier_may_be_set_before_verify_peer() {
    let (_server, socket) = spawn_server();

    let client = make_client(
        socket,
        QuicConfig::builder()
            .with_cert_verifier(|_: &PeerCertificates<'_>| Err(CertRejected::new("no thanks")))
            .verify_peer(true)
            .build(),
    );

    let err = get(&client).await.expect_err("handshake should fail");
    assert_rejected_with(&err, "no thanks");
}
