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

//! Integration tests for [`CrpcClient`].
//!
//! These tests run a HTTP/3-over-QUIC server reachable through an in-memory mock SCION socket,
//! and exercise the client against it — including the multi-remote failover behaviour.

use std::{
    convert::Infallible, io, net::Ipv4Addr, pin::Pin, sync::Arc, task::Poll, time::Duration,
};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::{Body, Frame};
use prost::Message as _;
use scion_connect_rpc::client::{ConnectRpcClient, CrpcClient, RemoteEndpoint};
use scion_quic::{
    h3::server::{H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    quic::{
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{Metrics, QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::{BoxedSocketError, GenericScionUdpSocket},
};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

const SERVICE_URL: &str = "https://localhost/test.v1.EchoService/Echo";

/// A tiny prost message used for the echo round-trip.
#[derive(Clone, PartialEq, prost::Message)]
struct Echo {
    #[prost(string, tag = "1")]
    value: String,
}

struct MockDatagram {
    data: Vec<u8>,
    src: ScionSocketIpAddr,
    dst: ScionSocketIpAddr,
}

struct MockScionSocket {
    recv_channel: Mutex<mpsc::Receiver<MockDatagram>>,
    send_channel: mpsc::Sender<MockDatagram>,
    local_addr: ScionSocketIpAddr,
}

impl MockScionSocket {
    fn pair(
        queue_size: usize,
        addr_a: ScionSocketIpAddr,
        addr_b: ScionSocketIpAddr,
    ) -> (MockScionSocket, MockScionSocket) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(queue_size);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(queue_size);

        let socket_a = MockScionSocket {
            recv_channel: Mutex::new(a_to_b_rx),
            send_channel: b_to_a_tx,
            local_addr: addr_a,
        };
        let socket_b = MockScionSocket {
            recv_channel: Mutex::new(b_to_a_rx),
            send_channel: a_to_b_tx,
            local_addr: addr_b,
        };
        (socket_a, socket_b)
    }
}

#[async_trait::async_trait]
impl GenericScionUdpSocket for MockScionSocket {
    async fn send_to(
        &self,
        payload: &[u8],
        destination: ScionSocketIpAddr,
    ) -> Result<(), BoxedSocketError> {
        let datagram = MockDatagram {
            data: payload.to_vec(),
            src: self.local_addr,
            dst: destination,
        };
        self.send_channel
            .send(datagram)
            .await
            .map_err(|e| Box::new(e) as BoxedSocketError)
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketIpAddr), BoxedSocketError> {
        loop {
            let datagram = self.recv_channel.lock().await.recv().await.ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed",
                )) as BoxedSocketError
            })?;

            if datagram.dst != self.local_addr {
                continue;
            }

            let len = datagram.data.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram.data[..len]);
            return Ok((len, datagram.src));
        }
    }

    fn local_addr(&self) -> ScionSocketIpAddr {
        self.local_addr
    }
}

/// A SCION socket that silently drops everything it sends and never receives, simulating a remote
/// to which the QUIC handshake never completes (i.e. an unreachable service).
struct BlackholeSocket {
    local_addr: ScionSocketIpAddr,
}

#[async_trait::async_trait]
impl GenericScionUdpSocket for BlackholeSocket {
    async fn send_to(
        &self,
        _payload: &[u8],
        _dst: ScionSocketIpAddr,
    ) -> Result<(), BoxedSocketError> {
        Ok(())
    }

    async fn recv_from(
        &self,
        _buf: &mut [u8],
    ) -> Result<(usize, ScionSocketIpAddr), BoxedSocketError> {
        // Never delivers a datagram: the handshake against this remote can only ever time out.
        std::future::pending().await
    }

    fn local_addr(&self) -> ScionSocketIpAddr {
        self.local_addr
    }
}

fn scion_addr(idx: u8, host_octet: u8, port: u16) -> ScionSocketIpAddr {
    let ia = "1-1".parse().unwrap();
    ScionSocketIpAddr::new(ia, Ipv4Addr::new(10, 0, idx, host_octet).into(), port)
}

/// Builds a server-side [`squiche::Config`] with a freshly generated self-signed certificate. The
/// returned temp files must be kept alive until the config has been fully loaded.
fn make_server_quic_config() -> (squiche::Config, NamedTempFile, NamedTempFile) {
    let mut config = QuicConfig::builder()
        .verify_peer(false)
        .build()
        .to_quiche_config()
        .expect("to_quiche_config");

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen cert gen");

    let mut cert_file = NamedTempFile::new().expect("cert temp file");
    let mut key_file = NamedTempFile::new().expect("key temp file");

    use std::io::Write as _;
    cert_file
        .write_all(cert.cert.pem().as_bytes())
        .expect("write cert");
    key_file
        .write_all(cert.signing_key.serialize_pem().as_bytes())
        .expect("write key");

    config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .expect("load cert");
    config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .expect("load key");

    (config, cert_file, key_file)
}

/// An [`HttpService`] that echoes the request's `value` back, prefixed with `prefix` so the test
/// can tell which server responded.
#[derive(Clone)]
struct EchoService {
    prefix: &'static str,
}

impl HttpService for EchoService {
    type Body = H3RequestBody;
    type ResponseBody = FullBody;

    async fn call(&self, req: http::Request<H3RequestBody>) -> http::Response<FullBody> {
        let body = read_request_body(req.into_body()).await;
        let echo = Echo::decode(&body[..]).unwrap_or_default();
        let response = Echo {
            value: format!("{}{}", self.prefix, echo.value),
        };
        http::Response::builder()
            .status(StatusCode::OK)
            .body(FullBody::new(response.encode_to_vec()))
            .expect("response is always well-formed")
    }
}

/// Spawns an echo Connect-RPC server reachable through a fresh mock socket pair. Each request is
/// answered by echoing the request's `value` back, prefixed with `prefix` so the test can tell
/// which server responded. Returns the client-side socket and the SCION address to dial.
fn spawn_echo_server(
    idx: u8,
    prefix: &'static str,
) -> (Arc<dyn GenericScionUdpSocket>, ScionSocketIpAddr) {
    let client_addr = scion_addr(idx, 1, 100 + idx as u16);
    let server_addr = scion_addr(idx, 2, 200 + idx as u16);
    let (client_socket, server_socket) = MockScionSocket::pair(1024, client_addr, server_addr);
    let server_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(server_socket);

    let (server_config, cert_file, key_file) = make_server_quic_config();
    let endpoint = QuicScionServerEndpoint::new(
        [7u8; 32],
        server_config,
        server_socket.local_addr(),
        Metrics::new_without_registry(),
    );
    let driver = QuicScionEndpointDriver::with_config(
        endpoint,
        server_socket,
        // Requests are served by the endpoint's internal HTTP/3 dispatch, so the per-connection
        // handle is not needed here.
        |_handle: ConnectionHandle<Http3Server<EchoService>>| {},
        Http3ServerConfig::new(EchoService { prefix }),
    );

    tokio::spawn(async move {
        // Keep the certificate temp files alive for the lifetime of the server.
        let _temp_files = (cert_file, key_file);
        let _ = driver.run(CancellationToken::new()).await;
    });

    (Arc::new(client_socket), server_addr)
}

/// Reads an HTTP/3 request body to completion, concatenating its data frames.
async fn read_request_body(mut body: H3RequestBody) -> Vec<u8> {
    let mut data = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        if let Ok(frame) = frame
            && let Ok(chunk) = frame.into_data()
        {
            data.extend_from_slice(&chunk);
        }
    }
    data
}

/// A minimal HTTP/3 response body that yields its bytes in a single data frame.
struct FullBody(Option<Bytes>);

impl FullBody {
    fn new(data: Vec<u8>) -> Self {
        if data.is_empty() {
            Self(None)
        } else {
            Self(Some(Bytes::from(data)))
        }
    }
}

impl Body for FullBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }
}

/// A `RemoteEndpoint` that can never be connected to (handshake always times out).
fn unreachable_endpoint(idx: u8) -> RemoteEndpoint {
    let local_addr = scion_addr(idx, 1, 100 + idx as u16);
    let remote_addr = scion_addr(idx, 2, 200 + idx as u16);
    RemoteEndpoint::new(remote_addr, Arc::new(BlackholeSocket { local_addr }))
}

fn client_config() -> QuicConfig {
    QuicConfig::builder()
        .verify_peer(false)
        // Keep the unreachable-remote handshakes from dominating the wall-clock of tests that
        // intentionally wait for them to fail.
        .handshake_timeout(Duration::from_millis(500))
        .build()
}

async fn echo_request(client: &CrpcClient, value: &str) -> String {
    let response: Echo = client
        .unary_request(
            Method::POST,
            Url::parse(SERVICE_URL).unwrap(),
            &Echo {
                value: value.to_string(),
            },
        )
        .await
        .expect("unary_request should succeed");
    response.value
}

/// A single reachable remote answers a unary request.
#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn single_remote_round_trip() {
    let (client_socket, server_addr) = spawn_echo_server(1, "echo: ");

    let client = CrpcClient::with_config(
        RemoteEndpoint::new(server_addr, client_socket),
        Some("localhost".to_string()),
        None,
        client_config(),
    )
    .await
    .expect("client should connect to the reachable remote");

    assert_eq!(echo_request(&client, "ping").await, "echo: ping");
}

/// The client must race past an unreachable remote to a reachable one during construction, and
/// subsequent requests must be served by that reachable remote.
#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn races_past_unreachable_remote() {
    let (client_socket, server_addr) = spawn_echo_server(2, "from-reachable: ");

    let client = CrpcClient::with_remotes_and_config(
        vec![
            // First remote is a black hole; the client must fail over to the second.
            unreachable_endpoint(3),
            RemoteEndpoint::new(server_addr, client_socket),
        ],
        Some("localhost".to_string()),
        None,
        client_config(),
    )
    .await
    .expect("client should fail over to the reachable remote");

    assert_eq!(
        echo_request(&client, "hi").await,
        "from-reachable: hi",
        "request must be served by the reachable remote"
    );
}

/// Construction fails when none of the remotes can be connected to.
#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn fails_when_all_remotes_unreachable() {
    let result = CrpcClient::with_remotes_and_config(
        vec![unreachable_endpoint(4), unreachable_endpoint(5)],
        Some("localhost".to_string()),
        None,
        client_config(),
    )
    .await;

    assert!(
        result.is_err(),
        "construction must fail when no remote is reachable"
    );
}
