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

//! Integration tests: `tokio-quiche` HTTP/3 clients against the endpoint-based
//! [`Http3Server`] running an [`HttpService`].

mod common;

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::SinkExt;
use http::{Request, Response};
use http_body::{Body, Frame};
use scion_sdk_quic_scion::{
    h3::server::{H3Error, H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    quic::{
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::GenericScionUdpSocket,
};
use test_log::test;
use tokio::sync::mpsc;
use tokio_quiche::{
    http3::driver::{
        ClientH3Event, H3Event, InboundFrame, InboundFrameStream, IncomingH3Headers,
        NewClientRequest, OutboundFrame, OutboundFrameSender,
    },
    quiche::h3::{Header, NameValue},
};
use tokio_util::sync::CancellationToken;

use crate::common::{
    ConfiguredPerPeerLimitGate, GatedTestScionSocket, PassAll, TrafficGate, bind_localhost_udp,
    connect_test_client, connect_test_client_with_budget, generate_server_config, test_metrics,
};

// --------------------------------------------------------------------------
// Services
// --------------------------------------------------------------------------

/// The bytes the hello service returns for a matching request.
const HELLO_BODY: &[u8] = b"hello from scion/h3";

/// Answers `GET example.com/hello` with [`HELLO_BODY`], everything else `404`.
#[derive(Clone)]
struct HelloService;

impl HttpService for HelloService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<OnceBody> {
        if request_matches(&req, &http::Method::GET, "/hello") {
            ok_response(HELLO_BODY)
        } else {
            not_found()
        }
    }
}

/// Echoes the request body back in the response for `POST example.com/echo`.
#[derive(Clone)]
struct EchoService;

impl HttpService for EchoService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<OnceBody> {
        if !request_matches(&req, &http::Method::POST, "/echo") {
            return not_found();
        }

        // Read the full request body (streamed directly via `recv_body`) and
        // echo it back.
        let mut body = req.into_body();
        let mut collected = Vec::new();
        while let Some(Ok(frame)) =
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            if let Ok(data) = frame.into_data() {
                collected.extend_from_slice(&data);
            }
        }
        ok_response(&collected)
    }
}

/// A bidirectional `CONNECT` echo tunnel: the response body simply re-emits the
/// request body, so upstream tunnel bytes are piped straight back downstream.
#[derive(Clone)]
struct ConnectEchoService;

impl HttpService for ConnectEchoService {
    type Body = H3RequestBody;
    // Echo: the downstream (response) body *is* the upstream (request) body.
    type ResponseBody = H3RequestBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<H3RequestBody> {
        let accept = req.method() == http::Method::CONNECT
            && req.uri().authority().map(|a| a.as_str()) == Some("example.com:443");
        let status = if accept {
            http::StatusCode::OK
        } else {
            http::StatusCode::NOT_FOUND
        };
        // `ResponseBody` must be `H3RequestBody`, so hand the request body back
        // as the response body (the tunnel echo).
        Response::builder()
            .status(status)
            .body(req.into_body())
            .unwrap()
    }
}

/// A `CONNECT` tunnel that ASCII-uppercases the upstream bytes before echoing
/// them downstream.
#[derive(Clone)]
struct ConnectUppercaseService;

impl HttpService for ConnectUppercaseService {
    type Body = H3RequestBody;
    type ResponseBody = UppercaseBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<UppercaseBody> {
        let accept = req.method() == http::Method::CONNECT
            && req.uri().authority().map(|a| a.as_str()) == Some("example.com:443");
        let status = if accept {
            http::StatusCode::OK
        } else {
            http::StatusCode::NOT_FOUND
        };
        Response::builder()
            .status(status)
            .body(UppercaseBody {
                inner: req.into_body(),
            })
            .unwrap()
    }
}

/// A response body that ASCII-uppercases every data frame of the wrapped request
/// body, passing any non-data frames through unchanged.
struct UppercaseBody {
    inner: H3RequestBody,
}

impl Body for UppercaseBody {
    type Data = Bytes;
    type Error = H3Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, H3Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                match frame.into_data() {
                    Ok(data) => {
                        let mut bytes = data.to_vec();
                        bytes.make_ascii_uppercase();
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes)))))
                    }
                    Err(non_data) => Poll::Ready(Some(Ok(non_data))),
                }
            }
            other => other,
        }
    }
}

/// Returns a fixed response *without* reading the request body. This exercises
/// stream cleanup: the unread read side must still be released so the stream is
/// collected (otherwise the connection's stream-concurrency limit is exhausted).
#[derive(Clone)]
struct IgnoreBodyService;

impl HttpService for IgnoreBodyService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, _req: Request<H3RequestBody>) -> Response<OnceBody> {
        ok_response(b"ok")
    }
}

/// Reflects the request header `x-echo` back as the response header
/// `x-echo-reply`, and returns the request line (`<method> <path>`) as the body.
/// Exercises request/response header propagation through the server.
#[derive(Clone)]
struct HeaderEchoService;

impl HttpService for HeaderEchoService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<OnceBody> {
        let echoed = req.headers().get("x-echo").cloned();
        let line = format!("{} {}", req.method(), req.uri().path());

        let mut builder = Response::builder().status(http::StatusCode::OK);
        if let Some(value) = echoed {
            builder = builder.header("x-echo-reply", value);
        }
        builder.body(OnceBody::full(line.as_bytes())).unwrap()
    }
}

/// Reads the request body to completion and, if a trailing header section
/// carrying `x-trailer` was received, returns its value as the response body
/// (otherwise `404`). Exercises the request-trailers read path
/// (`ReadState::Trailers`).
#[derive(Clone)]
struct TrailerEchoService;

impl HttpService for TrailerEchoService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<OnceBody> {
        let mut body = req.into_body();
        let mut trailer_value: Option<Vec<u8>> = None;
        while let Some(Ok(frame)) =
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            // Body data is ignored; only the trailing header section matters.
            if let Err(non_data) = frame.into_data()
                && let Ok(trailers) = non_data.into_trailers()
                && let Some(value) = trailers.get("x-trailer")
            {
                trailer_value = Some(value.as_bytes().to_vec());
            }
        }
        match trailer_value {
            Some(value) => ok_response(&value),
            None => not_found(),
        }
    }
}

/// Returns a fixed body followed by a trailing `x-trailer` header. Exercises the
/// server's response-trailers send path.
#[derive(Clone)]
struct ResponseTrailerService;

impl HttpService for ResponseTrailerService {
    type Body = H3RequestBody;
    type ResponseBody = BodyWithTrailers;

    async fn call(&self, _req: Request<H3RequestBody>) -> Response<BodyWithTrailers> {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("trailer-value"));
        Response::builder()
            .status(http::StatusCode::OK)
            .body(BodyWithTrailers {
                data: Some(Bytes::from_static(b"body")),
                trailers: Some(trailers),
            })
            .unwrap()
    }
}

/// Panics for `GET /panic`, otherwise replies `200 ok`. Exercises the server's
/// panic isolation: a panicking handler must not take down the connection.
#[derive(Clone)]
struct MaybePanicService;

impl HttpService for MaybePanicService {
    type Body = H3RequestBody;
    type ResponseBody = OnceBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<OnceBody> {
        if req.uri().path() == "/panic" {
            panic!("intentional panic in service handler (test)");
        }
        ok_response(b"ok")
    }
}

fn request_matches(req: &Request<H3RequestBody>, method: &http::Method, path: &str) -> bool {
    req.method() == method
        && req.uri().authority().map(|a| a.as_str()) == Some("example.com")
        && req.uri().path() == path
}

fn ok_response(body: &[u8]) -> Response<OnceBody> {
    Response::builder()
        .status(http::StatusCode::OK)
        .body(OnceBody::full(body))
        .unwrap()
}

fn not_found() -> Response<OnceBody> {
    Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .body(OnceBody::empty())
        .unwrap()
}

/// A minimal response body that yields its bytes in a single frame.
struct OnceBody(Option<Bytes>);

impl OnceBody {
    fn full(data: &[u8]) -> Self {
        Self(Some(Bytes::copy_from_slice(data)))
    }

    fn empty() -> Self {
        Self(None)
    }
}

impl Body for OnceBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }
}

/// A response body that yields a single data frame followed by a trailing
/// header section, then ends.
struct BodyWithTrailers {
    data: Option<Bytes>,
    trailers: Option<http::HeaderMap>,
}

impl Body for BodyWithTrailers {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(data) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

// --------------------------------------------------------------------------
// Harness / client helpers
// --------------------------------------------------------------------------

/// A running [`Http3Server`] endpoint; the driver task is cancelled on
/// [`ServerHarness::cancel`].
struct ServerHarness {
    local_addr: SocketAddr,
    cancel: CancellationToken,
}

/// Spawns an endpoint driver running [`Http3Server`] with `service`, passing all
/// traffic.
async fn spawn_server<S>(service: S) -> ServerHarness
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    spawn_server_with_gate(service, PassAll).await
}

/// Like [`spawn_server`], but routes the server socket through `gate` (e.g. to
/// drop packets).
async fn spawn_server_with_gate<S, G>(service: S, gate: G) -> ServerHarness
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
    G: TrafficGate + 'static,
{
    let udp = bind_localhost_udp().await;
    let local_addr = udp.local_addr().unwrap();

    let (config, cert, key) = generate_server_config();
    let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(GatedTestScionSocket::new(gate, udp));
    let scion_addr = socket.local_addr();
    let metrics = test_metrics();
    let endpoint = QuicScionServerEndpoint::new([0u8; 32], config, scion_addr, metrics);

    let driver = QuicScionEndpointDriver::with_config(
        endpoint,
        socket,
        // We don't need the per-connection handle here; requests flow through
        // the service via the server's internal dispatch.
        |_handle: ConnectionHandle<Http3Server<S>>| {},
        Http3ServerConfig::new(service),
    );

    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();
    tokio::spawn(async move {
        // Keep the certificate/key temp files alive for the server's lifetime.
        let _keep_alive = (cert, key);
        let _ = driver.run(cancel_for_task).await;
    });

    ServerHarness { local_addr, cancel }
}

/// Builds the pseudo-headers for a request to `example.com`.
fn request_headers(method: &[u8], path: &[u8]) -> Vec<Header> {
    vec![
        Header::new(b":method", method),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"example.com"),
        Header::new(b":path", path),
    ]
}

/// Reads the next HTTP/3 response (status + full body) from the client event
/// stream.
async fn read_response(
    events: &mut mpsc::UnboundedReceiver<ClientH3Event>,
) -> (Option<u16>, Vec<u8>) {
    let mut status = None;
    let mut body = Vec::new();

    while let Some(event) = events.recv().await {
        let ClientH3Event::Core(core) = event else {
            continue;
        };
        match core {
            H3Event::IncomingHeaders(IncomingH3Headers {
                headers, mut recv, ..
            }) => {
                for header in &headers {
                    if header.name() == b":status" {
                        status = std::str::from_utf8(header.value())
                            .ok()
                            .and_then(|value| value.parse().ok());
                    }
                }

                // Read the streamed response body to completion.
                while let Some(frame) = recv.recv().await {
                    match frame {
                        InboundFrame::Body(data, fin) => {
                            body.extend_from_slice(&data);
                            if fin {
                                break;
                            }
                        }
                        InboundFrame::Datagram(_) => {}
                    }
                }
                return (status, body);
            }
            H3Event::ConnectionError(err) => panic!("connection error before response: {err:?}"),
            H3Event::ConnectionShutdown(err) => {
                panic!("connection shut down before response: {err:?}")
            }
            _ => {}
        }
    }

    (status, body)
}

/// Like [`read_response`], but also returns the full response header list as
/// `(name, value)` byte pairs (not just the parsed status).
async fn read_response_full(
    events: &mut mpsc::UnboundedReceiver<ClientH3Event>,
) -> (Option<u16>, Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) {
    let mut status = None;
    let mut response_headers = Vec::new();
    let mut body = Vec::new();

    while let Some(event) = events.recv().await {
        let ClientH3Event::Core(core) = event else {
            continue;
        };
        match core {
            H3Event::IncomingHeaders(IncomingH3Headers {
                headers, mut recv, ..
            }) => {
                for header in &headers {
                    if header.name() == b":status" {
                        status = std::str::from_utf8(header.value())
                            .ok()
                            .and_then(|value| value.parse().ok());
                    }
                    response_headers.push((header.name().to_vec(), header.value().to_vec()));
                }

                // Read the streamed response body to completion.
                while let Some(frame) = recv.recv().await {
                    match frame {
                        InboundFrame::Body(data, fin) => {
                            body.extend_from_slice(&data);
                            if fin {
                                break;
                            }
                        }
                        InboundFrame::Datagram(_) => {}
                    }
                }
                return (status, response_headers, body);
            }
            H3Event::ConnectionError(err) => panic!("connection error before response: {err:?}"),
            H3Event::ConnectionShutdown(err) => {
                panic!("connection shut down before response: {err:?}")
            }
            _ => {}
        }
    }

    (status, response_headers, body)
}

/// Reads the client event stream until the response head arrives, returning the
/// status and the [`InboundFrameStream`] carrying the (downstream) body so the
/// caller can keep streaming it interactively (as needed for `CONNECT`).
async fn read_response_head(
    events: &mut mpsc::UnboundedReceiver<ClientH3Event>,
) -> (Option<u16>, InboundFrameStream) {
    while let Some(event) = events.recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
                headers,
                recv,
                ..
            })) => {
                let mut status = None;
                for header in &headers {
                    if header.name() == b":status" {
                        status = std::str::from_utf8(header.value())
                            .ok()
                            .and_then(|value| value.parse().ok());
                    }
                }
                return (status, recv);
            }
            ClientH3Event::Core(H3Event::ConnectionError(err)) => {
                panic!("connection error before response: {err:?}")
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(err)) => {
                panic!("connection shut down before response: {err:?}")
            }
            _ => {}
        }
    }
    panic!("event stream ended before the response head");
}

/// Reads at least `n` bytes of tunnel (body) data from a downstream
/// [`InboundFrameStream`].
async fn read_tunnel_bytes(down: &mut InboundFrameStream, n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    while buf.len() < n {
        match down.recv().await {
            Some(InboundFrame::Body(data, _fin)) => buf.extend_from_slice(&data),
            Some(InboundFrame::Datagram(_)) => {}
            None => break,
        }
    }
    buf
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

/// A `tokio-quiche` client sends a bodyless `GET example.com/hello`; the server
/// service returns fixed bytes, which the client must observe in the response
/// body.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_get_hello() {
    let server = spawn_server(HelloService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"GET", b"/hello"),
            body_writer: None,
        })
        .expect("send request");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "unexpected response status");
    assert_eq!(body, HELLO_BODY, "unexpected response body");

    server.cancel.cancel();
}

/// Sends several `POST example.com/echo` requests in sequence, each with a
/// distinct body, and asserts the echo server returns each body verbatim.
#[test(tokio::test)]
#[ntest::timeout(15_000)]
async fn http3_service_multiple_request_bodies() {
    let server = spawn_server(EchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    const REQUESTS: u64 = 5;
    let sender = client.controller.request_sender();
    let events = client.controller.event_receiver_mut();

    for n in 0..REQUESTS {
        let payload = format!("request-body-{n}").into_bytes();

        // Send the request head (no FIN), then stream the body to completion.
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<OutboundFrameSender>();
        sender
            .send(NewClientRequest {
                request_id: n,
                headers: request_headers(b"POST", b"/echo"),
                body_writer: Some(body_tx),
            })
            .expect("send request");

        let mut frame_sender = body_rx.await.expect("obtain request body writer");
        frame_sender
            .send(OutboundFrame::Body(Bytes::from(payload.clone()), true))
            .await
            .expect("send request body");

        let (status, body) = read_response(events).await;
        assert_eq!(status, Some(200), "request {n}: unexpected status");
        assert_eq!(body, payload, "request {n}: response did not echo the body");
    }

    server.cancel.cancel();
}

/// Attempts a single `POST example.com/echo` request over a fresh connection
/// that declares the given packet `budget` in-band (see
/// [`connect_test_client_with_budget`]), returning whether the server echoed the
/// body back successfully.
///
/// A short client idle timeout means a connection that cannot complete its
/// handshake (too few packets allowed through) gives up quickly; the bounded
/// wait on the response covers the case where the handshake completes but the
/// request itself cannot be delivered.
///
/// The idle timeout only governs how fast a doomed connection gives up (the
/// dropped packets make it fail regardless), so it can be kept short. A
/// legitimate success completes in a few milliseconds over localhost, so 1s
/// still leaves a large margin for slow/loaded CI runners.
async fn attempt_echo_request(server_addr: SocketAddr, budget: u64) -> bool {
    let config = QuicConfig::builder()
        .verify_peer(false)
        .idle_timeout(Duration::from_secs(1))
        .build();

    let Ok(mut client) = connect_test_client_with_budget(server_addr, &config, budget).await else {
        return false;
    };

    let payload = format!("budget-{budget}").into_bytes();
    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    if client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"POST", b"/echo"),
            body_writer: Some(body_tx),
        })
        .is_err()
    {
        return false;
    }
    let Ok(mut frame_sender) = body_rx.await else {
        return false;
    };
    if frame_sender
        .send(OutboundFrame::Body(Bytes::from(payload.clone()), true))
        .await
        .is_err()
    {
        return false;
    }

    match tokio::time::timeout(
        Duration::from_secs(2),
        read_response(client.controller.event_receiver_mut()),
    )
    .await
    {
        Ok((status, body)) => status == Some(200) && body == payload,
        Err(_) => false,
    }
}

/// Each connection declares its own client->server packet budget in-band (a
/// leading config packet carrying the budget, counted inclusively: budget `1`
/// allows nothing past the config packet, budget `n` allows `n - 1` further
/// packets, `0` is unlimited). Connections whose budget is too small to finish
/// the handshake *and* deliver the request fail; once the budget is large enough
/// the request succeeds, and every larger budget must succeed too.
///
/// Because the budget travels in-band ([`ConfiguredPerPeerLimitGate`]) rather
/// than being assigned by observation order, the connections can be attempted
/// concurrently. The results are sorted by declared budget afterwards, and the
/// success/failure pattern must be monotonic: failures for the smallest budgets,
/// then successes for every budget at or above some threshold.
#[test(tokio::test)]
#[ntest::timeout(60_000)]
async fn http3_service_succeeds_once_packet_budget_suffices() {
    // Budgets count the leading config packet, so budget `1` leaves zero packets
    // for the handshake. Range up to `11` to give the largest budget the same
    // 10-QUIC-packet headroom the sequential gate allowed.
    const MAX_BUDGET: u64 = 11;

    let server = spawn_server_with_gate(EchoService, ConfiguredPerPeerLimitGate::new()).await;

    // Attempt every budget concurrently; each runs on its own connection and
    // declares its budget itself, so completion order is irrelevant.
    let attempts = (1..=MAX_BUDGET).map(|budget| {
        let server_addr = server.local_addr;
        tokio::spawn(async move { (budget, attempt_echo_request(server_addr, budget).await) })
    });
    let mut results = futures::future::join_all(attempts)
        .await
        .into_iter()
        .map(|joined| joined.expect("attempt task panicked"))
        .collect::<Vec<_>>();

    server.cancel.cancel();

    // Reason about the outcomes in budget order regardless of completion order.
    results.sort_by_key(|&(budget, _)| budget);
    let ok: Vec<bool> = results.iter().map(|&(_, ok)| ok).collect();

    // The smallest budget cannot even complete the handshake, and there must be
    // a budget at which the request starts succeeding.
    let threshold = ok
        .iter()
        .position(|&ok| ok)
        .unwrap_or_else(|| panic!("no request succeeded; budgets too small: {results:?}"));
    assert!(
        threshold > 0,
        "the smallest budget should not succeed: {results:?}"
    );
    // Once a request succeeds, every larger-budget request must succeed too.
    assert!(
        ok[threshold..].iter().all(|&ok| ok),
        "a request failed after a smaller-budget one succeeded: {results:?}"
    );
}

/// Opens a `CONNECT` tunnel and exchanges several rounds of data: the client
/// sends bytes, waits for the server to echo them, then sends more, proving the
/// tunnel streams continuously in both directions before being closed.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_connect_echo_tunnel() {
    let server = spawn_server(ConnectEchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    // Open the tunnel: a CONNECT request (authority-form, with a body).
    let (up_tx, up_rx) = tokio::sync::oneshot::channel();
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: vec![
                Header::new(b":method", b"CONNECT"),
                Header::new(b":authority", b"example.com:443"),
            ],
            body_writer: Some(up_tx),
        })
        .expect("send CONNECT");

    // `up` streams bytes towards the server; `down` carries the echoed bytes.
    let mut up = up_rx.await.expect("obtain tunnel writer");
    let (status, mut down) = read_response_head(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "CONNECT was not accepted");

    // Several interactive send/echo rounds: each round must complete (echo
    // received) before the next is sent, so a single buffered response would not
    // satisfy it.
    for round in 0..3u32 {
        let payload = format!("tunnel-chunk-{round}").into_bytes();
        up.send(OutboundFrame::Body(Bytes::from(payload.clone()), false))
            .await
            .expect("send tunnel data");
        let echoed = read_tunnel_bytes(&mut down, payload.len()).await;
        assert_eq!(
            echoed, payload,
            "round {round}: tunnel did not echo the data"
        );
    }

    // Close the tunnel by sending a FIN.
    up.send(OutboundFrame::Body(Bytes::new(), true))
        .await
        .expect("close tunnel");

    server.cancel.cancel();
}

/// Like the echo tunnel, but the server ASCII-uppercases the upstream bytes. In
/// each round the client sends a different, growing lowercase payload (`a`,
/// `ab`, `abc`, ...) and asserts the downstream response is exactly its
/// uppercase.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_connect_uppercase_tunnel() {
    let server = spawn_server(ConnectUppercaseService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    let (up_tx, up_rx) = tokio::sync::oneshot::channel();
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: vec![
                Header::new(b":method", b"CONNECT"),
                Header::new(b":authority", b"example.com:443"),
            ],
            body_writer: Some(up_tx),
        })
        .expect("send CONNECT");

    let mut up = up_rx.await.expect("obtain tunnel writer");
    let (status, mut down) = read_response_head(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "CONNECT was not accepted");

    for round in 0..5u32 {
        // Round 0 sends "a", round 1 "ab", round 2 "abc", ...
        let payload: Vec<u8> = (b'a'..=b'z').take(round as usize + 1).collect();
        let expected: Vec<u8> = payload.iter().map(u8::to_ascii_uppercase).collect();

        up.send(OutboundFrame::Body(Bytes::from(payload.clone()), false))
            .await
            .expect("send tunnel data");
        let response = read_tunnel_bytes(&mut down, expected.len()).await;
        assert_eq!(
            response, expected,
            "round {round}: server did not uppercase the data"
        );
    }

    up.send(OutboundFrame::Body(Bytes::new(), true))
        .await
        .expect("close tunnel");

    server.cancel.cancel();
}

/// Regression test for stream cleanup: a service that ignores request bodies
/// must still release each stream's read side, otherwise the unread read sides
/// pile up and the client stalls once it reaches the server's bidi-stream limit
/// (`initial_max_streams_bidi`, 100 by default). Sending well beyond that many
/// requests with bodies on a *single* connection must therefore all succeed.
#[test(tokio::test)]
#[ntest::timeout(30_000)]
async fn http3_service_releases_streams_when_body_ignored() {
    let server = spawn_server(IgnoreBodyService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    // Comfortably exceed the default bidi-stream limit of 100.
    const REQUESTS: u64 = 150;
    let sender = client.controller.request_sender();
    let events = client.controller.event_receiver_mut();

    for n in 0..REQUESTS {
        // Each request carries a body that the server never reads.
        let (body_tx, body_rx) = tokio::sync::oneshot::channel();
        sender
            .send(NewClientRequest {
                request_id: n,
                headers: request_headers(b"POST", b"/ignored"),
                body_writer: Some(body_tx),
            })
            .expect("send request");

        let mut frame_sender = body_rx.await.expect("obtain request body writer");
        frame_sender
            .send(OutboundFrame::Body(Bytes::from_static(b"payload"), true))
            .await
            .expect("send request body");

        let (status, _body) = read_response(events).await;
        assert_eq!(
            status,
            Some(200),
            "request {n}: no response (stream limit?)"
        );
    }

    server.cancel.cancel();
}

/// A request for a path the service does not handle must yield the service's
/// `404` response with an empty body, exercising the non-200 status path.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_not_found() {
    let server = spawn_server(HelloService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"GET", b"/does-not-exist"),
            body_writer: None,
        })
        .expect("send request");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(404), "unexpected response status");
    assert!(body.is_empty(), "404 response should have an empty body");

    server.cancel.cancel();
}

/// A custom request header must reach the service, and a response header set by
/// the service must reach the client; the service must also observe the
/// request's method and path. Exercises header parsing/serialization on both
/// sides.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_round_trips_headers() {
    let server = spawn_server(HeaderEchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    let headers = vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"example.com"),
        Header::new(b":path", b"/resource"),
        Header::new(b"x-echo", b"round-trip-value"),
    ];
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers,
            body_writer: None,
        })
        .expect("send request");

    let (status, headers, body) = read_response_full(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "unexpected response status");
    let expected_line: &[u8] = b"GET /resource";
    assert_eq!(body, expected_line, "service did not observe method/path");

    let reply = headers
        .iter()
        .find(|(name, _)| name == b"x-echo-reply")
        .map(|(_, value)| value.as_slice());
    assert_eq!(
        reply,
        Some(b"round-trip-value".as_slice()),
        "response did not carry the reflected header: {headers:?}"
    );

    server.cancel.cancel();
}

/// Echoes a body far larger than the flow-control window, exercising the
/// response writer's partial-write/backpressure loop (`write_waker` +
/// `conn.writable()`) and the request reader's window replenishment.
#[test(tokio::test)]
#[ntest::timeout(20_000)]
async fn http3_service_echo_large_body() {
    let server = spawn_server(EchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    const SIZE: usize = 1 << 20; // 1 MiB, comfortably beyond the default windows.
    let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"POST", b"/echo"),
            body_writer: Some(body_tx),
        })
        .expect("send request");

    let mut frame_sender = body_rx.await.expect("obtain request body writer");
    frame_sender
        .send(OutboundFrame::Body(Bytes::from(payload.clone()), true))
        .await
        .expect("send request body");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "unexpected response status");
    assert_eq!(
        body.len(),
        payload.len(),
        "echoed body has the wrong length"
    );
    assert!(
        body == payload,
        "echoed body did not match the request body"
    );

    server.cancel.cancel();
}

/// Opens many request streams on a single connection without awaiting any
/// response, then collects them all. Exercises concurrent stream multiplexing:
/// multiple live per-stream states with responses completing independently.
#[test(tokio::test)]
#[ntest::timeout(20_000)]
async fn http3_service_concurrent_multiplexed_requests() {
    let server = spawn_server(EchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    const REQUESTS: u64 = 20;
    let sender = client.controller.request_sender();

    // Send every request head first, collecting each stream's body writer.
    let mut writers = Vec::with_capacity(REQUESTS as usize);
    let mut expected = Vec::with_capacity(REQUESTS as usize);
    for n in 0..REQUESTS {
        let (body_tx, body_rx) = tokio::sync::oneshot::channel();
        sender
            .send(NewClientRequest {
                request_id: n,
                headers: request_headers(b"POST", b"/echo"),
                body_writer: Some(body_tx),
            })
            .expect("send request");
        writers.push(body_rx);
        expected.push(format!("multiplexed-{n}").into_bytes());
    }

    // Stream every body (still without reading any response).
    for (body_rx, payload) in writers.into_iter().zip(expected.iter()) {
        let mut frame_sender = body_rx.await.expect("obtain request body writer");
        frame_sender
            .send(OutboundFrame::Body(Bytes::from(payload.clone()), true))
            .await
            .expect("send request body");
    }

    // Collect all responses; they may complete in any order, so compare as sets.
    let events = client.controller.event_receiver_mut();
    let mut got = Vec::with_capacity(REQUESTS as usize);
    for _ in 0..REQUESTS {
        let (status, body) = read_response(events).await;
        assert_eq!(status, Some(200), "unexpected response status");
        got.push(body);
    }

    got.sort();
    expected.sort();
    assert_eq!(got, expected, "echoed bodies did not match the requests");

    server.cancel.cancel();
}

/// A bodyless `POST` (immediate FIN) must still produce a `200` with an empty
/// echo, exercising the immediate-EOF read path for a body-reading service.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_empty_body_post() {
    let server = spawn_server(EchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"POST", b"/echo"),
            body_writer: None,
        })
        .expect("send request");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "unexpected response status");
    assert!(body.is_empty(), "empty request should echo an empty body");

    server.cancel.cancel();
}

/// A `CONNECT` to an authority the tunnel service does not accept must be
/// answered with `404` (the negative branch of the tunnel services).
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_connect_rejected() {
    let server = spawn_server(ConnectEchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    let (up_tx, up_rx) = tokio::sync::oneshot::channel();
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: vec![
                Header::new(b":method", b"CONNECT"),
                Header::new(b":authority", b"not-allowed.example.com:443"),
            ],
            body_writer: Some(up_tx),
        })
        .expect("send CONNECT");

    // Hold the tunnel writer so the request stays open until the head arrives.
    let _up = up_rx.await.expect("obtain tunnel writer");
    let (status, _down) = read_response_head(client.controller.event_receiver_mut()).await;
    assert_eq!(
        status,
        Some(404),
        "rejected CONNECT should be answered with 404"
    );

    server.cancel.cancel();
}

/// The client sends a request body followed by a trailing header section; the
/// service must observe the trailer and echo its value. Exercises the
/// request-trailers read path (`ReadState::Trailers`).
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_request_trailers() {
    let server = spawn_server(TrailerEchoService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"POST", b"/with-trailers"),
            body_writer: Some(body_tx),
        })
        .expect("send request");

    let mut frame_sender = body_rx.await.expect("obtain request body writer");
    // Some body without a FIN, then a trailing header section closes the stream.
    frame_sender
        .send(OutboundFrame::Body(
            Bytes::from_static(b"body-bytes"),
            false,
        ))
        .await
        .expect("send request body");
    frame_sender
        .send(OutboundFrame::Trailers(
            vec![Header::new(b"x-trailer", b"trailer-value")],
            None,
        ))
        .await
        .expect("send request trailers");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "service did not observe the trailer");
    let expected: &[u8] = b"trailer-value";
    assert_eq!(body, expected, "wrong trailer value echoed");

    server.cancel.cancel();
}

/// The service returns a response body that ends with a trailing header
/// section. Exercises the server's response-trailers send path: the body and a
/// well-formed trailing HEADERS section must be delivered so the response
/// completes cleanly (correct status, full body, FIN, no stream/connection
/// error).
///
/// Note: the `tokio-quiche` client deliberately discards received trailers
/// ("For now ignore any additional HEADERS"), so we cannot assert the trailer
/// *value* here. What we verify is that mainline quiche accepts the trailing
/// section and finishes the stream without error — a malformed trailer or a
/// double-FIN would surface as a client error or a stalled stream instead.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn http3_service_sends_response_trailers() {
    let server = spawn_server(ResponseTrailerService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    client
        .controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: request_headers(b"GET", b"/trailers"),
            body_writer: None,
        })
        .expect("send request");

    let (status, body) = read_response(client.controller.event_receiver_mut()).await;
    assert_eq!(status, Some(200), "unexpected response status");
    let expected_body: &[u8] = b"body";
    assert_eq!(body, expected_body, "unexpected response body");

    server.cancel.cancel();
}

/// A panicking service handler must be isolated: the client gets a `500`, the
/// stream is cleaned up (so streams don't leak and the bidi-stream limit isn't
/// exhausted), and the connection stays usable for later requests.
///
/// Sending far more panicking requests than the default 100-stream limit on a
/// single connection would stall if the panic path leaked streams; a final
/// non-panicking request confirms the connection still works.
#[test(tokio::test)]
#[ntest::timeout(30_000)]
async fn http3_service_handler_panic_is_isolated() {
    let server = spawn_server(MaybePanicService).await;

    let mut client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    let sender = client.controller.request_sender();
    let events = client.controller.event_receiver_mut();

    // Comfortably exceed the default bidi-stream limit of 100.
    const PANICS: u64 = 150;
    for n in 0..PANICS {
        sender
            .send(NewClientRequest {
                request_id: n,
                headers: request_headers(b"GET", b"/panic"),
                body_writer: None,
            })
            .expect("send request");

        let (status, body) = read_response(events).await;
        assert_eq!(status, Some(500), "request {n}: a panic should yield 500");
        assert!(
            body.is_empty(),
            "request {n}: 500 should have an empty body"
        );
    }

    // The connection must still serve a normal request after all those panics.
    sender
        .send(NewClientRequest {
            request_id: PANICS,
            headers: request_headers(b"GET", b"/ok"),
            body_writer: None,
        })
        .expect("send request");

    let (status, body) = read_response(events).await;
    assert_eq!(
        status,
        Some(200),
        "connection unusable after handler panics"
    );
    let expected: &[u8] = b"ok";
    assert_eq!(body, expected, "unexpected body after handler panics");

    server.cancel.cancel();
}
