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

//! Integration tests for the HTTP/3 client ([`Http3Client`]) running a loopback
//! against the HTTP/3 server ([`Http3Server`]) over an in-memory SCION socket
//! pair. Both stacks share the `QuicScionApplication` machinery, so these
//! exercise the full request/response, streaming-body, multiplexing, reconnect,
//! cancellation, and `CONNECT`-tunnel paths end to end.

mod common;

use std::{
    collections::VecDeque,
    convert::Infallible,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body::{Body, Frame};
use scion_quic::{
    h3::{
        client::{H3DuplexStream, H3ResponseBody, Http3Client, RequestError},
        server::{H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    },
    quic::{
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{Metrics, QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::GenericScionUdpSocket,
};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::common::{MockScionSocket, generate_server_config_with_idle_timeout, test_metrics};

// --------------------------------------------------------------------------
// Config helpers
// --------------------------------------------------------------------------

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

fn client_config(idle: Duration) -> QuicConfig {
    QuicConfig::builder()
        .verify_peer(false)
        .idle_timeout(idle)
        .build()
}

/// A running server endpoint backed by one half of an in-memory socket pair.
/// The other half is handed to the client.
struct TestServer {
    /// Number of connections the endpoint reported as established.
    established: Arc<AtomicUsize>,
    /// Endpoint metrics (gauges share state with the running endpoint, so they
    /// reflect live values).
    metrics: Metrics,
    cancel: CancellationToken,
}

impl TestServer {
    /// The number of connections the endpoint currently has registered. Drops
    /// back to zero once an idle connection has been torn down, which the tests
    /// use as a close signal instead of waiting a fixed duration.
    fn registered_connections(&self) -> i64 {
        self.metrics.routed_source_cids_gauge.get()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Spawns a server running `service` and returns the server plus the
/// client-side socket connected to it.
fn spawn_server<S>(service: S, idle: Duration) -> (TestServer, Arc<MockScionSocket>)
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    let (client_socket, server_socket) = MockScionSocket::pair(8192, client_addr(), server_addr());
    let server_socket: Arc<dyn GenericScionUdpSocket> = Arc::new(server_socket);
    let scion_addr = server_socket.local_addr();

    let (config, cert, key) = generate_server_config_with_idle_timeout(idle);
    let metrics = test_metrics();
    let endpoint = QuicScionServerEndpoint::new([7u8; 32], config, scion_addr, metrics.clone());

    let established = Arc::new(AtomicUsize::new(0));
    let established_cb = established.clone();
    let driver = QuicScionEndpointDriver::with_config(
        endpoint,
        server_socket,
        move |_handle: ConnectionHandle<Http3Server<S>>| {
            established_cb.fetch_add(1, Ordering::SeqCst);
        },
        Http3ServerConfig::new(service),
    );

    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        // Keep the certificate/key temp files alive for the server's lifetime.
        let _keep_alive = (cert, key);
        let _ = driver.run(cancel_task).await;
    });

    (
        TestServer {
            established,
            metrics,
            cancel,
        },
        Arc::new(client_socket),
    )
}

fn make_client(socket: Arc<MockScionSocket>, idle: Duration) -> Http3Client {
    Http3Client::with_config(
        server_addr(),
        socket,
        Some("localhost".to_string()),
        client_config(idle),
    )
}

const LONG_IDLE: Duration = Duration::from_secs(30);

// --------------------------------------------------------------------------
// Request bodies (client side)
// --------------------------------------------------------------------------

/// A request body that yields a single buffer.
struct FullBody(Option<Bytes>);

impl FullBody {
    fn new(data: impl Into<Bytes>) -> Self {
        Self(Some(data.into()))
    }
}

impl Body for FullBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
    }
}

// --------------------------------------------------------------------------
// Server services
// --------------------------------------------------------------------------

/// A response body yielding queued data chunks followed by optional trailers.
struct ChunkedBody {
    chunks: VecDeque<Bytes>,
    trailers: Option<http::HeaderMap>,
}

impl Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(chunk) = self.chunks.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// `GET /stream` → three body chunks plus an `x-trailer` trailing header.
#[derive(Clone)]
struct StreamingService;

impl HttpService for StreamingService {
    type Body = H3RequestBody;
    type ResponseBody = ChunkedBody;

    async fn call(&self, _req: http::Request<H3RequestBody>) -> http::Response<ChunkedBody> {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
        let chunks = VecDeque::from(vec![
            Bytes::from_static(b"chunk-1;"),
            Bytes::from_static(b"chunk-2;"),
            Bytes::from_static(b"chunk-3"),
        ]);
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header("x-kind", "streaming")
            .body(ChunkedBody {
                chunks,
                trailers: Some(trailers),
            })
            .unwrap()
    }
}

/// `POST /echo` → echoes the request body back as the response body.
#[derive(Clone)]
struct EchoService;

impl HttpService for EchoService {
    type Body = H3RequestBody;
    type ResponseBody = H3RequestBody;

    async fn call(&self, req: http::Request<H3RequestBody>) -> http::Response<H3RequestBody> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(req.into_body())
            .unwrap()
    }
}

/// Never responds: holds the request open forever (used to fault on close).
#[derive(Clone)]
struct HangingService;

impl HttpService for HangingService {
    type Body = H3RequestBody;
    type ResponseBody = ChunkedBody;

    async fn call(&self, _req: http::Request<H3RequestBody>) -> http::Response<ChunkedBody> {
        std::future::pending().await
    }
}

/// An infinite streaming response body (used for cancellation tests).
struct InfiniteBody;

impl Body for InfiniteBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&[0u8; 1024])))))
    }
}

/// `GET /infinite` → an unbounded response body.
#[derive(Clone)]
struct InfiniteService;

impl HttpService for InfiniteService {
    type Body = H3RequestBody;
    type ResponseBody = InfiniteBody;

    async fn call(&self, _req: http::Request<H3RequestBody>) -> http::Response<InfiniteBody> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(InfiniteBody)
            .unwrap()
    }
}

/// A response body that yields one data frame, then waits for an external gate
/// before erroring. The test releases the gate only once the CONNECT head has
/// been received, so the reset always lands on an *established* stream (used to
/// test peer-reset surfacing) rather than racing the head delivery.
struct ResetBody {
    sent: bool,
    /// Released (sent on or closed) by the test once the head has arrived; the
    /// body resets the stream only after this fires.
    gate: Option<oneshot::Receiver<()>>,
}

impl Body for ResetBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if !self.sent {
            self.sent = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"pre-reset")))));
        }
        if let Some(gate) = self.gate.as_mut() {
            // Both a value and a closed channel mean "go ahead and reset".
            match Pin::new(gate).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => self.gate = None,
            }
        }
        Poll::Ready(Some(Err(io::Error::other("intentional reset"))))
    }
}

/// `CONNECT example.com:443` → accepts, sends a chunk, then resets the stream
/// once the test releases the gate (signalling the head has been received).
#[derive(Clone)]
struct ConnectResetService {
    gate: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

impl HttpService for ConnectResetService {
    type Body = H3RequestBody;
    type ResponseBody = ResetBody;

    async fn call(&self, _req: http::Request<H3RequestBody>) -> http::Response<ResetBody> {
        let gate = self.gate.lock().await.take();
        http::Response::builder()
            .status(http::StatusCode::OK)
            .body(ResetBody { sent: false, gate })
            .unwrap()
    }
}

/// `CONNECT example.com:443` → echo tunnel (response body is the request body);
/// any other authority → `404`.
#[derive(Clone)]
struct ConnectEchoService;

impl HttpService for ConnectEchoService {
    type Body = H3RequestBody;
    type ResponseBody = H3RequestBody;

    async fn call(&self, req: http::Request<H3RequestBody>) -> http::Response<H3RequestBody> {
        let accept = req.method() == http::Method::CONNECT
            && req.uri().authority().map(|a| a.as_str()) == Some("example.com:443");
        let status = if accept {
            http::StatusCode::OK
        } else {
            http::StatusCode::NOT_FOUND
        };
        http::Response::builder()
            .status(status)
            .body(req.into_body())
            .unwrap()
    }
}

/// Reads the request body to completion and echoes the value of a trailing
/// `x-trailer` header back as the response body (`200`), or `404` if the request
/// carried no such trailer. Used to verify the client sends request trailers.
#[derive(Clone)]
struct RequestTrailerEchoService;

impl HttpService for RequestTrailerEchoService {
    type Body = H3RequestBody;
    type ResponseBody = FullBody;

    async fn call(&self, req: http::Request<H3RequestBody>) -> http::Response<FullBody> {
        let mut body = req.into_body();
        let mut trailer_value: Option<Bytes> = None;
        while let Some(Ok(frame)) =
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            // Body data is ignored; only the trailing header section matters.
            if let Err(non_data) = frame.into_data()
                && let Ok(trailers) = non_data.into_trailers()
                && let Some(value) = trailers.get("x-trailer")
            {
                trailer_value = Some(Bytes::copy_from_slice(value.as_bytes()));
            }
        }
        let (status, body) = match trailer_value {
            Some(value) => (http::StatusCode::OK, value),
            None => (http::StatusCode::NOT_FOUND, Bytes::new()),
        };
        http::Response::builder()
            .status(status)
            .body(FullBody::new(body))
            .unwrap()
    }
}

/// `GET /hello` → `200` with a body; any other path → `404` with an empty body.
/// Used to verify a non-CONNECT error status is surfaced as a normal response.
#[derive(Clone)]
struct StatusService;

impl HttpService for StatusService {
    type Body = H3RequestBody;
    type ResponseBody = FullBody;

    async fn call(&self, req: http::Request<H3RequestBody>) -> http::Response<FullBody> {
        let (status, body) = if req.uri().path() == "/hello" {
            (http::StatusCode::OK, Bytes::from_static(b"hello"))
        } else {
            (http::StatusCode::NOT_FOUND, Bytes::new())
        };
        http::Response::builder()
            .status(status)
            .body(FullBody::new(body))
            .unwrap()
    }
}

// --------------------------------------------------------------------------
// Client helpers
// --------------------------------------------------------------------------

async fn read_body<B>(mut body: B) -> (Vec<u8>, Option<http::HeaderMap>)
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.expect("response body frame error");
        match frame.into_data() {
            Ok(bytes) => data.extend_from_slice(&bytes),
            Err(non_data) => {
                if let Ok(t) = non_data.into_trailers() {
                    trailers = Some(t);
                }
            }
        }
    }
    (data, trailers)
}

/// Builds a headers-only request (the body is driven separately via the
/// [`RequestBodyWriter`]).
fn head_request(method: http::Method, path: &str) -> http::Request<()> {
    http::Request::builder()
        .method(method)
        .uri(format!("https://example.com{path}"))
        .body(())
        .unwrap()
}

/// Issues a GET over `request`, finishing the (empty) request body
/// before awaiting the response. The empty FIN never blocks on flow control, so
/// finishing inline is safe.
async fn get(
    client: &Http3Client,
    path: &str,
) -> Result<http::Response<H3ResponseBody>, RequestError> {
    let (response, writer) = client
        .request(head_request(http::Method::GET, path))
        .await?;
    // Finishing the empty body errors only if the connection is already gone, in
    // which case the response future surfaces the fault.
    let _ = writer.finish().await;
    response.await
}

/// Issues a POST with a fixed body over `request`, driving the body on a
/// spawned task — the pattern callers use now that the client only exposes the
/// streamed API — while the response is awaited concurrently. This avoids the
/// request-vs-response deadlock that a synchronous "send then await" would hit
/// against a server that streams its response while reading the request.
async fn post(
    client: &Http3Client,
    path: &str,
    body: impl Into<Bytes>,
) -> Result<http::Response<H3ResponseBody>, RequestError> {
    let body = body.into();
    let (response, mut writer) = client
        .request(head_request(http::Method::POST, path))
        .await?;
    tokio::spawn(async move {
        if !body.is_empty() {
            let _ = writer.write_chunk(body).await;
        }
        let _ = writer.finish().await;
    });
    response.await
}

/// Opens a full-duplex byte stream over a `CONNECT` request issued through
/// `request`, returning the response head and an [`H3DuplexStream`].
/// Does not enforce a 2xx status; the caller inspects `parts.status`.
async fn connect_tunnel(
    client: &Http3Client,
    authority: &str,
) -> Result<(http::response::Parts, H3DuplexStream), RequestError> {
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{authority}"))
        .body(())
        .unwrap();
    let (response, writer) = client.request(req).await?;
    let response = response.await?;
    let (parts, body) = response.into_parts();
    Ok((parts, H3DuplexStream::new(writer, body)))
}

/// Polls `cond` until it returns `true`, yielding between checks. Bounded by the
/// caller's `#[ntest::timeout]`; used to await an observable condition instead of
/// sleeping a fixed (and racy) duration.
async fn wait_until(mut cond: impl FnMut() -> bool) {
    while !cond() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

/// A request/response with a streamed multi-chunk response body and trailers;
/// the head, body chunks, and trailers all arrive correctly.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn request_response_streamed_body_and_trailers() {
    let (_server, socket) = spawn_server(StreamingService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let response = get(&client, "/stream").await.expect("request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.headers().get("x-kind").map(|v| v.as_bytes()),
        Some(b"streaming".as_slice())
    );

    let (data, trailers) = read_body(response.into_body()).await;
    assert_eq!(data, b"chunk-1;chunk-2;chunk-3");
    let trailers = trailers.expect("response should carry trailers");
    assert_eq!(
        trailers.get("x-trailer").map(|v| v.as_bytes()),
        Some(b"done".as_slice())
    );
}

/// A streamed request body larger than the flow-control window is echoed back
/// verbatim: the upload is driven on a spawned task while the response body is
/// read concurrently (the echo server interleaves reading the request and
/// writing the response, so the two must progress together). A bodyless request
/// finished immediately echoes nothing.
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn streamed_request_body_echo_and_bodyless() {
    let (_server, socket) = spawn_server(EchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    // Large body: comfortably beyond the 1 MiB per-stream window, sent in chunks.
    let payload: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let (response, mut writer) = client
        .request(head_request(http::Method::POST, "/echo"))
        .await
        .expect("request");
    let upload = {
        let payload = payload.clone();
        tokio::spawn(async move {
            for chunk in payload.chunks(64 * 1024) {
                writer
                    .write_chunk(Bytes::copy_from_slice(chunk))
                    .await
                    .expect("write chunk");
            }
            writer.finish().await.expect("finish body");
        })
    };
    let response = response.await.expect("response head");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (echoed, _) = read_body(response.into_body()).await;
    upload.await.expect("upload task panicked");
    assert_eq!(echoed.len(), payload.len(), "echoed length mismatch");
    assert!(echoed == payload, "echoed body mismatch");

    // Bodyless POST: finish immediately, empty echo.
    let response = post(&client, "/echo", Bytes::new())
        .await
        .expect("bodyless request");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (echoed, _) = read_body(response.into_body()).await;
    assert!(echoed.is_empty(), "bodyless request should echo nothing");
}

/// The response head can be observed before the request body is finished: the
/// echo server returns its head as soon as the request head arrives, so the
/// caller awaits the response, then writes and finishes the body, and reads the
/// echo back — the two directions progress independently.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn streamed_response_observed_before_body_finished() {
    let (_server, socket) = spawn_server(EchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (response, mut writer) = client
        .request(head_request(http::Method::POST, "/echo"))
        .await
        .expect("request");

    // Observe the response head before any body byte is written or finished.
    let response = response.await.expect("response head");
    assert_eq!(response.status(), http::StatusCode::OK);

    // Now drive the body and finish it; the echo comes back on the read side.
    writer
        .write_chunk(Bytes::from_static(b"late-body"))
        .await
        .expect("write body");
    writer.finish().await.expect("finish body");

    let (echoed, _) = read_body(response.into_body()).await;
    assert_eq!(echoed, b"late-body");
}

/// Dropping the body writer before finishing resets only the request's write
/// side: a server that ignores the request body still streams its full response,
/// which the caller reads to completion on the untouched read side.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn streamed_writer_drop_resets_write_side_only() {
    let (_server, socket) = spawn_server(StreamingService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (response, mut writer) = client
        .request(head_request(http::Method::POST, "/stream"))
        .await
        .expect("request");

    // Write a partial body, observe the response head, then drop the writer
    // without finishing: the write side is reset (H3_REQUEST_CANCELLED), the read
    // side is left alone.
    writer
        .write_chunk(Bytes::from_static(b"partial"))
        .await
        .expect("write partial body");

    let response = response.await.expect("response head despite aborted body");
    assert_eq!(response.status(), http::StatusCode::OK);
    drop(writer);
    let (data, trailers) = read_body(response.into_body()).await;
    assert_eq!(
        data, b"chunk-1;chunk-2;chunk-3",
        "the response read side must be unaffected by the write-side reset"
    );
    assert!(trailers.is_some(), "response trailers should still arrive");
}

/// Streamed requests with a caller-driven body release all per-stream state once
/// the body is finished and the response is fully read: issuing far more than the
/// 100 bidi-stream limit on one connection therefore all succeed and leave no
/// tracked state behind.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn streamed_request_with_body_releases_stream_state() {
    let (_server, socket) = spawn_server(EchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    const REQUESTS: usize = 150;
    for i in 0..REQUESTS {
        let (response, mut writer) = client
            .request(head_request(http::Method::POST, "/echo"))
            .await
            .unwrap_or_else(|err| panic!("request {i} failed (streams leaked?): {err:?}"));
        let payload = format!("body-{i}");
        let upload = {
            let payload = payload.clone();
            tokio::spawn(async move {
                writer
                    .write_chunk(Bytes::from(payload))
                    .await
                    .expect("write body");
                writer.finish().await.expect("finish body");
            })
        };
        let response = response.await.expect("response head");
        assert_eq!(response.status(), http::StatusCode::OK);
        let (echoed, _) = read_body(response.into_body()).await;
        upload.await.expect("upload task panicked");
        assert_eq!(echoed, payload.as_bytes(), "request {i} echo mismatch");
    }

    assert_eq!(
        client.tracked_stream_state().await,
        0,
        "completed streamed requests must release their per-stream state"
    );
}

/// Many requests issued concurrently on one connection, each routed back to its
/// own caller (independent, possibly out-of-order responses, no cross-talk).
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn concurrent_requests_independent_routing() {
    let (_server, socket) = spawn_server(EchoService, LONG_IDLE);
    let client = Arc::new(make_client(socket, LONG_IDLE));

    const N: usize = 20;
    let mut tasks = Vec::new();
    for i in 0..N {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let payload = format!("concurrent-{i}");
            let response = post(&client, "/echo", payload.clone())
                .await
                .expect("request");
            assert_eq!(response.status(), http::StatusCode::OK);
            let (echoed, _) = read_body(response.into_body()).await;
            assert_eq!(echoed, payload.as_bytes(), "request {i} cross-talk");
        }));
    }
    for task in tasks {
        task.await.expect("task panicked");
    }
}

/// A `CONNECT` to an accepted authority opens a 2xx tunnel that streams bytes in
/// both directions (the rejected-authority case is covered separately).
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn connect_tunnel_established_and_bidirectional() {
    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (parts, mut stream) = connect_tunnel(&client, "example.com:443")
        .await
        .expect("CONNECT should be accepted");
    assert_eq!(parts.status, http::StatusCode::OK);

    // Several interactive send/echo rounds (each completes before the next).
    for round in 0..3u32 {
        let payload = format!("tunnel-round-{round}").into_bytes();
        stream.write_all(&payload).await.expect("write tunnel");
        stream.flush().await.expect("flush tunnel");
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.expect("read tunnel echo");
        assert_eq!(got, payload, "round {round} echo mismatch");
    }
}

/// A CONNECT to a disallowed authority comes back as a normal non-2xx response
/// (the caller inspects the status); no special error variant is involved.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn connect_tunnel_refused() {
    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (parts, _stream) = connect_tunnel(&client, "not-allowed.example.com:443")
        .await
        .expect("CONNECT request itself succeeds; the status reports refusal");
    assert_eq!(
        parts.status,
        http::StatusCode::NOT_FOUND,
        "a disallowed authority should be refused with a non-2xx status"
    );
}

/// After the connection idles out and closes, the next request transparently
/// establishes a fresh connection (the server reports a further establishment).
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn lazy_reconnect_after_close() {
    let idle = Duration::from_millis(300);
    let (server, socket) = spawn_server(EchoService, idle);
    let client = make_client(socket, idle);

    let response = post(&client, "/echo", "first")
        .await
        .expect("first request");
    let (body, _) = read_body(response.into_body()).await;
    assert_eq!(body, b"first");
    assert_eq!(server.established.load(Ordering::SeqCst), 1);

    // Wait for the idle connection to actually be torn down server-side (the
    // registered-connection gauge drops back to zero) rather than guessing a
    // fixed sleep that races the idle timeout. Once it is gone, the next request
    // must establish a fresh connection.
    wait_until(|| server.registered_connections() == 0).await;

    let response = post(&client, "/echo", "second")
        .await
        .expect("second request after reconnect");
    let (body, _) = read_body(response.into_body()).await;
    assert_eq!(body, b"second");
    assert!(
        server.established.load(Ordering::SeqCst) >= 2,
        "a fresh connection should have been established after the idle close"
    );
}

/// Many requests issued concurrently on a fresh client establish exactly one
/// connection (concurrent first-use is serialized, so no redundant reconnects).
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn concurrent_first_use_opens_one_connection() {
    let (server, socket) = spawn_server(EchoService, LONG_IDLE);
    let client = Arc::new(make_client(socket, LONG_IDLE));

    const N: usize = 8;
    let mut tasks = Vec::new();
    for i in 0..N {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let response = post(&client, "/echo", format!("c-{i}"))
                .await
                .expect("request");
            let (body, _) = read_body(response.into_body()).await;
            assert_eq!(body, format!("c-{i}").as_bytes());
        }));
    }
    for task in tasks {
        task.await.expect("task panicked");
    }

    assert_eq!(
        server.established.load(Ordering::SeqCst),
        1,
        "concurrent first-use must open only one connection"
    );
}

/// A request in flight when the connection closes faults with a
/// connection-closed error and is not retried automatically.
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn inflight_request_faults_on_close() {
    let idle = Duration::from_millis(500);
    let (server, socket) = spawn_server(HangingService, idle);
    let client = make_client(socket, idle);

    // The service never responds; the connection idles out and closes, faulting
    // the pending request.
    let result = get(&client, "/hang").await;
    match result {
        Err(RequestError::ConnectionClosed) | Err(RequestError::Reset(_)) => {}
        Err(other) => panic!("expected a connection-closed fault, got {other:?}"),
        Ok(_) => panic!("hanging service should not have produced a response"),
    }

    // Exactly one connection was established; the fault was not retried.
    assert_eq!(
        server.established.load(Ordering::SeqCst),
        1,
        "the faulted request must not trigger an automatic retry"
    );
}

/// Dropping a response body before end-of-stream resets the stream and releases
/// per-stream state. Issuing far more than the bidi-stream limit (100) of
/// drop-after-head requests on one connection therefore all succeed.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn dropping_response_body_resets_stream() {
    let (_server, socket) = spawn_server(InfiniteService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    // Comfortably exceed the default 100 bidi-stream limit; if the dropped
    // response bodies did not reset their streams, this would stall.
    const REQUESTS: usize = 150;
    for i in 0..REQUESTS {
        let response = get(&client, "/infinite")
            .await
            .unwrap_or_else(|err| panic!("request {i} failed (streams leaked?): {err:?}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        // Drop the response (and its streaming body) without reading it,
        // exercising reset-on-drop.
        drop(response);
    }
}

/// A writer that keeps writing while the peer stops reading eventually pends
/// (the QUIC window provides backpressure, no unbounded buffering), and resumes
/// once the reader drains.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn connect_tunnel_backpressure() {
    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (_parts, stream) = connect_tunnel(&client, "example.com:443")
        .await
        .expect("CONNECT");
    let (mut rd, mut wr) = tokio::io::split(stream);

    // Far larger than the per-stream flow-control window (1 MiB).
    const TOTAL: usize = 4 * 1024 * 1024;
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let done = done.clone();
        tokio::spawn(async move {
            let chunk = vec![0xABu8; 64 * 1024];
            let mut written = 0;
            while written < TOTAL {
                wr.write_all(&chunk).await.expect("write tunnel");
                written += chunk.len();
            }
            wr.flush().await.expect("flush tunnel");
            done.store(true, Ordering::SeqCst);
        })
    };

    // Without reading, the writer must block on flow control.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !done.load(Ordering::SeqCst),
        "writer should be blocked by backpressure while the reader is idle"
    );

    // Drain the echoed bytes; the writer then completes.
    let mut got = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while got < TOTAL {
        let n = rd.read(&mut buf).await.expect("read tunnel");
        assert_ne!(n, 0, "unexpected EOF before draining all bytes");
        got += n;
    }
    writer.await.expect("writer task panicked");
    assert!(done.load(Ordering::SeqCst));
    assert_eq!(got, TOTAL);
}

/// Shutting down the tunnel's write half sends a FIN; the echo server then
/// finishes the response, so the read half reaches EOF.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn connect_tunnel_write_half_shutdown() {
    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (_parts, mut stream) = connect_tunnel(&client, "example.com:443")
        .await
        .expect("CONNECT");

    stream.write_all(b"hello").await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = [0u8; 5];
    stream.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, b"hello");

    // FIN the write half; the echo response then ends, so the read half hits EOF.
    stream.shutdown().await.expect("shutdown write half");
    let n = stream.read(&mut [0u8; 16]).await.expect("read after FIN");
    assert_eq!(n, 0, "read half should reach EOF after the echo finishes");
}

/// When the server resets the stream, reads on the tunnel fail with an I/O
/// error.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn connect_tunnel_peer_reset_is_io_error() {
    let (gate_tx, gate_rx) = oneshot::channel();
    let service = ConnectResetService {
        gate: Arc::new(Mutex::new(Some(gate_rx))),
    };
    let (_server, socket) = spawn_server(service, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let (parts, mut stream) = connect_tunnel(&client, "example.com:443")
        .await
        .expect("CONNECT");
    assert_eq!(parts.status, http::StatusCode::OK);

    // The head has arrived and the tunnel is established; release the reset.
    let _ = gate_tx.send(());

    let mut buf = vec![0u8; 64];
    let err = loop {
        match stream.read(&mut buf).await {
            Ok(0) => panic!("expected a reset I/O error, got a clean EOF"),
            Ok(_) => continue, // the pre-reset chunk
            Err(err) => break err,
        }
    };
    assert_eq!(
        err.kind(),
        io::ErrorKind::ConnectionReset,
        "peer reset should surface as a ConnectionReset I/O error"
    );
}

/// A TCP connection spliced through a `CONNECT` tunnel with `copy_bidirectional`
/// carries bytes in both directions until close.
#[test_log::test(tokio::test)]
#[ntest::timeout(20_000)]
async fn tcp_forward_proxy_through_connect_tunnel() {
    use tokio::net::{TcpListener, TcpStream};

    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = Arc::new(make_client(socket, LONG_IDLE));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    // The proxy: accept one TCP connection, open a CONNECT tunnel, and splice.
    let proxy = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let (_parts, mut tunnel) = connect_tunnel(&client, "example.com:443")
            .await
            .expect("CONNECT");
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut tunnel).await;
    });

    let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let payload = b"ping-through-proxy";
    tcp.write_all(payload).await.unwrap();

    // The tunneled echo server returns the bytes back through the proxy.
    let mut got = vec![0u8; payload.len()];
    tcp.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // Close the write half; closure propagates through the tunnel and unwinds
    // the bidirectional copy.
    tcp.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tcp.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());

    proxy.await.expect("proxy task panicked");
}

/// Cleanly completed requests release their per-stream state: many requests
/// fully read to EOF (body + trailers) on a single connection must not
/// accumulate per-stream bookkeeping. Without collection on the clean path this
/// state would grow unbounded over the connection's life; afterwards the
/// tracked-state count returns to zero.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn completed_requests_release_stream_state() {
    let (_server, socket) = spawn_server(StreamingService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    // Comfortably more than the 100 bidi-stream limit, on one connection.
    const REQUESTS: usize = 150;
    for i in 0..REQUESTS {
        let response = get(&client, "/stream")
            .await
            .unwrap_or_else(|err| panic!("request {i} failed: {err:?}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let (data, trailers) = read_body(response.into_body()).await;
        assert_eq!(data, b"chunk-1;chunk-2;chunk-3");
        assert!(trailers.is_some(), "request {i} should carry trailers");
    }

    assert_eq!(
        client.tracked_stream_state().await,
        0,
        "completed requests must release their per-stream state"
    );
}

/// Cleanly closed `CONNECT` tunnels release their per-stream state: opening a
/// tunnel, exchanging bytes, half-closing it, and draining to EOF must leave no
/// per-stream bookkeeping behind once the tunnel is dropped.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn closed_tunnels_release_stream_state() {
    let (_server, socket) = spawn_server(ConnectEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    const TUNNELS: usize = 150;
    for i in 0..TUNNELS {
        let (_parts, mut stream) = connect_tunnel(&client, "example.com:443")
            .await
            .unwrap_or_else(|err| panic!("CONNECT {i} failed: {err:?}"));

        let payload = format!("tunnel-{i}").into_bytes();
        stream.write_all(&payload).await.expect("write tunnel");
        stream.flush().await.expect("flush tunnel");
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.expect("read tunnel echo");
        assert_eq!(got, payload, "tunnel {i} echo mismatch");

        // Half-close: the echo server then finishes, so the read half hits EOF.
        stream.shutdown().await.expect("shutdown write half");
        let n = stream.read(&mut [0u8; 16]).await.expect("read after FIN");
        assert_eq!(n, 0, "tunnel {i} read half should reach EOF");
        drop(stream);
    }

    assert_eq!(
        client.tracked_stream_state().await,
        0,
        "cleanly closed tunnels must release their per-stream state"
    );
}

/// A request body that ends with a trailing header section has its trailers sent
/// to the server: the service reads the `x-trailer` request trailer and echoes
/// its value back, which only succeeds if the client serialized the trailers.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn request_trailers_are_sent() {
    let (_server, socket) = spawn_server(RequestTrailerEchoService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", http::HeaderValue::from_static("trailer-value"));

    let (response, mut writer) = client
        .request(head_request(http::Method::POST, "/with-trailers"))
        .await
        .expect("request");
    tokio::spawn(async move {
        writer
            .write_chunk(Bytes::from_static(b"body-bytes"))
            .await
            .expect("write body");
        writer
            .write_trailers(trailers)
            .await
            .expect("write trailers");
    });
    let response = response.await.expect("request with trailers");
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "server did not observe the request trailer"
    );
    let (body, _) = read_body(response.into_body()).await;
    assert_eq!(
        body, b"trailer-value",
        "server echoed the wrong trailer value"
    );
}

/// A non-CONNECT request whose path the service answers with a non-2xx status
/// yields that status as a normal `Response` (not a `RequestError`), with the
/// body intact, and the connection stays usable for a subsequent request.
#[test_log::test(tokio::test)]
#[ntest::timeout(15_000)]
async fn error_status_surfaced_without_fault() {
    let (_server, socket) = spawn_server(StatusService, LONG_IDLE);
    let client = make_client(socket, LONG_IDLE);

    // A 404 is a valid response, not a request error.
    let response = get(&client, "/does-not-exist")
        .await
        .expect("a non-2xx status must surface as a normal response");
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    let (body, _) = read_body(response.into_body()).await;
    assert!(body.is_empty(), "404 response should have an empty body");

    // The connection remains usable for a subsequent successful request.
    let response = get(&client, "/hello")
        .await
        .expect("follow-up request after a 404");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (body, _) = read_body(response.into_body()).await;
    assert_eq!(body, b"hello");
}
