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

//! A PocketSCION topology with an HTTP/3 server in it, run as a process.
//!
//! For testing any HTTP/3-over-SCION client, from any language, against a real request path. On
//! start-up it prints one line of JSON describing everything a client needs to reach it, and then
//! runs until its standard input closes or it is killed. Closing standard input is the intended way
//! to stop it, so a harness that dies without killing it leaves no topology behind.
//!
//! ```bash
//! cargo run --release -p scion-h3-test-server
//! ```
//!
//! ```text
//! {"endhost_api_url":"http://127.0.0.1:34517","auth_token":"...","base_url":"https://localhost:45123", ...}
//! ```
//!
//! # What the JSON says
//!
//! | Field | Purpose |
//! | --- | --- |
//! | `endhost_api_url` | The endhost API of AS 1-ff00:0:132, where a client discovers its connectivity. |
//! | `auth_token` | The topology's development token, for the endhost API and the SNAP control plane. |
//! | `base_url` | Where the server is, as a URL: `https://localhost:<port>`. |
//! | `target` | The server's SCION address, without a port. The topology has no TSAR records, so a client either resolves `localhost` itself or passes this as an address override. |
//! | `ca_pem` | The self-signed certificate the server presents, to be trusted as an anchor. |
//! | `control_url` | The control API below, on loopback TCP. |
//!
//! # Request paths
//!
//! Served over HTTP/3 in AS 2-ff00:0:212. Each one exists to make a single client behaviour
//! observable.
//!
//! | Path | Serves | Useful for |
//! | --- | --- | --- |
//! | `GET /hello` | `world` | Liveness, and showing that a connection still works after something else went wrong on it. |
//! | `POST /echo` | The request body, unchanged | Bodies that survive both directions byte for byte, at any size. |
//! | `GET /echo-headers` | The request headers as JSON | What headers actually reached the server, including repeated ones and their order. |
//! | `* /method` | The request method | Methods arriving unchanged, including ones with no special handling anywhere. |
//! | `GET /repeated-headers` | Two `set-cookie` fields | Response headers that a map keyed by name cannot represent. |
//! | `GET /status/{code}` | That status | Status codes arriving unchanged. |
//! | `GET /trailers` | A body and an `x-checksum` trailer | The trailing header section, which no ordinary handler produces. |
//! | `GET /slow?ms=` | A response after a delay | Request deadlines. Defaults to a second. |
//! | `GET /big?bytes=` | That many bytes | Response size limits, and reassembly of a body spanning many frames. Defaults to a kilobyte. |
//! | `GET /invalid-utf8` | Two bytes that are not UTF-8 | Bodies that must not be decoded on the way through. |
//! | `GET /endless-body?tag=` | A chunk every 50 ms, forever | Cancellation. The count for `tag` stops going up once the client's `STOP_SENDING` arrives, which is the only way to see from outside that a cancelled request reached the server. |
//!
//! # Control API
//!
//! Plain HTTP over loopback TCP, so a client that is being tested never sees it.
//!
//! | Path | Serves |
//! | --- | --- |
//! | `GET /stats` | `{"endless_chunks": {tag: count}, "requests": {path: count}}`. Chunks sent per endless-body tag, and completed requests per path. |
//!
//! # Options
//!
//! Two settings exist because the conditions they create cannot be provoked from the client side:
//! `--max-streams 0` makes every request fail against the peer's concurrent-stream limit, and
//! `--alpn` set to anything but `h3` makes every connection attempt fail to agree on a protocol.
//!
//! Everything binds to loopback. Reaching it from a device or an emulator needs PocketSCION to bind
//! its components to a routable address, which it cannot be told to do yet.

use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use clap::Parser;
use pocketscion::util::{
    dev_auth_token,
    topologies::{IA132, IA212, PsSetup, UnderlayType, minimal::minimal_topology},
};
use scion_quic::quic::config::QuicConfig;
use scion_stack::ScionStackBuilder;
use tokio_util::sync::CancellationToken;

/// The name in the server certificate, and therefore the host a client must use.
const SERVER_NAME: &str = "localhost";

/// How often the endless body produces a chunk.
const ENDLESS_BODY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Parser)]
#[command(about = "A PocketSCION topology serving HTTP/3")]
struct Args {
    /// Concurrent request streams the server allows.
    ///
    /// Zero makes every request fail against the peer's stream limit, which is otherwise
    /// impossible to provoke deliberately.
    #[arg(long, default_value_t = 100)]
    max_streams: u64,

    /// The ALPN protocol the server negotiates.
    ///
    /// Anything but `h3` makes every candidate fail on ALPN, which is what a client reports as a
    /// TLS failure rather than as an unreachable peer.
    #[arg(long, default_value = "h3")]
    alpn: String,
}

/// Counters the control API reports, and the routes that move them.
#[derive(Default)]
struct Counters {
    /// Chunks sent per endless-body tag.
    ///
    /// After a client cancels a request, its tag stops going up, which only happens once
    /// `STOP_SENDING` has reached the server. That is how a test sees a cancellation arrive. Per
    /// tag, so that concurrent tests do not read each other's.
    endless_chunks: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    /// Completed requests per path, so a test can prove a later request really reached the server.
    requests: Mutex<BTreeMap<String, u64>>,
}

impl Counters {
    fn endless_chunks(&self, tag: &str) -> Arc<AtomicU64> {
        self.endless_chunks
            .lock()
            .expect("lock poisoned")
            .entry(tag.to_owned())
            .or_default()
            .clone()
    }

    fn record_request(&self, path: &str) {
        *self
            .requests
            .lock()
            .expect("lock poisoned")
            .entry(path.to_owned())
            .or_default() += 1;
    }

    fn snapshot(&self) -> serde_json::Value {
        let endless: BTreeMap<String, u64> = self
            .endless_chunks
            .lock()
            .expect("lock poisoned")
            .iter()
            .map(|(tag, count)| (tag.clone(), count.load(Ordering::Relaxed)))
            .collect();
        let requests = self.requests.lock().expect("lock poisoned").clone();
        serde_json::json!({ "endless_chunks": endless, "requests": requests })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let args = Args::parse();
    let counters = Arc::new(Counters::default());
    let shutdown = CancellationToken::new();

    let ps = minimal_topology(UnderlayType::Udp).await;
    let control_url = serve_control(counters.clone(), shutdown.clone()).await?;
    let server = serve_scion(&ps, &args, counters, shutdown.clone()).await?;

    let description = serde_json::json!({
        "endhost_api_url": ps.endhost_api(IA132).expect("endhost API for IA132").to_string(),
        "auth_token": dev_auth_token(),
        "base_url": format!("https://{SERVER_NAME}:{}", server.port),
        "target": server.address,
        "ca_pem": server.ca_pem,
        "control_url": control_url,
    });
    println!("{description}");
    std::io::stdout().flush()?;

    wait_for_stdin_close().await;
    tracing::info!("Standard input closed, shutting down");
    shutdown.cancel();
    Ok(())
}

/// Everything about the running HTTP/3 server that a client needs.
struct ServerHandle {
    port: u16,
    address: String,
    ca_pem: String,
}

async fn serve_scion(
    ps: &PsSetup,
    args: &Args,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
) -> Result<ServerHandle, Box<dyn std::error::Error>> {
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).expect("endhost API for IA212"))
        .with_auth_token(dev_auth_token())
        .build()
        .await?;
    let socket = Arc::new(stack.bind(None).await?);
    let address = socket.local_addr();

    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let ca_pem = cert.cert.pem();
    // Files, because squiche loads a server's own certificate chain and private key from paths and
    // from nothing else. `QuicConfig::ca_certs_pem` is not the counterpart: it configures trust
    // anchors, which is what a client verifies against, and the client side of these tests does use
    // it. Loading an identity from memory needs a squiche addition mirroring
    // `load_verify_locations_from_memory`.
    let cert_file = write_temp_file(ca_pem.as_bytes())?;
    let key_file = write_temp_file(cert.signing_key.serialize_pem().as_bytes())?;

    let mut quic = QuicConfig::builder().verify_peer(false).build();
    quic.initial_max_streams_bidi = args.max_streams;
    quic.application_protos = vec![args.alpn.as_bytes().to_vec()];
    let mut quic = quic.to_quiche_config()?;
    quic.load_cert_chain_from_pem_file(path_str(&cert_file))?;
    quic.load_priv_key_from_pem_file(path_str(&key_file))?;

    let router = router(counters);
    tokio::spawn(async move {
        // The stack outlives the server: a socket bound from it works only while it is alive. The
        // key file likewise, since squiche reads it during the handshake.
        let _stack = stack;
        let _cert_file = cert_file;
        let _key_file = key_file;
        if let Err(error) = scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
            socket, router, quic, shutdown,
        )
        .await
        {
            tracing::error!(%error, "The HTTP/3 server stopped");
        }
    });

    Ok(ServerHandle {
        port: address.port(),
        address: address.host().to_string(),
        ca_pem,
    })
}

fn router(counters: Arc<Counters>) -> Router {
    Router::new()
        .route("/hello", get(|| async { "world" }))
        .route("/echo", post(|body: Bytes| async move { body }))
        .route("/echo-headers", get(echo_headers))
        .route(
            "/method",
            any(|method: Method| async move { method.to_string() }),
        )
        .route("/repeated-headers", get(repeated_headers))
        .route("/status/{code}", get(status))
        .route("/trailers", get(trailers))
        .route("/slow", get(slow))
        .route("/big", get(big))
        .route("/invalid-utf8", get(invalid_utf8))
        .route("/endless-body", get(endless_body))
        .layer(middleware::from_fn_with_state(counters.clone(), count))
        .with_state(counters)
}

async fn count(State(counters): State<Arc<Counters>>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    counters.record_request(&path);
    response
}

/// Reports the request's headers, so a test can see what actually reached the server rather than
/// what it believes it sent.
async fn echo_headers(headers: HeaderMap) -> Response {
    let mut fields = Vec::new();
    for (name, value) in &headers {
        fields.push(serde_json::json!({
            "name": name.as_str(),
            "value": String::from_utf8_lossy(value.as_bytes()),
        }));
    }
    axum::Json(serde_json::Value::Array(fields)).into_response()
}

/// Sends one field name twice, which a client that keeps response headers in a map keyed by name
/// cannot represent.
async fn repeated_headers() -> Response {
    let mut response = "cookies".into_response();
    let headers = response.headers_mut();
    headers.append("set-cookie", HeaderValue::from_static("a=1"));
    headers.append("set-cookie", HeaderValue::from_static("b=2"));
    response
}

async fn status(Path(code): Path<u16>) -> Response {
    StatusCode::from_u16(code).map_or_else(
        |_| (StatusCode::BAD_REQUEST, "not a status code").into_response(),
        |code| (code, "").into_response(),
    )
}

/// Sends a trailing header section, which is the one part of a response that cannot be produced by
/// returning a value from a handler.
async fn trailers() -> Response {
    Response::new(Body::new(TrailerBody {
        data: Some(Bytes::from_static(b"with trailers")),
        trailers: Some(HeaderMap::from_iter([(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("42"),
        )])),
    }))
}

async fn slow(Query(query): Query<BTreeMap<String, String>>) -> Response {
    let millis = query
        .get("ms")
        .and_then(|ms| ms.parse().ok())
        .unwrap_or(1000);
    tokio::time::sleep(Duration::from_millis(millis)).await;
    "eventually".into_response()
}

async fn big(Query(query): Query<BTreeMap<String, String>>) -> Response {
    let bytes = query
        .get("bytes")
        .and_then(|bytes| bytes.parse().ok())
        .unwrap_or(1024);
    Bytes::from(vec![b'x'; bytes]).into_response()
}

async fn invalid_utf8() -> Response {
    Bytes::from_static(&[0xff, 0xfe]).into_response()
}

/// A response body that never ends, counting the chunks it sends.
///
/// A client that cancels its request sends `STOP_SENDING`, the transport stops asking this for
/// more, and the count for that tag stops going up. That is the only way a test can tell a
/// cancellation that reached the server from one that only looked tidy on the client.
async fn endless_body(
    State(counters): State<Arc<Counters>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let tag = query.get("tag").cloned().unwrap_or_default();
    let chunks = counters.endless_chunks(&tag);
    let stream = futures::stream::unfold(chunks, |chunks| {
        async move {
            tokio::time::sleep(ENDLESS_BODY_INTERVAL).await;
            chunks.fetch_add(1, Ordering::Relaxed);
            Some((
                Ok::<_, std::convert::Infallible>(Bytes::from_static(b"drip")),
                chunks,
            ))
        }
    });
    Response::new(Body::from_stream(stream))
}

/// One data frame followed by a trailing header section.
struct TrailerBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl http_body::Body for TrailerBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            return Poll::Ready(Some(Ok(http_body::Frame::data(data))));
        }
        Poll::Ready(
            this.trailers
                .take()
                .map(|t| Ok(http_body::Frame::trailers(t))),
        )
    }
}

/// Serves the control API on loopback, returning its URL.
async fn serve_control(
    counters: Arc<Counters>,
    shutdown: CancellationToken,
) -> Result<String, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);

    let app =
        Router::new()
            .route(
                "/stats",
                get(|State(counters): State<Arc<Counters>>| {
                    async move { axum::Json(counters.snapshot()) }
                }),
            )
            .with_state(counters);
    tokio::spawn(async move {
        let served = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await;
        if let Err(error) = served {
            tracing::error!(%error, "The control server stopped");
        }
    });

    Ok(url)
}

/// Resolves when standard input reaches end of file.
async fn wait_for_stdin_close() {
    let _ = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        while std::io::stdin().lock().read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    })
    .await;
}

fn write_temp_file(contents: &[u8]) -> std::io::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.as_file_mut().write_all(contents)?;
    file.as_file_mut().flush()?;
    Ok(file)
}

fn path_str(file: &tempfile::NamedTempFile) -> &str {
    file.path().to_str().expect("a UTF-8 temporary path")
}
