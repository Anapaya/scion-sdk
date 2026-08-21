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

//! What the server serves over HTTP/3, and the counters the control API reports.
//!
//! Every route here exists to make a single client behaviour observable; the table in the crate
//! documentation says which. Nothing in this module knows about SCION.

use std::{
    collections::BTreeMap,
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
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};

/// How often the endless body produces a chunk.
const ENDLESS_BODY_INTERVAL: Duration = Duration::from_millis(50);

/// The largest body `/big` will produce.
///
/// Well above both the client's own default limit and anything a test asks for, and there only so
/// that a mistyped `bytes` is answered rather than allocated: the handler builds the whole body in
/// memory, so one extra digit would take the process down and report itself as the server exiting
/// halfway through an unrelated test.
const MAX_BIG_BYTES: usize = 64 * 1024 * 1024;

/// Counters the control API reports, and the routes that move them.
#[derive(Default)]
pub struct Counters {
    /// Chunks sent per endless-body tag.
    ///
    /// After a client cancels a request, its tag stops going up, which only happens once
    /// `STOP_SENDING` has reached the server. That is how a test sees a cancellation arrive. Per
    /// tag, so that concurrent tests do not read each other's.
    endless_chunks: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    /// Completed requests per path, so a test can prove a later request really reached the server.
    requests: Mutex<BTreeMap<String, u64>>,
    /// Requests per path that reached a handler, whether or not they finished.
    started: Mutex<BTreeMap<String, u64>>,
    /// How many times the HTTP/3 server has been restarted.
    restarts: AtomicU64,
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

    fn record_started(&self, path: &str) {
        *self
            .started
            .lock()
            .expect("lock poisoned")
            .entry(path.to_owned())
            .or_default() += 1;
    }

    /// Called when the HTTP/3 server has been stood up again.
    pub fn record_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    /// What `GET /stats` reports.
    pub fn snapshot(&self) -> serde_json::Value {
        let endless: BTreeMap<String, u64> = self
            .endless_chunks
            .lock()
            .expect("lock poisoned")
            .iter()
            .map(|(tag, count)| (tag.clone(), count.load(Ordering::Relaxed)))
            .collect();
        let requests = self.requests.lock().expect("lock poisoned").clone();
        let started = self.started.lock().expect("lock poisoned").clone();
        serde_json::json!({
            "endless_chunks": endless,
            "requests": requests,
            "started": started,
            "restarts": self.restarts.load(Ordering::Relaxed),
        })
    }
}

/// The application the HTTP/3 server serves.
pub fn router(counters: Arc<Counters>) -> Router {
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
        .route("/reset-stream", get(reset_stream))
        // axum refuses a request body over 2 MiB by default, which is a sensible thing for a server
        // that takes bodies from strangers and the wrong thing here: the limits under test are the
        // client's own, and a test that wants to push megabytes through the transport should get a
        // transport failure or a response, never a 413 from the framework.
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(counters.clone(), count))
        .with_state(counters)
}

async fn count(State(counters): State<Arc<Counters>>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    counters.record_started(&path);
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
    if bytes > MAX_BIG_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            format!("bytes must be at most {MAX_BIG_BYTES}, not {bytes}"),
        )
            .into_response();
    }
    Bytes::from(vec![b'x'; bytes]).into_response()
}

async fn invalid_utf8() -> Response {
    Bytes::from_static(&[0xff, 0xfe]).into_response()
}

/// A response that starts and then breaks off: a status, one chunk, and a body error.
///
/// The server's frame pump stops on the error and the stream's teardown resets the write side, so
/// the client sees `RESET_STREAM` after a response it had already begun to read. That ordering is
/// the point: a client that only ever sees clean responses and unreachable peers has no test for
/// the arm in between, and there is no way to provoke it from the client side.
async fn reset_stream() -> Response {
    let stream = futures::stream::iter([
        Ok(Bytes::from_static(b"partial")),
        Err(std::io::Error::other("deliberate mid-body failure")),
    ]);
    Response::new(Body::from_stream(stream))
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
