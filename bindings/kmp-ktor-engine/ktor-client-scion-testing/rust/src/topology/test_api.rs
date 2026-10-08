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

//! The test API that the server serves over HTTP/3 and inside a tunnel.
//!
//! | Path | Serves |
//! | --- | --- |
//! | `GET /hello` | `world` |
//! | `POST /echo` | The request body |
//! | `GET\|POST /echo-headers` | The request headers as a JSON list of `name` and `value` |
//! | `GET /repeated-headers` | Two `set-cookie` fields |
//! | `GET /status/{code}` | That status |
//! | `GET /slow?ms=` | `eventually` after `ms` milliseconds, 1000 by default |
//! | `GET /big?bytes=` | That many bytes, 1024 by default, [`MAX_BIG_BYTES`] at most |

use std::{collections::BTreeMap, time::Duration};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};

/// The largest body that `/big` sends.
///
/// The handler builds the whole body in memory. The limit turns a mistyped
/// `bytes` into a 400, not into an out-of-memory exit.
pub const MAX_BIG_BYTES: usize = 64 * 1024 * 1024;

/// The route table in the module doc.
pub struct TestApi;

impl TestApi {
    /// The test API, without a fallback.
    pub fn router() -> Router {
        Router::new()
            .route("/hello", get(|| async { "world" }))
            .route("/echo", post(|body: Bytes| async move { body }))
            .route(
                "/echo-headers",
                get(Self::echo_headers).post(Self::echo_headers),
            )
            .route("/repeated-headers", get(Self::repeated_headers))
            .route("/status/{code}", get(Self::status))
            .route("/slow", get(Self::slow))
            .route("/big", get(Self::big))
            // The tests probe the size limits of the engine, not those of axum.
            .layer(DefaultBodyLimit::disable())
    }

    async fn echo_headers(headers: HeaderMap) -> Response {
        let fields = headers
            .iter()
            .map(|(name, value)| {
                serde_json::json!({
                    "name": name.as_str(),
                    "value": String::from_utf8_lossy(value.as_bytes()),
                })
            })
            .collect();
        axum::Json(serde_json::Value::Array(fields)).into_response()
    }

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
}
