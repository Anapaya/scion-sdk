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

//! Responses and body collection.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use scion_quic::h3::client::{H3ResponseBody, Http3Client};

use crate::error::{Error, TimeoutPhase};

/// A response whose head has arrived and whose body is still on the wire.
///
/// [`bytes`](Self::bytes) and [`text`](Self::text) collect the body (and
/// trailers, if any) under the remainder of the request deadline, so "request
/// timeout" covers head *and* body.
///
/// The deadline is absolute, fixed when the request started, and it keeps
/// running while this value is held. Time spent between receiving the head and
/// collecting the body comes out of the same budget, so a response parked while
/// the caller does other work can fail with
/// [`Error::Timeout`] `{ phase: `[`Body`](TimeoutPhase::Body)` }` even though
/// its bytes have already arrived. Collect promptly, or give such requests a
/// longer [`request_timeout`](crate::RequestBuilder::request_timeout).
pub struct Response {
    parts: http::response::Parts,
    body: H3ResponseBody,
    deadline: tokio::time::Instant,
    timeout: Duration,
    /// Keeps the connection the body streams over alive until the body is
    /// collected: the pool may evict the origin at any time, and dropping the
    /// last reference to the transport client would fault the body mid-read.
    _connection: Arc<Http3Client>,
}

impl Response {
    pub(crate) fn new(
        response: http::Response<H3ResponseBody>,
        deadline: tokio::time::Instant,
        timeout: Duration,
        connection: Arc<Http3Client>,
    ) -> Self {
        let (parts, body) = response.into_parts();
        Response {
            parts,
            body,
            deadline,
            timeout,
            _connection: connection,
        }
    }

    /// The response status code.
    #[must_use]
    pub fn status(&self) -> http::StatusCode {
        self.parts.status
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &http::HeaderMap {
        &self.parts.headers
    }

    /// Whether the status code is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.parts.status.is_success()
    }

    /// Collects the response body, returning it together with the trailers
    /// (HTTP/3 trailing header section), if the server sent any.
    ///
    /// `max_size` bounds how much is buffered; a larger body fails with
    /// [`Error::BodyTooLarge`]. `None` means unbounded — prefer a limit
    /// whenever the server is not fully trusted. Collection runs under the
    /// remainder of the request deadline.
    pub async fn bytes(
        self,
        max_size: Option<usize>,
    ) -> Result<(Bytes, Option<http::HeaderMap>), Error> {
        let collected = tokio::time::timeout_at(self.deadline, self.body.bytes(max_size))
            .await
            .map_err(|_| {
                Error::Timeout {
                    phase: TimeoutPhase::Body,
                    timeout: self.timeout,
                }
            })?
            .map_err(|e| Error::from_collect_error(e, max_size))?;
        let (body, trailers) = collected;
        Ok((body.freeze(), trailers))
    }

    /// Collects the response body as a UTF-8 string, returning it together
    /// with the trailers, if the server sent any.
    ///
    /// Same limits and deadline as [`bytes`](Self::bytes); a body that is not
    /// valid UTF-8 fails with [`Error::InvalidBody`].
    pub async fn text(
        self,
        max_size: Option<usize>,
    ) -> Result<(String, Option<http::HeaderMap>), Error> {
        tokio::time::timeout_at(self.deadline, self.body.text(max_size))
            .await
            .map_err(|_| {
                Error::Timeout {
                    phase: TimeoutPhase::Body,
                    timeout: self.timeout,
                }
            })?
            .map_err(|e| Error::from_collect_to_string_error(e, max_size))
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.parts.status)
            .field("headers", &self.parts.headers)
            .finish_non_exhaustive()
    }
}
