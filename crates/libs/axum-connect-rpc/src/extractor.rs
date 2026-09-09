// Copyright 2025 Anapaya Systems
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
//! Connect RPC axum extractors.
//!
//! This module holds the content type handling, the [`Codec`] negotiation and
//! the [`ConnectRpcRejection`] envelopes; the extractors themselves are
//! re-exported from a private submodule.

use axum::{
    extract::rejection::BytesRejection,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::error::{CrpcError, CrpcErrorCode};

mod buffa;

pub use buffa::{ConnectRpc, ConnectRpcAny, CrpcOrJson};

// Expected content type for Connect RPC requests.
const APPLICATION_PROTO: &str = "application/proto";
// Content type of the Connect JSON codec.
const APPLICATION_JSON: &str = "application/json";

/// Strips any parameters from a media type, e.g. `application/json; charset=utf-8`.
///
/// Compare the result with [`str::eq_ignore_ascii_case`]: RFC 9110 makes the
/// type and subtype case-insensitive.
fn media_type(value: &str) -> &str {
    let (media_type, _parameters) = value.split_once(';').unwrap_or((value, ""));
    media_type.trim()
}

fn check_crpc_content_type(headers: &HeaderMap) -> Result<(), ConnectRpcRejection> {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return Err(ConnectRpcRejection::InvalidContentType(
            "Missing content type".into(),
        ));
    };

    let Ok(content_type) = content_type.to_str() else {
        return Err(ConnectRpcRejection::InvalidContentType(
            "Failed to parse content type".into(),
        ));
    };

    if !media_type(content_type).eq_ignore_ascii_case(APPLICATION_PROTO) {
        return Err(ConnectRpcRejection::InvalidContentType(format!(
            "Expected: {APPLICATION_PROTO}, got: {content_type}"
        )));
    }

    Ok(())
}

/// The codec a Connect RPC request was encoded with.
///
/// See <https://connectrpc.com/docs/protocol/#unary-request>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Codec {
    /// Binary protobuf, `application/proto`.
    Proto,
    /// Canonical protobuf JSON, `application/json`.
    Json,
}

impl Codec {
    /// The `Content-Type` this codec is sent and returned with.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Proto => APPLICATION_PROTO,
            Self::Json => APPLICATION_JSON,
        }
    }

    fn from_headers(headers: &HeaderMap) -> Result<Self, ConnectRpcRejection> {
        let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
            return Err(ConnectRpcRejection::InvalidContentType(
                "Missing content type".into(),
            ));
        };
        let Ok(content_type) = content_type.to_str() else {
            return Err(ConnectRpcRejection::InvalidContentType(
                "Failed to parse content type".into(),
            ));
        };

        let media_type = media_type(content_type);
        if media_type.eq_ignore_ascii_case(APPLICATION_PROTO) {
            Ok(Self::Proto)
        } else if media_type.eq_ignore_ascii_case(APPLICATION_JSON) {
            Ok(Self::Json)
        } else {
            Err(ConnectRpcRejection::InvalidContentType(format!(
                "Expected: {APPLICATION_PROTO} or {APPLICATION_JSON}, got: {media_type}"
            )))
        }
    }
}

/// Possible rejections when extracting a Connect RPC request.
#[derive(Debug)]
pub enum ConnectRpcRejection {
    /// Failed to extract bytes.
    BytesRejection(BytesRejection),
    /// Invalid content type.
    InvalidContentType(String),
    /// Failed to decode the message.
    DecodingFailed,
}

impl IntoResponse for ConnectRpcRejection {
    fn into_response(self) -> Response {
        // Connect requires the body of a failed unary call to be a JSON error
        // envelope, so a rejection is reported as one rather than as plain text.
        // The status is not taken from the code, so that axum's own rejections
        // keep theirs.
        let (status, error) = match self {
            ConnectRpcRejection::BytesRejection(rejection) => {
                let status = rejection.status();
                (status, CrpcError::new(status.into(), rejection.body_text()))
            }
            ConnectRpcRejection::DecodingFailed => {
                (
                    StatusCode::BAD_REQUEST,
                    CrpcError::new(
                        CrpcErrorCode::InvalidArgument,
                        "failed to decode request message".to_string(),
                    ),
                )
            }
            ConnectRpcRejection::InvalidContentType(reason) => {
                (
                    StatusCode::BAD_REQUEST,
                    CrpcError::new(
                        CrpcErrorCode::InvalidArgument,
                        format!("invalid content type: {reason}"),
                    ),
                )
            }
        };

        let body = serde_json::to_string(&error).unwrap_or_else(|_| {
            r#"{"code":"internal","message":"failed to serialize error"}"#.to_string()
        });

        (status, [(header::CONTENT_TYPE, APPLICATION_JSON)], body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, extract::Request, http::header, response::Response};

    pub(super) fn request(content_type: &str, body: impl Into<Body>) -> Request {
        Request::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(body.into())
            .expect("valid request")
    }

    /// Drives a future that is known not to pend.
    ///
    /// `FromRequest` is async because a request body is generally a stream, but
    /// these tests build bodies from in-memory buffers, which resolve on the
    /// first poll. Extracting them this way keeps an async runtime out of the
    /// dev-dependencies.
    pub(super) fn extract<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("future pended on an in-memory body"),
        }
    }

    /// Reads a response body, for asserting on error envelopes.
    pub(super) fn body_of(response: Response) -> serde_json::Value {
        let bytes = extract(axum::body::to_bytes(response.into_body(), usize::MAX))
            .expect("response body is readable");
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    #[test]
    fn content_type_parameters_are_ignored() {
        assert_eq!(
            super::media_type("application/json; charset=utf-8"),
            "application/json"
        );
        assert_eq!(super::media_type("application/proto"), "application/proto");
    }
}
