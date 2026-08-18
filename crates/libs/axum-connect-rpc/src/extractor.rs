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

use std::fmt::Debug;

use axum::{
    extract::{FromRequest, Request, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;

use crate::error::{CrpcError, CrpcErrorCode};

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

/// Wrapper connect RPC type for a prost message.
pub struct ConnectRpc<T: prost::Message + Default + Sized + 'static>(pub T);

impl<T: prost::Message + Default + Sized + 'static> ConnectRpc<T> {
    /// Extract the inner message.
    pub fn into_inner(self) -> T {
        self.0
    }
}
impl<T: prost::Message + Default + Sized + 'static + Debug> std::fmt::Debug for ConnectRpc<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConnectRpc").field(&self.0).finish()
    }
}

impl<T: prost::Message + Default + Sized + 'static> std::ops::Deref for ConnectRpc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequest<S> for ConnectRpc<T>
where
    S: Send + Sync,
    T: prost::Message + Default + Sized + 'static,
{
    type Rejection = ConnectRpcRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers().clone();

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(ConnectRpcRejection::BytesRejection)?;

        check_crpc_content_type(&headers)?;

        let message = T::decode(bytes).map_err(|_e| ConnectRpcRejection::DecodingFailed)?;

        Ok(ConnectRpc(message))
    }
}

impl<T> IntoResponse for ConnectRpc<T>
where
    T: prost::Message + Default + Sized + 'static,
{
    fn into_response(self) -> Response {
        let ConnectRpc(message) = self;
        let buf = message.encode_to_vec();

        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, APPLICATION_PROTO)],
            buf,
        )
            .into_response()
    }
}

impl<T: prost::Message + Default + Sized + 'static> From<T> for ConnectRpc<T> {
    fn from(value: T) -> Self {
        ConnectRpc(value)
    }
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

/// Wrapper connect RPC type whose codec is negotiated per request.
///
/// Unlike [`ConnectRpc`], which is protobuf-only, this accepts both
/// `application/proto` and `application/json`, and answers in the codec the
/// caller used. Use it for services reachable from a web browser, which cannot
/// encode protobuf without pulling in a codec of its own.
///
/// A response can only be built with [`ConnectRpcAny::reply`], which carries the
/// request's codec over, so a handler cannot answer in the wrong one:
///
/// ```ignore
/// async fn handler(
///     request: ConnectRpcAny<MyRequest>,
/// ) -> Result<ConnectRpcAny<MyResponse>, CrpcError> {
///     let response = do_work(&request.some_field)?;
///     Ok(request.reply(response))
/// }
/// ```
///
/// Errors need no codec: per the Connect protocol, a unary error response is
/// always a JSON [`CrpcError`] envelope, whichever codec the request used.
pub struct ConnectRpcAny<T> {
    message: T,
    codec: Codec,
}

impl<T> ConnectRpcAny<T> {
    /// Extract the inner message.
    pub fn into_inner(self) -> T {
        self.message
    }

    /// The codec this message was decoded from, or will be encoded with.
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Wraps a response message with this request's codec.
    pub fn reply<U>(&self, message: U) -> ConnectRpcAny<U> {
        ConnectRpcAny {
            message,
            codec: self.codec,
        }
    }
}

impl<T: Debug> std::fmt::Debug for ConnectRpcAny<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectRpcAny")
            .field("message", &self.message)
            .field("codec", &self.codec)
            .finish()
    }
}

impl<T> std::ops::Deref for ConnectRpcAny<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<S, T> FromRequest<S> for ConnectRpcAny<T>
where
    S: Send + Sync,
    T: prost::Message + Default + serde::de::DeserializeOwned + 'static,
{
    type Rejection = ConnectRpcRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let codec = Codec::from_headers(req.headers())?;

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(ConnectRpcRejection::BytesRejection)?;

        let message = match codec {
            Codec::Proto => T::decode(bytes).map_err(|_e| ConnectRpcRejection::DecodingFailed)?,
            Codec::Json => {
                serde_json::from_slice(&bytes).map_err(|_e| ConnectRpcRejection::DecodingFailed)?
            }
        };

        Ok(Self { message, codec })
    }
}

impl<T> IntoResponse for ConnectRpcAny<T>
where
    T: prost::Message + serde::Serialize + Sized + 'static,
{
    fn into_response(self) -> Response {
        let body = match self.codec {
            Codec::Proto => self.message.encode_to_vec(),
            Codec::Json => {
                match serde_json::to_vec(&self.message) {
                    Ok(body) => body,
                    Err(_e) => {
                        return CrpcError::new(
                            CrpcErrorCode::Internal,
                            "failed to serialize response".to_string(),
                        )
                        .into_response();
                    }
                }
            }
        };

        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, self.codec.content_type())],
            body,
        )
            .into_response()
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
    use axum::{
        body::Body,
        extract::{FromRequest as _, Request},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
    };

    use super::{APPLICATION_JSON, APPLICATION_PROTO, Codec, ConnectRpc, ConnectRpcAny};

    #[derive(prost::Message)]
    struct EmptyMessage {}

    #[derive(prost::Message, serde::Serialize, serde::Deserialize)]
    struct Greeting {
        #[prost(string, tag = "1")]
        name: String,
    }

    fn request(content_type: &str, body: impl Into<Body>) -> Request {
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
    fn extract<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("future pended on an in-memory body"),
        }
    }

    #[test]
    fn into_response_sets_content_type_application_proto() {
        let msg = ConnectRpc(EmptyMessage {});
        let response = msg.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            APPLICATION_PROTO,
        );
    }

    /// Reads a response body, for asserting on error envelopes.
    fn body_of(response: Response) -> serde_json::Value {
        let bytes = extract(axum::body::to_bytes(response.into_body(), usize::MAX))
            .expect("response body is readable");
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    #[test]
    fn any_accepts_a_mixed_case_content_type() {
        // RFC 9110 makes the media type case-insensitive.
        let extracted: ConnectRpcAny<Greeting> = extract(ConnectRpcAny::from_request(
            request("Application/JSON", r#"{"name":"ada"}"#),
            &(),
        ))
        .expect("mixed-case content type is accepted");

        assert_eq!(extracted.codec(), Codec::Json);
    }

    #[test]
    fn proto_extractor_accepts_a_mixed_case_content_type() {
        let body = prost::Message::encode_to_vec(&Greeting { name: "ada".into() });
        let extracted: ConnectRpc<Greeting> = extract(ConnectRpc::from_request(
            request("APPLICATION/PROTO", body),
            &(),
        ))
        .expect("mixed-case content type is accepted");

        assert_eq!(extracted.name, "ada");
    }

    #[test]
    fn rejections_are_connect_error_envelopes() {
        // A browser client parses the envelope, so a rejection must not be
        // plain text.
        for (content_type, body) in [("text/plain", "hi"), (APPLICATION_JSON, "{not json")] {
            let result: Result<ConnectRpcAny<Greeting>, _> = extract(ConnectRpcAny::from_request(
                request(content_type, body),
                &(),
            ));
            let response = result.expect_err("request is rejected").into_response();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                APPLICATION_JSON,
            );
            assert_eq!(body_of(response)["code"], "invalid_argument");
        }
    }

    #[test]
    fn content_type_parameters_are_ignored() {
        assert_eq!(
            super::media_type("application/json; charset=utf-8"),
            "application/json"
        );
        assert_eq!(super::media_type("application/proto"), "application/proto");
    }

    #[test]
    fn any_decodes_json_and_replies_in_json() {
        let extracted: ConnectRpcAny<Greeting> = extract(ConnectRpcAny::from_request(
            request(APPLICATION_JSON, r#"{"name":"ada"}"#),
            &(),
        ))
        .expect("json body is accepted");

        assert_eq!(extracted.codec(), Codec::Json);
        assert_eq!(extracted.name, "ada");

        let response = extracted
            .reply(Greeting { name: "ok".into() })
            .into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            APPLICATION_JSON,
        );
        let body = extract(axum::body::to_bytes(response.into_body(), usize::MAX))
            .expect("response body is readable");
        assert_eq!(body.as_ref(), br#"{"name":"ok"}"#);
    }

    #[test]
    fn any_decodes_proto_and_replies_in_proto() {
        let body = prost::Message::encode_to_vec(&Greeting { name: "ada".into() });
        let extracted: ConnectRpcAny<Greeting> = extract(ConnectRpcAny::from_request(
            request(APPLICATION_PROTO, body),
            &(),
        ))
        .expect("proto body is accepted");

        assert_eq!(extracted.codec(), Codec::Proto);
        assert_eq!(extracted.name, "ada");

        let response = extracted
            .reply(Greeting { name: "ok".into() })
            .into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            APPLICATION_PROTO,
        );
    }

    #[test]
    fn any_accepts_a_charset_parameter() {
        let extracted: ConnectRpcAny<Greeting> = extract(ConnectRpcAny::from_request(
            request("application/json; charset=utf-8", r#"{"name":"ada"}"#),
            &(),
        ))
        .expect("parameterised content type is accepted");

        assert_eq!(extracted.codec(), Codec::Json);
    }

    #[test]
    fn any_rejects_an_unsupported_content_type() {
        let result: Result<ConnectRpcAny<Greeting>, _> = extract(ConnectRpcAny::from_request(
            request("text/plain", "hi"),
            &(),
        ));

        let response = result.expect_err("text/plain is rejected").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn any_rejects_a_malformed_json_body() {
        let result: Result<ConnectRpcAny<Greeting>, _> = extract(ConnectRpcAny::from_request(
            request(APPLICATION_JSON, "{not json"),
            &(),
        ));

        let response = result
            .expect_err("malformed json is rejected")
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
