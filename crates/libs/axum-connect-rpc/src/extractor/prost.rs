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
//! Connect RPC axum extractors for [`prost`] messages.
//!
//! Codec negotiation, the rejection type and the error envelopes live in the
//! parent module and are shared with the [`buffa`](super::buffa) path; only the
//! encode/decode calls differ.

use std::fmt::Debug;

use axum::{
    extract::{FromRequest, Request},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;

use super::{APPLICATION_PROTO, Codec, ConnectRpcRejection, check_crpc_content_type};
use crate::error::{CrpcError, CrpcErrorCode};

/// Wrapper connect RPC type for a prost message.
pub struct ConnectRpc<T: ::prost::Message + Default + Sized + 'static>(pub T);

impl<T: ::prost::Message + Default + Sized + 'static> ConnectRpc<T> {
    /// Extract the inner message.
    pub fn into_inner(self) -> T {
        self.0
    }
}
impl<T: ::prost::Message + Default + Sized + 'static + Debug> std::fmt::Debug for ConnectRpc<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConnectRpc").field(&self.0).finish()
    }
}

impl<T: ::prost::Message + Default + Sized + 'static> std::ops::Deref for ConnectRpc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequest<S> for ConnectRpc<T>
where
    S: Send + Sync,
    T: ::prost::Message + Default + Sized + 'static,
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
    T: ::prost::Message + Default + Sized + 'static,
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

impl<T: ::prost::Message + Default + Sized + 'static> From<T> for ConnectRpc<T> {
    fn from(value: T) -> Self {
        ConnectRpc(value)
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
pub struct ConnectRpcAny<T: CrpcOrJson> {
    message: T,
    codec: Codec,
}

impl<T: CrpcOrJson> ConnectRpcAny<T> {
    /// Extract the inner message.
    pub fn into_inner(self) -> T {
        self.message
    }

    /// The codec this message was decoded from, or will be encoded with.
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Wraps a response message with this request's codec.
    pub fn reply<U: CrpcOrJson>(&self, message: U) -> ConnectRpcAny<U> {
        ConnectRpcAny {
            message,
            codec: self.codec,
        }
    }

    /// Creates a new `ConnectRpcAny` with the given message and codec.
    pub fn from_parts(message: T, codec: Codec) -> Self {
        ConnectRpcAny { message, codec }
    }
}

impl<T: CrpcOrJson + Debug> std::fmt::Debug for ConnectRpcAny<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectRpcAny")
            .field("message", &self.message)
            .field("codec", &self.codec)
            .finish()
    }
}

impl<T: CrpcOrJson> std::ops::Deref for ConnectRpcAny<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<S, T: CrpcOrJson> FromRequest<S> for ConnectRpcAny<T>
where
    S: Send + Sync,
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

impl<T: CrpcOrJson> IntoResponse for ConnectRpcAny<T> {
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

/// `ConnectRpcAny` can only be used with types that are both prost messages and
/// JSON serializable, so that it can decode and encode both codecs.
pub trait CrpcOrJson:
    ::prost::Message + Default + serde::de::DeserializeOwned + serde::Serialize + Sized + 'static
{
}
impl<
    AnyMessage: ::prost::Message + Default + serde::de::DeserializeOwned + serde::Serialize + Sized + 'static,
> CrpcOrJson for AnyMessage
{
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::FromRequest as _,
        http::{StatusCode, header},
        response::IntoResponse as _,
    };

    use super::{ConnectRpc, ConnectRpcAny};
    use crate::extractor::{
        APPLICATION_JSON, APPLICATION_PROTO, Codec,
        tests::{body_of, extract, request},
    };

    #[derive(prost::Message)]
    struct EmptyMessage {}

    #[derive(prost::Message, serde::Serialize, serde::Deserialize)]
    struct Greeting {
        #[prost(string, tag = "1")]
        name: String,
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
