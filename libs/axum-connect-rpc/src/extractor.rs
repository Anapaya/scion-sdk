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

// Expected content type for Connect RPC requests.
const APPLICATION_PROTO: &str = "application/proto";

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

    if content_type != APPLICATION_PROTO {
        return Err(ConnectRpcRejection::InvalidContentType(format!(
            "Expected: {APPLICATION_PROTO}, got: {content_type}"
        )));
    }

    Ok(())
}

/// Possible rejections when extracting a Connect RPC request.
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
        match self {
            ConnectRpcRejection::BytesRejection(bytes_rejection) => bytes_rejection.into_response(),
            ConnectRpcRejection::DecodingFailed => {
                (StatusCode::BAD_REQUEST, "Failed to decode message").into_response()
            }
            ConnectRpcRejection::InvalidContentType(reason) => {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid content type: {reason}"),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    use super::{APPLICATION_PROTO, ConnectRpc};

    #[derive(prost::Message)]
    struct EmptyMessage {}

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
}
