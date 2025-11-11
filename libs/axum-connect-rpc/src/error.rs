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
// Copied from `reqwest-connect-rpc` and adapted for axum.
//! Connect RPC error types and conversions.

use axum::{http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A connect RPC error returned by the server. See <https://connectrpc.com/docs/protocol/#error-end-stream>.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq, Hash)]
pub struct CrpcError {
    /// The connect RPC error code.
    pub code: CrpcErrorCode,
    /// A human-readable message providing more details about the error.
    pub message: String,
    /// Json encoded detail.
    pub detail: Option<Box<serde_json::value::Value>>,
}

impl CrpcError {
    /// Creates a new [`CrpcError`] from a [`CrpcErrorCode`] and a message.
    pub fn new(code: CrpcErrorCode, message: String) -> Self {
        Self {
            code,
            message,
            detail: None,
        }
    }

    /// Creates a new [`CrpcError`] from a [`axum::http::StatusCode`].
    pub fn new_from_status(status: StatusCode) -> Self {
        Self {
            code: status.into(),
            message: match status {
                StatusCode::BAD_REQUEST => "Invalid request".to_string(),
                StatusCode::UNAUTHORIZED => "Unauthorized".to_string(),
                StatusCode::FORBIDDEN => "Forbidden".to_string(),
                StatusCode::NOT_FOUND => "Not found".to_string(),
                StatusCode::TOO_MANY_REQUESTS => "Too many requests".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR => "Internal server error".to_string(),
                StatusCode::BAD_GATEWAY => "Bad gateway".to_string(),
                StatusCode::SERVICE_UNAVAILABLE => "Service unavailable".to_string(),
                StatusCode::GATEWAY_TIMEOUT => "Gateway timeout".to_string(),
                _ => "Unknown error".to_string(),
            },
            detail: None,
        }
    }
}

impl std::error::Error for CrpcError {}

impl std::fmt::Display for CrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "connect RPC error (code: {}): {}",
            self.code, self.message
        )
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, Copy, PartialEq, Eq, Hash)]
/// Connect RPC error codes. See <https://connectrpc.com/docs/protocol/#error-code>.
#[serde(rename_all = "snake_case")]
pub enum CrpcErrorCode {
    /// RPC canceled, usually by the caller.
    Canceled,
    /// Catch-all for errors of unclear origin and errors without a more appropriate code.
    Unknown,
    /// Request is invalid, regardless of system state.
    InvalidArgument,
    /// Deadline expired before RPC could complete or before the client received the response.
    DeadlineExceeded,
    /// User requested a resource (for example, a file or directory) that can't be found.
    NotFound,
    /// Caller attempted to create a resource that already exists.
    AlreadyExists,
    /// Caller isn't authorized to perform the operation.
    PermissionDenied,
    /// Operation can't be completed because some resource is exhausted. Use unavailable if the
    /// server is temporarily overloaded and the caller should retry later.
    ResourceExhausted,
    /// Operation can't be completed because the system isn't in the required state.
    FailedPrecondition,
    /// The operation was aborted, often because of concurrency issues like a database transaction
    /// abort.
    Aborted,
    /// The operation was attempted past the valid range.
    OutOfRange,
    /// The operation isn't implemented, supported, or enabled.
    Unimplemented,
    /// An invariant expected by the underlying system has been broken. Reserved for serious
    /// errors.
    Internal,
    /// The service is currently unavailable, usually transiently. Clients should back off and
    /// retry idempotent operations.
    Unavailable,
    /// Unrecoverable data loss or corruption.
    DataLoss,
    /// Caller doesn't have valid authentication credentials for the operation.
    Unauthenticated,
}

impl std::fmt::Display for CrpcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canceled => write!(f, "canceled"),
            Self::Unknown => write!(f, "unknown"),
            Self::InvalidArgument => write!(f, "invalid_argument"),
            Self::DeadlineExceeded => write!(f, "deadline_exceeded"),
            Self::NotFound => write!(f, "not_found"),
            Self::AlreadyExists => write!(f, "already_exists"),
            Self::PermissionDenied => write!(f, "permission_denied"),
            Self::ResourceExhausted => write!(f, "resource_exhausted"),
            Self::FailedPrecondition => write!(f, "failed_precondition"),
            Self::Aborted => write!(f, "aborted"),
            Self::OutOfRange => write!(f, "out_of_range"),
            Self::Unimplemented => write!(f, "unimplemented"),
            Self::Internal => write!(f, "internal"),
            Self::Unavailable => write!(f, "unavailable"),
            Self::DataLoss => write!(f, "data_loss"),
            Self::Unauthenticated => write!(f, "unauthenticated"),
        }
    }
}

impl<E: std::fmt::Display> From<(StatusCode, E)> for CrpcError {
    fn from((status, err): (StatusCode, E)) -> Self {
        CrpcError {
            code: status.into(),
            message: err.to_string(),
            detail: None,
        }
    }
}
/// See <https://connectrpc.com/docs/protocol/#http-to-error-code>.
impl From<StatusCode> for CrpcErrorCode {
    fn from(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => Self::InvalidArgument,
            StatusCode::UNAUTHORIZED => Self::Unauthenticated,
            StatusCode::FORBIDDEN => Self::PermissionDenied,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::TOO_MANY_REQUESTS => Self::Unavailable,
            StatusCode::INTERNAL_SERVER_ERROR => Self::Internal,
            StatusCode::BAD_GATEWAY => Self::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE => Self::Unavailable,
            StatusCode::GATEWAY_TIMEOUT => Self::Unavailable,
            _ => Self::Unknown,
        }
    }
}

impl From<CrpcErrorCode> for StatusCode {
    fn from(code: CrpcErrorCode) -> Self {
        match code {
            CrpcErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            CrpcErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            CrpcErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
            CrpcErrorCode::NotFound => StatusCode::NOT_FOUND,
            CrpcErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            CrpcErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            CrpcErrorCode::ResourceExhausted => StatusCode::SERVICE_UNAVAILABLE,

            // Not Standardized
            CrpcErrorCode::Canceled => StatusCode::REQUEST_TIMEOUT,
            CrpcErrorCode::DeadlineExceeded => StatusCode::REQUEST_TIMEOUT,
            CrpcErrorCode::Aborted => StatusCode::REQUEST_TIMEOUT,

            CrpcErrorCode::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            CrpcErrorCode::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,

            CrpcErrorCode::AlreadyExists => StatusCode::CONFLICT,
            CrpcErrorCode::FailedPrecondition => StatusCode::PRECONDITION_FAILED,

            CrpcErrorCode::OutOfRange => StatusCode::BAD_REQUEST,
            CrpcErrorCode::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

impl IntoResponse for CrpcError {
    fn into_response(self) -> axum::response::Response {
        let status: StatusCode = self.code.into();
        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            r#"{"code":"internal","message":"failed to serialize error"}"#.to_string()
        });

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn crpc_error_serializes_and_deserializes() {
        let err = CrpcError {
            code: CrpcErrorCode::InvalidArgument,
            message: "invalid argument".to_string(),
            detail: Some(serde_json::json!({"foo": "bar"}).into()),
        };
        let serialized = serde_json::to_string(&err).expect("failed to serialize");

        assert_eq!(
            r#"{"code":"invalid_argument","message":"invalid argument","detail":{"foo":"bar"}}"#,
            serialized
        );

        let deserialized: CrpcError =
            serde_json::from_str(&serialized).expect("failed to deserialize");

        assert_eq!(
            err.code as u8, deserialized.code as u8,
            "error code should match after serialization round-trip"
        );
        assert_eq!(
            err.message, deserialized.message,
            "error message should match after serialization round-trip"
        );
    }
}
