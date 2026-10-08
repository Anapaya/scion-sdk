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

//! The ways a request reaches the origin.
//!
//! [`http3::Http3Transport`] sends each request over HTTP/3 to the origin.
//! [`connect::ConnectTransport`] sends each request through a `CONNECT` tunnel to a
//! PathGuard WebGateway.

pub(crate) mod connect;
pub(crate) mod http3;

use std::time::Duration;

use async_trait::async_trait;
use scion_http3::{
    TimeoutPhase,
    bytes::Bytes,
    http::{self, HeaderMap, Method, Uri},
};

use crate::{
    engine::describe_error,
    ffi::types::{CoreError, CoreHeader, CoreRequest, CoreResponse},
};

/// Sends requests and collects the responses.
#[async_trait]
pub(crate) trait Transport: Send + Sync {
    /// Buffers the body up to the limit that the transport got at construction.
    async fn send(&self, request: Request) -> Result<CoreResponse, CoreError>;

    /// Closes the connections. Without it, peers wait out the QUIC idle
    /// timeout instead of getting a CONNECTION_CLOSE.
    async fn close(&self);
}

/// A request that passed the checks that every transport needs.
pub(crate) struct Request {
    pub(crate) http: http::Request<Bytes>,
    /// Overrides the request timeout of the transport.
    pub(crate) timeout: Option<Duration>,
}

impl Request {
    /// The host of the URL.
    pub(crate) fn host(&self) -> &str {
        let host = self.http.uri().host();
        debug_assert!(host.is_some(), "Request::try_from checks the host");
        host.unwrap_or_default()
    }
}

impl TryFrom<CoreRequest> for Request {
    type Error = CoreError;

    fn try_from(request: CoreRequest) -> Result<Self, CoreError> {
        // Check the method and the URL.
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| CoreError::invalid(format!("bad method {}", request.method)))?;
        let uri: Uri = request
            .url
            .parse()
            .map_err(|error| CoreError::invalid(format!("bad URL {}: {error}", request.url)))?;
        if uri.host().is_none() {
            return Err(CoreError::invalid(format!(
                "the URL {} has no host",
                request.url
            )));
        }

        // Build the request.
        let mut builder = http::Request::builder().method(method).uri(uri);
        for header in request.headers {
            builder = builder.header(header.name, header.value);
        }

        // Add the body.
        let http = builder
            .body(Bytes::from(request.body))
            .map_err(|error| CoreError::invalid(describe_error(&error)))?;
        Ok(Request {
            http,
            // Apply request timeout, without it the transport uses its default.
            timeout: (request.timeout_ms > 0).then(|| Duration::from_millis(request.timeout_ms)),
        })
    }
}

fn convert_headers(headers: &HeaderMap) -> Vec<CoreHeader> {
    headers
        .iter()
        .map(|(name, value)| {
            CoreHeader {
                name: name.as_str().to_owned(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            }
        })
        .collect()
}

fn classify(error: scion_http3::Error) -> CoreError {
    let message = describe_error(&error);
    classify_with_message(&error, message)
}

fn classify_with_message(error: &scion_http3::Error, message: String) -> CoreError {
    use scion_http3::Error as E;

    match error {
        E::StackBuild { .. } => CoreError::Connectivity { message },
        E::Resolution { .. } => CoreError::Resolution { message },
        E::Connect { .. } | E::TunnelRefused { .. } => CoreError::Connect { message },
        E::Tls { .. } => CoreError::Tls { message },
        E::Timeout {
            phase: TimeoutPhase::Connect,
            ..
        } => CoreError::ConnectTimeout { message },
        E::Timeout { .. } => CoreError::Timeout { message },
        E::StreamReset { .. } | E::Protocol { .. } | E::ConnectionLimit => {
            CoreError::Protocol { message }
        }
        E::BodyTooLarge { .. } => CoreError::BodyTooLarge { message },
        E::InvalidRequest { .. } => CoreError::InvalidArgument { message },
        E::Closed => CoreError::Closed,
        _ => CoreError::Internal { message },
    }
}
