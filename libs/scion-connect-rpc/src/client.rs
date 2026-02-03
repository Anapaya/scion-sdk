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

//! Connect-RPC client implementation over HTTP/3 and QUIC.
//!
//! This module provides a generic Connect-RPC client using HTTP/3 via QUIC over SCION.

use std::{borrow::Cow, sync::Arc};

use scion_proto::address::SocketAddr;
use scion_sdk_quic_scion::h3::client::{H3Client, H3ConnectionError, request::H3Request};
use scion_stack::scionstack::UdpScionSocket;
use thiserror::Error;
use url::Url;

use crate::error::CrpcError;

/// Connect RPC client error.
#[derive(Debug, Error)]
pub enum RequestError {
    /// Error that occurs when there is a connection issue.
    #[error("connection error {context}: {source:#?}")]
    ConnectionError {
        /// Additional context about the connection error.
        context: Cow<'static, str>,
        /// The underlying source error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Error returned by the server.
    #[error("server returned an error: {0:#?}")]
    CrpcError(CrpcError),
    /// Error decoding the response body.
    #[error("failed to decode response body: {context}: {source:#?}")]
    DecodeError {
        /// Additional context about the decoding error.
        context: Cow<'static, str>,
        /// The underlying source error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        /// The response body, if available.
        body: Option<Vec<u8>>,
    },
}

/// Trait for a Connect-RPC client.
#[async_trait::async_trait]
pub trait ConnectRpcClient {
    /// Make a unary Connect-RPC request.
    async fn unary_request<Req, Res>(
        &self,
        method: http::Method,
        url: Url,
        request: Req,
    ) -> Result<Res, RequestError>
    where
        Req: prost::Message + Default,
        Res: prost::Message + Default;
}

/// A Connect-RPC client using HTTP/3 over QUIC with SCION transport.
///
/// This client provides a high-level interface for making Connect-RPC requests
/// over HTTP/3, using QUIC as the transport protocol and SCION for networking.
pub struct CrpcClient {
    h3_client: H3Client,
    authorization_token: Option<String>,
}

impl CrpcClient {
    /// Create a new Connect-RPC client with the given configuration and UDP SCION socket.
    ///
    /// # Arguments
    /// * `remote` - The remote SCION socket address of the server.
    /// * `socket` - The SCION UDP socket to use for sending/receiving packets
    /// * `server_name` - Optional server name for TLS SNI (also used as :authority header)
    /// * `authorization_token` - Optional authorization token for authentication
    ///
    /// # Returns
    /// A new client instance that is ready to connect.
    pub async fn new(
        remote: SocketAddr,
        socket: Arc<UdpScionSocket>,
        server_name: Option<String>,
        authorization_token: Option<String>,
    ) -> Result<Self, H3ConnectionError> {
        let h3_client = H3Client::new(remote, socket, server_name).await?;

        Ok(Self {
            h3_client,
            authorization_token,
        })
    }
}

#[async_trait::async_trait]
impl ConnectRpcClient for CrpcClient {
    /// Make a unary Connect-RPC request.
    async fn unary_request<Req, Res>(
        &self,
        method: http::Method,
        url: Url,
        req: Req,
    ) -> Result<Res, RequestError>
    where
        Req: prost::Message + Default,
        Res: prost::Message + Default,
    {
        let request_body = req.encode_to_vec();

        tracing::debug!(
            ?method,
            ?url,
            body_len = request_body.len(),
            "sending Connect-RPC request"
        );

        // Build HTTP/3 request
        let mut request = H3Request::builder(method, url).body(request_body);

        // Add authorization header if token is provided
        if let Some(token) = &self.authorization_token {
            request = request.header("Authorization", token);
        }
        let request = request.build();

        // Send the request and await the response
        let response = match self.h3_client.request(request).await {
            Ok(response) => response,
            Err(err) => {
                return Err(RequestError::ConnectionError {
                    context: Cow::Borrowed("sending Connect-RPC request"),
                    source: Box::new(err),
                });
            }
        };

        if !response.is_success() {
            // Try to parse the body as a CrpcError, otherwise create a generic one.
            match std::str::from_utf8(&response.body)
                .ok()
                .and_then(|body_str| serde_json::from_str::<CrpcError>(body_str).ok())
            {
                Some(crpc_err) => {
                    return Err(RequestError::CrpcError(crpc_err));
                }
                None => {
                    return Err(RequestError::CrpcError(CrpcError::new(
                        response.status.into(),
                        String::from_utf8_lossy(&response.body).into_owned(),
                    )));
                }
            }
        }
        tracing::debug!(
            body_len = response.body.len(),
            "received Connect-RPC response"
        );

        Res::decode(&response.body[..]).map_err(|e| {
            RequestError::DecodeError {
                context: "error decoding response body".into(),
                source: e.into(),
                body: Some(response.body.clone()),
            }
        })
    }
}
