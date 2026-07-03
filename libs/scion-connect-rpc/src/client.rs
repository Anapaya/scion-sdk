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

use scion_sdk_quic_scion::{
    h3::deprecated::{
        client::{H3Client, H3ConnectionError},
        request::{H3Request, H3Response},
    },
    quic::config::QuicConfig,
    socket::GenericScionUdpSocket,
};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use thiserror::Error;
use tokio::sync::Mutex;
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
        request: &Req,
    ) -> Result<Res, RequestError>
    where
        Req: prost::Message,
        Res: prost::Message + Default;
}

/// Remote endpoint for a Connect-RPC client, consisting of a SCION socket address and a socket for
/// the underlying transport.
// XXX(bunert): if the underlying H3 client supports multiple connections per socket, we could rely
// on a single socket for multiple remotes and remove this.
#[derive(Clone)]
pub struct RemoteEndpoint {
    remote: ScionSocketIpAddr,
    socket: Arc<dyn GenericScionUdpSocket>,
}

impl RemoteEndpoint {
    /// Creates a new remote endpoint with the given SCION socket address and socket.
    pub fn new(remote: ScionSocketIpAddr, socket: Arc<dyn GenericScionUdpSocket>) -> Self {
        Self { remote, socket }
    }
}

/// A Connect-RPC client using HTTP/3 over QUIC with SCION transport.
///
/// This client provides a high-level interface for making Connect-RPC requests
/// over HTTP/3, using QUIC as the transport protocol and SCION for networking.
///
/// When multiple remotes are configured, the client races a connection attempt against all of
/// them in parallel and keeps the first one that succeeds as the active client. If the active
/// client later becomes unreachable, the next request transparently re-races the remotes.
#[derive(Clone)]
pub struct CrpcClient {
    /// Remotes to connect to, each with its own socket.
    remotes: Vec<RemoteEndpoint>,
    server_name: Option<String>,
    config: QuicConfig,
    authorization_token: Option<String>,
    /// The currently working client paired with a generation counter, shared across clones. The
    /// generation is bumped on every successful (re-)connection so concurrent requests can detect
    /// that another task has already reconnected and avoid racing the remotes redundantly.
    current: Arc<Mutex<(Option<H3Client>, u64)>>,
}

/// HTTP/3 connection error.
#[derive(Debug, Error)]
pub enum CrpcClientError {
    /// Underlying HTTP/3 connection error.
    #[error(transparent)]
    H3Error(#[from] H3ConnectionError),
    /// No remotes were provided to connect to.
    #[error("no remotes provided")]
    NoRemotes,
}

impl CrpcClient {
    /// Create a new Connect-RPC client for the given SCION remote endpoint.
    ///
    /// # Arguments
    /// * `remote` - The remote SCION endpoint.
    /// * `server_name` - Optional server name for TLS SNI (also used as :authority header)
    /// * `authorization_token` - Optional authorization token for authentication
    ///
    /// # Returns
    /// A new client instance that is ready to connect.
    pub async fn new(
        remote: RemoteEndpoint,
        server_name: Option<String>,
        authorization_token: Option<String>,
    ) -> Result<Self, CrpcClientError> {
        Self::with_remotes_and_config(
            vec![remote],
            server_name,
            authorization_token,
            QuicConfig::default(),
        )
        .await
    }

    /// Create a new Connect-RPC client with the given QUIC configuration and SCION remote endpoint.
    ///
    /// # Arguments
    /// * `remote` - The remote SCION endpoint.
    /// * `server_name` - Optional server name for TLS SNI (also used as :authority header)
    /// * `authorization_token` - Optional authorization token for authentication
    /// * `config` - Custom QUIC configuration for the client
    ///
    /// # Returns
    /// A new client instance that is ready to connect.
    pub async fn with_config(
        remote: RemoteEndpoint,
        server_name: Option<String>,
        authorization_token: Option<String>,
        config: QuicConfig,
    ) -> Result<Self, CrpcClientError> {
        Self::with_remotes_and_config(vec![remote], server_name, authorization_token, config).await
    }

    /// Create a new Connect-RPC client that races a connection across multiple remotes.
    ///
    /// A connection attempt is raced against all remotes in parallel and the first one that
    /// succeeds becomes the active client. If the active client later becomes unreachable, the next
    /// request transparently re-races the remotes.
    ///
    /// # Arguments
    /// * `remotes` - The remote SCION endpoints.
    /// * `server_name` - Optional server name for TLS SNI (also used as :authority header)
    /// * `authorization_token` - Optional authorization token for authentication
    /// * `config` - Custom QUIC configuration for the client
    ///
    /// # Returns
    /// A new client instance that is ready to connect. Returns an error if none of the remotes is
    /// reachable.
    pub async fn with_remotes_and_config(
        remotes: Vec<RemoteEndpoint>,
        server_name: Option<String>,
        authorization_token: Option<String>,
        config: QuicConfig,
    ) -> Result<Self, CrpcClientError> {
        if remotes.is_empty() {
            return Err(CrpcClientError::NoRemotes);
        }

        let client = Self {
            remotes,
            server_name,
            config,
            authorization_token,
            current: Arc::new(Mutex::new((None, 0))),
        };

        // Race a connection against all remotes so construction validates connectivity (and fails
        // if no remote is reachable).
        let established = client.race_connect().await?;
        *client.current.lock().await = (Some(established), 0);

        Ok(client)
    }

    /// Sends an HTTP/3 request, racing across the configured remotes on (re-)connection.
    ///
    /// The currently active client is used directly when available. If it fails (or none is yet
    /// established), a connection is raced against all remotes and the first to succeed becomes the
    /// new active client.
    async fn request(&self, request: H3Request) -> Result<H3Response, RequestError> {
        // Reuse active client.
        let (client, generation) = {
            let guard = self.current.lock().await;
            (guard.0.clone(), guard.1)
        };

        if let Some(client) = client {
            // We only try to fail over to a different client(remote) if the h3 request fails, we
            // don't check the h3 response as this is not seen as a failure.
            //
            // XXX(bunert): We could check for a `resource_exhausted` error code where failover
            // makes sense but that's omitted for now.
            match client.request(request.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    tracing::debug!(?err, "active client failed, re-racing remotes");
                }
            }
        }

        // Re-establish a working client by racing all remotes.
        let client = self.reconnect(generation).await.map_err(|err| {
            RequestError::ConnectionError {
                context: Cow::Borrowed("connecting to remote"),
                source: Box::new(err),
            }
        })?;

        client.request(request).await.map_err(|err| {
            RequestError::ConnectionError {
                context: Cow::Borrowed("sending Connect-RPC request"),
                source: Box::new(err),
            }
        })
    }

    /// Re-establishes the active client by racing all remotes, caching and returning the winner.
    ///
    /// Reconnection is deduplicated via the generation counter: if another task already reconnected
    /// since the caller observed `seen_generation`, that fresh client is returned without racing
    /// again. The `current` lock is held across the race so only one reconnection happens at a
    /// time.
    async fn reconnect(&self, seen_generation: u64) -> Result<H3Client, H3ConnectionError> {
        let mut guard = self.current.lock().await;

        // Another task reconnected while we waited for the lock; reuse its result.
        if guard.1 != seen_generation
            && let Some(client) = &guard.0
        {
            return Ok(client.clone());
        }

        let client = self.race_connect().await?;
        // Update the active client and bump the generation counter.
        *guard = (Some(client.clone()), guard.1.wrapping_add(1));
        Ok(client)
    }

    /// Races a connection attempt against all configured remotes, returning the first to succeed.
    async fn race_connect(&self) -> Result<H3Client, H3ConnectionError> {
        let attempts = self.remotes.iter().map(|endpoint| {
            let remote = endpoint.remote;
            let socket = endpoint.socket.clone();
            let server_name = self.server_name.clone();
            let config = self.config.clone();
            Box::pin(async move {
                H3Client::with_config(remote, socket, server_name, config)
                    .await
                    .inspect_err(|err| {
                        tracing::debug!(?remote, ?err, "failed to connect to remote");
                    })
            })
        });

        // Return the first successful connection or the last error if all fail.
        futures::future::select_ok(attempts)
            .await
            .map(|(client, _remaining)| client)
    }
}

#[async_trait::async_trait]
impl ConnectRpcClient for CrpcClient {
    /// Make a unary Connect-RPC request.
    async fn unary_request<Req, Res>(
        &self,
        method: http::Method,
        url: Url,
        req: &Req,
    ) -> Result<Res, RequestError>
    where
        Req: prost::Message,
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

        // Send the request and await the response, failing over across remotes if needed.
        let response = self.request(request).await?;

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
            status = %response.status,
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
