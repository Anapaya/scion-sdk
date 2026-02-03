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
//! Connect-RPC client library using reqwest.

use std::{borrow::Cow, sync::Arc, time::Duration};

use anyhow::Context as _;
use bytes::Bytes;
use reqwest::header::{self, HeaderMap, HeaderValue};
use thiserror::Error;
use tracing::Instrument;

use crate::{
    error::CrpcError,
    token_source::{TokenSource, TokenSourceError},
};

/// Connect RPC client error.
#[derive(Debug, Error)]
pub enum CrpcClientError {
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
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        /// The response body, if available.
        body: Option<Bytes>,
    },
    /// Error retrieving a token from the token source.
    #[error("failed to retrieve token: {0}")]
    TokenSourceError(#[from] TokenSourceError),
}

const APPLICATION_PROTO: &str = "application/proto";

/// A Connect-RPC client.
pub struct CrpcClient {
    http_client: reqwest::Client,
    base_url: url::Url,
    token_source: Option<Arc<dyn TokenSource>>,
    user_agent: HeaderValue,
}

impl CrpcClient {
    /// Creates a new [`CrpcClient`] for the given base URL.
    pub fn new(base_url: &url::Url) -> anyhow::Result<Self> {
        let http_client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()
            .context("error creating HTTP client")?;

        Self::new_with_client(base_url, http_client)
    }

    /// Creates a new [`CrpcClient`] for the given base URL and explicit [`reqwest::Client`].
    pub fn new_with_client(
        base_url: &url::Url,
        http_client: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let user_agent =
            HeaderValue::from_str(&format!("reqwest-crpc {}", env!("CARGO_PKG_VERSION")))
                .context("error creating user agent header")?;

        Ok(CrpcClient {
            http_client,
            base_url: base_url.clone(),
            token_source: None,
            user_agent,
        })
    }

    /// Uses given token source for authentication of all following requests.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.token_source = Some(token_source);
        self
    }

    /// Sets the user agent header for all following requests.
    pub fn use_user_agent(&mut self, user_agent: &str) -> anyhow::Result<&mut Self> {
        self.user_agent = HeaderValue::from_str(user_agent)
            .with_context(|| format!("error creating user agent header from {user_agent}"))?;
        Ok(self)
    }

    /// Unary RPC request.
    pub async fn unary_request<Req, Res>(
        &self,
        path: &str,
        req: Req,
    ) -> Result<Res, CrpcClientError>
    where
        Req: prost::Message + Default,
        Res: prost::Message + Default,
    {
        self.do_unary_request(path, req)
            .instrument(tracing::info_span!("request", %path, id = rand::random::<u16>()))
            .await
    }

    /// Sends a unary request to the endhost API.
    async fn do_unary_request<Req, Res>(&self, path: &str, req: Req) -> Result<Res, CrpcClientError>
    where
        Req: prost::Message + Default,
        Res: prost::Message + Default,
    {
        let url = self.base_url.join(path).map_err(|e| {
            CrpcClientError::ConnectionError {
                context: "error joining base URL and path".into(),
                source: e.into(),
            }
        })?;

        let mut headers = HeaderMap::with_capacity(3);
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static(APPLICATION_PROTO),
        );
        headers.insert(header::USER_AGENT, self.user_agent.clone());
        if let Some(token_source) = &self.token_source {
            let token = token_source.get_token().await?;
            let token_header = header::HeaderValue::from_str(&token_source.format_header(token))
                .map_err(|e| {
                    CrpcClientError::TokenSourceError(
                        format!("error formatting token as header value: {e:?}").into(),
                    )
                })?;

            headers.insert(header::AUTHORIZATION, token_header);
        }

        tracing::debug!("Sending request");

        let body = req.encode_to_vec();
        let response = self
            .http_client
            .post(url)
            .body(reqwest::Body::from(body))
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                CrpcClientError::ConnectionError {
                    context: "error sending request".into(),
                    source: e.into(),
                }
            })?;

        tracing::debug!(status=%response.status(), body_len=%response.content_length().unwrap_or(0), "Got response");

        let status = response.status();
        if !status.is_success() {
            let response_raw = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());

            // Try to parse the body as a CrpcError, otherwise create a generic one.
            match serde_json::from_str::<CrpcError>(&response_raw) {
                Ok(crpc_err) => {
                    return Err(CrpcClientError::CrpcError(crpc_err));
                }
                Err(_) => {
                    return Err(CrpcClientError::CrpcError(CrpcError::new(
                        status.into(),
                        response_raw,
                    )));
                }
            }
        }

        let body = response.bytes().await.map_err(|e| {
            CrpcClientError::DecodeError {
                context: "error reading response body".into(),
                source: Some(e.into()),
                body: None,
            }
        })?;

        Res::decode(&body[..]).map_err(|e| {
            CrpcClientError::DecodeError {
                context: "error decoding response body".into(),
                source: Some(e.into()),
                body: Some(body.clone()),
            }
        })
    }
}
