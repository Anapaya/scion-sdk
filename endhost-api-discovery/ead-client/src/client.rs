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

//! # Endhost API Discovery Client
//!
//! Endhost API discovery client library. Allows discovering available endhost APIs through
//! a Connect-RPC based discovery service.

use std::{ops::Deref, sync::Arc};

use endhost_api_discovery_models::{
    EndhostApiInfo, RpcEndhostApiDiscoveryService,
    proto::endhost::discovery::v1::{RpcGetEndhostApisRequest, RpcGetEndhostApisResponse},
};
use scion_sdk_reqwest_connect_rpc::{
    client::{CrpcClient, CrpcClientError},
    token_source::TokenSource,
};

/// Endhost API client trait.
#[async_trait::async_trait]
pub trait EndhostApiDiscoveryClient: Send + Sync {
    /// Lists the available endhost APIs
    async fn discover_endhost_api(&self) -> Result<Vec<EndhostApiInfo>, CrpcClientError>;
}

/// Connect RPC endhost API discovery client.
pub struct CrpcEndhostApiDiscoveryClient {
    client: CrpcClient,
}

impl Deref for CrpcEndhostApiDiscoveryClient {
    type Target = CrpcClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl CrpcEndhostApiDiscoveryClient {
    /// Creates a new endhost API client from the given base URL.
    pub fn new(base_url: &url::Url) -> anyhow::Result<Self> {
        Ok(CrpcEndhostApiDiscoveryClient {
            client: CrpcClient::new(base_url)?,
        })
    }

    /// Creates a new endhost API client from the given base URL and [`reqwest::Client`].
    pub fn new_with_client(base_url: &url::Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(CrpcEndhostApiDiscoveryClient {
            client: CrpcClient::new_with_client(base_url, client)?,
        })
    }

    /// Uses the provided token source for authentication.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.client.use_token_source(token_source);
        self
    }
}

#[async_trait::async_trait]
impl EndhostApiDiscoveryClient for CrpcEndhostApiDiscoveryClient {
    async fn discover_endhost_api(&self) -> Result<Vec<EndhostApiInfo>, CrpcClientError> {
        let res = self
            .client
            .unary_request::<RpcGetEndhostApisRequest, RpcGetEndhostApisResponse>(
                &format!(
                    "{}{}",
                    RpcEndhostApiDiscoveryService::SERVICE_PATH,
                    RpcEndhostApiDiscoveryService::GET_ENDHOST_APIS_PATH
                ),
                RpcGetEndhostApisRequest {},
            )
            .await?;

        res.endhost_apis
            .into_iter()
            .map(|api_info| api_info.try_into())
            .collect::<Result<Vec<EndhostApiInfo>, _>>()
            .map_err(|e| {
                CrpcClientError::DecodeError {
                    context: "failed to decode endhost API info".into(),
                    source: Some(Box::new(e)),
                    body: None,
                }
            })
            .inspect(|res| {
                tracing::debug!("Discovered {} endhost APIs", res.len());
            })
    }
}
