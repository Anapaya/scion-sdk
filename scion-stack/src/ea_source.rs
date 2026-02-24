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

//! Endhost API Source.
//!
//! This module defines the `EndhostApiSource` trait, which is responsible for discovering and
//! providing access to the Endhost API. Implementations of this trait can be used to discover the
//! API in different environments, such as through environment variables, configuration files, or
//! network discovery.

use std::sync::Arc;

use endhost_api_discovery_client::client::{
    CrpcEndhostApiDiscoveryClient, EndhostApiDiscoveryClient,
};
use endhost_api_discovery_models::{EndhostApiGroup, EndhostApiInfo};
use snap_control::reexport::TokenSource;
use url::Url;

use crate::aa_client::AAClient;

/// Re-exports of Endhost API discovery models from `endhost_api_discovery_models`
pub mod models {
    pub use endhost_api_discovery_models::*;
}

/// Error type for failures to retrieve Endhost APIs from an `EndhostApiSource`.
#[derive(Debug, thiserror::Error)]
#[error("Failed to retrieve Endhost APIs: {error}")]
pub struct EndhostApiSourceError {
    /// The underlying error that occurred while trying to retrieve the Endhost APIs
    pub error: anyhow::Error,
    /// If true, the error is considered transient and the client may retry
    pub transient: bool,
}

/// Returns available Endhost APIs for the client to use
///
/// Endhost APIs are grouped into `EndhostApiGroup`s.
/// The client should attempt to use the first Group
#[async_trait::async_trait]
pub trait EndhostApiSource: Send + Sync + 'static {
    /// Returns the available Endhost APIs.
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError>;
}

/// Fetches Endhost API discovery information from the AA and returns the available Endhost APIs.
pub struct AAEndhostApiSource {
    client: Arc<AAClient>,
    fallback: Option<Box<dyn EndhostApiSource>>,
}

impl AAEndhostApiSource {
    /// Creates a new `AAEndhostApiSource`
    pub fn new(client: Arc<AAClient>) -> Self {
        Self {
            client,
            fallback: None,
        }
    }

    /// Adds a fallback Endhost API source to use if AA-based discovery fails.
    pub fn with_fallback(mut self, fallback: Box<dyn EndhostApiSource>) -> Self {
        self.fallback = Some(fallback);
        self
    }
}

#[async_trait::async_trait]
impl EndhostApiSource for AAEndhostApiSource {
    /// Returns the available Endhost APIs.
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
        let discovery_apis = self
            .client
            .get_endhost_api_discovery_apis()
            .await
            .map_err(|e| {
                EndhostApiSourceError {
                    error: e.context("Failed to get Endhost API discovery APIs from AA"),
                    transient: true,
                }
            })?;

        if discovery_apis.is_empty() {
            return Err(EndhostApiSourceError {
                error: anyhow::anyhow!("AA returned empty list of Endhost API discovery APIs"),
                // XXX(ake): An empty list likely indicates a misconfiguration that won't be
                // resolved by retrying
                transient: false,
            });
        }

        match discover_endhost_apis(discovery_apis, None).await {
            Ok(apis) => Ok(apis),
            Err(e) => {
                tracing::warn!(error = ?e, "Endhost API discovery through AA failed");
                if let Some(fallback) = &self.fallback {
                    // If discovery through AA fails, try the fallback source if configured
                    fallback.endhost_apis().await
                } else {
                    // If no fallback is configured, return the original error
                    Err(e)
                }
            }
        }
    }
}

/// A static list of Endhost API discovery services which the stack can use to discover Endhost
/// APIs.
pub struct StaticEndhostApiDiscovery {
    discovery_apis: Vec<Url>,
}

impl StaticEndhostApiDiscovery {
    const GLOBAL_DISCOVERY_APIS: &[&'static str] = &["https://scion-discovery.anapaya.net"];

    /// Creates a new `StaticEndhostApiDiscovery` with the given list of discovery API URLs.
    pub fn new(discovery_apis: Vec<Url>) -> Self {
        Self { discovery_apis }
    }

    /// Creates a new `StaticEndhostApiDiscovery` with the global list of discovery API URLs.
    pub fn global() -> Self {
        let discovery_apis = Self::GLOBAL_DISCOVERY_APIS
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL in GLOBAL_DISCOVERY_APIS"))
            .collect();

        Self { discovery_apis }
    }
}

#[async_trait::async_trait]
impl EndhostApiSource for StaticEndhostApiDiscovery {
    /// Returns the available Endhost APIs.
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
        if self.discovery_apis.is_empty() {
            return Err(EndhostApiSourceError {
                error: anyhow::anyhow!(
                    "No Endhost API discovery APIs configured in StaticEndhostApiDiscovery"
                ),
                transient: false,
            });
        }

        discover_endhost_apis(self.discovery_apis.clone(), None).await
    }
}

/// A static list of Endhost APIs which the stack can use.
#[derive(Default)]
pub struct StaticEndhostApis {
    /// List of Endhost API groups to use
    groups: Vec<EndhostApiGroup>,
}

impl StaticEndhostApis {
    /// Creates a new empty `StaticEndhostApis`
    pub fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Adds a group of Endhost APIs to the list of available APIs.
    ///
    /// Endhost APIs in one group must offer the same data when queried. Meaning they should know
    /// the same set of underlays and segments.
    ///
    /// The client can freely failover between APIs in the same group.
    ///
    /// Endhost APIs in different groups can differ in the data they offer, however the client must
    /// close all open connections to failover between groups.
    pub fn add_group(mut self, group: Vec<Url>) -> Self {
        self.groups.push(EndhostApiGroup {
            apis: group
                .into_iter()
                .map(|url| EndhostApiInfo { address: url })
                .collect(),
        });

        self
    }
}

#[async_trait::async_trait]
impl EndhostApiSource for StaticEndhostApis {
    /// Returns the available Endhost APIs.
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
        Ok(self.groups.clone())
    }
}

/// Attempts to discover Endhost APIs using all provided discovery API URLs, returning the first
/// successful result or an error if all discovery APIs fail.
///
/// On failure, returns the last error encountered or a generic error if no discovery APIs were
/// provided.
async fn discover_endhost_apis(
    discovery_apis: Vec<Url>,
    token_source: Option<Arc<dyn TokenSource>>,
) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
    let mut last_error = None;
    for discovery_api in discovery_apis.iter() {
        // Try all apis in order, return the first successful one
        let client = {
            let mut client = match CrpcEndhostApiDiscoveryClient::new(discovery_api) {
                Ok(client) => client,
                Err(e) => {
                    tracing::warn!(%discovery_api, error = ?e, "Failed to create Endhost API discovery client");
                    // Track last error so we can return it if all discovery APIs fail
                    last_error = Some(EndhostApiSourceError {
                        error: e.context(format!(
                            "Failed to create Endhost API discovery client for {}",
                            discovery_api
                        )),
                        transient: false,
                    });
                    continue;
                }
            };

            if let Some(token_source) = token_source.clone() {
                client.use_token_source(token_source);
            }

            client
        };

        match client.discover_endhost_apis().await {
            Ok(discovered_apis) => {
                tracing::debug!(%discovery_api, "Successfully discovered Endhost APIs");
                return Ok(discovered_apis);
            }
            Err(e) => {
                tracing::warn!(%discovery_api, error = ?e, "Failed to discover Endhost APIs");
                // Track last error so we can return it if all discovery APIs fail
                last_error = Some(EndhostApiSourceError {
                    error: anyhow::Error::new(e),
                    transient: true,
                });

                continue;
            }
        }
    }

    // If we exhausted all discovery APIs, return the last error we encountered or a generic
    // error if we had no discovery APIs configured
    match last_error {
        Some(e) => {
            let transient = e.transient;

            Err(EndhostApiSourceError {
                error: anyhow::Error::new(e)
                    .context("Failed to discover Endhost APIs using any configured discovery APIs"),
                transient,
            })
        }
        None => {
            Err(EndhostApiSourceError {
                error: anyhow::anyhow!(
                    "Attempted to discover Endhost APIs with empty list of discovery APIs"
                ),
                transient: false,
            })
        }
    }
}
