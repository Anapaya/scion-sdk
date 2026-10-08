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

//! Authentication through the Anapaya AA service.
//!
//! The client sends its API key to the AA `AuthenticateByKey` call. The AA
//! returns a SNAP token, which also authenticates with the endhost API. The
//! answer can also carry a discovery URL for the endhost APIs of the user.
//!
//! [`AaRefresher`] fetches and renews the token, and it publishes the
//! discovery URL of each answer. [`AaDiscovery`] waits for the first answer,
//! then discovers the endhost APIs through that URL, or through the global
//! discovery service if the AA sent none.

use anapaya_aa_client::{ApiKeyTokenRefresher, CrpcAaAuthClient};
use scion_http3::{
    scion_stack::{
        ea_source::{
            EndhostApiSource, EndhostApiSourceError, StaticEndhostApiDiscovery,
            models::EndhostApiGroup,
        },
        reqwest,
        reqwest_connect_rpc::token_source::{
            TokenSourceError,
            refresh::{TokenRefresher, TokenWithExpiry},
        },
    },
    url::Url,
};
use tokio::sync::watch;

/// What the last AA answer said about discovery. `None` until the first answer.
type DiscoveryState = Option<Result<Option<Url>, AaFailure>>;

#[derive(Clone)]
struct AaFailure {
    message: String,
    transient: bool,
}

/// Fetches SNAP tokens from the AA and publishes the discovery URL.
pub(crate) struct AaRefresher {
    refresher: ApiKeyTokenRefresher,
    discovery: watch::Sender<DiscoveryState>,
    http: Option<reqwest::Client>,
}

impl AaRefresher {
    /// `http` carries the trust anchors for the AA and the discovery service.
    /// If `None`, both use the reqwest default.
    pub(crate) fn new(
        aa_url: &Url,
        api_key: String,
        device_id: String,
        http: Option<reqwest::Client>,
    ) -> anyhow::Result<Self> {
        let client = match http.clone() {
            Some(http) => CrpcAaAuthClient::new_with_client(aa_url, http)?,
            None => CrpcAaAuthClient::new(aa_url)?,
        };
        Ok(AaRefresher {
            refresher: ApiKeyTokenRefresher::new(client, api_key, device_id),
            discovery: watch::Sender::new(None),
            http,
        })
    }

    pub(crate) fn discovery(&self) -> AaDiscovery {
        AaDiscovery {
            state: self.discovery.subscribe(),
            http: self.http.clone(),
        }
    }
}

#[async_trait::async_trait]
impl TokenRefresher for AaRefresher {
    async fn refresh(&self) -> Result<TokenWithExpiry, TokenSourceError> {
        match self.refresher.refresh_with_metadata().await {
            Ok((token, metadata)) => {
                let url = metadata
                    .and_then(|metadata| metadata.endhost_api_discovery_url)
                    .filter(|url| !url.is_empty())
                    .map(|url| {
                        url.parse::<Url>().map_err(|error| {
                            AaFailure {
                                message: format!("the AA sent a bad discovery URL {url}: {error}"),
                                transient: false,
                            }
                        })
                    })
                    .transpose();
                self.discovery.send_replace(Some(url));
                Ok(token)
            }
            Err(error) => {
                // Describe the failure.
                let transient = error.is_transient();
                let failure = AaFailure {
                    message: format!("AA authentication failed: {error:#}"),
                    transient,
                };
                // A failed renewal keeps the discovery URL of an earlier answer.
                self.discovery.send_if_modified(|state| {
                    if matches!(state, Some(Ok(_))) {
                        return false;
                    }

                    *state = Some(Err(failure));
                    true
                });

                let token_error = if transient {
                    TokenSourceError::unavailable(error)
                } else {
                    TokenSourceError::rejected(error)
                };
                Err(token_error)
            }
        }
    }
}

/// The endhost APIs that the AA answer points to.
#[derive(Clone)]
pub(crate) struct AaDiscovery {
    state: watch::Receiver<DiscoveryState>,
    http: Option<reqwest::Client>,
}

#[async_trait::async_trait]
impl EndhostApiSource for AaDiscovery {
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
        // Wait for the first AA answer.
        let mut receiver = self.state.clone();
        let state = receiver
            .wait_for(Option::is_some)
            .await
            .map_err(|_| EndhostApiSourceError::new("the AA token source stopped", false))?
            .as_ref()
            .expect("wait_for(Option::is_some) only returns a value that is Some")
            .clone();

        // Discover through what the answer says.
        match state {
            Ok(Some(url)) => {
                attach_http_client(StaticEndhostApiDiscovery::new(vec![url]), self.http.clone())
                    .endhost_apis()
                    .await
            }
            Ok(None) => {
                attach_http_client(StaticEndhostApiDiscovery::global(), self.http.clone())
                    .endhost_apis()
                    .await
            }
            Err(failure) => {
                Err(EndhostApiSourceError::new(
                    failure.message,
                    failure.transient,
                ))
            }
        }
    }
}

/// Sets `http` on `discovery`, if present.
pub(crate) fn attach_http_client(
    discovery: StaticEndhostApiDiscovery,
    http: Option<reqwest::Client>,
) -> StaticEndhostApiDiscovery {
    match http {
        Some(http) => discovery.with_http_client(http),
        None => discovery,
    }
}
