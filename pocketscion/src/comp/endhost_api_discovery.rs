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

//! Endhost API Discovery allows clients to discover Endhost APIs available to them

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use endhost_api_discovery_api::{
    reexport::axum_client_ip::ClientIpSource, routes::nest_endhost_discovery_api,
};
use endhost_api_discovery_models::{EndhostApiDiscovery, EndhostApiGroup, EndhostApiInfo};
use scion_sdk_observability::info_trace_layer;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task::JoinHandle};
use utoipa::ToSchema;

use crate::{io_config::IoConfig, state::PocketScionState, util::addr_to_http_url};

/// Implements Endhost API discovery through pocketscion state
#[derive(Clone)]
pub struct EndhostApiDiscoveryService {
    /// ID of the Endhost API Discovery API instance, used to retrieve the relevant state and
    /// config.
    #[expect(unused)]
    id: EndhostApiDiscoveryApiId,
    app_state: PocketScionState,
    io_config: IoConfig,
}

#[async_trait::async_trait]
impl EndhostApiDiscovery for EndhostApiDiscoveryService {
    async fn discover_endhost_apis(&self, public_ip: IpAddr) -> Vec<EndhostApiGroup> {
        let mut groups = BTreeMap::new();
        for (id, eh_api) in self.app_state.endhost_apis().into_iter() {
            let addr = self.io_config.endhost_api_addr(id);
            let Some(addr) = addr else {
                tracing::debug!(
                    "Endhost API {} does not have a socket address configured, skipping",
                    id
                );
                continue;
            };

            let url = addr_to_http_url(addr);

            for ia in eh_api.local_ases {
                groups
                    .entry(ia)
                    .or_insert_with(Vec::new)
                    .push(EndhostApiInfo {
                        address: url.clone(),
                    });
            }
        }

        let len = groups.len();
        tracing::debug!(?public_ip, len, "Discovered Endhost APIs");

        groups
            .into_values()
            .map(|apis| EndhostApiGroup { apis })
            .collect()
    }
}

impl EndhostApiDiscoveryService {
    /// Starts the Endhost API Discovery service for the given API ID on the provided listener.
    ///
    /// ### Parameters
    /// - `id`: ID of the Endhost API Discovery API instance to start the service for. Must exist in
    ///   the application state.
    /// - `listener`: TCP listener to serve the API on. Must already be bound to the desired
    ///   address.
    /// - `app_state`: The application state, used to access the Endhost API Discovery API state and
    ///   Endhost API state.
    /// - `io_config`: The I/O configuration, used to discover addresses the Endhost API returns.
    pub async fn start(
        id: EndhostApiDiscoveryApiId,
        listener: TcpListener,
        app_state: PocketScionState,
        io_config: IoConfig,
    ) -> anyhow::Result<(Arc<EndhostApiDiscoveryService>, JoinHandle<()>)> {
        // Must exist in state to be started
        if app_state.endhost_api_discovery_api(id).is_none() {
            anyhow::bail!("No Endhost API Discovery API configured with the given ID");
        }

        let local_addr = listener.local_addr().context(
            "error getting local address of listen socket for Endhost API Discovery API",
        )?;

        // Prepare API
        let (app, service) = {
            let service = Self {
                id,
                app_state: app_state.clone(),
                io_config: io_config.clone(),
            };

            let service = Arc::new(service);

            let router = nest_endhost_discovery_api(
                axum::Router::new(),
                service.clone(),
                // Connect Info - extracts the client IP from the TCP connection info
                ClientIpSource::ConnectInfo,
            );

            (router.layer(info_trace_layer()), service)
        };

        // Start API server in background task
        tracing::info!(%local_addr, ?id, "Starting endhost API discovery");
        let handle = tokio::spawn(async move {
            let e = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;

            match e {
                Ok(()) => {
                    tracing::info!(%local_addr, ?id, "Endhost API discovery server has stopped")
                }
                Err(e) => {
                    tracing::error!(%local_addr, ?id, err=?e, "Endhost API discovery server has stopped with error")
                }
            }
        });

        Ok((service, handle))
    }
}

/// State for EndhostApiDiscoveryApp, stored in PocketScionState
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct EndhostApiDiscoveryState;

/// Endhost Discovery API instance identifier.
#[derive(
    Debug, PartialEq, Clone, Copy, Serialize, Deserialize, Ord, PartialOrd, Eq, Hash, ToSchema,
)]
pub struct EndhostApiDiscoveryApiId(usize);

impl From<usize> for EndhostApiDiscoveryApiId {
    fn from(value: usize) -> Self {
        EndhostApiDiscoveryApiId(value)
    }
}

impl From<EndhostApiDiscoveryApiId> for usize {
    fn from(value: EndhostApiDiscoveryApiId) -> Self {
        value.0
    }
}

impl EndhostApiDiscoveryApiId {
    /// Consumes the ID and returns the inner usize.
    pub fn into_inner(self) -> usize {
        self.0
    }
}

impl PocketScionState {
    /// Adds a new Endhost API Discovery API to the system state and returns its id.
    pub fn add_endhost_api_discovery_api(&mut self) -> EndhostApiDiscoveryApiId {
        let mut sstate = self.write();
        let id = sstate.endhost_api_discovery_api.len().into();

        sstate
            .endhost_api_discovery_api
            .insert(id, EndhostApiDiscoveryState);

        id
    }

    /// Returns a map of all Endhost API Discovery APIs in the system state.
    pub(crate) fn endhost_api_discovery_apis(
        &self,
    ) -> BTreeMap<EndhostApiDiscoveryApiId, EndhostApiDiscoveryState> {
        self.read().endhost_api_discovery_api.clone()
    }

    /// Returns the state of the Endhost API Discovery API with the given id, if it exists.
    pub(crate) fn endhost_api_discovery_api(
        &self,
        id: EndhostApiDiscoveryApiId,
    ) -> Option<EndhostApiDiscoveryState> {
        self.read().endhost_api_discovery_api.get(&id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::Utc;
    use sciparse::identifier::isd_asn::IsdAsn;
    use url::Url;

    use super::*;
    use crate::comp::endhost_api::{EndhostApiId, EndhostApiState};

    #[tokio::test]
    async fn should_return_apis_grouped_by_local_as() {
        let as1: IsdAsn = "1-ff00:0:110".parse().unwrap();
        let as2: IsdAsn = "1-ff00:0:111".parse().unwrap();
        let as3: IsdAsn = "1-ff00:0:112".parse().unwrap();

        let app_state = PocketScionState::new(Utc::now());
        {
            let mut state = app_state.write();
            state.endhost_apis.insert(
                EndhostApiId::from(1),
                EndhostApiState {
                    local_ases: vec![as1].into_iter().collect(),
                },
            );
            state.endhost_apis.insert(
                EndhostApiId::from(2),
                EndhostApiState {
                    local_ases: vec![as2].into_iter().collect(),
                },
            );
            state.endhost_apis.insert(
                EndhostApiId::from(3),
                EndhostApiState {
                    local_ases: vec![as2, as3].into_iter().collect(),
                },
            );
        }

        let io_config = IoConfig::default();
        io_config.set_endhost_api_addr(
            EndhostApiId::from(1),
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 1),
        );
        io_config.set_endhost_api_addr(
            EndhostApiId::from(2),
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 2),
        );
        io_config.set_endhost_api_addr(
            EndhostApiId::from(3),
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 3),
        );

        let api_id = EndhostApiDiscoveryApiId::from(1);
        let svc = EndhostApiDiscoveryService {
            id: api_id,
            app_state,
            io_config,
        };

        let result = svc
            .discover_endhost_apis(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await;

        let expected_groups = [
            EndhostApiGroup {
                apis: vec![EndhostApiInfo {
                    address: Url::parse("http://127.0.0.1:1").unwrap(),
                }],
            },
            EndhostApiGroup {
                apis: vec![
                    EndhostApiInfo {
                        address: Url::parse("http://127.0.0.1:2").unwrap(),
                    },
                    EndhostApiInfo {
                        address: Url::parse("http://127.0.0.1:3").unwrap(),
                    },
                ],
            },
            EndhostApiGroup {
                apis: vec![EndhostApiInfo {
                    address: Url::parse("http://127.0.0.1:3").unwrap(),
                }],
            },
        ];

        assert!(
            result.contains(&expected_groups[0]),
            "Group1 is missing from result: {result:#?}"
        );
        assert!(
            result.contains(&expected_groups[1]),
            "Group2 is missing from result: {result:#?}"
        );
        assert!(
            result.contains(&expected_groups[2]),
            "Group3 is missing from result: {result:#?}"
        );

        assert_eq!(result.len(), 3)
    }
}
