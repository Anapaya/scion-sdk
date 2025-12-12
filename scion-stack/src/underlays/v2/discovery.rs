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
//! Underlay discovery.
use std::{
    collections::{HashMap, HashSet},
    net::{self},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use endhost_api_client::client::EndhostApiClient;
use scion_proto::{address::IsdAsn, path::PathInterface};
use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use scion_sdk_utils::backoff::ExponentialBackoff;
use tokio::task::JoinHandle;
use url::Url;

/// Trait that exposes available SCION underlay data planes.
/// The returned underlays are expected to be up too date and
/// sorted by priority.
pub trait UnderlayDiscovery: Send + Sync {
    /// Returns discovered underlays that match the given ISD-AS.
    /// Wildcard ISD-ASes are supported.
    /// The underlays are returned in the order of priority.
    fn underlays(&self, isd_as: IsdAsn) -> Vec<(IsdAsn, UnderlayInfo)>;
    /// Returns the set of ISD-ASes for which underlays are available.
    fn isd_ases(&self) -> HashSet<IsdAsn>;
    /// Resolves the next hop for the given ISD-AS and interface ID.
    fn resolve_udp_underlay_next_hop(&self, interface: PathInterface) -> Option<net::SocketAddr>;
}

/// Underlay discovery information for a SCION router.
#[derive(Clone, Debug)]
pub struct ScionRouter {
    /// The internal interface socket address of the SCION router.
    internal_interface: net::SocketAddr,
    /// The list of SCION interfaces available on the SCION router.
    interfaces: Vec<u16>,
}

/// Information about a discovered underlay.
#[derive(Clone, Debug)]
pub enum UnderlayInfo {
    /// A snap control plane API address.
    Snap(Url),
    /// A SCION router.
    Udp(Vec<ScionRouter>),
}

struct PeriodicUnderlayDiscoveryInner {
    pub underlays: ArcSwap<Vec<(IsdAsn, UnderlayInfo)>>,
    /// Map of underlay next hops to make the lookup faster.
    pub udp_underlay_next_hops: ArcSwap<HashMap<PathInterface, net::SocketAddr>>,
}

/// Implementation of the UnderlayDiscovery trait that periodically discovers underlays.
/// When created starts a background task that periodically discovers underlays
/// and updates the underlays.
pub struct PeriodicUnderlayDiscovery {
    inner: Arc<PeriodicUnderlayDiscoveryInner>,
    task: JoinHandle<()>,
}

impl Drop for PeriodicUnderlayDiscovery {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl UnderlayDiscovery for PeriodicUnderlayDiscovery {
    fn underlays(&self, isd_as: IsdAsn) -> Vec<(IsdAsn, UnderlayInfo)> {
        self.inner
            .underlays
            .load()
            .iter()
            .filter(|(ia, _)| isd_as.matches(*ia))
            .map(|(ia, info)| (*ia, info.clone()))
            .collect()
    }

    fn isd_ases(&self) -> HashSet<IsdAsn> {
        HashSet::from_iter(self.inner.underlays.load().iter().map(|(ia, _)| *ia))
    }

    fn resolve_udp_underlay_next_hop(&self, interface: PathInterface) -> Option<net::SocketAddr> {
        self.inner
            .udp_underlay_next_hops
            .load()
            .get(&interface)
            .cloned()
    }
}

impl PeriodicUnderlayDiscovery {
    /// Creates a new periodic underlay discovery.
    /// Does an initial underlay discovery and returns an error if it fails.
    pub async fn new(
        api_client: Arc<dyn EndhostApiClient>,
        fetch_interval: Duration,
        backoff: ExponentialBackoff,
    ) -> Result<Self, CrpcClientError> {
        let (initial_underlays, initial_udp_underlay_next_hops) =
            discover_underlays(&api_client).await?;
        tracing::debug!(
            underlays=?initial_underlays,
            "Successfully discovered initial underlays"
        );
        let inner = Arc::new(PeriodicUnderlayDiscoveryInner {
            underlays: ArcSwap::new(Arc::new(initial_underlays)),
            udp_underlay_next_hops: ArcSwap::new(Arc::new(initial_udp_underlay_next_hops)),
        });

        let inner_clone = inner.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(fetch_interval).await;
                let mut failed_attempts = 0;
                loop {
                    match discover_underlays(&api_client).await {
                        Ok((underlays, udp_underlay_next_hops)) => {
                            tracing::debug!(
                                underlays=?underlays,
                                "Successfully discovered underlays"
                            );
                            inner_clone.underlays.store(Arc::new(underlays));
                            inner_clone
                                .udp_underlay_next_hops
                                .store(Arc::new(udp_underlay_next_hops));
                            break;
                        }
                        Err(e) => {
                            failed_attempts += 1;
                            tracing::warn!(err = ?e, attempt = failed_attempts, "Failed to discover underlays");
                            tokio::time::sleep(backoff.duration(failed_attempts)).await;
                        }
                    }
                }
            }
        });

        Ok(Self { inner, task })
    }
}

async fn discover_underlays(
    api_client: &Arc<dyn EndhostApiClient>,
) -> Result<
    (
        Vec<(IsdAsn, UnderlayInfo)>,
        HashMap<PathInterface, net::SocketAddr>,
    ),
    CrpcClientError,
> {
    let res = api_client.list_underlays(IsdAsn::WILDCARD).await?;
    let mut udp_underlays = HashMap::new();
    for underlay in res.udp_underlay.into_iter() {
        let entry = udp_underlays.entry(underlay.isd_as).or_insert(vec![]);
        entry.push(ScionRouter {
            internal_interface: underlay.internal_interface,
            interfaces: underlay.interfaces,
        });
    }

    // Create a direct lookup map for the UDP underlay next hops.
    let mut udp_underlay_next_hops = HashMap::new();
    for (isd_as, routers) in udp_underlays.iter() {
        for router in routers.iter() {
            for interface_id in router.interfaces.iter() {
                udp_underlay_next_hops.insert(
                    PathInterface {
                        isd_asn: *isd_as,
                        id: *interface_id,
                    },
                    router.internal_interface,
                );
            }
        }
    }

    // Create the underlays list.
    let mut underlays: Vec<(IsdAsn, UnderlayInfo)> = udp_underlays
        .into_iter()
        .map(|(isd_as, routers)| (isd_as, UnderlayInfo::Udp(routers)))
        .collect();
    for underlay in res.snap_underlay.iter() {
        for isd_as in underlay.isd_ases.iter() {
            underlays.push((*isd_as, UnderlayInfo::Snap(underlay.address.clone())));
        }
    }
    Ok((underlays, udp_underlay_next_hops))
}
