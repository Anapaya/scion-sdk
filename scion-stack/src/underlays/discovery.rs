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
use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use scion_sdk_utils::backoff::ExponentialBackoff;
use sciparse::{identifier::isd_asn::IsdAsn, path::metadata::path_interface::PathInterface};
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

/// A single SCION router entry used to build a [StaticUnderlayDiscovery].
#[derive(Clone, Debug)]
pub struct StaticUdpRouter {
    /// The ISD-AS the router belongs to.
    pub isd_as: IsdAsn,
    /// The internal interface socket address of the SCION router (the UDP next hop).
    pub internal_interface: net::SocketAddr,
    /// The SCION interface IDs reachable via this router.
    pub interfaces: Vec<u16>,
}

/// Implementation of the [UnderlayDiscovery] trait backed by a static, in-memory topology.
///
/// Unlike [PeriodicUnderlayDiscovery], this does not contact an endhost API and runs no background
/// task. It is intended for fully-local UDP stacks where the topology (SCION routers and the
/// interfaces they serve) is known up front, e.g. from configuration.
pub struct StaticUnderlayDiscovery {
    underlays: Vec<(IsdAsn, UnderlayInfo)>,
    udp_underlay_next_hops: HashMap<PathInterface, net::SocketAddr>,
}

impl StaticUnderlayDiscovery {
    /// Creates a new static underlay discovery from the given SCION routers.
    ///
    /// Routers are grouped by ISD-AS into a single [UnderlayInfo::Udp] entry per ISD-AS, and a
    /// direct next-hop lookup is built mapping each served [PathInterface] to the router's internal
    /// interface.
    pub fn new(routers: impl IntoIterator<Item = StaticUdpRouter>) -> Self {
        let mut grouped: HashMap<IsdAsn, Vec<ScionRouter>> = HashMap::new();
        let mut udp_underlay_next_hops = HashMap::new();
        for router in routers {
            for interface_id in router.interfaces.iter() {
                udp_underlay_next_hops.insert(
                    PathInterface::new(router.isd_as, *interface_id),
                    router.internal_interface,
                );
            }
            grouped.entry(router.isd_as).or_default().push(ScionRouter {
                internal_interface: router.internal_interface,
                interfaces: router.interfaces,
            });
        }

        let underlays = grouped
            .into_iter()
            .map(|(isd_as, routers)| (isd_as, UnderlayInfo::Udp(routers)))
            .collect();

        Self {
            underlays,
            udp_underlay_next_hops,
        }
    }
}

impl UnderlayDiscovery for StaticUnderlayDiscovery {
    fn underlays(&self, isd_as: IsdAsn) -> Vec<(IsdAsn, UnderlayInfo)> {
        self.underlays
            .iter()
            .filter(|(ia, _)| isd_as.matches(*ia))
            .map(|(ia, info)| (*ia, info.clone()))
            .collect()
    }

    fn isd_ases(&self) -> HashSet<IsdAsn> {
        HashSet::from_iter(self.underlays.iter().map(|(ia, _)| *ia))
    }

    fn resolve_udp_underlay_next_hop(&self, interface: PathInterface) -> Option<net::SocketAddr> {
        self.udp_underlay_next_hops.get(&interface).cloned()
    }
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
                        isd_asn: (*isd_as),
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
            underlays.push(((*isd_as), UnderlayInfo::Snap(underlay.address.clone())));
        }
    }
    Ok((underlays, udp_underlay_next_hops))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn isd_as(s: &str) -> IsdAsn {
        IsdAsn::from_str(s).unwrap()
    }

    fn sock(s: &str) -> net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn static_discovery_resolves_configured_next_hops() {
        let ia = isd_as("1-ff00:0:110");
        let router = sock("127.0.0.1:30041");
        let discovery = StaticUnderlayDiscovery::new([StaticUdpRouter {
            isd_as: ia,
            internal_interface: router,
            interfaces: vec![1, 2],
        }]);

        assert_eq!(
            discovery.resolve_udp_underlay_next_hop(PathInterface::new(ia, 1)),
            Some(router)
        );
        assert_eq!(
            discovery.resolve_udp_underlay_next_hop(PathInterface::new(ia, 2)),
            Some(router)
        );
    }

    #[test]
    fn static_discovery_unknown_interface_has_no_next_hop() {
        let ia = isd_as("1-ff00:0:110");
        let discovery = StaticUnderlayDiscovery::new([StaticUdpRouter {
            isd_as: ia,
            internal_interface: sock("127.0.0.1:30041"),
            interfaces: vec![1],
        }]);

        assert_eq!(
            discovery.resolve_udp_underlay_next_hop(PathInterface::new(ia, 99)),
            None
        );
        assert_eq!(
            discovery.resolve_udp_underlay_next_hop(PathInterface::new(isd_as("1-ff00:0:111"), 1)),
            None
        );
    }

    #[test]
    fn static_discovery_reports_known_isd_ases_and_udp_underlays() {
        let ia1 = isd_as("1-ff00:0:110");
        let ia2 = isd_as("1-ff00:0:111");
        let discovery = StaticUnderlayDiscovery::new([
            StaticUdpRouter {
                isd_as: ia1,
                internal_interface: sock("127.0.0.1:30041"),
                interfaces: vec![1],
            },
            StaticUdpRouter {
                isd_as: ia2,
                internal_interface: sock("127.0.0.2:30041"),
                interfaces: vec![5],
            },
        ]);

        let isd_ases = discovery.isd_ases();
        assert_eq!(isd_ases.len(), 2);
        assert!(isd_ases.contains(&ia1));
        assert!(isd_ases.contains(&ia2));

        let underlays = discovery.underlays(ia1);
        assert_eq!(underlays.len(), 1);
        assert_eq!(underlays[0].0, ia1);
        assert!(matches!(underlays[0].1, UnderlayInfo::Udp(_)));
    }
}
