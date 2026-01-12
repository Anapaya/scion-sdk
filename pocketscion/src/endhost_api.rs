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
//! PocketSCION Endhost API.

use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use derive_more::{Deref, Display};
use endhost_api::routes::nest_endhost_api;
use endhost_api_models::{
    UnderlayDiscovery,
    underlays::{ScionRouter, Snap, Underlays},
};
use scion_proto::address::IsdAsn;
use scion_sdk_observability::info_trace_layer;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use utoipa::ToSchema;

use crate::{
    addr_to_http_url,
    io_config::SharedPocketScionIoConfig,
    state::{SharedPocketScionState, endhost_segment_lister::StateEndhostSegmentLister},
};

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    ToSchema,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deref,
    Display,
)]

/// Endhost API instance identifier.
pub struct EndhostApiId(usize);
impl From<usize> for EndhostApiId {
    fn from(value: usize) -> Self {
        EndhostApiId(value)
    }
}
impl From<EndhostApiId> for usize {
    fn from(value: EndhostApiId) -> Self {
        value.0
    }
}
impl EndhostApiId {
    /// Consumes the ID and returns the inner usize.
    pub fn into_inner(self) -> usize {
        self.0
    }
}

/// State per EndhostAPI instance
#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize, ToSchema)]
pub struct EndhostApiState {
    pub(crate) local_ases: BTreeSet<IsdAsn>,
}

/// PocketSCION Endhost API implementation
pub struct PsEndhostApi;

impl PsEndhostApi {
    /// Starts the Endhost API
    pub async fn start(
        this_id: EndhostApiId,
        ps_state: SharedPocketScionState,
        ps_io: SharedPocketScionIoConfig,
    ) -> anyhow::Result<()> {
        let state = ps_state
            .endhost_api(this_id)
            .context("no endhost api was set up with the given ID")?;

        let underlay_discovery = PsEndhostApiUnderlayDiscovery {
            id: this_id,
            system_state: ps_state.clone(),
            io_config: ps_io.clone(),
        };

        let segment_lister = StateEndhostSegmentLister::new(ps_state, state.local_ases.clone());
        let router = nest_endhost_api(
            axum::Router::new(),
            Arc::new(underlay_discovery),
            Arc::new(segment_lister),
        );

        // Setup Server
        let listen_addr = ps_io
            .endhost_api_addr(this_id)
            .unwrap_or(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0));
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("error binding tcp listener")?;

        let local_addr = listener
            .local_addr()
            .context("error getting local address of listen socket")?;

        // Update IoConfig
        ps_io.set_endhost_api_addr(this_id, local_addr);

        // Start
        tracing::info!(%local_addr, local_ases = ?state.local_ases, "Starting endhost API");
        axum::serve(
            listener,
            router.layer(info_trace_layer()).into_make_service(),
        )
        .await
        .context("error serving axum api")
    }
}

/// Underlay Discovery implementation for Endhost API
struct PsEndhostApiUnderlayDiscovery {
    id: EndhostApiId,
    system_state: SharedPocketScionState,
    io_config: SharedPocketScionIoConfig,
}
impl PsEndhostApiUnderlayDiscovery {
    // Extracts own state from pocket scion state
    fn own_state(&self) -> anyhow::Result<EndhostApiState> {
        self.system_state
            .endhost_api(self.id)
            .with_context(|| format!("missing state for endhost api with id {}", self.id))
    }
}
impl UnderlayDiscovery for PsEndhostApiUnderlayDiscovery {
    fn list_underlays(
        &self,
        request_as: scion_proto::address::IsdAsn,
    ) -> endhost_api_models::underlays::Underlays {
        let this = self.own_state().expect("endhost api must exist");

        if !(request_as.matches_any_in(&this.local_ases)) {
            // Request AS not local - can't list
            return Underlays {
                udp_underlay: vec![],
                snap_underlay: vec![],
            };
        }

        // Collect udp underlays
        let mut udp_underlay = Vec::new();
        let routers = self.system_state.routers();
        for (router_id, router) in routers {
            if !this.local_ases.contains(&router.isd_as) {
                // This underlay is not in the ASes this Endhost API knows
                continue;
            }

            if !(request_as.matches(router.isd_as)) {
                continue;
            }

            let internal_interface = match self.io_config.router_socket_addr(router_id) {
                Some(addr) => addr,
                None => {
                    tracing::error!(
                        router_id = %router_id,
                        "Router has no socket address set, cannot list in endhost API"
                    );
                    continue;
                }
            };

            udp_underlay.push(ScionRouter {
                isd_as: router.isd_as,
                internal_interface,
                interfaces: router.if_ids.iter().map(|intf| intf.get()).collect(),
            })
        }

        // Collect Snap underlays
        let mut snap_underlay = Vec::new();
        let snaps = self.system_state.snaps();
        for (snap_id, snap) in snaps {
            let snap_isd_ases = snap.isd_ases();

            if !this
                .local_ases
                .iter()
                .any(|local| snap_isd_ases.contains(local))
            {
                continue;
            }

            if !(request_as.matches_any_in(&snap_isd_ases)) {
                continue;
            }

            let address = match self.io_config.snap_control_addr(snap_id) {
                Some(addr) => addr,
                None => {
                    tracing::warn!(
                        snap_id = %snap_id,
                        "SNAP has no socket address set, cannot list in endhost API"
                    );
                    continue;
                }
            };

            snap_underlay.push(Snap {
                address: addr_to_http_url(address),
                isd_ases: snap_isd_ases.into_iter().collect(),
            });
        }

        Underlays {
            udp_underlay,
            snap_underlay,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZero, str::FromStr, time::SystemTime};

    use anyhow::Ok;

    use super::*;

    struct TestSetup {
        ias: (IsdAsn, IsdAsn, IsdAsn),
        snap_cp_addrs: (SocketAddr, SocketAddr, SocketAddr),
        snap_dp_addrs: (SocketAddr, SocketAddr, SocketAddr),
        router_addrs: (SocketAddr, SocketAddr, SocketAddr),

        disc_snaps: (Snap, Snap, Snap),
        disc_udp_underlays: (ScionRouter, ScionRouter),
    }

    fn addr(i: u16) -> SocketAddr {
        let mut sock: SocketAddr = "127.0.0.1:0".parse().unwrap();
        sock.set_port(i);
        sock
    }

    /// Prepares a system state with:
    /// - Three ASes (1-1, 1-2, 1-3)
    /// - Three Snaps with following ases:
    ///   1. (1-1)
    ///   2. (1-1, 1-2)
    ///   3. (1-3)
    ///
    /// - Two Routers with following ases:
    ///   1. (1-1)
    ///   2. (1-2)
    fn setup() -> anyhow::Result<(SharedPocketScionState, SharedPocketScionIoConfig, TestSetup)> {
        let mut state = SharedPocketScionState::new(SystemTime::now());
        let io = SharedPocketScionIoConfig::new();

        let ia1 = IsdAsn::from_str("1-1")?;
        let ia2 = IsdAsn::from_str("1-2")?;
        let ia3 = IsdAsn::from_str("1-3")?;

        let snap11 = addr(11);
        let snap12 = addr(12);
        let snap13 = addr(13);

        let ips = TestSetup {
            ias: (ia1, ia2, ia3),
            snap_cp_addrs: (snap11, snap12, snap13),
            snap_dp_addrs: (addr(21), addr(221), addr(23)),
            router_addrs: (addr(31), addr(32), addr(33)),

            disc_snaps: (
                Snap {
                    address: addr_to_http_url(snap11),
                    isd_ases: vec![ia1],
                },
                Snap {
                    address: addr_to_http_url(snap12),
                    isd_ases: vec![ia2],
                },
                Snap {
                    address: addr_to_http_url(snap13),
                    isd_ases: vec![ia3],
                },
            ),

            disc_udp_underlays: (
                ScionRouter {
                    isd_as: ia1,
                    internal_interface: addr(31),
                    interfaces: vec![1],
                },
                ScionRouter {
                    isd_as: ia2,
                    internal_interface: addr(32),
                    interfaces: vec![1],
                },
            ),
        };

        let snap0_id = state.add_snap(ia1)?;
        io.set_snap_control_addr(snap0_id, ips.snap_cp_addrs.0);
        io.set_snap_data_plane_addr(snap0_id, ips.snap_dp_addrs.0);

        let snap1_id = state.add_snap(ia2)?;
        io.set_snap_control_addr(snap1_id, ips.snap_cp_addrs.1);
        io.set_snap_data_plane_addr(snap1_id, ips.snap_dp_addrs.1);

        let snap2_id = state.add_snap(ia3)?;
        io.set_snap_control_addr(snap2_id, ips.snap_cp_addrs.2);
        io.set_snap_data_plane_addr(snap2_id, ips.snap_dp_addrs.2);

        let nz = NonZero::new(1).expect("Last time I checked 1 was not 0");

        let rid = state.add_router(ia1, vec![nz], vec![], BTreeMap::new());
        io.set_router_socket_addr(rid, ips.router_addrs.0);

        let rid = state.add_router(ia2, vec![nz], vec![], BTreeMap::new());
        io.set_router_socket_addr(rid, ips.router_addrs.1);

        Ok((state, io, ips))
    }

    // Sort Underlays to be able to compare them
    fn sort(mut res: Underlays) -> Underlays {
        res.snap_underlay.sort();
        for snap in &mut res.snap_underlay {
            snap.isd_ases.sort();
        }
        res.udp_underlay.sort();
        res
    }

    #[test]
    fn should_return_empty_if_non_local() {
        let (mut state, io, t) = setup().unwrap();

        // Discovery only in 1-1
        let service = PsEndhostApiUnderlayDiscovery {
            id: state.add_endhost_api(vec![t.ias.0]),
            system_state: state.clone(),
            io_config: io.clone(),
        };

        // Non Local - should return none
        let res = service.list_underlays(t.ias.1);
        assert!(res.snap_underlay.is_empty());
        assert!(res.udp_underlay.is_empty());
    }

    #[test]
    fn should_return_correct_in_every_as() {
        // Discovery only in 1-1
        {
            let (mut state, io, t) = setup().unwrap();

            let service = PsEndhostApiUnderlayDiscovery {
                id: state.add_endhost_api(vec![t.ias.0]),
                system_state: state.clone(),
                io_config: io.clone(),
            };

            let res = service.list_underlays(t.ias.0);
            let expected = Underlays {
                udp_underlay: vec![t.disc_udp_underlays.0],
                snap_underlay: vec![t.disc_snaps.0],
            };

            assert_eq!(sort(res), sort(expected));
        }

        // Discovery only in 1-2
        {
            let (mut state, io, t) = setup().unwrap();
            let service = PsEndhostApiUnderlayDiscovery {
                id: state.add_endhost_api(vec![t.ias.1]),
                system_state: state.clone(),
                io_config: io.clone(),
            };
            let res = service.list_underlays(t.ias.1);
            let expected = Underlays {
                udp_underlay: vec![t.disc_udp_underlays.1],
                snap_underlay: vec![t.disc_snaps.1],
            };

            assert_eq!(sort(res), sort(expected));
        }

        // Discovery only in 1-3
        {
            let (mut state, io, t) = setup().unwrap();
            let service = PsEndhostApiUnderlayDiscovery {
                id: state.add_endhost_api(vec![t.ias.2]),
                system_state: state.clone(),
                io_config: io.clone(),
            };
            let res = service.list_underlays(t.ias.2);
            let expected = Underlays {
                udp_underlay: vec![],
                snap_underlay: vec![t.disc_snaps.2],
            };

            assert_eq!(sort(res), sort(expected));
        }
    }

    #[test]
    fn should_return_correct_in_every_as_using_filtering() {
        // Discovery in all
        let (mut state, io, t) = setup().unwrap();
        let service = PsEndhostApiUnderlayDiscovery {
            id: state.add_endhost_api(vec![t.ias.0, t.ias.1, t.ias.2]),
            system_state: state.clone(),
            io_config: io.clone(),
        };

        {
            let (_, _, t) = setup().unwrap();

            let res = service.list_underlays(t.ias.0);
            let expected = Underlays {
                udp_underlay: vec![t.disc_udp_underlays.0],
                snap_underlay: vec![t.disc_snaps.0],
            };

            assert_eq!(sort(res), sort(expected));
        }

        // Discovery only in 1-2
        {
            let (_, _, t) = setup().unwrap();

            let res = service.list_underlays(t.ias.1);
            let expected = Underlays {
                udp_underlay: vec![t.disc_udp_underlays.1],
                snap_underlay: vec![t.disc_snaps.1],
            };

            assert_eq!(sort(res), sort(expected));
        }

        // Discovery only in 1-3
        {
            let (_, _, t) = setup().unwrap();

            let res = service.list_underlays(t.ias.2);
            let expected = Underlays {
                udp_underlay: vec![],
                snap_underlay: vec![t.disc_snaps.2],
            };

            assert_eq!(sort(res), sort(expected));
        }
    }
}
