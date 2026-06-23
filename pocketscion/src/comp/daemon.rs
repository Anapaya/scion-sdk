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

//! SCION Daemon service.

pub mod api;
pub mod model;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use anyhow::{Context, bail};
use scion_proto::address::IsdAsn;
use scion_protobuf::daemon::v1::{
    self as proto, AsRequest, daemon_service_server::DaemonServiceServer,
};
use scion_sdk_axum_connect_rpc::error::CrpcError;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tonic::service::Routes;
use utoipa::ToSchema;

use crate::{
    comp::daemon::{api::grpc::DaemonGrpcApi, model::DaemonService},
    io_config::IoConfig,
    state::PocketScionState,
};

/// SCION Daemon service implementation through PocketScion
pub struct PsDaemonService {
    /// The local ISD-AS of the SCION Daemon instance.
    local_ia: scion_proto::address::IsdAsn,
    /// Shared state of the PocketScion application, used to fulfill requests.
    state: PocketScionState,
    /// IO configuration, used to determine the underlay next hop for paths if no override is set.
    io_config: IoConfig,
}
impl PsDaemonService {
    /// Creates a new PsDaemonService with the given local ISD-AS and shared state.
    pub async fn start(
        isd_asn: scion_proto::address::IsdAsn,
        state: PocketScionState,
        io_config: IoConfig,
        socket: TcpListener,
    ) -> anyhow::Result<Arc<PsDaemonService>> {
        {
            let guard = state.read();

            guard
                .daemon_services
                .get(&isd_asn)
                .with_context(|| format!("No DaemonServiceState found for local IA {}", isd_asn))?;
        }

        let svc = Arc::new(PsDaemonService {
            local_ia: isd_asn,
            state: state.clone(),
            io_config,
        });

        let grpc_api = DaemonGrpcApi::new(svc.clone());

        let grpc_router = Routes::new(DaemonServiceServer::new(grpc_api)).into_axum_router();
        let app = axum::Router::new().merge(grpc_router);

        // Start the server

        let addr = socket
            .local_addr()
            .context("Failed to get local address of TCP listener")?;
        let listener = socket
            .into_std()
            .context("Failed to convert TCP listener to std")?;

        // SCION Daemon uses plaintext HTTP/2
        let server =
            axum_server::from_tcp(listener).context("Failed to create server from TCP listener")?;

        tokio::task::spawn(async move {
            tracing::info!(%isd_asn, %addr, "Daemon service listening");
            match server.serve(app.into_make_service()).await {
                Ok(_) => tracing::info!("Daemon service stopped gracefully"),
                Err(e) => tracing::error!("Daemon service stopped with error: {:?}", e),
            }
        });

        Ok(svc)
    }
}

#[async_trait::async_trait]
impl DaemonService for PsDaemonService {
    /// Return a set of paths to the requested destination.
    async fn paths(&self, _req: proto::PathsRequest) -> Result<proto::PathsResponse, CrpcError> {
        let proto::PathsRequest {
            destination_isd_as: dst,
            source_isd_as: src,
            .. // ignore unsupported fields for now
        } = _req;

        let state_guard = self.state.read();

        let self_state = state_guard
            .daemon_services
            .get(&self.local_ia)
            .expect("DaemonServiceState for local IA is must exist");

        let src = match IsdAsn(src) {
            IsdAsn::WILDCARD => self.local_ia,
            ia => ia,
        };

        if src != self.local_ia {
            return Err(CrpcError::new(
                scion_sdk_axum_connect_rpc::error::CrpcErrorCode::InvalidArgument,
                "source ISD-AS does not match local ISD-AS".to_string(),
            ));
        }

        let mut paths = state_guard
            .segment_registry
            .paths(src, dst.into(), chrono::Utc::now(), &state_guard.topology)
            .map_err(|e| {
                tracing::error!("Error listing paths from {} to {}: {:?}", src, dst, e);
                CrpcError::new(
                    scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Internal,
                    "failed to list paths".to_string(),
                )
            })?;

        match self_state.override_path_underlay_next_hop {
            Some(next_hop) => {
                for path in &mut paths {
                    path.underlay_next_hop = Some(next_hop);
                }
            }
            None => {
                // Get all local routers and their interfaces to determine the underlay next hop for
                // each path
                let mut interfaces: Vec<(Vec<u16>, SocketAddr)> = vec![];

                // Fallback to any router if none match
                let mut fallback = None;

                for (router_id, router) in state_guard
                    .routers
                    .iter()
                    .filter(|(_, r)| r.isd_as == self.local_ia)
                {
                    let socket_addr = self.io_config.router_socket_addr(*router_id);

                    // Skip routers that don't have a socket address configured
                    let Some(socket_addr) = socket_addr else {
                        continue;
                    };

                    let if_ids = router.if_ids.iter().map(|intf| (*intf).into()).collect();

                    if fallback.is_none() {
                        fallback = Some(socket_addr);
                    }

                    interfaces.push((if_ids, socket_addr));
                }

                for path in &mut paths {
                    match path.first_hop_egress_interface() {
                        None => {
                            path.underlay_next_hop = fallback;
                            continue;
                        }
                        Some(intf) => {
                            // try to find a matching interface in the local AS
                            for (if_ids, socket_addr) in &interfaces {
                                if if_ids.contains(&intf.id) {
                                    path.underlay_next_hop = Some(*socket_addr);
                                    break;
                                }
                            }

                            // if none of the interfaces matched, use the fallback
                            if path.underlay_next_hop.is_none() {
                                path.underlay_next_hop = fallback;
                            }
                        }
                    }
                }
            }
        }

        let paths = paths.into_iter().map(|p| p.into_grpc()).collect();
        return Ok(proto::PathsResponse { paths });
    }

    /// Return information about an AS.
    async fn as_info(&self, req: proto::AsRequest) -> Result<proto::AsResponse, CrpcError> {
        let AsRequest { isd_as } = req;
        let state_guard = self.state.read();
        let topo = &state_guard.topology;

        let isd_as = match IsdAsn(isd_as) {
            IsdAsn::WILDCARD => self.local_ia,
            ia => ia,
        };

        let tas = topo.as_map.get(&isd_as).ok_or_else(|| {
            tracing::error!("AS {} not found in topology", isd_as);
            CrpcError::new(
                scion_sdk_axum_connect_rpc::error::CrpcErrorCode::NotFound,
                "AS not found".to_string(),
            )
        })?;

        /// The MTU is not currently stored in the topology, so we return a default value for now.
        const DEFAULT_MTU: u16 = 1500;

        let res = proto::AsResponse {
            isd_as: isd_as.to_u64(),
            core: tas.is_core(),
            mtu: DEFAULT_MTU as u32,
        };

        Ok(res)
    }

    /// Return the underlay addresses associated with the specified interfaces.
    async fn interfaces(
        &self,
        _req: proto::InterfacesRequest,
    ) -> Result<proto::InterfacesResponse, CrpcError> {
        let state_guard = self.state.read();
        let topo = &state_guard.topology;
        // Collect all Interfaces
        let interfaces = topo.iter_scion_links_by_as(&self.local_ia).map(|link| {
            link.get_directed_from(&self.local_ia)
                .expect("local_ia is guaranteed to be part of the link")
                .from
                .if_id
        });

        let underlays = interfaces
            .map(|if_id| (if_id, topo.get_router(&self.local_ia, if_id).address))
            .map(|(if_id, ip)| {
                (
                    if_id as u64,
                    proto::Interface {
                        address: Some(proto::Underlay {
                            address: ip.to_string(),
                        }),
                    },
                )
            })
            .collect();

        Ok(proto::InterfacesResponse {
            interfaces: underlays,
        })
    }

    /// Return the underlay addresses associated with the specified services.
    async fn services(
        &self,
        _req: proto::ServicesRequest,
    ) -> Result<proto::ServicesResponse, CrpcError> {
        Err(CrpcError::new(
            scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unimplemented,
            "not implemented".to_string(),
        ))
    }

    /// Inform the SCION Daemon of a revocation.
    async fn notify_interface_down(
        &self,
        _req: proto::NotifyInterfaceDownRequest,
    ) -> Result<proto::NotifyInterfaceDownResponse, CrpcError> {
        // XXX(ake): Just return success for now
        Ok(proto::NotifyInterfaceDownResponse {})
    }

    /// Returns the endhost port range defined in the local AS.
    ///
    /// Related to: <https://docs.scion.org/en/latest/protocols/underlay.html#ports-overview>
    ///
    /// We are forwarding all UDP ports to the Endhost, so we return the full range of ports here.
    async fn port_range(&self) -> Result<proto::PortRangeResponse, CrpcError> {
        return Ok(proto::PortRangeResponse {
            dispatched_port_start: 1,
            dispatched_port_end: 65535,
        });
    }

    /// DRKeyASHost returns a key that matches the request.
    async fn dr_key_as_host(
        &self,
        _req: proto::DrKeyAsHostRequest,
    ) -> Result<proto::DrKeyAsHostResponse, CrpcError> {
        Err(CrpcError::new(
            scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unimplemented,
            "not implemented".to_string(),
        ))
    }

    /// DRKeyHostAS returns a key that matches the request.
    async fn dr_key_host_as(
        &self,
        _req: proto::DrKeyHostAsRequest,
    ) -> Result<proto::DrKeyHostAsResponse, CrpcError> {
        Err(CrpcError::new(
            scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unimplemented,
            "not implemented".to_string(),
        ))
    }

    /// DRKeyHostHost returns a key that matches the request.
    async fn dr_key_host_host(
        &self,
        _req: proto::DrKeyHostHostRequest,
    ) -> Result<proto::DrKeyHostHostResponse, CrpcError> {
        Err(CrpcError::new(
            scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Unimplemented,
            "not implemented".to_string(),
        ))
    }
}

/// State of the SCION Daemon service, stored in the shared PocketScion state.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct DaemonServiceState {
    /// This overrides the `next_hop`/`interface` fields in the paths returned by the Daemon
    /// service.
    ///
    /// Without this override the `interface` field will be set to an existing `router` interface
    /// of the local AS. If no router interface exists, and no override is set, the `interface`
    /// field will be empty.
    #[schema(value_type = String, example = "127.0.0.1:8080")]
    override_path_underlay_next_hop: Option<SocketAddr>,
}
impl DaemonServiceState {
    /// Creates a new DaemonServiceState with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables overriding the `next_hop`/`interface` fields in the paths returned by the Daemon
    /// service.
    ///
    /// Without this override the `interface` field will be set to an existing `router` interface of
    /// the local AS. If no router interface exists, and no override is set, the `interface`
    /// field will be empty.
    pub fn set_override_path_underlay_next_hop(&mut self, next_hop: SocketAddr) {
        self.override_path_underlay_next_hop = Some(next_hop);
    }
}

impl PocketScionState {
    /// Adds a new DaemonServiceState for the given local ISD-AS to the shared state.
    pub fn add_daemon_service(
        &self,
        local_ia: IsdAsn,
        daemon_service_state: DaemonServiceState,
    ) -> anyhow::Result<()> {
        let mut guard = self.write();

        match guard.daemon_services.entry(local_ia) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(daemon_service_state);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                bail!("DaemonServiceState for ISD-AS {local_ia} already exists");
            }
        };

        Ok(())
    }

    /// Returns a copy of the DaemonServiceState map from the shared state.
    pub fn daemon_services(&self) -> BTreeMap<IsdAsn, DaemonServiceState> {
        self.read().daemon_services.clone()
    }
}
