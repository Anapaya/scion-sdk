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

use std::{collections::BTreeMap, sync::Arc};

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
    state::PocketScionState,
};

/// SCION Daemon service implementation through PocketScion
pub struct PsDaemonService {
    /// The local ISD-AS of the SCION Daemon instance.
    local_ia: scion_proto::address::IsdAsn,
    /// Shared state of the PocketScion application, used to fulfill requests.
    state: PocketScionState,
}

impl PsDaemonService {
    /// Creates a new PsDaemonService with the given local ISD-AS and shared state.
    pub async fn start(
        isd_asn: scion_proto::address::IsdAsn,
        state: PocketScionState,
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

        let paths = state_guard
            .segment_registry
            .paths(
                src.into(),
                dst.into(),
                chrono::Utc::now(),
                &state_guard.topology,
            )
            .map_err(|e| {
                tracing::error!("Error listing paths from {} to {}: {:?}", src, dst, e);
                CrpcError::new(
                    scion_sdk_axum_connect_rpc::error::CrpcErrorCode::Internal,
                    "failed to list paths".to_string(),
                )
            })?;

        return Ok(proto::PathsResponse {
            paths: paths.into_iter().map(|p| p.into_grpc()).collect(),
        });
    }

    /// Return information about an AS.
    async fn as_info(&self, req: proto::AsRequest) -> Result<proto::AsResponse, CrpcError> {
        let AsRequest { isd_as } = req;
        let isd_as = IsdAsn(isd_as);
        let state_guard = self.state.read();
        let topo = &state_guard.topology;

        let tas = topo.as_map.get(&isd_as).ok_or_else(|| {
            tracing::error!("AS {} not found in topology", isd_as);
            CrpcError::new(
                scion_sdk_axum_connect_rpc::error::CrpcErrorCode::NotFound,
                "AS not found".to_string(),
            )
        })?;

        /// The MTU is not currently stored in the topology, so we return a default value for now.
        const DEFAULT_MTU: u16 = 1500;

        Ok(proto::AsResponse {
            isd_as: isd_as.to_u64(),
            core: tas.is_core(),
            mtu: DEFAULT_MTU as u32,
        })
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct DaemonServiceState;

impl Default for DaemonServiceState {
    fn default() -> Self {
        Self
    }
}

impl DaemonServiceState {
    /// Creates a new DaemonServiceState with default values.
    pub fn new() -> Self {
        Self
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
