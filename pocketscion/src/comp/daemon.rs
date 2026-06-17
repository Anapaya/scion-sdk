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

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::{Context, bail};
use scion_proto::address::{IsdAsn, ServiceAddr};
use scion_protobuf::daemon::v1::{self as proto, AsRequest};
use scion_sdk_axum_connect_rpc::error::CrpcError;
use scion_sdk_quic_scion::quic::config::QuicConfig;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    comp::{daemon::model::DaemonService, sim_network_stack::NetSimStack},
    state::PocketScionState,
    util::{crpc::server::AxumH3Server, path_providers::MirroringPathProvider},
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
    pub fn start(
        isd_asn: scion_proto::address::IsdAsn,
        state: PocketScionState,
    ) -> anyhow::Result<Arc<PsDaemonService>> {
        let self_state;
        let cert_tmp_dir;
        let key_pair;
        {
            let guard = state.read();

            cert_tmp_dir = guard.cert_dir.clone();

            self_state = guard
                .daemon_services
                .get(&isd_asn)
                .with_context(|| format!("No DaemonServiceState found for local IA {}", isd_asn))?
                .clone();

            key_pair = guard
                .topology
                .trust_store
                .as_key_pair(&isd_asn)
                .with_context(|| {
                    format!(
                        "Failed to get key pair for ISD-AS {} from topology trust store",
                        isd_asn
                    )
                })?
                .clone();
        }

        let addr = self_state.virtual_addr();

        state
            .add_svc_mapping(isd_asn, ServiceAddr::DAEMON, "QUIC".to_string(), addr)
            .context("Failed to add service mapping for Daemon Service")?;

        let svc = Arc::new(PsDaemonService {
            local_ia: isd_asn,
            state: state.clone(),
        });

        let app = axum::Router::new();
        let app = api::nest_api(app, svc.clone());

        // Start the server
        let stack = NetSimStack::bind(state.clone(), isd_asn, addr.ip(), 100)?;
        let sock = stack
            .bind_udp(addr.port())?
            .into_path_aware(MirroringPathProvider::default());

        let server_key = cert_tmp_dir
            .get_or_create_key_file(&key_pair.key)
            .context("Failed to get or create key file")?;
        let server_cert = cert_tmp_dir
            .get_or_create_cert_file(&[key_pair.cert])
            .context("Failed to get or create cert file")?;

        let conf = QuicConfig {
            verify_peer: false,
            ..Default::default()
        };

        let mut quiche_conf = conf.to_quiche_config()?;
        quiche_conf.load_cert_chain_from_pem_file(server_cert.to_str().unwrap())?;
        quiche_conf.load_priv_key_from_pem_file(server_key.to_str().unwrap())?;

        tokio::task::spawn(async move {
            tracing::info!(%isd_asn, %addr, "Daemon service listening");
            match AxumH3Server::serve(Arc::new(sock), app, quiche_conf).await {
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
pub struct DaemonServiceState {
    /// The virtual address of the SCION Daemon service in the AS
    #[schema(value_type = String, example = "[fd3a:9b6c:1f20:0003::]:4000")]
    virtual_address: SocketAddr,
}

impl Default for DaemonServiceState {
    fn default() -> Self {
        Self {
            virtual_address: std::net::SocketAddr::from_str("[fd3a:9b6c:1f20:0003::]:4000")
                .expect("Failed to parse hardcoded Daemon IP address"),
        }
    }
}

impl DaemonServiceState {
    /// Creates a new DaemonServiceState with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the virtual address of the SCION Daemon service.
    pub fn set_virtual_addr(&mut self, virtual_address: SocketAddr) {
        self.virtual_address = virtual_address;
    }

    /// Returns the virtual address of the SCION Daemon service.
    pub fn virtual_addr(&self) -> SocketAddr {
        self.virtual_address
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
