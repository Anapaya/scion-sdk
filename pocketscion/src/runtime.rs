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
//! PocketSCION runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use jsonwebtoken::DecodingKey;
use scion_proto::{address::IsdAsn, packet::ScionPacketRaw};
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_utils::{
    io::{get_tmp_path, read_file, write_file},
    task_handler::{CancelTaskSet, InProcess},
};
use snap_control::server::identity_registry::IdentityRegistry;
use snap_dataplane::tunnel_gateway::{
    dispatcher::TunnelGatewayDispatcher, metrics::TunnelGatewayDispatcherMetrics,
    start_tunnel_gateway,
};
use thiserror::Error;
use tokio::{net::TcpListener, time::sleep};
use x25519_dalek::StaticSecret;

use crate::{
    addr_to_http_url,
    api::admin,
    authorization_server,
    dto::{self, SystemStateDto},
    endhost_api::{EndhostApiId, PsEndhostApi},
    io_config::{IoConfig, SharedPocketScionIoConfig},
    management_api,
    network::{
        local::receivers::router_socket::{RouterSocket, SharedRouterSocket},
        scion::routing::ScionNetworkTime,
    },
    state::{
        RouterId, SharedPocketScionState, SystemState,
        control_service::ControlService,
        endhost_api_discovery::{EndhostApiDiscoveryApiId, EndhostApiDiscoveryService},
        endhost_segment_lister::StateEndhostSegmentLister,
        external_as::ExternalAsService,
        simulation_dispatcher::{AsNetSimDispatcher, NetSimDispatcher},
        snap::{SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL, SnapId},
    },
};

/// Default management API port.
pub const DEFAULT_MGMT_PORT: u16 = 9000;

/// Builder for a PocketSCION runtime.
pub struct PocketScionRuntimeBuilder {
    system_state: PathOrObject<SystemState>,
    io_config: PathOrObject<IoConfig>,
    mgmt_listen_addr: Option<SocketAddr>,
    start_time: TimestampOrNow,
}

impl PocketScionRuntimeBuilder {
    /// Create a new PocketSCION runtime builder.
    pub fn new() -> Self {
        Self {
            system_state: PathOrObject::Unspecified,
            io_config: PathOrObject::Unspecified,
            mgmt_listen_addr: None,
            start_time: TimestampOrNow::Now,
        }
    }

    /// Expose PocketSCION's management API on `mgmt_listen_addr`.
    pub fn with_mgmt_listen_addr(mut self, mgmt_listen_addr: SocketAddr) -> Self {
        self.mgmt_listen_addr = Some(mgmt_listen_addr);
        self
    }

    /// Set PocketSCION's initial IO-configuration to `io_config`.
    pub fn with_io_config(mut self, io_config: IoConfig) -> Self {
        self.io_config = PathOrObject::Object(io_config);
        self
    }

    /// Load PocketSCION's initial IO-configuration from `path`.
    pub fn with_io_config_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.io_config = PathOrObject::Path(path.as_ref().into());
        self
    }

    /// Set PocketSCION's initial system state to `system_state`.
    pub fn with_system_state(mut self, system_state: SystemState) -> Self {
        self.system_state = PathOrObject::Object(system_state);
        self
    }

    /// Load PocketSCION's initial system state from `path`.
    pub fn with_system_state_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.system_state = PathOrObject::Path(path.as_ref().into());
        self
    }

    /// Set the start time of PocketSCION to `time`. If `with_start_time` is _not_ called, the
    /// current system time is used when [Self::start] is called.
    pub fn with_start_time(mut self, time: SystemTime) -> Self {
        self.start_time = TimestampOrNow::Timestamp(time);
        self
    }

    /// Start the PocketSCION runtime.
    pub async fn start(self) -> Result<PocketScionRuntime, PocketScionRuntimeError> {
        self.start_with_task_set(CancelTaskSet::new()).await
    }

    /// Create an instance of a PocketSCION.
    pub async fn start_with_task_set(
        self,
        mut task_set: CancelTaskSet,
    ) -> Result<PocketScionRuntime, PocketScionRuntimeError> {
        let ready_state = Arc::new(AtomicBool::new(false));
        let start_time = match self.start_time {
            TimestampOrNow::Now => SystemTime::now(),
            TimestampOrNow::Timestamp(system_time) => system_time,
        };
        let system_state = self.system_state.load(start_time).await?;
        let root_secret = system_state.root_secret();
        let pstate = SharedPocketScionState::from_system_state(system_state);

        let io_config = self.io_config.load().await?;
        let io_config = SharedPocketScionIoConfig::from_state(io_config);

        let snap_token_decoding_key =
            DecodingKey::from_ed_pem(pem::encode(&pstate.snap_token_public_key()).as_bytes())
                .unwrap();
        let snap_token_verifier =
            snap_control::server::SnapTokenVerifier::new(snap_token_decoding_key);

        let mut snap_authz_map: BTreeMap<SnapId, Arc<IdentityRegistry>> = Default::default();

        // Start Control plane API for each SNAP
        for (snap_id, snap_state) in pstate.snaps() {
            let token = task_set.cancellation_token();

            let listener = match io_config.snap_control_addr(snap_id) {
                Some(addr) => {
                    TcpListener::bind(&addr).await.map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("Failed to bind to SNAP CP addr {addr}: {e}"),
                        )
                    })?
                }
                None => {
                    tracing::debug!(snap=%snap_id, "No control plane API port for SNAP specified");
                    let listener =
                        TcpListener::bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
                    io_config.set_snap_control_addr(snap_id, listener.local_addr()?);
                    listener
                }
            };

            let dp_discovery = pstate.snap_data_plane_discovery(snap_id, io_config.clone());
            let snap_resolver = pstate.snap_resolver(snap_id, io_config.clone());
            let identity_registry = Arc::new(IdentityRegistry::new());
            let token_verifier = snap_token_verifier.clone();

            let local_ases = snap_state.isd_ases();

            let segment_lister =
                StateEndhostSegmentLister::new(pstate.clone(), local_ases.into_iter().collect());

            task_set.join_set.spawn({
                let identity_registry = identity_registry.clone();
                async move {
                    snap_control::server::start(
                        token,
                        listener,
                        dp_discovery,
                        segment_lister,
                        snap_resolver,
                        identity_registry,
                        token_verifier,
                        snap_control::server::metrics::Metrics::new(&MetricsRegistry::new()),
                    )
                    .await
                }
            });
            snap_authz_map.insert(snap_id, identity_registry);
        }

        for (id, _) in pstate.endhost_apis() {
            let pstate = pstate.clone();
            let io_config = io_config.clone();
            task_set.join_set.spawn(async move {
                PsEndhostApi::start(id, pstate, io_config)
                    .await
                    .map_err(|e| io::Error::other(format!("{e:?}")))
            });
        }

        // General setup

        // Only one snap per ISD-AS is allowed.
        let mut seen_ases = BTreeSet::new();
        for (_, snap_state) in pstate.snaps() {
            // Only allow one snap per ISD-AS.
            for isd_as in snap_state.isd_ases() {
                if seen_ases.contains(&isd_as) {
                    return Err(PocketScionRuntimeError::StartupError(
                        "Only one snap per ISD-AS is allowed".to_string(),
                    ));
                }
                seen_ases.insert(isd_as);
            }
        }
        // Do not allow any AS to have both routers and SNAPs configured.
        for (_, router) in pstate.routers() {
            if seen_ases.contains(&router.isd_as) {
                return Err(PocketScionRuntimeError::StartupError(
                    "Only one router per ISD-AS is allowed".to_string(),
                ));
            }
        }

        for (snap_id, snap) in pstate.snaps() {
            let metrics_registry = MetricsRegistry::new();
            let key = root_secret.derive_from_iter(vec![
                SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL.into(),
                snap_id.to_string().into(),
            ]);
            let static_secret = StaticSecret::from(key.as_array());

            let socket = match io_config.snap_data_plane_addr(snap_id) {
                Some(addr) => tokio::net::UdpSocket::bind(addr).await?,
                None => {
                    tracing::debug!(%snap_id, "No listen address specified for SNAP dataplane");
                    let udp_socket =
                        tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                            .await?;
                    io_config.set_snap_data_plane_addr(snap_id, udp_socket.local_addr()?);
                    udp_socket
                }
            };

            let addr = socket.local_addr()?;

            let tun_gw_metrics = TunnelGatewayDispatcherMetrics::new(&metrics_registry);
            let (tunnel_gw_dispatcher, tun_dispatcher_rx) =
                TunnelGatewayDispatcher::new(tun_gw_metrics);

            // XXX(scionstack-v2): If a SNAP is configured, then it is registered as wildcard
            // sim_receiver and all traffic is forwarded to the SNAP.
            let tunnel_gw_dispatcher = Arc::new(tunnel_gw_dispatcher);
            for isd_as in snap.isd_ases() {
                pstate
                    .add_wildcard_sim_receiver(isd_as, tunnel_gw_dispatcher.clone())
                    .expect("Failed to add wildcard receiver");
            }
            let authz = snap_authz_map
                .remove(&snap_id)
                .expect("no authz found for snap");

            tracing::info!(%addr, %snap_id, "Starting snap dataplane");
            start_tunnel_gateway(
                &mut task_set,
                socket,
                authz,
                Arc::new(NetSimDispatcher::new(pstate.clone())),
                tun_dispatcher_rx,
                static_secret,
            );
        }

        // Start Endhost Discovery APIs
        for (id, _) in pstate.endhost_api_discovery_apis() {
            let pstate = pstate.clone();
            let io_config = io_config.clone();
            EndhostApiDiscoveryService::start(id, pstate, io_config)
                .await
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
        }

        // Start External AS adapters
        for (isd_as, _state) in pstate.external_ases() {
            let pstate = pstate.clone();
            let io_config = io_config.clone();
            let ext_as = ExternalAsService::start(isd_as, pstate.clone(), io_config.clone())
                .await
                .map_err(|e| io::Error::other(format!("{e:?}")))?;

            // Add the the handler to the simulation
            pstate
                .register_external_as_handler(isd_as, ext_as)
                .map_err(|e| {
                    io::Error::other(format!(
                        "Failed to register external AS handler for AS {isd_as}: {e:?}"
                    ))
                })?;
        }

        // Control Services
        for (isd_as, _) in pstate.get_control_services() {
            let pstate = pstate.clone();
            task_set.join_set.spawn(async move {
                match ControlService::start(isd_as, pstate) {
                    Ok(_) => {
                        tracing::info!(isd_as = %isd_as, "Control Service started");
                        Ok(())
                    },
                    Err(e) => {
                        tracing::error!(isd_as = %isd_as, error = ?e, "Failed to start Control Service");
                        Err(io::Error::other(format!("Failed to start Control Service for AS {isd_as}: {e:?}")))
                    }
                }
            });
        }

        // Start router sockets
        for sock_id in pstate.router_ids() {
            let udp_socket = {
                let bind_addr = match io_config.router_socket_addr(sock_id) {
                    Some(addr) => addr,
                    None => {
                        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                        io_config.set_router_socket_addr(sock_id, bind_addr);
                        bind_addr
                    }
                };
                let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
                io_config.set_router_socket_addr(sock_id, socket.local_addr()?);
                socket
            };

            let router_state = pstate
                .router(sock_id)
                .expect("We iterate over existing routers, Router should exist");

            let router_dispatcher = AsNetSimDispatcher::new(router_state.isd_as, pstate.clone());
            let router_socket = RouterSocket::new(
                udp_socket,
                router_state.snap_data_plane_interfaces,
                router_state.snap_data_plane_excludes,
                Arc::new(router_dispatcher),
            )
            .await?;
            let router_socket = SharedRouterSocket::new(router_socket);

            pstate
                .add_wildcard_sim_receiver(router_state.isd_as, Arc::new(router_socket.clone()))
                .expect("Failed to add wildcard receiver");

            task_set.spawn_cancellable_task(async move { router_socket.run().await });
        }

        ready_state.store(true, std::sync::atomic::Ordering::Relaxed);

        // Only start the mgmt API when everything else is ready.
        let mgmt_listen_addr = {
            let ready_state_clone = ready_state.clone();
            let token = task_set.cancellation_token();
            let system_state = pstate.clone();
            let io_config = io_config.clone();

            let listener = TcpListener::bind(
                self.mgmt_listen_addr
                    .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_MGMT_PORT))),
            )
            .await?;
            let listen_address = listener.local_addr()?;

            tracing::info!(addr=%listen_address, "Starting management API");

            task_set.join_set.spawn(async move {
                management_api::start(token, ready_state_clone, system_state, io_config, listener)
                    .await
            });
            io::Result::Ok(listen_address)
        }?;

        if pstate.has_auth_server() {
            let auth_server = pstate.auth_server();

            let io_config = io_config.clone();
            let token = task_set.cancellation_token();
            task_set.join_set.spawn(async move {
                authorization_server::api::start(token, auth_server, io_config).await
            });
        }
        let client = admin::client::ApiClient::new(&addr_to_http_url(mgmt_listen_addr))
            .expect("create client");

        Ok(PocketScionRuntime {
            handle: InProcess::new(task_set),
            state: pstate,
            io_config,
            client,
        })
    }
}

impl Default for PocketScionRuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory PocketSCION runtime.
pub struct PocketScionRuntime {
    handle: InProcess,
    // TODO(ake): all api functions should be replaced with direct function calls and the client
    // should be removed.
    state: SharedPocketScionState,
    io_config: SharedPocketScionIoConfig,
    // Eventually, the in-memory representation should use direct function calls
    // and not go through the http-interface.
    client: admin::client::ApiClient,
}

impl PocketScionRuntime {
    /// Returns the socket address of given endhost api, if it exists.
    pub fn endhost_api_addr(&self, id: EndhostApiId) -> Option<SocketAddr> {
        self.state
            .endhost_api(id)
            .and_then(|_| self.io_config.endhost_api_addr(id))
    }

    /// Returns the socket address of given endhost api discovery api, if it exists.
    pub fn endhost_api_discovery_addr(&self, id: EndhostApiDiscoveryApiId) -> Option<SocketAddr> {
        self.state
            .endhost_api_discovery_api(id)
            .and_then(|_| self.io_config.endhost_api_discovery_api_addr(id))
    }

    /// Returns the socket address of the interface with the given id of the external AS, if it
    /// exists.
    pub fn external_as_interface_addr(&self, ia: IsdAsn, interface_id: u16) -> Option<SocketAddr> {
        self.state
            .external_as(ia)
            .and_then(|_| self.io_config.external_as_interface_addr(ia, interface_id))
    }

    /// Returns the socket address of the control plane API of the snap with the given id, if it
    /// exists.
    pub fn snap_control_addr(&self, snap_id: SnapId) -> Option<SocketAddr> {
        self.state
            .snap(snap_id)
            .and_then(|_| self.io_config.snap_control_addr(snap_id))
    }

    /// Returns the socket address of the data plane API of the snap with the given id, if it
    /// exists.
    pub fn snap_data_plane_addr(&self, snap_id: SnapId) -> Option<SocketAddr> {
        self.state
            .snap(snap_id)
            .and_then(|_| self.io_config.snap_data_plane_addr(snap_id))
    }

    /// Returns the socket address of the router with the given id, if it exists.
    pub fn router_socket_addr(&self, router_id: RouterId) -> Option<SocketAddr> {
        self.state
            .router(router_id)
            .and_then(|_| self.io_config.router_socket_addr(router_id))
    }

    /// Returns a handle to the shared state of the PocketSCION runtime.
    pub fn state(&self) -> SharedPocketScionState {
        self.state.clone()
    }
}
impl PocketScionRuntime {
    /// Dispatches a packet through PocketScions Network simulation.
    ///
    /// ## Parameters
    /// - `local_as`: The ISD-AS the packet starts processing
    /// - `local_interface`: Interface where the packet starts processing. 0 means packet originated
    ///   in the AS.
    /// - `now`: The timestamp to dispatch the packet at.
    /// - `packet`: The raw SCION packet to dispatch.
    pub fn dispatch_packet(
        &self,
        local_as: IsdAsn,
        local_interface: u16,
        now: ScionNetworkTime,
        packet: ScionPacketRaw,
    ) {
        self.state
            .dispatch_to_network_sim(local_as, local_interface, now, packet);
    }
}

const MAX_ATTEMPTS: i32 = 5;
const ATTEMPT_WAIT: Duration = Duration::from_millis(200);

/// PocketSCION runtime error.
#[derive(Error, Debug)]
pub enum PocketScionRuntimeError {
    /// PocketSCION admin API client error.
    #[error("client error: {0:?}")]
    ClientError(#[from] admin::client::ClientError),
    /// PocketSCION not ready.
    #[error("pocket-scion not ready: {0}")]
    PocketScionNotReady(String),
    /// I/O error.
    #[error("i/o error {0}")]
    IoError(#[from] std::io::Error),
    /// Startup error.
    #[error("startup error: {0}")]
    StartupError(String),
}

impl PocketScionRuntime {
    /// Stop and join all the tasks. This is primarily intended to be used in tests.
    pub async fn stop_and_join(&mut self) {
        self.handle.task_set.cancellation_token().cancel();
        self.join().await;
    }

    /// Join all tasks.
    pub async fn join(&mut self) {
        self.handle.task_set.join_all().await;
    }

    /// Wait until PocketSCION is ready.
    pub async fn wait_for_ready(&self) -> Result<(), PocketScionRuntimeError> {
        let mut err = PocketScionRuntimeError::PocketScionNotReady("Unknown state".to_string());
        for _ in 1..=MAX_ATTEMPTS {
            err = match self.client.get_status().await {
                Ok(status) => {
                    if status.state == admin::api::ReadyState::Ready {
                        return Ok(());
                    }
                    PocketScionRuntimeError::PocketScionNotReady(format!("{status:?}"))
                }
                Err(e) => PocketScionRuntimeError::ClientError(e),
            };

            tracing::debug!("Waiting for Pocket SCION to be ready: {:?}", err);
            sleep(ATTEMPT_WAIT).await;
        }
        Err(err)
    }

    /// Returns an API client connected to the management API of PocketSCION.
    pub fn api_client(&self) -> admin::client::ApiClient {
        self.client.clone()
    }
}

#[derive(Debug, Default)]
pub(crate) enum PathOrObject<T> {
    #[default]
    Unspecified,
    Path(PathBuf),
    Object(T),
}

impl PathOrObject<SystemState> {
    /// # Panics
    ///
    /// This method panics in case of i/o-errors. We deem this acceptable as it
    /// is primarily used in testing.
    #[allow(unused)]
    pub(crate) async fn sync_to_file(self) -> anyhow::Result<Option<PathBuf>> {
        let state = match self {
            PathOrObject::Unspecified => return Ok(None),
            PathOrObject::Path(path_buf) => return Ok(Some(path_buf)),
            PathOrObject::Object(s) => s,
        };
        let path = get_tmp_path("system_state.json");
        let dto: SystemStateDto = (&state).into();
        write_file(path.clone(), &dto)
            .await
            .context("failed to write system state")?;

        Ok(Some(path))
    }

    pub(crate) async fn load(self, start_time: SystemTime) -> Result<SystemState, std::io::Error> {
        match self {
            PathOrObject::Unspecified => Ok(SystemState::default_from_start_time(start_time)),
            PathOrObject::Path(path_buf) => {
                let dto: dto::SystemStateDto = read_file(path_buf).await?;
                SystemState::try_from(dto).map_err(io::Error::other)
            }
            PathOrObject::Object(t) => Ok(t),
        }
    }
}

impl PathOrObject<IoConfig> {
    /// # Panics
    ///
    /// This method panics in case of i/o-errors. We deem this acceptable as it
    /// is primarily used in testing.
    #[allow(unused)]
    pub(crate) async fn sync_to_file(self) -> Option<PathBuf> {
        let state = match self {
            PathOrObject::Unspecified => return None,
            PathOrObject::Path(path_buf) => return Some(path_buf),
            PathOrObject::Object(s) => s,
        };
        let path = get_tmp_path("io_config.json");
        let dto = crate::dto::IoConfigDto::from(&state);
        write_file(path.clone(), &dto).await.expect("failed");
        Some(path)
    }

    pub(crate) async fn load(self) -> Result<IoConfig, std::io::Error> {
        match self {
            PathOrObject::Unspecified => Ok(IoConfig::default()),
            PathOrObject::Path(path_buf) => {
                let dto: dto::IoConfigDto = read_file(path_buf).await?;
                IoConfig::try_from(dto).map_err(io::Error::other)
            }
            PathOrObject::Object(t) => Ok(t),
        }
    }
}

impl PathOrObject<IoConfig> {
    #[allow(unused)]
    pub(crate) async fn write_to_temp_file(&self) -> PathBuf {
        todo!()
    }
}

#[derive(Debug, Clone)]
enum TimestampOrNow {
    Now,
    Timestamp(SystemTime),
}
