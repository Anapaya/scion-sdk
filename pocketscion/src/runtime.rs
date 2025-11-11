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
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use jsonwebtoken::DecodingKey;
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_token_validator::validator::Validator;
use scion_sdk_utils::{
    io::{get_tmp_path, read_file, write_file},
    task_handler::{CancelTaskSet, InProcess},
};
use snap_dataplane::{
    session::state::insecure_const_session_key_pair,
    state::Id,
    tunnel_gateway::{
        dispatcher::TunnelGatewayDispatcher, metrics::TunnelGatewayDispatcherMetrics,
        start_tunnel_gateway, state::SharedTunnelGatewayState,
    },
};
use thiserror::Error;
use tokio::{net::TcpListener, time::sleep};

use crate::{
    addr_to_http_url,
    api::admin,
    authorization_server,
    dto::{self},
    endhost_api::PsEndhostApi,
    io_config::{IoConfig, SharedPocketScionIoConfig},
    management_api,
    network::local::receivers::{
        router_socket::{RouterSocket, SharedRouterSocket},
        tunnel_gateway::TunnelGatewayReceiver,
    },
    state::{
        SharedPocketScionState, SystemState, TunnelGatewayStates,
        address_allocator::StateSnapAddressAllocator,
        endhost_segment_lister::StateEndhostSegmentLister,
        simulation_dispatcher::{AsNetSimDispatcher, NetSimDispatcher},
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
        let pstate = SharedPocketScionState::from_system_state(system_state);
        let mut tunnel_gateway_states = TunnelGatewayStates::default();

        let io_config = self.io_config.load().await?;
        let io_config = SharedPocketScionIoConfig::from_state(io_config);

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
            let session_manager = pstate.snap_session_manager(snap_id, io_config.clone());
            let decoding_key =
                DecodingKey::from_ed_pem(pem::encode(&pstate.snap_token_public_key()).as_bytes())
                    .unwrap();

            let local_ases = snap_state.isd_ases();

            let segment_lister = StateEndhostSegmentLister::new(pstate.clone(), local_ases);

            task_set.join_set.spawn(async move {
                snap_control::server::start(
                    token,
                    listener,
                    dp_discovery,
                    session_manager,
                    segment_lister,
                    decoding_key,
                    snap_control::server::metrics::Metrics::new(&MetricsRegistry::new()),
                )
                .await
            });
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

        for snap_id in pstate.snaps_ids() {
            let (_, session_decoding_key) = insecure_const_session_key_pair(snap_id.as_usize());
            let validator = Arc::new(Validator::new(session_decoding_key, None));

            // Start TunnelGateway for each SNAP data plane
            for snap_dp_id in pstate.snap_data_planes(snap_id) {
                let address_allocator =
                    Arc::new(StateSnapAddressAllocator::new(pstate.clone(), snap_dp_id));

                let metrics_registry = MetricsRegistry::new();

                let (_cert_der, server_config) = scion_sdk_utils::test::generate_cert(
                    [42u8; 32],
                    vec!["localhost".into()],
                    vec![b"snaptun".to_vec()],
                );

                // tunnel gateway server quinn endpoint
                let server_endpoint = match io_config.snap_data_plane_addr(snap_dp_id) {
                    Some(addr) => quinn::Endpoint::server(server_config, addr)?,
                    None => {
                        tracing::debug!(data_plane_id=%snap_dp_id, "No listen address specified for SNAP data plane");
                        let server_endpoint = quinn::Endpoint::server(
                            server_config,
                            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                        )?;
                        io_config
                            .set_snap_data_plane_addr(snap_dp_id, server_endpoint.local_addr()?);
                        server_endpoint
                    }
                };

                let shared_tunnel_gw_state = SharedTunnelGatewayState::new();
                tunnel_gateway_states
                    .entry(snap_id)
                    .or_default()
                    .insert(snap_dp_id, shared_tunnel_gw_state.clone());
                let tunnel_gw_dispatcher = TunnelGatewayDispatcher::new(
                    shared_tunnel_gw_state.clone(),
                    TunnelGatewayDispatcherMetrics::new(&metrics_registry),
                );

                task_set.spawn_cancellable_task({
                    let dispatcher = tunnel_gw_dispatcher.clone();
                    async move { dispatcher.start_dispatching().await }
                });

                let registrations = pstate
                    .snap_data_plane_prefixes(snap_dp_id)
                    .expect("Data plane registrations should exist");

                // Register the tunnel gateway dispatcher for each prefix
                for (ias, ipnets) in registrations {
                    for ipnet in ipnets {
                        pstate
                            .add_sim_receiver(
                                ias,
                                ipnet,
                                Arc::new(TunnelGatewayReceiver::new(tunnel_gw_dispatcher.clone())),
                            )
                            .expect("Failed to add dispatcher");
                    }
                }

                start_tunnel_gateway(
                    &mut task_set,
                    shared_tunnel_gw_state,
                    address_allocator,
                    validator.clone(),
                    server_endpoint,
                    Arc::new(NetSimDispatcher::new(pstate.clone())),
                    metrics_registry,
                );
            }
        }

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

            let ias = pstate
                .router_ias(sock_id)
                .expect("We iterate through existing routers, should exist");

            let router_dispatcher = AsNetSimDispatcher::new(ias, pstate.clone());
            let router_socket = RouterSocket::new(udp_socket, Arc::new(router_dispatcher)).await?;
            let router_socket = SharedRouterSocket::new(router_socket);

            pstate
                .add_wildcard_sim_receiver(ias, Arc::new(router_socket.clone()))
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
                management_api::start(
                    token,
                    ready_state_clone,
                    system_state,
                    io_config,
                    tunnel_gateway_states,
                    listener,
                )
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
    // Eventually, the in-memory representation should use direct function calls
    // and not go through the http-interface.
    client: admin::client::ApiClient,
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
    pub(crate) async fn sync_to_file(self) -> Option<PathBuf> {
        let state = match self {
            PathOrObject::Unspecified => return None,
            PathOrObject::Path(path_buf) => return Some(path_buf),
            PathOrObject::Object(s) => s,
        };
        let path = get_tmp_path("system_state.json");
        let dto = crate::dto::SystemStateDto::from(&state);
        write_file(path.clone(), &dto).await.expect("failed");
        Some(path)
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
