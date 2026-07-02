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

//! PocketSCION Runtime - the main runtime that manages the state and tasks of a PocketSCION
//! simulation.
//!
//! The runtime is responsible for starting and stopping all components of the simulation, such as
//! the control plane, data plane, APIs, and network forwarders. It holds the shared state of the
//! simulation and a set of tasks that are running.
//!
//! To create a runtime, use [PocketScionRuntimeBuilder](builder::PocketScionRuntimeBuilder) to
//! configure the desired state and then call `start()` to start the runtime.

pub mod api;
pub mod builder;

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use dhsd::DhsdSecret;
use jsonwebtoken::DecodingKey;
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_utils::task_handler::CancelTaskSet;
use snap_control::server::identity_registry::IdentityRegistry;
use snap_dataplane::tunnel_gateway::{
    NoopTunnelGatewayObserver, dispatcher::TunnelGatewayDispatcher,
    metrics::TunnelGatewayDispatcherMetrics, start_tunnel_gateway,
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;
use x25519_dalek::StaticSecret;

use crate::{
    comp::{
        authorization_server,
        control_service::{ControlService, segment_lookup::SegmentListingCache},
        daemon::PsDaemonService,
        echo_responder::PsEchoResponder,
        endhost_api::PsEndhostApi,
        endhost_api_discovery::EndhostApiDiscoveryService,
        endhost_segment_lister::StateEndhostSegmentLister,
        external_as::ExternalAsService,
        network_forwarder::NetworkForwarder,
        simulation_dispatcher::{AsNetSimDispatcher, NetSimDispatcher},
        snap::{SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL, SnapId},
    },
    io_config::IoConfig,
    network::local::receivers::router_socket::{RouterSocket, SharedRouterSocket},
    state::PocketScionState,
    util::addr_to_http_url,
};

/// PocketSCION Runtime
///
/// This struct represents a running instance of PocketSCION. It holds the state of the simulation
/// and the tasks that are running.
///
/// Use [PocketScionRuntimeBuilder](builder::PocketScionRuntimeBuilder) to create an instance of
/// pocketscion.
///
/// Dropping the runtime will stop all tasks. Store the runtime in a variable to keep it running.
#[must_use = "Immediately dropping the runtime will stop all tasks. Store the runtime in a variable to keep it running."]
pub struct PocketScionRuntime {
    join_set: JoinSet<Result<(), io::Error>>,
    _cancel_token: CancellationToken,
    state: PocketScionState,
    io_config: IoConfig,
}

impl PocketScionRuntime {
    /// Initialises and starts all runtime components, returning a running [PocketScionRuntime].
    async fn start(
        state: PocketScionState,
        io_config: IoConfig,
        mut join_set: JoinSet<Result<(), io::Error>>,
    ) -> anyhow::Result<PocketScionRuntime> {
        let cancel_token = CancellationToken::new();
        let root_secret = state.root_secret();

        Self::validate_state(&state)?;

        Self::start_echo_responder(&state)?;
        Self::start_endhost_apis(&mut join_set, &state, &io_config).await?;
        let snap_authz_map =
            Self::start_snap_control_planes(&mut join_set, &state, &io_config).await?;
        Self::start_snap_data_planes(
            &mut join_set,
            &cancel_token,
            &state,
            &io_config,
            &root_secret,
            snap_authz_map,
        )
        .await?;

        Self::start_endhost_discovery_apis(&state, &io_config).await?;
        Self::start_external_ases(&state, &io_config).await?;
        Self::start_control_services(&state, &io_config, &cancel_token).await?;
        Self::start_daemon_services(&state, &io_config).await?;
        Self::start_router_sockets(&mut join_set, &state, &io_config).await?;
        Self::start_network_forwarders(&mut join_set, &state, &io_config).await?;
        Self::start_auth_server(&mut join_set, &cancel_token, &state, &io_config).await?;

        Ok(PocketScionRuntime {
            join_set,
            state,
            io_config,
            _cancel_token: cancel_token,
        })
    }

    /// Stops all tasks and waits for them to finish.
    ///
    /// At the moment this does not do a graceful shutdown, but simply aborts all tasks.
    /// In the future, a more graceful shutdown procedure may be implemented.
    pub async fn stop_and_join(mut self) {
        self.join_set.abort_all();
        self.join_set.join_all().await;
    }

    /// Waits for all tasks to finish. This will run indefinitely until the runtime is dropped.
    pub async fn join(mut self) {
        while let Some(res) = self.join_set.join_next().await {
            if let Err(e) = res {
                tracing::error!("Task failed with error: {e}");
            }
        }
    }

    /// Validates that no ISD-AS has more than one SNAP, and no ISD-AS has both a router and a SNAP.
    fn validate_state(pstate: &PocketScionState) -> anyhow::Result<()> {
        let mut seen_ases = BTreeSet::new();
        for (_, snap_state) in pstate.snaps() {
            for isd_as in snap_state.isd_ases() {
                if seen_ases.contains(&isd_as) {
                    anyhow::bail!("Only one snap per ISD-AS is allowed");
                }
                seen_ases.insert(isd_as);
            }
        }
        for (_, router) in pstate.routers() {
            if seen_ases.contains(&router.isd_as) {
                anyhow::bail!("Only one router per ISD-AS is allowed");
            }
        }
        Ok(())
    }

    /// Binds a UDP socket to `addr`, or to a random localhost port if `None`.
    /// Writes the actual bound address back via `set_addr`.
    async fn bind_udp_or_random(
        addr: Option<SocketAddr>,
        set_addr: impl FnOnce(SocketAddr),
        context: impl std::fmt::Display,
    ) -> anyhow::Result<tokio::net::UdpSocket> {
        let bind_addr = addr.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket for {context}"))?;
        set_addr(socket.local_addr()?);
        Ok(socket)
    }

    /// Binds a TCP listener to `addr`, or to a random localhost port if `None`.
    /// Writes the actual bound address back via `set_addr`.
    async fn bind_tcp_or_random(
        addr: Option<SocketAddr>,
        set_addr: impl FnOnce(SocketAddr),
        context: impl std::fmt::Display,
    ) -> anyhow::Result<TcpListener> {
        let bind_addr = addr.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind TCP listener for {context}"))?;
        set_addr(listener.local_addr()?);
        Ok(listener)
    }

    /// Starts the control plane API server for each configured SNAP.
    /// Returns a map of SNAP ID to its identity registry, used later by the data plane.
    async fn start_snap_control_planes(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<BTreeMap<SnapId, Arc<IdentityRegistry>>> {
        let snap_token_decoding_key =
            DecodingKey::from_ed_pem(pem::encode(&pstate.snap_token_public_key()).as_bytes())
                .unwrap();
        let snap_token_verifier =
            snap_control::server::SnapTokenVerifier::new(snap_token_decoding_key);

        let mut snap_authz_map: BTreeMap<SnapId, Arc<IdentityRegistry>> = Default::default();

        {
            if pstate.read().segment_listing_cache.is_some() {
                tracing::info!("Starting segment listing cache cleanup loop");
                let state = pstate.clone();
                join_set.spawn(async move {
                    SegmentListingCache::cleanup_loop(state, Duration::from_secs(60)).await;
                    tracing::info!("Segment listing cache cleanup loop exited");
                    Ok(())
                });
            }
        }

        for (snap_id, snap_state) in pstate.snaps() {
            let local_ases = snap_state.isd_ases();

            let dp_discovery = pstate.snap_data_plane_discovery(snap_id, io_config.clone());
            let snap_resolver = pstate.snap_resolver(snap_id, io_config.clone());
            let identity_registry = Arc::new(IdentityRegistry::new());
            let segment_lister =
                StateEndhostSegmentLister::new(pstate.clone(), local_ases.into_iter().collect());

            let io_config = io_config.clone();
            let listener = Self::bind_tcp_or_random(
                io_config.snap_control_addr(snap_id),
                |addr| {
                    io_config.set_snap_control_addr(snap_id, addr);
                },
                format_args!("SNAP {snap_id} control plane"),
            )
            .await?;

            let snap_cp_api = match listener.local_addr() {
                Ok(addr) => addr_to_http_url(addr),
                Err(e) => {
                    bail!("Failed to get local address for SNAP control plane API: {e}");
                }
            };

            let app = snap_control::server::build_router(
                dp_discovery,
                snap_cp_api,
                segment_lister,
                snap_resolver,
                identity_registry.clone(),
                None,
                None,
                snap_token_verifier.clone(),
                snap_control::server::metrics::Metrics::new(&MetricsRegistry::new()),
            )?;

            join_set.spawn({
                let identity_registry = identity_registry.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(30));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                    loop {
                        interval.tick().await;
                        identity_registry.remove_expired(std::time::Instant::now());
                    }
                }
            });

            join_set.spawn(async move {
                axum_server::from_tcp(listener.into_std().expect("no fail"))
                    .map_err(|e| {
                        io::Error::other(format!("failed to build server from TCP listener: {e}"))
                    })?
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .map_err(|e| {
                        io::Error::other(format!(
                            "SNAP control plane API server stopped unexpectedly: {e}"
                        ))
                    })
            });

            snap_authz_map.insert(snap_id, identity_registry);
        }

        Ok(snap_authz_map)
    }

    /// Starts the data plane tunnel gateway for each configured SNAP.
    async fn start_snap_data_planes(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        cancel_token: &CancellationToken,
        pstate: &PocketScionState,
        io_config: &IoConfig,
        root_secret: &DhsdSecret,
        mut snap_authz_map: BTreeMap<SnapId, Arc<IdentityRegistry>>,
    ) -> anyhow::Result<()> {
        for (snap_id, snap) in pstate.snaps() {
            let metrics_registry = MetricsRegistry::new();
            let key = root_secret.derive_from_iter(vec![
                SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL.into(),
                snap_id.to_string().into(),
            ]);
            let static_secret = StaticSecret::from(key.as_array());

            let io_config = io_config.clone();
            let socket = Self::bind_udp_or_random(
                io_config.snap_data_plane_addr(snap_id),
                |addr| {
                    io_config.set_snap_data_plane_addr(snap_id, addr);
                },
                format_args!("SNAP {snap_id} data plane"),
            )
            .await?;

            let addr = socket.local_addr()?;
            tracing::info!(%addr, %snap_id, "Starting snap dataplane");

            let tun_gw_metrics = TunnelGatewayDispatcherMetrics::new(&metrics_registry);
            let (tunnel_gw_dispatcher, tun_dispatcher_rx) =
                TunnelGatewayDispatcher::new(tun_gw_metrics);
            let tunnel_gw_dispatcher = Arc::new(tunnel_gw_dispatcher);

            for isd_as in snap.isd_ases() {
                pstate
                    .add_wildcard_sim_receiver(isd_as, tunnel_gw_dispatcher.clone())
                    .expect("Failed to add wildcard receiver");
            }

            let authz = snap_authz_map
                .remove(&snap_id)
                .expect("no authz found for snap");

            // TODO: This hack needs to be removed when the CancelTaskSet is removed
            let mut c_task_set = CancelTaskSet::new_from_parts(
                std::mem::replace(join_set, JoinSet::new()),
                cancel_token.clone(),
            );
            start_tunnel_gateway(
                &mut c_task_set,
                socket,
                authz,
                Arc::new(NetSimDispatcher::new(pstate.clone())),
                Arc::new(NoopTunnelGatewayObserver),
                tun_dispatcher_rx,
                static_secret,
            );
            let (reclaimed, _) = c_task_set.into_parts();
            *join_set = reclaimed;
        }

        Ok(())
    }

    /// Binds and spawns a task for each configured endhost API.
    async fn start_endhost_apis(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for (id, _) in pstate.endhost_apis() {
            let listener = Self::bind_tcp_or_random(
                io_config.endhost_api_addr(id),
                |addr| {
                    io_config.set_endhost_api_addr(id, addr);
                },
                format_args!("endhost API {id}"),
            )
            .await?;

            let pstate = pstate.clone();
            let io_config = io_config.clone();
            join_set.spawn(async move {
                PsEndhostApi::serve(id, listener, pstate, io_config)
                    .await
                    .map_err(|e| io::Error::other(format!("{e:?}")))
            });
        }

        Ok(())
    }

    /// Starts the endhost API discovery service for each configured discovery API.
    async fn start_endhost_discovery_apis(
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for (id, _) in pstate.endhost_api_discovery_apis() {
            let listener = Self::bind_tcp_or_random(
                io_config.endhost_api_discovery_api_addr(id),
                |addr| {
                    io_config.set_endhost_api_discovery_api_addr(id, addr);
                },
                format_args!("endhost API discovery {id:?}"),
            )
            .await?;

            EndhostApiDiscoveryService::start(id, listener, pstate.clone(), io_config.clone())
                .await
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
        }
        Ok(())
    }

    /// Starts the external AS adapter for each configured external AS and registers it with the
    /// simulation.
    async fn start_external_ases(
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for (isd_as, ext_state) in pstate.external_ases() {
            let mut sockets = std::collections::HashMap::new();
            for &iface_id in ext_state.interfaces.keys() {
                let socket = Self::bind_udp_or_random(
                    io_config.external_as_interface_addr(isd_as, iface_id),
                    |addr| {
                        io_config.set_external_as_interface_addr(isd_as, iface_id, addr);
                    },
                    format_args!("external AS {isd_as} interface {iface_id}"),
                )
                .await?;
                sockets.insert(iface_id, socket);
            }

            let ext_as = ExternalAsService::start(isd_as, pstate.clone(), sockets)
                .await
                .map_err(|e| io::Error::other(format!("{e:?}")))?;

            pstate
                .register_external_as_handler(isd_as, ext_as)
                .map_err(|e| {
                    io::Error::other(format!(
                        "Failed to register external AS handler for AS {isd_as}: {e:?}"
                    ))
                })?;
        }
        Ok(())
    }

    /// Spawns a control service task for each configured ISD-AS.
    async fn start_control_services(
        pstate: &PocketScionState,
        io_config: &IoConfig,
        cancel_token: &CancellationToken,
    ) -> anyhow::Result<()> {
        for (isd_as, cs_state) in pstate.control_services() {
            let host_socket_listener = match cs_state.host_socket_enabled() {
                true => {
                    let io_config = io_config.clone();
                    let listener = Self::bind_tcp_or_random(
                        io_config.control_service_addr(isd_as),
                        |addr| {
                            io_config.set_control_service_addr(isd_as, addr);
                        },
                        format!("control service gRPC for ISD-AS {isd_as}"),
                    )
                    .await?;
                    Some(listener)
                }
                false => None,
            };

            let pstate = pstate.clone();
            ControlService::start(isd_as, pstate, host_socket_listener, cancel_token.clone())
                .with_context(|| format!("Failed to start Control Service for ISD-AS {isd_as}"))?;
        }

        Ok(())
    }

    /// Spawns a daemon service task for each configured ISD-AS.
    async fn start_daemon_services(
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for (isd_as, _) in pstate.daemon_services() {
            let tcp_listener = Self::bind_tcp_or_random(
                io_config.daemon_service_addr(isd_as),
                |addr| {
                    io_config.set_daemon_service_addr(isd_as, addr);
                },
                format_args!("daemon service {isd_as}"),
            )
            .await?;

            let pstate = pstate.clone();
            PsDaemonService::start(isd_as, pstate, io_config.clone(), tcp_listener)
                .await
                .with_context(|| format!("Failed to start Daemon Service for ISD-AS {isd_as}"))?;
        }

        Ok(())
    }

    /// Binds and starts a UDP router socket for each configured router, registering it as a
    /// wildcard receiver.
    async fn start_router_sockets(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for sock_id in pstate.router_ids() {
            let io_config = io_config.clone();
            let udp_socket = Self::bind_udp_or_random(
                io_config.router_socket_addr(sock_id),
                |addr| {
                    io_config.set_router_socket_addr(sock_id, addr);
                },
                format_args!("router socket {sock_id}"),
            )
            .await?;

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

            join_set.spawn(async move { router_socket.run().await });
        }
        Ok(())
    }

    /// Binds and starts a network forwarder for each configured forwarder address.
    async fn start_network_forwarders(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        for (sci_addr, forwarder_state) in pstate.network_forwarders() {
            if sci_addr.ip() != forwarder_state.sim_addr {
                return Err(io::Error::other(format!(
                    "SCION address {sci_addr} does not match the simulation address \
                     {sim_addr} configured for the forwarder",
                    sim_addr = forwarder_state.sim_addr
                ))
                .into());
            }

            let listen_addr = io_config
                .network_forwarder_addr(sci_addr.isd_asn(), forwarder_state.sim_addr)
                .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));

            let forwarder = NetworkForwarder::bind(
                pstate.clone(),
                forwarder_state.local_as,
                forwarder_state.sim_addr,
                forwarder_state.queue_size,
                listen_addr,
                forwarder_state.forward_addr,
            )
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "Failed to start network forwarder for {sci_addr}: {e}"
                ))
            })?;

            io_config.set_network_forwarder_addr(
                sci_addr.isd_asn(),
                forwarder_state.sim_addr,
                forwarder.listen_addr(),
            );

            join_set.spawn(async move {
                forwarder.run().await;
                Ok(())
            });
        }

        Ok(())
    }

    /// Starts the authorization server if one is configured in the system state.
    async fn start_auth_server(
        join_set: &mut JoinSet<Result<(), io::Error>>,
        cancel_token: &CancellationToken,
        pstate: &PocketScionState,
        io_config: &IoConfig,
    ) -> anyhow::Result<()> {
        if pstate.has_auth_server() {
            let listener = Self::bind_tcp_or_random(
                io_config.auth_server_addr(),
                |addr| {
                    io_config.set_auth_server_addr(addr);
                },
                "auth server",
            )
            .await?;

            let auth_server = pstate.auth_server();
            let token = cancel_token.clone();
            join_set.spawn(async move {
                authorization_server::api::start(token, auth_server, listener).await
            });
        }
        Ok(())
    }

    /// Starts a SCMP echo responder for all ASes in the system if one is configured in the system
    /// state.
    fn start_echo_responder(pstate: &PocketScionState) -> anyhow::Result<()> {
        let mut guard = pstate.write();

        if let Some(listen_net) = guard.global_scmp_echo_responder {
            let echo_responder = Arc::new(PsEchoResponder::new(pstate.clone()));

            for isd_as in guard.topology.as_map.keys().cloned().collect::<Vec<_>>() {
                guard
                    .sim_receivers
                    .add_receiver(isd_as, listen_net, echo_responder.clone())
                    .with_context(|| {
                        format!("Failed to add ping responder for ISD-AS {isd_as} on {listen_net}")
                    })?;
            }
        }
        Ok(())
    }
}
