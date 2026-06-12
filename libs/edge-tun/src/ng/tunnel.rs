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

use std::{net::IpAddr, sync::Arc, time::Duration};

use ana_gotatun::x25519::{self, PublicKey};
use bytes::Bytes;
use ipnet::IpNet;
use rand::TryRng;
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_quic_scion::{h3::client::H3ConnectionError, socket::GenericScionUdpSocket};
use scion_sdk_scion_connect_rpc::client::CrpcClient;
use scion_sdk_utils::backoff::ExponentialBackoff;
use sciparse::address::socket_addr::ScionSocketAddr;
use tracing::instrument;

use crate::{
    fragmenting::metrics::{DefragmentMetrics, FragmentMetrics},
    ng::{
        control::{
            EdgeTunDataPlaneConfig,
            api::client::{EdgeTunClientError, EdgeTunControlPlaneClient},
        },
        data::{
            client::{EdgeTunClient, EdgeTunClientRecvError, EdgeTunClientSendError},
            client_state::EdgeTunClientConfig,
            common::EdgePacketBufPool,
        },
    },
};

const DEFAULT_RECEIVE_QUEUE_CAPACITY: usize = 256;
const REGISTRATION_INTERVAL: Duration = Duration::from_secs(150); // 2.5 minutes
const MAX_REGISTRATION_RETRIES: u32 = 5;
const DEFAULT_PERSISTENT_KEEP_ALIVE_SEC: u16 = 15; // 0.25 minutes

/// Generate a random static private key for WireGuard identity.
pub fn random_static_private() -> x25519::StaticSecret {
    let mut static_private_bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut static_private_bytes)
        .expect("try_fill_bytes failed");
    x25519::StaticSecret::from(static_private_bytes)
}

type AuthTokenFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>,
            > + Send,
    >,
>;
type AuthTokenGetter = dyn Fn() -> AuthTokenFuture + Send + Sync;

/// Options for creating an [`EdgeTunnel`].
#[derive(Debug, Clone)]
pub struct EdgeTunnelOptions {
    /// Optional server name for TLS certificate verification.
    pub control_server_name: Option<String>,
    /// Optional QUIC configuration for the control plane client.
    /// If `None` the default config (validated against server name if provided) is used.
    pub control_client_quic_config: Option<scion_sdk_quic_scion::quic::config::QuicConfig>,
    /// Requested IP address (may not be honored by server).
    pub requested_ip: Option<IpAddr>,
    /// Rate limit for WireGuard handshake initiations.
    pub rate_limit: u64,
    /// MTU for outgoing packet fragmentation.
    pub mtu: u16,
    /// Number of defragmentation queues.
    pub defrag_queue_counts: usize,
    /// Metrics for the fragmenter.
    pub fragmenter_metrics: FragmentMetrics,
    /// Metrics for the defragmenter.
    pub defragmenter_metrics: DefragmentMetrics,
    /// Persistent keep alive.
    pub persistent_keep_alive: Option<u16>,
}

impl EdgeTunnelOptions {
    /// Create a builder for [`EdgeTunnelOptions`].
    pub fn builder() -> EdgeTunnelOptionsBuilder {
        EdgeTunnelOptionsBuilder::default()
    }
}

/// Builder for [`EdgeTunnelOptions`].
pub struct EdgeTunnelOptionsBuilder {
    opts: EdgeTunnelOptions,
}

impl Default for EdgeTunnelOptionsBuilder {
    fn default() -> Self {
        let metrics = MetricsRegistry::default();

        Self {
            opts: EdgeTunnelOptions {
                control_server_name: None,
                control_client_quic_config: None,
                requested_ip: None,
                rate_limit: 256,
                mtu: 1000,
                defrag_queue_counts: 64,
                fragmenter_metrics: FragmentMetrics::new(&metrics),
                defragmenter_metrics: DefragmentMetrics::new(&metrics),
                persistent_keep_alive: Some(DEFAULT_PERSISTENT_KEEP_ALIVE_SEC),
            },
        }
    }
}

impl EdgeTunnelOptionsBuilder {
    /// Set the control-plane TLS server name for certificate verification.
    pub fn control_server_name(mut self, control_server_name: Option<String>) -> Self {
        self.opts.control_server_name = control_server_name;
        self
    }

    /// Set a custom QUIC configuration for the control-plane client.
    pub fn control_client_quic_config(
        mut self,
        control_client_quic_config: Option<scion_sdk_quic_scion::quic::config::QuicConfig>,
    ) -> Self {
        self.opts.control_client_quic_config = control_client_quic_config;
        self
    }

    /// Set a requested IP address for address assignment.
    pub fn requested_ip(mut self, requested_ip: Option<IpAddr>) -> Self {
        self.opts.requested_ip = requested_ip;
        self
    }

    /// Set WireGuard handshake rate limiting.
    pub fn rate_limit(mut self, rate_limit: u64) -> Self {
        self.opts.rate_limit = rate_limit;
        self
    }

    /// Set MTU used by the fragmenter.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.opts.mtu = mtu;
        self
    }

    /// Set the number of defragmentation queues.
    pub fn defrag_queue_counts(mut self, defrag_queue_counts: usize) -> Self {
        self.opts.defrag_queue_counts = defrag_queue_counts;
        self
    }

    /// Set metrics for fragmentation.
    pub fn fragmenter_metrics(mut self, fragmenter_metrics: FragmentMetrics) -> Self {
        self.opts.fragmenter_metrics = fragmenter_metrics;
        self
    }

    /// Set metrics for defragmentation.
    pub fn defragmenter_metrics(mut self, defragmenter_metrics: DefragmentMetrics) -> Self {
        self.opts.defragmenter_metrics = defragmenter_metrics;
        self
    }

    /// Build the finalized [`EdgeTunnelOptions`].
    pub fn build(self) -> EdgeTunnelOptions {
        self.opts
    }
}

/// Error type for [`EdgeTunnel`] operations.
#[derive(Debug, thiserror::Error)]
pub enum EdgeTunnelError {
    /// Failed to obtain an auth token.
    #[error("auth token acquisition failed")]
    ControlAuthToken(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Failed to establish the control plane connection.
    #[error("control plane connection failed")]
    ControlConnect(#[source] H3ConnectionError),
    /// A control plane RPC call failed.
    #[error("control plane RPC failed")]
    ControlRpc(#[from] EdgeTunClientError),
    /// The server did not assign an address.
    #[error("no address assigned by server")]
    NoAddressAssigned,
    /// The server assigned a different address on re-registration.
    #[error("assigned address changed on re-registration")]
    AssignedAddressChanged {
        /// The previously assigned address.
        old_addr: IpAddr,
        /// The newly assigned address.
        new_addr: Option<IpAddr>,
    },
    /// Periodic identity re-registration failed after exhausting retries.
    #[error("periodic identity registration task failed after {retries} retries")]
    IdentityRegistration {
        /// Number of retries attempted.
        retries: u32,
        /// The error from the last attempt.
        #[source]
        last_error: Box<EdgeTunnelError>,
    },
}

/// A high-level edge-tun tunnel coordinating control and data planes.
///
/// Created via [`EdgeTunnel::connect`]. The caller must drive
/// [`EdgeTunnel::main_loop`] to keep the identity registration alive.
pub struct EdgeTunnel {
    data_plane_client: EdgeTunClient,
    assigned_addr: IpAddr,
    announced_routes: Vec<IpNet>,
    // Fields needed for identity re-registration in main_loop.
    static_public: PublicKey,
    control_address: ScionSocketAddr,
    control_server_name: Option<String>,
    control_client_quic_config: Option<scion_sdk_quic_scion::quic::config::QuicConfig>,
    control_socket: Arc<dyn GenericScionUdpSocket>,
    get_auth_token: Box<AuthTokenGetter>,
}

impl EdgeTunnel {
    /// Establish an edge-tun connection.
    ///
    /// This creates a control plane connection, registers the client identity,
    /// obtains an assigned address and routes, fetches the data plane config,
    /// and spawns the data plane client. The WireGuard handshake is initiated
    /// asynchronously when data is sent; this method does **not** wait for it to complete.
    #[instrument(name = "edge_tunnel::connect", skip_all)]
    pub async fn connect(
        control_address: ScionSocketAddr,
        control_socket: Arc<dyn GenericScionUdpSocket>,
        data_socket: Arc<dyn GenericScionUdpSocket>,
        pool: EdgePacketBufPool,
        static_private: x25519::StaticSecret,
        opts: EdgeTunnelOptions,
        get_auth_token: impl Fn() -> AuthTokenFuture + Send + Sync + 'static,
    ) -> Result<Self, EdgeTunnelError> {
        let EdgeTunnelOptions {
            control_server_name,
            control_client_quic_config,
            requested_ip,
            rate_limit,
            mtu,
            defrag_queue_counts,
            fragmenter_metrics,
            defragmenter_metrics,
            persistent_keep_alive,
        } = opts;

        let static_public = PublicKey::from(&static_private);

        let auth_token = get_auth_token()
            .await
            .map_err(EdgeTunnelError::ControlAuthToken)?;

        tracing::debug!("Creating edge app server control plane client");
        let control_client = Self::create_control_plane_client(
            control_address,
            control_socket.clone(),
            control_server_name.clone(),
            control_client_quic_config.clone(),
            auth_token,
        )
        .await?;

        tracing::debug!("Registering identity to edge app server");
        // Register identity.
        let (server_static, _) = control_client
            .register_edge_tun_identity(static_public, None)
            .await?;

        // Assign address.
        tracing::debug!("Requesting address assignment from edge app server");
        let assigned_addr = control_client
            .assign_address(static_public, requested_ip)
            .await?
            .ok_or(EdgeTunnelError::NoAddressAssigned)?;

        // Get announced routes.
        tracing::debug!(%assigned_addr, "Fetching announced routes from edge app server");
        let announced_routes = control_client
            .get_route_advertisement(static_public)
            .await?;

        // Get data plane config.
        let EdgeTunDataPlaneConfig {
            data_plane_scion_sockaddr,
            ..
        } = control_client.get_data_plane_configuration().await?;

        // Drop the control client (and its underlying CrpcClient connection).
        drop(control_client);

        // Create and start the data plane client.
        let client = EdgeTunClient::new(
            EdgeTunClientConfig {
                peer_static: server_static,
                static_secret: static_private,
                rate_limit,
                mtu,
                defrag_queue_counts,
                persistent_keep_alive,
            },
            data_socket,
            data_plane_scion_sockaddr,
            DEFAULT_RECEIVE_QUEUE_CAPACITY,
            pool,
            fragmenter_metrics,
            defragmenter_metrics,
        );

        Ok(Self {
            data_plane_client: client,
            assigned_addr,
            announced_routes,
            static_public,
            control_address,
            control_server_name,
            control_client_quic_config,
            control_socket,
            get_auth_token: Box::new(get_auth_token),
        })
    }

    async fn create_control_plane_client(
        control_address: ScionSocketAddr,
        control_socket: Arc<dyn GenericScionUdpSocket>,
        control_server_name: Option<String>,
        control_client_quic_config: Option<scion_sdk_quic_scion::quic::config::QuicConfig>,
        auth_token: Option<String>,
    ) -> Result<EdgeTunControlPlaneClient<CrpcClient>, EdgeTunnelError> {
        let crpc_client = if let Some(quic_config) = control_client_quic_config {
            CrpcClient::with_quic_config(
                control_address,
                control_socket,
                control_server_name,
                auth_token,
                quic_config,
            )
            .await
        } else {
            CrpcClient::new(
                control_address,
                control_socket,
                control_server_name,
                auth_token,
            )
            .await
        }
        .map_err(EdgeTunnelError::ControlConnect)?;

        Ok(EdgeTunControlPlaneClient::new(crpc_client))
    }

    /// Run the tunnel main loop performing periodic identity re-registration.
    ///
    /// This method runs until an unrecoverable error occurs (e.g., all
    /// re-registration retry attempts exhausted). The caller should tear down
    /// the tunnel when this returns.
    #[instrument(name = "edge_tunnel::main_loop", skip_all)]
    pub async fn main_loop(&self) -> Result<(), EdgeTunnelError> {
        let backoff = ExponentialBackoff::new(2.5, 30.0, 1.3, 0.5);

        loop {
            tokio::time::sleep(REGISTRATION_INTERVAL).await;

            let mut last_err = None;
            for attempt in 0..MAX_REGISTRATION_RETRIES {
                match self.register_identity_once().await {
                    Ok(()) => {
                        last_err = None;
                        tracing::debug!(
                            attempt = attempt + 1,
                            "identity re-registration successful"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(attempt, err=?e, "identity re-registration failed");
                        last_err = Some(e);
                        if attempt + 1 < MAX_REGISTRATION_RETRIES {
                            tokio::time::sleep(backoff.duration(attempt)).await;
                        }
                    }
                }
            }
            if let Some(e) = last_err {
                tracing::error!(err=?e, "identity re-registration exhausted all retries");
                return Err(EdgeTunnelError::IdentityRegistration {
                    retries: MAX_REGISTRATION_RETRIES,
                    last_error: Box::new(e),
                });
            }
        }
    }

    async fn register_identity_once(&self) -> Result<(), EdgeTunnelError> {
        let token = (self.get_auth_token)()
            .await
            .map_err(EdgeTunnelError::ControlAuthToken)?;

        let control_client = Self::create_control_plane_client(
            self.control_address,
            self.control_socket.clone(),
            self.control_server_name.clone(),
            self.control_client_quic_config.clone(),
            token,
        )
        .await?;
        control_client
            .register_edge_tun_identity(self.static_public, None)
            .await?;
        let new_assigned_address = control_client
            .assign_address(self.static_public, Some(self.assigned_addr))
            .await?;
        if Some(self.assigned_addr) != new_assigned_address {
            return Err(EdgeTunnelError::AssignedAddressChanged {
                old_addr: self.assigned_addr,
                new_addr: new_assigned_address,
            });
        }
        // control_client and its CrpcClient are dropped here.
        Ok(())
    }

    /// Send an IP packet through the tunnel.
    #[instrument(name = "edge_tunnel::send", skip_all)]
    pub async fn send(
        &self,
        packet: ana_gotatun::packet::Packet,
    ) -> Result<(), EdgeTunClientSendError> {
        self.data_plane_client.send(packet).await
    }

    /// Receive the next decrypted IP packet from the tunnel.
    #[instrument(name = "edge_tunnel::recv", skip_all)]
    pub async fn recv(&self) -> Result<Bytes, EdgeTunClientRecvError> {
        self.data_plane_client.recv().await
    }

    /// The IP address assigned to this client by the server.
    pub fn assigned_addr(&self) -> IpAddr {
        self.assigned_addr
    }

    /// The routes announced by the server.
    pub fn announced_routes(&self) -> &[IpNet] {
        &self.announced_routes
    }
}
