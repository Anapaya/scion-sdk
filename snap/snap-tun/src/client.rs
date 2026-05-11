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
//! SNAP tunnel client.

mod tunnel;

use std::{
    collections::{
        BTreeMap,
        btree_map::Entry::{Occupied, Vacant},
    },
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use ana_gotatun::{
    packet::PacketBufPool,
    x25519::{self, PublicKey},
};

/// Size of the packet buffer pool used for SNAP tunnels.
/// This represents the maximum packet size that can be handled.
pub const PACKET_BUF_POOL_SIZE: usize = 65535;

/// Use a default value of 10 seconds for Persistent keepalive seconds for SNAP tunnels.
/// This should be short enough to keep NAT mappings alive.
pub const PERSISTENT_KEEPALIVE_SECONDS: u16 = 10;

use scion_sdk_reqwest_connect_rpc::{client::CrpcClientError, token_source::TokenSource};
use scion_sdk_utils::backoff::{BackoffConfig, ExponentialBackoff};
use tokio::task::{AbortHandle, JoinSet};
pub use tunnel::{SnapTunnel, SnapTunnelDriverError, SnapTunnelReceiveError};

/// Trait for a control plane client.
#[async_trait::async_trait]
pub trait SnapTunControlPlaneClient: Send + Sync {
    /// Register an identity with the control plane.
    async fn register_identity(
        &self,
        identity: PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, CrpcClientError>;

    /// Register an identity with the control plane with retries.
    async fn register_identity_with_retries(
        &self,
        identity: PublicKey,
        psk_share: Option<[u8; 32]>,
        backoff: ExponentialBackoff,
        max_attempts: u32,
    ) -> Result<Option<[u8; 32]>, CrpcClientError> {
        let mut attempt = 0u32;
        loop {
            match self.register_identity(identity, psk_share).await {
                Ok(psk_share) => return Ok(psk_share),
                Err(e) => {
                    if attempt == max_attempts - 1 {
                        return Err(e);
                    }
                    attempt += 1;
                    tokio::time::sleep(backoff.duration(attempt)).await;
                }
            }
        }
    }
}

/// Struct to hold information about a snap-tun control plane
/// and the number of tunnels connected to it.
struct SnapTunControlPlane {
    address: url::Url,
    client: Arc<dyn SnapTunControlPlaneClient>,
    tunnel_count: u64,
}

impl Clone for SnapTunControlPlane {
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            client: self.client.clone(),
            tunnel_count: self.tunnel_count,
        }
    }
}

struct SnapTunEndpointState {
    control_planes: Arc<Mutex<BTreeMap<url::Url, SnapTunControlPlane>>>,
    pub static_private: x25519::StaticSecret,
    pub static_public: x25519::PublicKey,
    pub backoff: ExponentialBackoff,
    pub max_attempts: u32,
}

/// Guard that decrements the tunnel count when dropped.
/// When the tunnel count reaches 0, the control plane is removed from the map
/// of managed control planes.
pub(super) struct TunnelGuard {
    endpoint_state: Arc<SnapTunEndpointState>,
    control_plane: url::Url,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.endpoint_state
            .remove_tunnel(self.control_plane.clone());
    }
}

impl SnapTunEndpointState {
    /// Task to register the endpoints identity with all control planes
    async fn identity_registration_loop(&self, token_source: Arc<dyn TokenSource>) {
        let mut watch = token_source.watch();
        // drop first bogus update, as initial registration is done in add_tunnel()
        let _ = watch.borrow_and_update();
        loop {
            // register the identity with all managed control planes.
            let control_planes = self
                .control_planes
                .lock()
                .expect("lock poisoned")
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let mut set = JoinSet::new();
            for control_plane in control_planes {
                let static_public = self.static_public;
                let backoff = self.backoff;
                let max_attempts = self.max_attempts;
                set.spawn(async move {
                    if let Err(e) = control_plane.client.register_identity_with_retries(static_public, None, backoff, max_attempts).await {
                        tracing::error!(cp_address=%control_plane.address, err=?e, "error registering identity with control plane");
                    }
                });
            }
            set.join_all().await;
            if watch.changed().await.is_err() {
                tracing::info!(
                    "token source watch channel closed, stopping identity registration loop"
                );
                return;
            }
            let r = watch.borrow();
            if let Some(Ok(r)) = &*r {
                // assume token is a JWT-token, the signature is a unique
                // identifier for this token.
                let token_sig = r.rsplit('.').next().unwrap_or("");
                tracing::debug!(token_sig, "token renewal in registration loop");
            }
        }
    }

    async fn add_tunnel(
        self: Arc<Self>,
        address: url::Url,
        client: Arc<dyn SnapTunControlPlaneClient>,
    ) -> Result<TunnelGuard, CrpcClientError> {
        let new = {
            let mut control_planes = self.control_planes.lock().expect("lock poisoned");
            match control_planes.entry(address.clone()) {
                Occupied(mut entry) => {
                    entry.get_mut().tunnel_count += 1;
                    false
                }
                Vacant(entry) => {
                    entry.insert(SnapTunControlPlane {
                        address: address.clone(),
                        client: client.clone(),
                        tunnel_count: 1,
                    });
                    true
                }
            }
        };
        if new {
            let static_public = self.static_public;
            let backoff = self.backoff;
            let max_attempts = self.max_attempts / 2;
            client
                .register_identity_with_retries(static_public, None, backoff, max_attempts)
                .await?;
        }
        Ok(TunnelGuard {
            endpoint_state: self.clone(),
            control_plane: address,
        })
    }

    fn remove_tunnel(&self, address: url::Url) {
        let mut control_planes = self.control_planes.lock().unwrap();
        if let Occupied(mut entry) = control_planes.entry(address) {
            entry.get_mut().tunnel_count -= 1;
            if entry.get().tunnel_count == 0 {
                entry.remove();
            }
        }
    }
}

/// Snap tunnel endpoint that allows creating new snap tun connections.
/// It holds one static identity and manages the registration of this identity with all connected
/// control planes.
pub struct SnapTunEndpoint {
    state: Arc<SnapTunEndpointState>,
    identity_registration_abort_handle: AbortHandle,
}

impl Drop for SnapTunEndpoint {
    fn drop(&mut self) {
        self.identity_registration_abort_handle.abort();
    }
}

/// Error when connecting to a SNAP tunnel.
#[derive(Debug, thiserror::Error)]
pub enum ConnectSnapTunSocketError {
    /// Error when connecting to the snaptun control plane to register the identity.
    #[error("error registering identity with control plane: {0}")]
    SnapTunControlPlaneClientError(#[from] CrpcClientError),
    /// Error when creating the SNAP tunnel connection.
    #[error("error connecting snap tunnel: {0}")]
    SnapTunConnectionError(#[from] SnapTunnelDriverError),
}

impl SnapTunEndpoint {
    /// Creates a new SNAP tunnel socket manager.
    pub fn new(token_source: Arc<dyn TokenSource>, static_private: x25519::StaticSecret) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);
        let state = Arc::new(SnapTunEndpointState {
            control_planes: Arc::new(Mutex::new(BTreeMap::new())),
            static_private,
            static_public,
            backoff: ExponentialBackoff::new_from_config(BackoffConfig {
                minimum_delay_secs: 1.0,
                maximum_delay_secs: 20.0,
                factor: 1.2,
                jitter_secs: 0.1,
            }),
            max_attempts: 10,
        });
        let state_clone = state.clone();
        let abort_handle =
            tokio::spawn(async move { state_clone.identity_registration_loop(token_source).await })
                .abort_handle();
        Self {
            state,
            identity_registration_abort_handle: abort_handle,
        }
    }

    /// Connects a new SNAP tunnel. If the endpoints static identity is not already registered with
    /// the selected snap-tun control plane, it is registered before this method returns.
    pub async fn connect_tunnel(
        &self,
        peer_public: x25519::PublicKey,
        dataplane_address: SocketAddr,
        control_plane: url::Url,
        control_plane_client: Arc<dyn SnapTunControlPlaneClient>,
        underlay_socket: Arc<tokio::net::UdpSocket>,
        receive_queue_capacity: usize,
        pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
    ) -> Result<SnapTunnel, ConnectSnapTunSocketError> {
        let guard = self
            .state
            .clone()
            .add_tunnel(control_plane, control_plane_client)
            .await?;
        Ok(SnapTunnel::new(
            guard,
            self.state.static_private.clone(),
            peer_public,
            underlay_socket,
            dataplane_address,
            receive_queue_capacity,
            Some(PERSISTENT_KEEPALIVE_SECONDS),
            pool,
        )
        .await?)
    }
}
