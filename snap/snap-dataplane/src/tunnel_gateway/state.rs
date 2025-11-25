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
//! Tunnel gateway state.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};
use snap_tun::server::SnapTunToken;

pub mod dto;

type Inner<T> = Arc<RwLock<BTreeMap<SocketAddr, Arc<snap_tun::server::Sender<T>>>>>;

/// Shared tunnel gateway state.
#[derive(Debug, Default, Clone)]
pub struct SharedTunnelGatewayState<T: SnapTunToken>(
    /// Mapping from assigned addresses to their corresponding tunnel senders.
    Inner<T>,
);

impl<T: SnapTunToken> SharedTunnelGatewayState<T> {
    /// Creates a new, empty tunnel gateway state.
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(BTreeMap::new())))
    }
}

impl<T: SnapTunToken> Deref for SharedTunnelGatewayState<T> {
    type Target = Inner<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: SnapTunToken> SharedTunnelGatewayState<T> {
    /// Associates the given address with the given tunnel.
    ///
    /// If an existing mapping exists, it is overwritten.
    pub(crate) fn add_tunnel_mapping(
        &self,
        addr: SocketAddr,
        tunnel: Arc<snap_tun::server::Sender<T>>,
    ) {
        let mut tunnels = self.write().expect("no fail");

        match tunnels.insert(addr, tunnel) {
            Some(e) => {
                tracing::warn!(%addr, existing_remote=%e.remote_underlay_address(), "Overwriting existing snaptun connection mapping");
            }
            None => {
                tracing::debug!(%addr, "Adding snaptun connection mapping");
            }
        }
    }

    /// Removes the tunnel mapping for the given address.
    ///
    /// If no mapping exists, nothing happens.
    pub(crate) fn remove_tunnel_mapping_if_same(
        &self,
        addr: SocketAddr,
        should_contain: &Arc<snap_tun::server::Sender<T>>,
    ) {
        let mut tunnels = self.write().expect("no fail");
        match tunnels.entry(addr) {
            std::collections::btree_map::Entry::Vacant(_) => {
                tracing::debug!(%addr, "No snaptun connection mapping found to remove");
            }
            std::collections::btree_map::Entry::Occupied(occupied_entry) => {
                let tunnel = occupied_entry.get();
                if Arc::ptr_eq(tunnel, should_contain) {
                    tracing::debug!(%addr, "Removing snaptun connection mapping");
                    occupied_entry.remove();
                } else {
                    tracing::warn!(%addr, "Not removing snaptun connection mapping, is mapped to a different tunnel");
                }
            }
        }
    }

    /// Gets the tunnel mapped to the given address, if any.
    pub(crate) fn get_mapped_tunnel(
        &self,
        addr: SocketAddr,
    ) -> Option<Arc<snap_tun::server::Sender<T>>> {
        let tunnels = self.read().expect("no fail");
        tunnels.get(&addr).cloned()
    }
}

/// Tunnel gateway I/O configuration.
#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct TunnelGatewayIoConfig {
    /// Optional socket address to listen on for incoming SNAP tunnel connections.
    pub listen_addr: Option<SocketAddr>,
}

impl TunnelGatewayIoConfig {
    /// Creates a new tunnel gateway I/O configuration with the given listen address.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr: Some(listen_addr),
        }
    }
}
