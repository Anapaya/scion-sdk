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
//! PocketSCION I/O configuration.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, RwLock, RwLockReadGuard},
};

use anyhow::{Context, Ok};
use serde::{Deserialize, Serialize};
use snap_control::server::state::ControlPlaneIoConfig;
use snap_dataplane::{state::DataPlaneId, tunnel_gateway::state::TunnelGatewayIoConfig};

use crate::{
    authorization_server::api::IoAuthServerConfig,
    dto::{IoConfigDto, IoSnapConfigDto},
    endhost_api::EndhostApiId,
    state::{RouterId, SnapDataPlaneId, SnapId},
};

/// PocketSCION I/O configuration.
#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct IoConfig {
    /// The I/O state of the SNAPs.
    snaps: BTreeMap<SnapId, SnapIoConfig>,
    /// The I/O state of the authorization server.
    auth_server: IoAuthServerConfig,
    /// The I/O state of the SCION router sockets.
    router_sockets: BTreeMap<RouterId, SocketAddr>,
    /// Listen Socket for EndhostAPIs
    endhost_apis: BTreeMap<EndhostApiId, SocketAddr>,
}

impl AsRef<IoConfig> for RwLockReadGuard<'_, IoConfig> {
    fn as_ref(&self) -> &IoConfig {
        self
    }
}

impl TryFrom<IoConfigDto> for IoConfig {
    type Error = anyhow::Error;

    fn try_from(value: IoConfigDto) -> Result<Self, Self::Error> {
        let snaps = value
            .snaps
            .into_iter()
            .map(|(snap_id, snap_io_config)| {
                Ok((
                    snap_id,
                    snap_io_config
                        .try_into()
                        .with_context(|| format!("invalid SNAP I/O config ({snap_id})"))?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        let router_sockets = value
            .router_sockets
            .into_iter()
            .map(|(router_socket_id, addr)| {
                Ok((
                    router_socket_id,
                    addr.parse().context("invalid router socket address")?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        let endhost_apis = value
            .endhost_apis
            .into_iter()
            .map(|(id, addr)| {
                Ok((
                    id,
                    addr.parse().context("invalid endhost api socket address")?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        Ok(Self {
            snaps,
            router_sockets,
            auth_server: value
                .auth_server
                .try_into()
                .context("invalid auth server I/O config")?,
            endhost_apis,
        })
    }
}

impl From<&IoConfig> for IoConfigDto {
    fn from(config: &IoConfig) -> Self {
        Self {
            auth_server: (&config.auth_server).into(),
            snaps: config
                .snaps
                .iter()
                .map(|(snap_id, snap_io_config)| (*snap_id, snap_io_config.into()))
                .collect(),
            router_sockets: config
                .router_sockets
                .iter()
                .map(|(router_socket_id, addr)| (*router_socket_id, addr.to_string()))
                .collect(),
            endhost_apis: config
                .endhost_apis
                .iter()
                .map(|(id, addr)| (*id, addr.to_string()))
                .collect(),
        }
    }
}

/// Shared PocketSCION I/O configuration.
#[derive(Clone, Default)]
pub struct SharedPocketScionIoConfig {
    state: Arc<RwLock<IoConfig>>,
}

impl SharedPocketScionIoConfig {
    /// Creates a new, empty I/O configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new I/O configuration from the given state.
    pub fn from_state(state: IoConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Creates a new I/O configuration from the given DTO.
    pub fn from_dto(state: IoConfigDto) -> Result<Self, anyhow::Error> {
        let state = IoConfig::try_from(state)?;

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Converts the I/O configuration to a DTO.
    pub fn to_dto(&self) -> IoConfigDto {
        self.get_state().as_ref().into()
    }

    /// Gets a read lock on the I/O configuration state.
    pub fn get_state(&self) -> RwLockReadGuard<'_, IoConfig> {
        self.state.read().unwrap()
    }

    /// Consumes the shared I/O configuration and returns the inner state.
    pub fn into_state(self) -> IoConfig {
        Arc::into_inner(self.state)
            .expect("no fail")
            .into_inner()
            .expect("no fail")
    }
}

impl SharedPocketScionIoConfig {
    /// Set the address of given SNAP
    ///
    /// # Panics
    ///
    /// If address was already set
    pub fn set_snap_control_addr(&self, snap_id: SnapId, control_plane_api_addr: SocketAddr) {
        let mut sstate = self.state.write().unwrap();
        assert!(!sstate.snaps.contains_key(&snap_id), "SNAP already exists");
        sstate.snaps.insert(
            snap_id,
            SnapIoConfig {
                control_plane: ControlPlaneIoConfig {
                    api_addr: Some(control_plane_api_addr),
                },
                data_planes: Default::default(),
            },
        );
    }

    /// Sets the SNAP Data Plane address
    ///
    /// # Panics
    ///
    /// If address was already set
    pub fn set_snap_data_plane_addr(&self, snap_dp_id: SnapDataPlaneId, listen_addr: SocketAddr) {
        let mut sstate = self.state.write().unwrap();
        let snap_io_config = sstate
            .snaps
            .get_mut(&snap_dp_id.snap())
            .expect("SNAP doesn't exist");
        assert!(
            !snap_io_config
                .data_planes
                .contains_key(&snap_dp_id.data_plane()),
            "Data plane already exists",
        );
        snap_io_config.data_planes.insert(
            snap_dp_id.data_plane(),
            TunnelGatewayIoConfig::new(listen_addr),
        );
    }

    /// List all available SNAPs with the control plane API address.
    pub fn snaps(&self) -> Vec<(SnapId, Option<SocketAddr>)> {
        let rstate = self.state.read().expect("no fail");
        rstate
            .snaps
            .iter()
            .map(|(snap_id, snap_state)| (*snap_id, snap_state.control_plane.api_addr))
            .collect()
    }

    /// Get the control plane API address for a SNAP.
    ///
    /// Returns `None` if the SNAP doesn't exist or if the control plane API address
    /// hasn't been set yet.
    pub fn snap_control_addr(&self, snap_id: SnapId) -> Option<SocketAddr> {
        let rstate = self.state.read().expect("no fail");
        rstate
            .snaps
            .get(&snap_id)
            .and_then(|snap| snap.control_plane.api_addr)
    }

    /// Get the listen address for a SNAP data plane.
    ///
    /// Returns `None` if the SNAP or the SNAP data plane doesn't exist, or if
    /// the listen address hasn't been set yet.
    pub fn snap_data_plane_addr(&self, snap_dp_id: SnapDataPlaneId) -> Option<SocketAddr> {
        let rstate = self.state.read().expect("no fail");
        rstate.snaps.get(&snap_dp_id.snap()).and_then(|snap_state| {
            snap_state
                .data_planes
                .get(&snap_dp_id.data_plane())
                .and_then(|tunnel_gw| tunnel_gw.listen_addr)
        })
    }

    /// List all available SNAP data planes with their control plane API address.
    pub fn list_snap_data_planes(
        &self,
        snap_id: SnapId,
    ) -> Vec<(SnapDataPlaneId, Option<SocketAddr>)> {
        let rstate = self.state.read().expect("no fail");
        rstate
            .snaps
            .get(&snap_id)
            .map(|snap| {
                snap.data_planes
                    .iter()
                    .map(|(dp_id, state)| {
                        (SnapDataPlaneId::new(snap_id, *dp_id), state.listen_addr)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the socket address of a given router socket.
    pub fn router_socket_addr(&self, router_socket_id: RouterId) -> Option<SocketAddr> {
        let rstate = self.state.read().expect("no fail");
        rstate.router_sockets.get(&router_socket_id).copied()
    }

    /// Set the socket address of a given router socket.
    pub fn set_router_socket_addr(&self, router_socket_id: RouterId, addr: SocketAddr) {
        let mut sstate = self.state.write().unwrap();
        sstate.router_sockets.insert(router_socket_id, addr);
    }

    /// Get the authorization server API address.
    ///
    /// Returns `None` if the address hasn't been set yet.
    pub fn auth_server_addr(&self) -> Option<SocketAddr> {
        let rstate = self.state.read().expect("no fail");
        rstate.auth_server.addr
    }

    /// Add the authorization server API address.
    pub fn set_auth_server_addr(&self, addr: SocketAddr) {
        let mut sstate = self.state.write().unwrap();
        sstate.auth_server.addr = Some(addr);
    }

    /// Gets the given endhost-api's socket address.
    ///
    /// Returns `None` if the address hasn't been set yet.
    pub fn endhost_api_addr(&self, id: EndhostApiId) -> Option<SocketAddr> {
        self.state.read().unwrap().endhost_apis.get(&id).cloned()
    }

    /// Sets the given endhost-api's socket address.
    pub fn set_endhost_api_addr(&self, id: EndhostApiId, addr: SocketAddr) {
        self.state.write().unwrap().endhost_apis.insert(id, addr);
    }
}

/// PocketSCION SNAP I/O configuration.
#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct SnapIoConfig {
    /// The control plane I/O configuration.
    pub control_plane: ControlPlaneIoConfig,
    /// The data plane I/O configurations.
    pub data_planes: BTreeMap<DataPlaneId, TunnelGatewayIoConfig>,
}

impl From<&SnapIoConfig> for IoSnapConfigDto {
    fn from(value: &SnapIoConfig) -> Self {
        IoSnapConfigDto {
            control_plane: (&value.control_plane).into(),
            data_planes: value
                .data_planes
                .iter()
                .map(|(id, config)| (*id, config.into()))
                .collect(),
        }
    }
}

impl TryFrom<IoSnapConfigDto> for SnapIoConfig {
    type Error = anyhow::Error;

    fn try_from(value: IoSnapConfigDto) -> Result<Self, Self::Error> {
        let data_planes = value
            .data_planes
            .into_iter()
            .map(|(dp_id, dp_ip_config)| {
                Ok((
                    dp_id,
                    dp_ip_config
                        .try_into()
                        .with_context(|| format!("Invalid data plane config ({dp_id})"))?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        Ok(Self {
            control_plane: value.control_plane.try_into()?,
            data_planes,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use snap_dataplane::state::Id;

    use super::*;

    #[test]
    fn should_convert_to_dto_and_back_without_data_loss() {
        let io_config = SharedPocketScionIoConfig::new();
        let tunnel_addr = "127.0.0.1:9000".parse().unwrap();

        let cp_api = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 9002));
        let snap_id = SnapId::from_usize(1);
        let dp_id = SnapDataPlaneId::new(snap_id, DataPlaneId::from_usize(1));

        io_config.set_snap_control_addr(snap_id, cp_api);
        io_config.set_snap_data_plane_addr(dp_id, tunnel_addr);
        let before = io_config.state.read().unwrap().clone();

        let dto_io_config = io_config.to_dto();
        let after = IoConfig::try_from(dto_io_config).expect("failed to convert back");

        assert_eq!(before, after);
    }
}
