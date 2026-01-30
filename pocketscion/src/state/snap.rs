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

//! Pocket SCION SNAP state management.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{Arc, RwLock},
};

use derive_more::Display;
use pem::Pem;
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use snap_control::{
    crpc_api::api_service::model::{SnapDataPlane, SnapDataPlaneResolver},
    model::{SnapUnderlay, UdpUnderlay, UnderlayDiscovery},
};
use snap_dataplane::state::Id;
use utoipa::ToSchema;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    dto::SnapStateDto,
    io_config::SharedPocketScionIoConfig,
    state::{SharedPocketScionState, SystemState},
};

/// The path prefix for deterministic derivation of the SNAP's static secret.
pub const SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL: &str = "snaptun_server_private_key";

/// Pocket SCION SNAP state.
#[derive(Debug, PartialEq, Clone)]
pub struct SnapState {
    pub(crate) isd_as: IsdAsn,
}

impl SnapState {
    // List all ases this snap is connected to
    pub(crate) fn isd_ases(&self) -> Vec<IsdAsn> {
        // might be extended in the future to support multiple ASes
        vec![self.isd_as]
    }
}

impl From<SnapState> for SnapStateDto {
    fn from(value: SnapState) -> Self {
        Self {
            isd_as: value.isd_as,
        }
    }
}

impl TryFrom<SnapStateDto> for SnapState {
    type Error = anyhow::Error;

    fn try_from(value: SnapStateDto) -> Result<Self, Self::Error> {
        Ok(Self {
            isd_as: value.isd_as,
        })
    }
}

/// The SNAP identifier.
#[derive(
    Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(transparent)]
pub struct SnapId(usize);

impl TryFrom<String> for SnapId {
    type Error = <usize as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(SnapId::from_usize(s.parse()?))
    }
}

impl Id for SnapId {
    fn as_usize(&self) -> usize {
        self.0
    }

    fn from_usize(val: usize) -> Self {
        Self(val)
    }
}

// Shared State Snap Functions
impl SharedPocketScionState {
    /// Adds a new SNAP to the system state and returns its id.
    pub fn add_snap(&mut self, isd_as: IsdAsn) -> anyhow::Result<SnapId> {
        let mut system_state = self.system_state.write().unwrap();

        let snap_id = SnapId::from_usize(system_state.snaps.len());

        let existing_ases: BTreeSet<IsdAsn> =
            system_state.snaps.values().map(|s| s.isd_as).collect();

        if existing_ases.contains(&isd_as) {
            anyhow::bail!("A SNAP for ISD-AS {} already exists", isd_as);
        }

        system_state.snaps.insert(snap_id, SnapState { isd_as });

        Ok(snap_id)
    }

    /// Returns a map of all Snaps
    pub fn snaps(&self) -> BTreeMap<SnapId, SnapState> {
        let sstate = self.system_state.read().unwrap();
        sstate.snaps.clone()
    }

    /// Returns a vector of all existing SnapIds
    pub fn snaps_ids(&self) -> Vec<SnapId> {
        let sstate = self.system_state.read().unwrap();
        sstate.snaps.keys().cloned().collect()
    }

    /// Set the public key used to verify SNAP tokens.
    pub fn set_snap_token_public_pem(&mut self, pem: Pem) {
        let mut system_state = self.system_state.write().unwrap();
        system_state.snap_token_public_pem = pem;
    }

    /// Gets the public key used to verify SNAP tokens
    pub fn snap_token_public_key(&self) -> Pem {
        let sstate = self.system_state.read().unwrap();
        sstate.snap_token_public_pem.clone()
    }

    /// Returns all local IsdAses of a snap
    pub fn snap_isd_ases(&self, id: SnapId) -> Option<Vec<IsdAsn>> {
        self.system_state
            .read()
            .unwrap()
            .snaps
            .get(&id)
            .map(|s| s.isd_ases())
    }

    /// Get the [SnapDataPlaneDiscoveryHandle] of a specific snap
    pub(crate) fn snap_data_plane_discovery(
        &self,
        snap_id: SnapId,
        io_config: SharedPocketScionIoConfig,
    ) -> SnapDataPlaneDiscoveryHandle {
        SnapDataPlaneDiscoveryHandle {
            snap_id,
            system_state: self.system_state.clone(),
            io_config,
        }
    }

    /// Get the [SnapResolverHandle] of a specific snap
    pub(crate) fn snap_resolver(
        &self,
        snap_id: SnapId,
        io_config: SharedPocketScionIoConfig,
    ) -> SnapResolverHandle {
        SnapResolverHandle {
            snap_id,
            system_state: self.system_state.clone(),
            io_config,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SnapDataPlaneDiscoveryHandle {
    snap_id: SnapId,
    system_state: Arc<RwLock<SystemState>>,
    io_config: SharedPocketScionIoConfig,
}

impl UnderlayDiscovery for SnapDataPlaneDiscoveryHandle {
    fn list_snap_underlays(&self) -> Vec<SnapUnderlay> {
        let sstate = self.system_state.read().unwrap();
        let snap = sstate.snaps.get(&self.snap_id).expect("SNAP not found");

        let isd_ases: Vec<IsdAsn> = snap.isd_ases().into_iter().collect();

        self.io_config
            .snap_data_plane_addr(self.snap_id)
            .map(|address| vec![SnapUnderlay { address, isd_ases }])
            .unwrap_or_default()
    }

    fn list_udp_underlays(&self) -> Vec<UdpUnderlay> {
        vec![] // XXX(ake): Currently no mixed mode with both UDP and SNAP data planes is supported
    }
}

pub(crate) struct SnapResolverHandle {
    snap_id: SnapId,
    #[allow(unused)]
    system_state: Arc<RwLock<SystemState>>,
    io_config: SharedPocketScionIoConfig,
}

impl SnapDataPlaneResolver for SnapResolverHandle {
    fn get_data_plane_address(
        &self,
        _endhost_ip: std::net::IpAddr,
    ) -> Result<
        snap_control::crpc_api::api_service::model::SnapDataPlane,
        (http::StatusCode, anyhow::Error),
    > {
        let public_key = {
            let root_secret = self.system_state.read().unwrap().root_secret();
            let key = root_secret.derive_from_iter(vec![
                SNAPTUN_SERVER_PRIVATE_KEY_NODE_LABEL.into(),
                self.snap_id.to_string().into(),
            ]);
            PublicKey::from(&StaticSecret::from(key.as_array()))
        };
        Ok(SnapDataPlane {
            address: self
                .io_config
                .snap_data_plane_addr(self.snap_id)
                .ok_or_else(|| {
                    (
                        http::StatusCode::NOT_FOUND,
                        anyhow::anyhow!("No data plane available"),
                    )
                })?,
            snap_tun_control_address: self.io_config.snap_control_addr(self.snap_id),
            snap_static_x25519: Some(public_key),
        })
    }
}
