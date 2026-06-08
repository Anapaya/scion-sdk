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

//! Pocket SCION AS Router component.
//!
//! The Router component emulates a SCION AS router, which is responsible for routing SCION traffic
//! from inside the AS to the outside.
//!
//! A router here allows external sockets (e.g. from the host) to send SCION traffic into the
//! simulated network, and vice versa.

use std::{collections::BTreeMap, net::SocketAddr, num::NonZero};

use derive_more::Display;
use ipnet::IpNet;
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use snap_dataplane::state::Id;
use utoipa::ToSchema;

use crate::state::PocketScionState;

/// The router identifier.
#[derive(
    Debug,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(transparent)]
pub struct RouterId(usize);

impl RouterId {
    /// Creates a new `RouterId` from a `usize`.
    pub fn new(val: usize) -> Self {
        Self(val)
    }
}

impl Id for RouterId {
    fn as_usize(&self) -> usize {
        self.0
    }

    fn from_usize(val: usize) -> Self {
        Self(val)
    }
}

/// The state of a SCION router emulated by PocketScion.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RouterState {
    /// The ISD-AS of the router.
    pub isd_as: IsdAsn,
    /// The SCION interface IDs of the router.
    #[schema(value_type = Vec<u16>, example = json!([1, 2, 3]))]
    pub if_ids: Vec<NonZero<u16>>,
    /// The SNAP data planes that are connected to the router.
    /// Data plane ID -> udp underlay address
    #[schema(value_type = BTreeMap<String, String>)]
    pub snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
    /// Networks towards which SCION traffic will not be routed through
    /// the available SNAPs.
    #[schema(value_type = Vec<String>)]
    pub snap_data_plane_excludes: Vec<IpNet>,
}

// Router Mode
impl PocketScionState {
    /// Adds a new router.
    pub fn add_router(
        &mut self,
        isd_as: IsdAsn,
        if_ids: Vec<NonZero<u16>>,
        snap_data_plane_excludes: Vec<IpNet>,
        snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
    ) -> RouterId {
        let mut sstate = self.write();
        let router_id = RouterId::from_usize(sstate.routers.len());

        sstate.routers.insert(
            router_id,
            RouterState {
                isd_as,
                if_ids,
                snap_data_plane_excludes,
                snap_data_plane_interfaces,
            },
        );
        router_id
    }

    /// Returns a map of all Routers
    pub(crate) fn routers(&self) -> BTreeMap<RouterId, RouterState> {
        let sstate = self.read();
        sstate.routers.clone()
    }

    /// Returns the cloned state of the given router
    pub(crate) fn router(&self, router_id: RouterId) -> Option<RouterState> {
        self.read().routers.get(&router_id).cloned()
    }

    /// Returns a vec of all RouterIds
    pub(crate) fn router_ids(&self) -> Vec<RouterId> {
        let sstate = self.read();
        sstate.routers.keys().cloned().collect()
    }
}
