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

//! Network simulation related functions

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use ipnet::IpNet;
use scion_proto::address::{IsdAsn, ServiceAddr};

use crate::{
    network::{
        local::receivers::Receiver,
        scion::{
            segment::registry::SegmentRegistry,
            topology::{FastTopologyLookup, ScionTopology},
        },
    },
    state::PocketScionState,
};

// Network Sim
impl PocketScionState {
    /// Applies the given topology to the system state.
    /// If a topology is applied, pocket SCION will simulate the routing of packets.
    pub fn set_topology(&mut self, topology: ScionTopology) {
        let segment_store = SegmentRegistry::new(&FastTopologyLookup::new(&topology));
        let mut state_write_guard = self.write();

        state_write_guard.topology = topology;
        state_write_guard.segment_registry = segment_store;
    }

    /// Sets the state of a link in the topology.
    ///
    /// If the link does not exist, None is returned.
    /// Otherwise, the state of the link is updated and the previous state is returned.
    pub fn set_link_state(&self, isd_asn: IsdAsn, link_id: u16, up: bool) -> Option<bool> {
        let mut state_write_guard = self.write();
        state_write_guard
            .topology
            .mut_scion_link(&isd_asn, link_id)
            .map(|link| {
                let previous_state = link.is_up;
                link.set_is_up(up);
                previous_state
            })
    }

    /// Adds a wildcard receiver for the given ISD-AS to the network simulation.
    pub fn add_wildcard_sim_receiver(
        &self,
        ias: IsdAsn,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let mut state = self.write();
        state
            .sim_receivers
            .add_wildcard_receiver(ias, receiver)
            .context("error adding wildcard receiver")?;

        Ok(())
    }

    /// Adds a receiver bound to the given ISD-AS and IpNet to the network simulation.
    pub fn add_sim_receiver(
        &self,
        ias: IsdAsn,
        ipnet: IpNet,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let mut state = self.write();
        state
            .sim_receivers
            .add_receiver(ias, ipnet, receiver)
            .context("error adding receiver")?;

        Ok(())
    }

    /// Adds a mapping from the given ISD-AS and ServiceAddr to the given transport and socket
    /// address.
    pub fn add_svc_mapping(
        &self,
        ia: IsdAsn,
        dst_svc: ServiceAddr,
        transport: String,
        socket_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let mut state = self.write();
        state
            .sim_receivers
            .add_svc_mapping(ia, dst_svc, transport, socket_addr)
    }
}
