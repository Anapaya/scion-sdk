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

//! Runtime API for PocketSCION.

use std::net::{IpAddr, SocketAddr};

use sciparse::{
    identifier::isd_asn::IsdAsn,
    packet::view::ScionRawPacketView,
    path::{ScionPath, combinator::combine},
};

use crate::{
    comp::{
        endhost_api::EndhostApiId, endhost_api_discovery::EndhostApiDiscoveryApiId,
        router::RouterId, sim_network_stack::NetSimStack, snap::SnapId,
    },
    io_config::IoConfig,
    network::scion::{routing::ScionNetworkTime, segment::lister::types::ListPathSegments},
    runtime::PocketScionRuntime,
    state::PocketScionStateInner,
};

// General
impl PocketScionRuntime {
    /// Returns a snapshot of the current state of the system.
    ///
    /// The returned state is a copy of the current state and will not reflect any changes made to
    /// the system after the snapshot was taken.
    pub fn state_snapshot(&self) -> PocketScionStateInner {
        self.state.read().clone()
    }

    /// Returns a copy of the system's IO configuration.
    pub fn io_config(&self) -> IoConfig {
        IoConfig::from_inner(self.io_config.read().clone())
    }
}

// TODO: If we use this to provide all runtime APIs, we will have to mirror a lot of functions from
// the State here.
//
// We should consider if there is a pattern where we have to implement these functions only once
// (e.g. in the state) and let the user call them directly. ATM the problem is that it's unclear
// which functions on the State may be called after starting the runtime. Since the state is an ARC,
// using mutability as a signal is not really possible.

// Paths
impl PocketScionRuntime {
    /// Returns valid Segments from `src` to `dst` as raw SCION packets, if they exist.
    ///
    /// ### Parameters
    /// - `src`: Source ISD-AS for the path lookup.
    /// - `dst`: Destination ISD-AS for the path lookup.
    /// - `valid_after`: Returned paths are valid after this timestamp.
    pub fn segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        valid_after: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<ListPathSegments> {
        let sguard = self.state.read();
        let segments = sguard
            .segment_registry
            .endhost_list_segments(src, src, dst)?;

        segments.into_path_segments(&sguard.topology, valid_after, 0, 255)
    }

    /// Returns valid Paths from `src` to `dst` as raw SCION packets, if they exist.
    ///
    /// ### Parameters
    /// - `src`: Source ISD-AS for the path lookup.
    /// - `dst`: Destination ISD-AS for the path lookup.
    /// - `valid_after`: Returned paths are valid after this timestamp.
    pub fn paths(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        valid_after: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<ScionPath>> {
        let sguard = self.state.read();
        let segments = sguard
            .segment_registry
            .endhost_list_segments(src, src, dst)?;

        let (core_segments, non_core_segments) = {
            let segs = segments.into_path_segments(&sguard.topology, valid_after, 0, 255)?;

            (segs.core, segs.down.into_iter().chain(segs.up).collect())
        };

        Ok(combine(src, dst, core_segments, non_core_segments))
    }
}

// Addresses
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

    /// Returns the listening socket address of the network forwarder registered at the given AS and
    /// IP, if it exists.
    pub fn network_forwarder_addr(&self, isd_asn: IsdAsn, ip: IpAddr) -> Option<SocketAddr> {
        self.io_config.network_forwarder_addr(isd_asn, ip)
    }
}

// Networking
impl PocketScionRuntime {
    /// Changes the state of a link in the topology.
    ///
    /// Returns the previous state of the link if it exists, or None if the link does not exist.
    pub fn set_link_state(&self, isd_asn: IsdAsn, link_id: u16, up: bool) -> Option<bool> {
        self.state.set_link_state(isd_asn, link_id, up)
    }

    /// Binds a network stack`` to the given address and registers it as a simulation receiver for
    /// the given AS.
    ///
    /// Essentially this method allows you to create "virtual" IP devices that are connected to the
    /// PocketSCION network simulation. You can bind multiple `NetSimStack`s to the same AS, and
    /// they will be able to communicate with each other and with other entities in the AS through
    /// the network simulation.
    ///
    ///
    /// See [NetSimStack] for more details.
    pub fn bind_sim_network_stack(
        &self,
        local_as: IsdAsn,
        bind_addr: IpAddr,
        queue_size: usize,
    ) -> anyhow::Result<NetSimStack> {
        NetSimStack::bind(self.state.clone(), local_as, bind_addr, queue_size)
    }

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
        packet: &mut ScionRawPacketView,
    ) {
        self.state
            .dispatch_to_network_sim(local_as, local_interface, now, packet);
    }
}
