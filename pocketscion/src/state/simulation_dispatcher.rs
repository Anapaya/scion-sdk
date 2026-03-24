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
//! Dispatchers sending packets into the [NetworkSimulator]

use scion_proto::{address::IsdAsn, packet::ScionPacketRaw, wire_encoding::WireDecode};
use sciparse::{core::view::View, packet::view::ScionPacketView};
use snap_dataplane::dispatcher::Dispatcher;

use crate::{
    network::{scion::routing::ScionNetworkTime, simulator::NetworkSimulator},
    state::SharedPocketScionState,
};

/// Dispatches packets into the [NetworkSimulator]
///
/// Bound to a specific AS
pub(crate) struct AsNetSimDispatcher {
    local_as: IsdAsn,
    app_state: SharedPocketScionState,
}

impl AsNetSimDispatcher {
    pub(crate) fn new(local_as: IsdAsn, app_state: SharedPocketScionState) -> Self {
        Self {
            local_as,
            app_state,
        }
    }
}

impl Dispatcher for AsNetSimDispatcher {
    fn try_dispatch(&self, packet: &ScionPacketView) {
        // TODO(uniquefine): migrate NetworkSimulator to ScionPacketView
        let packet = match ScionPacketRaw::decode(&mut packet.as_bytes()) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error=%e, "AsNetSimDispatcher: failed to decode ScionPacketView");
                return;
            }
        };
        let network_time = ScionNetworkTime::now();
        self.app_state
            .dispatch_to_network_sim(self.local_as, 0, network_time, packet);
    }
}

/// Dispatches packets into the [NetworkSimulator]
///
/// Uses the packet's source address to determine the AS
pub(crate) struct NetSimDispatcher {
    app_state: SharedPocketScionState,
}

impl NetSimDispatcher {
    pub(crate) fn new(app_state: SharedPocketScionState) -> Self {
        Self { app_state }
    }
}

impl Dispatcher for NetSimDispatcher {
    fn try_dispatch(&self, packet: &ScionPacketView) {
        // TODO(uniquefine): migrate NetworkSimulator to ScionPacketView
        let packet = match ScionPacketRaw::decode(&mut packet.as_bytes()) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error=%e, "NetSimDispatcher: failed to decode ScionPacketView");
                return;
            }
        };
        let network_time = ScionNetworkTime::now();

        self.app_state.dispatch_to_network_sim(
            packet.headers.address.ia.source,
            0,
            network_time,
            packet,
        );
    }
}

impl SharedPocketScionState {
    /// Dispatches a packet into the Network Simulator, using the given AS as the source.
    ///
    /// ## Parameters:
    /// - `local_as`: The AS where the packet is being processed.
    /// - `local_interface`: Interface where the packet is being processed. 0 means packet
    ///   originated in the AS.
    /// - `now`: The current network time, used for scheduling the packet in the simulator.
    /// - `packet`: The raw SCION packet to be dispatched.
    pub fn dispatch_to_network_sim(
        &self,
        local_as: IsdAsn,
        local_interface: u16,
        now: ScionNetworkTime,
        packet: ScionPacketRaw,
    ) {
        let state_guard = self.system_state.read().unwrap();

        NetworkSimulator::new(
            &state_guard.sim_receivers,
            &state_guard.extern_as_handlers,
            state_guard.topology.as_ref(),
        )
        .dispatch(local_as, local_interface, now, packet);
    }
}
