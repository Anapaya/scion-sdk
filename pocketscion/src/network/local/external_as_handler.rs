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
//! Custom AS behavior for external ASes in the network simulation.
//!
//! Allows to define custom behavior for ASes that are marked as external in the topology.

use scion_proto::packet::ScionPacketRaw;

use crate::network::scion::topology::ScionGlobalInterfaceId;

/// Handler for processing packets targeting external ASes in the network simulation.
pub trait ExternalAsHandler: Sync + Send {
    /// Defines how a packet should be processed when targeting an external AS.
    ///
    /// # Parameters:
    /// - `from_interface`: The IsdAsn and Interface ID from which the packet is sent.
    /// - `to_interface`: The IsdAsn and Interface ID to which the packet is being sent.
    /// - `packet`: The raw SCION packet that is being processed.
    ///
    /// NOTE: Adapter **MUST NOT** try to lock the `SharedPocketScionState` in their
    /// `receive_packet` method, as the network simulation is holding this lock during dispatch.
    fn handle_incoming_packet(
        &self,
        from_interface: ScionGlobalInterfaceId,
        to_interface: ScionGlobalInterfaceId,
        packet: &mut ScionPacketRaw,
    );
}
