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
//! PocketSCION network receivers.

use scion_proto::{packet::ScionPacketRaw, wire_encoding::WireEncodeVec};
use sciparse::{core::view::View, packet::view::ScionPacketView};
use snap_dataplane::{dispatcher::Dispatcher, tunnel_gateway::dispatcher::TunnelGatewayDispatcher};

pub mod router_socket;

/// A simulated network receiver that can receive packets from the network simulation.
///
/// NOTE: Receivers **MUST NOT** try to aquire a write lock on the `SharedPocketScionState` in their
/// `receive_packet` method, as the network simulation is holding this lock during dispatch.
pub trait Receiver: Sync + Send {
    /// Callback called by the network simulation to deliver a packet to this receiver.
    fn receive_packet(&self, packet: ScionPacketRaw);
}

impl Receiver for TunnelGatewayDispatcher {
    fn receive_packet(&self, packet: ScionPacketRaw) {
        // XXX(uniquefine):
        // Encode the owned packet back to bytes and wrap in a zero-copy view for dispatch.
        // This conversion is an acknowledged temporary seam: the network simulator still passes
        // ScionPacketRaw, so we must re-encode here. A follow-up will migrate NetworkSimulator to
        // pass ScionPacketView directly.
        let bytes = packet.encode_to_bytes_vec().concat();
        match ScionPacketView::from_slice(&bytes) {
            Ok((view, _)) => self.try_dispatch(view),
            Err(e) => {
                tracing::debug!(error=?e, "TunnelGatewayDispatcher: failed to parse ScionPacketRaw as view");
            }
        }
    }
}
