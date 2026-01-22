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
// limitations under the License.'
//! Tunnel gateway dispatcher.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use scion_proto::{
    packet::{ScionPacketRaw, classify_scion_packet},
    wire_encoding::WireEncodeVec,
};
use scion_sdk_token_validator::validator::Token;
use serde::Deserialize;
use snap_tun::server_deprecated::{AddressAssignmentError, SendPacketError};
use tokio::sync::mpsc::{Receiver, Sender, error::TrySendError};

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{metrics::TunnelGatewayDispatcherMetrics, state::SharedTunnelGatewayState},
};

const DISPATCHER_CHANNEL_SIZE: usize = 10000;

/// Tunnel gateway dispatcher.
#[derive(Debug, Clone)]
pub struct TunnelGatewayDispatcher<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    sender: Sender<ScionPacketRaw>,
    receiver: Arc<Mutex<Option<Receiver<ScionPacketRaw>>>>,
    state: SharedTunnelGatewayState<T>,
    metrics: TunnelGatewayDispatcherMetrics,
}

impl<T> TunnelGatewayDispatcher<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    /// Create new tunnel gateway dispatcher instance.
    pub fn new(
        state: SharedTunnelGatewayState<T>,
        metrics: TunnelGatewayDispatcherMetrics,
    ) -> Self {
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<ScionPacketRaw>(DISPATCHER_CHANNEL_SIZE);

        Self {
            sender,
            receiver: Arc::new(Mutex::new(Some(receiver))),
            state,
            metrics,
        }
    }

    /// Start dispatching packets received from the LAN gateway to the corresponding SNAP tunnels.
    pub async fn start_dispatching(&self) -> std::io::Result<()> {
        let mut receiver = self.receiver.lock().unwrap().take().unwrap();

        while let Some(packet) = receiver.recv().await {
            self.metrics.dispatch_queue_size.dec();

            // Classify so we can get the port (if any)
            // XXX: Another packet duplication that should disappear.
            let classification = match classify_scion_packet(packet.clone()) {
                Ok(c) => c,
                Err(e) => {
                    self.metrics.invalid_packets_errors.inc();
                    tracing::debug!(error=%e, "Failed to classify packet");
                    continue;
                }
            };

            let Some(dest_addr) = classification.destination() else {
                self.metrics.invalid_packets_errors.inc();
                tracing::debug!("Could not deduce destination socket address after classification");
                continue;
            };

            let Some(mut sock_addr) = dest_addr.local_address() else {
                self.metrics.invalid_packets_errors.inc();
                tracing::debug!("Found invalid service address");
                continue;
            };
            let mut tun = self.state.get_mapped_tunnel(sock_addr);
            if tun.is_none() {
                // XXX: If we can't find the entry for a specific port, we try with
                // a wildcard ISD-AS and port.
                sock_addr.set_port(0);
                tun = self.state.get_mapped_tunnel(sock_addr);
            }

            match tun {
                Some(tun) => {
                    let raw: Bytes = packet.encode_to_bytes_vec().concat().into();
                    tracing::trace!(remote = %tun.remote_underlay_address(), remote_virt_addr = %dest_addr, pkt_len=%raw.len(), "Dispatching packet");
                    if let Err(e) = tun.send(raw) {
                        match e {
                            SendPacketError::ConnectionClosed => {
                                self.metrics.connection_closed_errors.inc()
                            }
                            SendPacketError::NewAssignedAddress(_) => {
                                self.metrics.new_assigned_address_errors.inc()
                            }
                            SendPacketError::AddressAssignmentError(
                                AddressAssignmentError::NoAddressAssigned,
                            ) => self.metrics.no_address_assigned_errors.inc(),
                            SendPacketError::SendDatagramError(_) => {
                                self.metrics.send_datagram_errors.inc()
                            }
                        }
                    }
                }
                _ => {
                    // No tunnel available for the destination address, drop the packet.
                    self.metrics.missing_tunnel_errors.inc();
                    tracing::debug!(addr=%dest_addr, "No tunnel mapping found for addr");
                }
            }
        }

        tracing::info!("Tunnel gateway dispatcher stopped");
        Ok(())
    }
}

impl<T> Dispatcher for TunnelGatewayDispatcher<T>
where
    T: for<'de> Deserialize<'de> + Token + Clone,
{
    /// Try dispatching a packet to the channel worked on by the tunnel gateway (LAN gateway ->
    /// tunnel gateway dispatcher channel).
    fn try_dispatch(&self, packet: ScionPacketRaw) {
        match self.sender.try_send(packet) {
            Ok(_) => self.metrics.dispatch_queue_size.inc(),
            Err(err) => {
                match err {
                    TrySendError::Full(_) => self.metrics.full_dispatch_queue_errors.inc(),
                    TrySendError::Closed(_) => self.metrics.closed_dispatch_queue_errors.inc(),
                }
            }
        }
    }
}
