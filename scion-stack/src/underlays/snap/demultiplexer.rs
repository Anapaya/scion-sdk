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

use std::sync::{Arc, Weak};

use bytes::Bytes;
use scion_proto::{
    address::SocketAddr,
    packet::{
        PacketClassification, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp,
        classify_scion_packet,
    },
    wire_encoding::WireDecode as _,
};
use tokio::{
    sync::mpsc::{Sender, error::TrySendError},
    time,
};

use crate::{scionstack::ScmpHandler, snap_tunnel::SnapTunnel};

/// Handle to [DemultiplexerHost] allowing registration of new sockets
pub struct DemultiplexerHandle {
    handle: Weak<DemultiplexerState>,
}
impl DemultiplexerHandle {
    /// Register an SCMP receiver for the given address.
    /// The sender will be cleaned up eventually after the receiver is closed.
    pub fn register_scmp_receiver(
        &self,
        addr: SocketAddr,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<(), RegistrationError> {
        tracing::trace!(%addr, "Registering SCMP handler");
        self.handle
            .upgrade()
            .ok_or(RegistrationError::ConnectionClosed)?
            .scmp_receivers
            .add_entry(addr, sender)
    }

    /// Register a UDP receiver for the given address.
    /// The sender will be cleaned up eventually after the receiver is closed.
    pub fn register_udp_receiver(
        &self,
        addr: SocketAddr,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<(), RegistrationError> {
        tracing::trace!(%addr, "Registering UDP handler");
        self.handle
            .upgrade()
            .ok_or(RegistrationError::ConnectionClosed)?
            .udp_receivers
            .add_entry(addr, sender)
    }

    /// Register a raw receiver for the given address.
    /// The sender will be cleaned up eventually after the receiver is closed.
    pub fn register_raw_receiver(
        &self,
        addr: SocketAddr,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<(), RegistrationError> {
        tracing::trace!(%addr, "Registering raw handler");
        self.handle
            .upgrade()
            .ok_or(RegistrationError::ConnectionClosed)?
            .raw_receivers
            .add_entry(addr, sender)
    }
}

struct DemultiplexerState {
    udp_receivers: Dispatcher<ScionPacketRaw>,
    raw_receivers: Dispatcher<ScionPacketRaw>,
    scmp_receivers: Dispatcher<ScionPacketRaw>,
    default_scmp_handler: Arc<dyn ScmpHandler>,
}

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("port already in use")]
    PortAlreadyInUse,
    #[error("SNAP underlay disconnected")]
    ConnectionClosed,
}

impl DemultiplexerState {
    fn new(default_scmp_handler: Arc<dyn ScmpHandler>) -> Self {
        Self {
            scmp_receivers: Dispatcher::new(),
            udp_receivers: Dispatcher::new(),
            raw_receivers: Dispatcher::new(),
            default_scmp_handler,
        }
    }

    fn cleanup_closed_senders(&self) {
        self.udp_receivers.cleanup_closed_senders();
        self.scmp_receivers.cleanup_closed_senders();
        self.raw_receivers.cleanup_closed_senders();
    }

    fn dispatch_udp(&self, addr: SocketAddr, packet: ScionPacketUdp) {
        self.udp_receivers.dispatch(addr, packet.into());
    }

    fn dispatch_scmp(&self, addr: SocketAddr, packet: ScionPacketScmp) {
        self.scmp_receivers.dispatch(addr, packet.into());
    }

    fn dispatch_raw(&self, addr: SocketAddr, packet: ScionPacketRaw) {
        self.raw_receivers.dispatch(addr, packet);
    }
}

pub struct DemultiplexerHost {
    underlay_receiver: std::sync::Arc<SnapTunnel>,
    state: Arc<DemultiplexerState>,
    // TODO(uniquefine): Add metrics:
    // - packets_received_total: How many packets are read from the underlay. Labels: kind (udp,
    //   scmp, unknown, invalid)
    // - dispatch_errors_total: How many errors were encountered while dispatching packets to the
    //   handlers. Labels: kind (udp, scmp, raw), reason (send_queue_full, invalid_scmp,
    //   invalid_udp)
    // - active_sockets_total: How many sockets are currently active (receivers are alive). Labels:
    //   kind (udp, scmp, raw)
}

impl DemultiplexerHost {
    pub fn new(
        underlay_receiver: std::sync::Arc<SnapTunnel>,
        default_scmp_handler: Arc<dyn ScmpHandler>,
    ) -> Self {
        Self {
            underlay_receiver,
            state: DemultiplexerState::new(default_scmp_handler).into(),
        }
    }

    pub fn handle(&self) -> DemultiplexerHandle {
        DemultiplexerHandle {
            handle: Arc::downgrade(&self.state),
        }
    }

    /// Main dispatch loop - should be run in its own task
    /// This will run until the underlay receiver is closed or an error occurs.
    pub async fn main_loop(mut self) {
        let mut cleanup_timer = time::interval(time::Duration::from_secs(30));
        loop {
            tokio::select! {
                biased;
                // Prioritize receiving incoming packets.
                result = self.underlay_receiver.read_datagram() => {
                    match result {
                        Ok(raw_data) => self.dispatch_packet(raw_data).await,
                        Err(err) => {
                            // TODO: this error never bubbles up and is never properly handled, it
                            // just stops the main loop
                            tracing::error!(%err, "Failed to receive datagram");
                            break;
                        }
                    }
                }
                _ = cleanup_timer.tick() => {
                    self.state.cleanup_closed_senders();
                }
            }
        }

        tracing::info!("SNAP underlay demultiplexer exiting")
    }

    async fn dispatch_packet(&mut self, mut raw_data: Bytes) {
        let packet = match ScionPacketRaw::decode(&mut raw_data) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to decode SCION packet, dropping");
                return;
            }
        };
        // Classify the SCION packet
        let classified_packet = match classify_scion_packet(packet) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to classify SCION packet, dropping");
                // TODO: increment counter for malformed packets
                return;
            }
        };

        let dst_addr = classified_packet.destination();

        match classified_packet {
            PacketClassification::Udp(udp_packet) => {
                self.dispatch_udp_packet(udp_packet, dst_addr);
            }
            PacketClassification::ScmpWithDestination(_, scmp_packet)
            | PacketClassification::ScmpWithoutDestination(scmp_packet) => {
                self.dispatch_scmp_packet(scmp_packet, dst_addr).await;
            }
            PacketClassification::Other(raw_packet) => {
                // TODO: increment counter for unknown protocols
                tracing::debug!(
                    proto_id = %raw_packet.headers.common.next_header,
                    "Received SCION packet with unknown protocol, dropping",
                );
            }
        }
    }

    fn dispatch_udp_packet(&mut self, udp_packet: ScionPacketUdp, dst_addr: Option<SocketAddr>) {
        let dst_addr: SocketAddr = match dst_addr {
            Some(addr) => addr,
            _ => {
                tracing::debug!("Received UDP packet without valid destination address, dropping");
                return;
            }
        };

        // Udp packets get dispatched to the UDP handler and a copy to the raw handler
        self.state.dispatch_udp(dst_addr, udp_packet.clone());
        self.state.dispatch_raw(dst_addr, udp_packet.into());
    }

    async fn dispatch_scmp_packet(
        &mut self,
        scmp_packet: ScionPacketScmp,
        dst_addr: Option<SocketAddr>,
    ) {
        match dst_addr {
            Some(dst_addr) => {
                self.state.dispatch_scmp(dst_addr, scmp_packet.clone());
                self.state
                    .dispatch_raw(dst_addr, scmp_packet.clone().into());
                self.state
                    .default_scmp_handler
                    .handle_packet(scmp_packet)
                    .await;
            }
            None => {
                self.state
                    .default_scmp_handler
                    .handle_packet(scmp_packet)
                    .await
            }
        };
    }
}

/// Dispatcher is a thread-safe map of packet senders indexed by address.
/// It can dispatch packets to the senders for the given address.
/// Cleanup of closed senders is done lazily.
struct Dispatcher<P>(scc::HashMap<SocketAddr, Sender<P>>);

impl<P: 'static> Dispatcher<P> {
    fn new() -> Self {
        Self(scc::HashMap::new())
    }

    // Add an entry to the dispatcher. If an alive sender with the same address already exists,
    // the operation is aborted with a PortAlreadyInUse error.
    fn add_entry(&self, addr: SocketAddr, sender: Sender<P>) -> Result<(), RegistrationError> {
        match self.0.entry_sync(addr) {
            scc::hash_map::Entry::Occupied(mut entry) => {
                if entry.is_closed() {
                    *entry = sender;
                } else {
                    return Err(RegistrationError::PortAlreadyInUse);
                }
            }
            scc::hash_map::Entry::Vacant(entry) => {
                entry.insert_entry(sender);
            }
        }
        Ok(())
    }

    // Remove all closed senders from the dispatcher.
    // This should be called periodically to avoid memory leaks.
    fn cleanup_closed_senders(&self) {
        self.0.retain_sync(|_, sender| !sender.is_closed());
    }

    // Dispatch a packet to the receiver for the given address.
    fn dispatch(&self, addr: SocketAddr, packet: P) {
        if let Some(entry) = self.0.get_sync(&addr) {
            match entry.try_send(packet) {
                Ok(_) => {
                    tracing::trace!(addr=%addr, "Dispatched packet to receiver");
                }
                Err(TrySendError::Closed(_)) => {
                    let _ = entry.remove();
                }
                Err(TrySendError::Full(_)) => {
                    tracing::warn!(addr=%addr, "Receive channel is full, dropping packet");
                }
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;

    static TEST_ADDR: std::sync::LazyLock<SocketAddr> =
        std::sync::LazyLock::new(|| "[1-ff00:0:110,10.0.0.1]:8080".parse().unwrap());

    // Add sender, dispatch -> Ok, value is received
    #[test(tokio::test)]
    async fn should_successfully_dispatch() {
        let dispatcher: Dispatcher<u32> = Dispatcher::new();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        dispatcher.dispatch(*TEST_ADDR, 1);
        assert_eq!(rx.recv().await.unwrap(), 1);
    }

    // Add sender, add another sender -> Error, PortAlreadyInUse
    #[test(test)]
    fn should_fail_if_port_is_already_in_use() {
        let dispatcher: Dispatcher<u32> = Dispatcher::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        let (tx, _) = tokio::sync::mpsc::channel::<u32>(1);
        let err = dispatcher.add_entry(*TEST_ADDR, tx);
        assert!(
            matches!(err, Err(RegistrationError::PortAlreadyInUse)),
            "Expected {:?}, got {:?}",
            RegistrationError::PortAlreadyInUse,
            err,
        );
        assert_eq!(dispatcher.len(), 1);
        drop(rx);
    }

    // Add sender, drop receiver, add another sender -> Ok, stale sender is removed.
    #[test(tokio::test)]
    async fn should_reuse_port_after_drop() {
        let dispatcher: Dispatcher<u32> = Dispatcher::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        drop(rx);
        // length is still 1 because the senders are cleaned up lazily.
        assert_eq!(dispatcher.len(), 1);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        dispatcher.dispatch(*TEST_ADDR, 1);
        assert_eq!(rx.recv().await.unwrap(), 1);
    }

    // Add sender, drop receiver, dispatch -> Ok, sender is removed
    #[test(test)]
    fn should_cleanup_closed_senders_on_dispatch() {
        let dispatcher: Dispatcher<u32> = Dispatcher::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        drop(rx);
        dispatcher.dispatch(*TEST_ADDR, 1);
        assert_eq!(dispatcher.len(), 0);
    }

    // Add sender, drop receiver, call cleanup_closed_senders -> Ok, sender is removed
    #[test(test)]
    fn should_cleanup_closed_senders_on_cleanup() {
        let dispatcher: Dispatcher<u32> = Dispatcher::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<u32>(1);
        dispatcher.add_entry(*TEST_ADDR, tx).unwrap();
        assert_eq!(dispatcher.len(), 1);

        drop(rx);
        dispatcher.cleanup_closed_senders();
        assert_eq!(dispatcher.len(), 0);
    }

    #[test]
    fn dispatcher_senders_notified_on_receiver_drop() {
        let dp = Dispatcher::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
        dp.add_entry(*TEST_ADDR, tx).unwrap();

        drop(dp);

        let res = rx.try_recv();

        assert_eq!(
            res,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected),
            "Must be disconnected now"
        );
    }
}
