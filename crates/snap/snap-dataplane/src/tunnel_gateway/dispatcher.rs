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
//! Dispatcher implementation for the tunnel gateway

use std::net::SocketAddr;

use ana_gotatun::packet::{Packet, WgData};
use sciparse::{core::view::View, packet::view::ScionPacketView};
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        gateway::{PACKET_BUF_SIZE, PacketPool},
        metrics::TunnelGatewayDispatcherMetrics,
    },
};

const OUTBOUND_QUEUE_SIZE: usize = 1024;
const BUFFER_POOL_INIT_SIZE: usize = 1024;
/// The largest SCION packet that fits into a datagram of the batch sender after encryption.
const MAX_PACKET_LEN: usize = PACKET_BUF_SIZE - WgData::OVERHEAD;

/// The implementation of the tunnel gateway dispatcher.
#[derive(Clone)]
pub struct TunnelGatewayDispatcher {
    metrics: TunnelGatewayDispatcherMetrics,
    pool: PacketPool,
    // The outbound queue contains the packets coming from the SCION network
    // headed towards the endhosts. The socket address is parsed out from the
    // packet and is redundant with the one indicated by the packet.
    outbound_queue: Sender<(SocketAddr, Packet)>,
}

impl TunnelGatewayDispatcher {
    /// Creates a pair of [TunnelGatewayDispatcher] and
    /// [TunnelGatewayDispatcherReceiver]. The [TunnelGatewayDispatcher] is the
    /// object that dispatches SCION packets coming from the SCION network
    /// towards the endhosts. The second object of type
    /// [TunnelGatewayDispatcherReceiver] is the receiving end which is given to
    /// the actual tunnel gateway.
    ///
    /// The separation is done due to the circular dependency between the
    /// different dispatchers.
    pub fn new(metrics: TunnelGatewayDispatcherMetrics) -> (Self, TunnelGatewayDispatcherReceiver) {
        let pool = ana_gotatun::packet::PacketBufPool::new(BUFFER_POOL_INIT_SIZE);
        let (tx, rx) = channel(OUTBOUND_QUEUE_SIZE);
        let myself = Self {
            metrics,
            pool: pool.clone(),
            outbound_queue: tx,
        };

        let rx = TunnelGatewayDispatcherReceiver {
            outbound_queue: rx,
            pool,
        };
        (myself, rx)
    }
}

impl Dispatcher for TunnelGatewayDispatcher {
    fn try_dispatch(&self, packet: &ScionPacketView) {
        let packet_len = packet.as_slice().len();
        if packet_len > MAX_PACKET_LEN {
            self.metrics.too_large.inc();
            tracing::debug!(
                packet_len,
                "Dropping packet that is too large to send to the endhost"
            );
            return;
        }

        let classification = match packet.try_classify() {
            Ok(c) => c,
            Err(e) => {
                self.metrics.invalid_destination.inc();
                tracing::debug!(error=%e, "Failed to classify packet");
                return;
            }
        };

        let sock_addr = match classification
            .dst_socket_addr()
            .and_then(|a| a.socket_addr())
        {
            Some(addr) => addr,
            None => {
                self.metrics.invalid_destination.inc();
                tracing::debug!("Could not deduce destination socket address from packet");
                return;
            }
        };

        let raw_bytes = packet.as_slice();
        let mut pooled_packet = self.pool.get();
        pooled_packet.as_mut()[..raw_bytes.len()].copy_from_slice(raw_bytes);
        pooled_packet.truncate(raw_bytes.len());

        match self.outbound_queue.try_send((sock_addr, pooled_packet)) {
            Ok(_) => {}
            Err(TrySendError::Closed(_)) => self.metrics.queue_closed.inc(),
            Err(TrySendError::Full(_)) => self.metrics.queue_full.inc(),
        }
    }
}

/// This is the type that is plugged into the TunnelGateway.
pub struct TunnelGatewayDispatcherReceiver {
    pub(crate) pool: PacketPool,
    pub(crate) outbound_queue: Receiver<(SocketAddr, Packet)>,
}

#[cfg(test)]
mod tests {
    use scion_sdk_observability::metrics::registry::MetricsRegistry;
    use sciparse::{
        core::encode::WireEncode, dataplane_path::model::DpPath, packet::model::ScionUdpPacket,
    };

    use super::*;
    use crate::{metrics::DataPlaneMetrics, tunnel_gateway::metrics::TunnelGatewayMetrics};

    /// Encodes a SCION/UDP packet to 10.0.0.2:1235 that is exactly `len` bytes long.
    fn udp_packet_of_len(len: usize) -> Vec<u8> {
        let packet = |payload_len| {
            ScionUdpPacket::new(
                "[1-ff00:0:110,10.0.0.1]:1234".parse().unwrap(),
                "[1-ff00:0:111,10.0.0.2]:1235".parse().unwrap(),
                DpPath::Empty,
                vec![0xab; payload_len],
            )
        };
        let header_len = packet(0).required_size();
        packet(len - header_len).try_encode_to_vec().unwrap()
    }

    fn dispatcher() -> (
        TunnelGatewayDispatcher,
        TunnelGatewayDispatcherReceiver,
        TunnelGatewayDispatcherMetrics,
    ) {
        let registry = MetricsRegistry::new();
        let metrics =
            TunnelGatewayMetrics::new(&registry, &DataPlaneMetrics::new(&registry)).dispatcher();
        let (dispatcher, receiver) = TunnelGatewayDispatcher::new(metrics.clone());
        (dispatcher, receiver, metrics)
    }

    /// A caller can pass a valid SCION packet that does not fit into a pool buffer. The
    /// dispatcher drops this packet and does not panic.
    #[test]
    fn packet_larger_than_the_buffer_is_dropped() {
        let (dispatcher, mut receiver, metrics) = dispatcher();
        let raw = udp_packet_of_len(PACKET_BUF_SIZE + 1);
        let (view, _) = ScionPacketView::try_from_slice(&raw).unwrap();

        dispatcher.try_dispatch(view);

        assert_eq!(metrics.too_large.get(), 1);
        assert!(receiver.outbound_queue.try_recv().is_err());
    }

    /// The dispatcher drops and counts a packet that fits into a pool buffer, but not into a
    /// datagram of the batch sender after encryption.
    #[test]
    fn packet_too_large_after_encryption_is_dropped() {
        let (dispatcher, mut receiver, metrics) = dispatcher();
        let raw = udp_packet_of_len(MAX_PACKET_LEN + 1);
        let (view, _) = ScionPacketView::try_from_slice(&raw).unwrap();

        dispatcher.try_dispatch(view);

        assert_eq!(metrics.too_large.get(), 1);
        assert!(receiver.outbound_queue.try_recv().is_err());
    }

    #[test]
    fn packet_of_the_max_len_is_queued() {
        let (dispatcher, mut receiver, metrics) = dispatcher();
        let raw = udp_packet_of_len(MAX_PACKET_LEN);
        let (view, _) = ScionPacketView::try_from_slice(&raw).unwrap();

        dispatcher.try_dispatch(view);

        let (addr, packet) = receiver
            .outbound_queue
            .try_recv()
            .expect("expected the packet to be queued");
        assert_eq!(addr, "10.0.0.2:1235".parse().unwrap());
        assert_eq!(&packet[..], raw.as_slice());
        assert_eq!(metrics.too_large.get(), 0);
    }
}
