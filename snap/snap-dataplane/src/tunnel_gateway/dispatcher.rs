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

use ana_gotatun::packet::Packet;
use scion_proto::packet::classify_scion_packet;
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        gateway::{PacketPool, wire_encode},
        metrics::TunnelGatewayDispatcherMetrics,
    },
};

const OUTBOUND_QUEUE_SIZE: usize = 1024;
const BUFFER_POOL_INIT_SIZE: usize = 1024;

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
    fn try_dispatch(&self, packet: scion_proto::packet::ScionPacketRaw) {
        // Classify so we can get the port (if any)
        // XXX: Another packet duplication that should disappear.
        let classification = match classify_scion_packet(packet.clone()) {
            Ok(c) => c,
            Err(e) => {
                self.metrics.invalid_packets_errors.inc();
                tracing::debug!(error=%e, "Failed to classify packet");
                return;
            }
        };

        let Some(dest_addr) = classification.destination() else {
            self.metrics.invalid_packets_errors.inc();
            tracing::debug!("Could not deduce destination socket address after classification");
            return;
        };

        let Some(sock_addr) = dest_addr.local_address() else {
            self.metrics.invalid_packets_errors.inc();
            tracing::debug!("Found invalid service address");
            return;
        };

        let mut pooled_packet = self.pool.get();
        let mut temp_buf = self.pool.get();
        wire_encode(&packet, &mut temp_buf, &mut pooled_packet);
        match self.outbound_queue.try_send((sock_addr, pooled_packet)) {
            Ok(_) => self.metrics.dispatch_queue_size.inc(),
            Err(TrySendError::Closed(_)) => self.metrics.closed_dispatch_queue_errors.inc(),
            Err(TrySendError::Full(_)) => self.metrics.full_dispatch_queue_errors.inc(),
        }
    }
}

/// This is the type that is plugged into the TunnelGateway.
pub struct TunnelGatewayDispatcherReceiver {
    pub(crate) pool: PacketPool,
    pub(crate) outbound_queue: Receiver<(SocketAddr, Packet)>,
}
