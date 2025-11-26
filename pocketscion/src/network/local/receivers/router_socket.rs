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
//! RouterSocket emulates a real internal UDP interface of a router.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use ipnet::IpNet;
use scion_proto::{
    packet::{ScionPacketRaw, classify_scion_packet},
    wire_encoding::WireDecode,
};
use snap_dataplane::dispatcher::Dispatcher;

use crate::network::local::receivers::Receiver;

/// The RouterSocket emulates a real internal UDP interface of a router.
///
/// 1. It receives packets from the real network via a UDP socket and dispatches them
/// 2. It receives packets from the NetworkSimulation and dispatches them to the real network
pub struct RouterSocket<D> {
    /// The underlying UDP socket.
    socket: tokio::net::UdpSocket,
    /// Snap data planes, snap data plane id -> internal address
    snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
    /// Excluded addresses
    snap_data_plane_excludes: Vec<IpNet>,
    /// Dispatcher to which packets received from the UDP socket are sent.
    dispatcher: Arc<D>,
}

impl<D> RouterSocket<D> {
    /// Creates a new `RouterSocket` bound to the specified address.
    pub async fn new(
        socket: tokio::net::UdpSocket,
        snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
        snap_data_plane_excludes: Vec<IpNet>,
        dispatcher: Arc<D>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            socket,
            snap_data_plane_interfaces,
            snap_data_plane_excludes,
            dispatcher,
        })
    }

    /// Returns the address the socket is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("socket should be bound")
    }
}

impl<D: Dispatcher> RouterSocket<D> {
    /// Start receiving packets on the socket and dispatch them to the network receiver.
    pub async fn run(&self) -> std::io::Result<()> {
        let mut buf = vec![0u8; 65536]; // 64 KiB buffer
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, src)) => {
                    let packet = match ScionPacketRaw::decode(&mut buf[..size].as_ref()) {
                        Ok(packet) => packet,
                        Err(e) => {
                            tracing::error!(error = %e, ?src, "Failed to decode SCION packet");
                            continue;
                        }
                    };
                    self.dispatcher.try_dispatch(packet);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to receive packet");
                }
            }
        }
    }
}

/// Shared router socket.
pub struct SharedRouterSocket<D: Dispatcher>(Arc<RouterSocket<D>>);

impl<D: Dispatcher> SharedRouterSocket<D> {
    /// Creates a new shared router socket.
    pub fn new(router_socket: RouterSocket<D>) -> Self {
        Self(Arc::new(router_socket))
    }

    /// Start receiving packets on the socket and dispatch them to the network receiver.
    pub async fn run(&self) -> std::io::Result<()> {
        self.0.run().await
    }
}

impl<D: Dispatcher> Clone for SharedRouterSocket<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<D: Dispatcher> Receiver for SharedRouterSocket<D> {
    fn receive_packet(&self, packet: ScionPacketRaw) {
        let classified_packet = match classify_scion_packet(packet) {
            Ok(classification) => classification,
            Err(e) => {
                tracing::error!(error = %e, "Failed to classify SCION packet");
                return;
            }
        };

        let dst_addr = match classified_packet.destination() {
            Some(addr) => addr,
            None => {
                tracing::error!("Could not extract destination address from SCION packet");
                return;
            }
        };

        let dst_addr = match dst_addr.local_address() {
            Some(addr) => addr,
            None => {
                tracing::error!("Svc address not supported");
                return;
            }
        };

        // Forward to the first SNAP data plane if there is one and the destination address is not
        // excluded.
        // XXX(uniquefine): this will change once we implement rendevouz routing.
        let forward_to = if let Some(snap_internal_addr) =
            self.0.snap_data_plane_interfaces.values().next()
            && !self
                .0
                .snap_data_plane_excludes
                .iter()
                .any(|net| net.contains(&dst_addr.ip()))
        {
            *snap_internal_addr
        } else {
            dst_addr
        };

        let src_addr = self.0.socket.local_addr().expect("no fail");

        tracing::debug!(?dst_addr, ?src_addr, "Router socket dispatching packet");

        // Send the packet on the UDP socket.
        // XXX(shitz): This allocates a new buffer for each packet.
        let raw = classified_packet.encode_to_vec();
        if let Err(e) = self.0.socket.try_send_to(&raw, forward_to) {
            tracing::error!(error = %e, %dst_addr, "Failed to send packet");
        }
    }
}
