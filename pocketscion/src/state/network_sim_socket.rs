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

//! In-Memory Socket interacting with the Network Simulator

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use anyhow::Context;
use bytes::Bytes;
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
    path::DataPlanePath,
};
use scion_sdk_quic_scion::socket::{BoxedSocketError, GenericScionUdpSocket};
use tokio::sync::{Mutex, mpsc};

use crate::{
    network::{local::receivers::Receiver, scion::routing::ScionNetworkTime},
    state::SharedPocketScionState,
};

/// A in-memory socket for sending/receiving packets in the network simulator
///
/// This is a general purpose socket that can be used by any application to send/receive packets
/// to/from the network simulator.
pub struct NetSimRawSocket<P: NetSimPathProvider> {
    state: SharedPocketScionState,
    rx_queue: Mutex<mpsc::Receiver<ScionPacketRaw>>,

    path_provider: P,

    // XXX(ake): The port is currently a workaround to be able to send UDP packets from this
    // socket. This should be split out so we can support multiple Sockets on a single Address
    // - e.g. for the control service listening and sending from the same AS and IP address.
    local_addr: SocketAddr,
}

/// Provider of paths for the Network Simulator Socket.
///
/// get_path will be called for every packet sent through the Network Simulator Socket.
pub trait NetSimPathProvider: Send + Sync + 'static {
    /// Returns a path from the given source AS to the given destination AS, if one exists.
    fn get_path(&self, src_as: IsdAsn, dst_as: IsdAsn) -> Option<DataPlanePath>;
}

impl<P: NetSimPathProvider> NetSimRawSocket<P> {
    /// Creates a new Network Simulator Memory Socket and a receiver for it.
    ///
    /// The receiver can be passed to the network simulation to receive packets destined to the
    /// given ISD-AS and address.
    ///
    /// The Socket is not bound to any specific protocol.
    pub fn new(
        topology: SharedPocketScionState,
        addr: SocketAddr,
        path_provider: P,
    ) -> anyhow::Result<(Self, NetSimSocketReceiver)> {
        let sock_addr = addr
            .local_address()
            .context("Address must be an IP address")?;

        // XXX(ake): The receiver ignores ports. this should be a raw socket so we can demultiplex
        // based on protocol and port
        let (tx, rx) = NetSimSocketReceiver::new(100, sock_addr.ip());

        Ok((
            Self {
                state: topology,
                path_provider,
                rx_queue: Mutex::new(rx),
                local_addr: addr,
            },
            tx,
        ))
    }

    /// Sends a packet to the network simulator from this socket.
    pub fn send(&self, pkt: ScionPacketRaw, now: ScionNetworkTime) {
        self.state
            .dispatch_to_network_sim(self.local_addr.isd_asn(), 0, now, pkt);
    }

    /// Attempts to receive a packet from the network simulator, returning an error if the receive
    /// channel is closed.
    pub async fn recv(&self) -> io::Result<ScionPacketRaw> {
        self.rx_queue.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Network Simulator Socket receiver channel closed",
            )
        })
    }

    /// Returns the ip address this socket is bound to.
    pub fn ip(&self) -> IpAddr {
        self.local_addr
            .local_address()
            .expect("we check this in new()")
            .ip()
    }

    /// Returns the SCION address corresponding to this socket's local AS and address.
    pub fn scion_addr(&self) -> ScionAddr {
        self.local_addr.scion_address()
    }

    /// Returns a reference to the path provider used by this socket.
    pub fn path_provider(&self) -> &P {
        &self.path_provider
    }
}

/// Receiver for the Network Simulator Memory Socket, responsible for receiving packets from the
/// network simulation and forwarding them to the socket's receive queue.
pub struct NetSimSocketReceiver {
    rx_queue_sender: mpsc::Sender<ScionPacketRaw>,
    local_addr: IpAddr,
}

impl NetSimSocketReceiver {
    /// Creates a new Network Simulator Socket Receiver with the given queue size and local address.
    pub fn new(queue_size: usize, local_addr: IpAddr) -> (Self, mpsc::Receiver<ScionPacketRaw>) {
        let (tx, rx) = mpsc::channel(queue_size);
        (
            Self {
                rx_queue_sender: tx,
                local_addr,
            },
            rx,
        )
    }
}

impl Receiver for NetSimSocketReceiver {
    fn receive_packet(&self, packet: ScionPacketRaw) {
        // Sanity check that we receive a packet with the correct destination address.
        if packet
            .headers
            .address
            .destination()
            .iter()
            .flat_map(|addr| addr.local_address())
            .next()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            != self.local_addr
        {
            tracing::warn!(
                packet_destination = ?packet.headers.address.destination(),
                local_address = ?self.local_addr,
                "Received packet with destination address that does not match socket's local address, dropping packet"
            );
            return;
        }

        match self.rx_queue_sender.try_send(packet) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "Failed to send packet to Network Simulator Socket receiver, dropping packet"
                );
            }
        }
    }
}

// XXX(ake): This must be implemented on Arc to be able to decouple the send() method from the
// caller. Otherwise we could run into extremely deep call stacks, and possibly deadlocks.
#[async_trait::async_trait]
impl<P: NetSimPathProvider> GenericScionUdpSocket for NetSimRawSocket<P> {
    /// Asynchronously sends a Datagram to the specified destination address.
    async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), BoxedSocketError> {
        let path = self
            .path_provider
            .get_path(self.local_addr.isd_asn(), destination.isd_asn())
            .ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::HostUnreachable,
                    format!(
                        "No path found from AS {} to destination AS {}",
                        self.local_addr.isd_asn(),
                        destination.isd_asn()
                    ),
                )) as BoxedSocketError
            })?;

        // Construct a SCION packet with the given payload and destination, and send it to the
        // network simulator.
        let pkt = ScionPacketUdp::new(
            ByEndpoint {
                source: self.local_addr,
                destination,
            },
            path,
            Bytes::copy_from_slice(payload),
        )
        .map_err(|e| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to construct SCION packet: {e}"),
            )) as BoxedSocketError
        })?;

        self.send(pkt.into(), ScionNetworkTime::now());

        Ok(())
    }

    /// Asynchronously receives a Datagram, writing it into the provided buffer, and returns the
    /// number of bytes read and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), BoxedSocketError> {
        let (pkt, src_addr) = loop {
            let pkt = self
                .recv()
                .await
                .map_err(|e| Box::new(e) as BoxedSocketError)?;

            let pkt = match ScionPacketUdp::try_from(pkt) {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Failed to parse received packet as SCION UDP, dropping packet"
                    );
                    continue;
                }
            };

            let sci_addr = match pkt.headers.address.source() {
                Some(addr) => addr,
                None => {
                    tracing::warn!("Received packet with unknown source address, dropping packet");
                    continue;
                }
            };

            let port = pkt.src_port();

            break (pkt, SocketAddr::new(sci_addr, port));
        };

        let payload = pkt.payload();

        // Copy the payload into the provided buffer, truncating if necessary.
        let payload_len = std::cmp::min(buf.len(), payload.len());
        buf[..payload_len].copy_from_slice(&payload[..payload_len]);

        Ok((payload_len, src_addr))
    }

    /// Returns the local socket address of this socket.
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}
