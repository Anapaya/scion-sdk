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

//! Network forwarder between the network simulation and the real network.
//!
//! The forwarder is a 1:1 forwarder between the network simulation and the real network. It listens
//! for packets from the network simulation on one Address and forwards them to a specified address
//! on the real network, and vice versa.
//!
//! Before dispatching the packet to the other side, the forwarder translates the source and
//! destination addresses to match the targets.

use std::{net::IpAddr, ops::ControlFlow};

use anyhow::Context;
use scion_proto::{
    address::{IsdAsn, ScionAddr},
    packet::{ByEndpoint, NextHeader, ScionPacketUdp},
    wire_encoding::{WireDecode, WireEncodeVec},
};
use serde::{Deserialize, Serialize};
use tokio::select;
use tracing::instrument;
use utoipa::ToSchema;

use crate::{
    network::scion::routing::ScionNetworkTime,
    state::{SharedPocketScionState, sim_network_stack::NetSimRawSocket},
};

/// Serializable state of a network forwarder stored in the system state. This is used to create a
/// [NetworkForwarder] when the app starts up.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct NetworkForwarderState {
    /// The AS number to listen for packets from the network simulation. The forwarder will only
    /// accept packets from this AS on the network simulation, and will forward packets to this AS
    /// on the network simulation.
    pub local_as: IsdAsn,
    /// The IP address to listen for packets from the network simulation. The forwarder will only
    /// accept packets to this address from the network simulation, and will forward packets as
    /// this address on the network simulation.
    #[schema(value_type = String)]
    pub sim_addr: IpAddr,
    /// The maximum number of packets that can be queued for the sim socket.
    pub queue_size: usize,
    /// The peer to send/receive packets to/from on the real network. The forwarder will only
    /// accept packets from this address on the real network, and will forward packets to this
    /// address on the real network.
    #[schema(value_type = String)]
    pub forward_addr: std::net::SocketAddr,
}

/// 1:1 forwarder between the network simulation and the real network. The forwarder listens for
/// packets from the network simulation on one Address and forwards them to a specified address on
/// the real network, and vice versa.
///
/// The forwarder does not change the destination address of the packets, so the packets forwarded
/// to the real network will still have the destination address of the network simulation.
pub struct NetworkForwarder {
    /// The raw socket used to send and receive packets from the network simulation
    sim_sock: NetSimRawSocket,
    /// The UDP socket used to forward packets to and receive packets from the real network
    udp_sock: tokio::net::UdpSocket,
    /// The address to forward packets to and receive packets from on the real network
    forward_addr: std::net::SocketAddr,
}

impl NetworkForwarder {
    /// Creates a new NetworkForwarder with the given state and addresses. The forwarder will listen
    /// for packets from the network simulation on the given AS and IP address, and forward them to
    /// the given address on the real network, and vice versa.
    ///
    /// The sim socket is automatically registered as a receiver for the network simulation, so
    /// packets sent to the given AS and IP address will be received by the forwarder. If a
    /// receiver for the given AS and IP address already exists, an error is returned.
    ///
    /// ## Parameters
    /// - `state`: The shared state of the PocketScion application, used to create the sim socket
    ///   and register it as a receiver for the network simulation.
    /// - `local_as`: The AS number to listen for packets from the network simulation.
    /// - `sim_addr`: The IP address to listen for packets from the network simulation.
    /// - `queue_size`: The maximum number of packets that can be queued for the sim socket.
    /// - `local_addr`: The address to bind the UDP socket to for receiving packets from the real
    ///   network.
    /// - `forward_addr`: The address to forward packets to and receive packets from on the real
    ///   network.
    pub async fn bind(
        state: SharedPocketScionState,
        local_as: IsdAsn,
        sim_addr: IpAddr,
        queue_size: usize,
        listen_addr: std::net::SocketAddr,
        forward_addr: std::net::SocketAddr,
    ) -> anyhow::Result<Self> {
        let stack = state
            .bind_sim_network_stack(local_as, sim_addr, queue_size)
            .context("Failed to bind simulation network stack")?;

        let sim_sock = stack.bind_raw();
        let udp_sock = tokio::net::UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?;

        // Initialize the NetworkForwarder with the provided state and addresses
        Ok(NetworkForwarder {
            sim_sock,
            udp_sock,
            forward_addr,
        })
    }

    /// Returns the local address that the forwarder is listening on for the real network.
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.udp_sock
            .local_addr()
            .expect("UDP socket should be bound")
    }

    /// Starts the forwarder loop, which listens for packets from both the network simulation and
    /// the real network and forwards them to the other side.
    #[instrument(skip(self), fields(ia = ?self.sim_sock.scion_addr().isd_asn(), sim_addr = ?self.sim_sock.scion_addr().host(), forward_addr = ?self.forward_addr))]
    pub async fn run(self) {
        tracing::info!("Network forwarder started");
        let mut recv_buf = Box::new([0u8; 65535]);
        loop {
            select! {
                res = self.sim_sock.recv() => {
                    if let ControlFlow::Break(_) = self.handle_sim_recv(res).await {
                        break;
                    }
                }
                res = self.udp_sock.recv_from(&mut recv_buf[..]) => {
                    if let ControlFlow::Break(_) = self.handle_real_recv(&recv_buf, res).await {
                        break;
                    }
                }
            }
        }

        tracing::info!("Network forwarder stopped");
    }

    async fn handle_real_recv(
        &self,
        recv_buf: &[u8; 65535],
        res: Result<(usize, std::net::SocketAddr), std::io::Error>,
    ) -> ControlFlow<()> {
        match res {
            Ok((size, addr)) => {
                if addr != self.forward_addr {
                    tracing::warn!(
                        peer = ?addr,
                        "Received packet from unexpected peer, dropping"
                    );
                    return ControlFlow::Continue(());
                }

                let mut pkt_bytes = &recv_buf[..size];
                let pkt = match scion_proto::packet::ScionPacketRaw::decode(&mut pkt_bytes) {
                    // forward the packet to the network simulation
                    Ok(pkt) => pkt,
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Failed to decode packet received from UDP socket, dropping"
                        );
                        return ControlFlow::Continue(());
                    }
                };

                // Translate the packet source address to the sim socket's address, so that the
                // network simulation can reply to the packet correctly.
                let pkt = match change_packet_addresses(Some(self.sim_sock.scion_addr()), None, pkt)
                {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Failed to change packet addresses, dropping packet"
                        );
                        return ControlFlow::Continue(());
                    }
                };

                match self.sim_sock.try_send(pkt, ScionNetworkTime::now()) {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Failed to forward packet to sim socket"
                        );
                        return ControlFlow::Continue(());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to receive packet from UDP socket");
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    async fn handle_sim_recv(
        &self,
        res: Result<scion_proto::packet::ScionPacketRaw, std::io::Error>,
    ) -> ControlFlow<()> {
        match res {
            Ok(pkt) => {
                // translate the packet destination address to the forward address.
                let dst = ScionAddr::new(
                    self.sim_sock.scion_addr().isd_asn(),
                    self.forward_addr.ip().into(),
                );
                let pkt = match change_packet_addresses(None, Some(dst), pkt) {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Failed to change packet addresses, dropping packet"
                        );
                        return ControlFlow::Continue(());
                    }
                };

                match self
                    .udp_sock
                    .send_to(&pkt.encode_to_bytes_vec().concat(), self.forward_addr)
                    .await
                {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            target_addr = ?self.forward_addr,
                            "Failed to forward packet"
                        );
                    }
                }
            }

            Err(_) => {
                // The sim socket is only closed when the app is shutting down, so we can just
                // exit the loop here
                tracing::error!("Sim socket closed, stopping network forwarder");
                return ControlFlow::Break(());
            }
        }

        ControlFlow::Continue(())
    }
}

/// Changes the source and destination addresses of the given SCION packet to the provided
/// addresses. If the packet is a UDP packet, the checksum is also updated accordingly. If the
/// provided addresses are `None`, the original addresses from the packet are used.
///
/// If no source or destination address can be determined (either from the provided addresses or the
/// packet), an error is returned.
fn change_packet_addresses(
    source: Option<scion_proto::address::ScionAddr>,
    destination: Option<scion_proto::address::ScionAddr>,
    pkt: scion_proto::packet::ScionPacketRaw,
) -> anyhow::Result<scion_proto::packet::ScionPacketRaw> {
    match pkt.headers.common.next_header {
        NextHeader::UDP => {
            let udp = ScionPacketUdp::try_from(pkt).context("Failed to parse packet as UDP")?;

            let src_port = udp.src_port();
            let dst_port = udp.dst_port();

            let source = source
                .map(|s| scion_proto::address::SocketAddr::new(s, src_port))
                .or_else(|| udp.source())
                .context("Packet is missing source address")?;
            let destination = destination
                .map(|d| scion_proto::address::SocketAddr::new(d, dst_port))
                .or_else(|| udp.destination())
                .context("Packet is missing destination address")?;

            // Create a new UDP packet with the updated addresses and correct checksum
            let new_udp = ScionPacketUdp::new(
                ByEndpoint {
                    source,
                    destination,
                },
                udp.headers.path,
                udp.datagram.payload,
            )
            .context("Failed to create new UDP packet with updated addresses")?;

            Ok(new_udp.into())
        }
        _ => {
            let source = source
                .or_else(|| pkt.headers.address.source())
                .context("Packet is missing source address")?;
            let destination = destination
                .or_else(|| pkt.headers.address.destination())
                .context("Packet is missing destination address")?;

            // Create a new packet with the updated addresses and the same payload and path
            let new_pkt = scion_proto::packet::ScionPacketRaw::new(
                ByEndpoint {
                    source,
                    destination,
                },
                pkt.headers.path,
                pkt.payload,
                pkt.headers.common.next_header,
                pkt.headers.common.flow_id,
            )
            .context("Failed to create new packet with updated addresses")?;

            Ok(new_pkt)
        }
    }
}

impl SharedPocketScionState {
    /// Adds a new network forwarder to the
    ///
    /// See [NetworkForwarder::bind] for more details on the parameters and behavior of the
    /// forwarder.
    pub fn add_network_forwarder(
        &self,
        local_as: IsdAsn,
        sim_addr: IpAddr,
        queue_size: usize,
        forward_addr: std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        let mut guard = self.system_state.write().unwrap();
        match guard
            .network_forwarders
            .entry(ScionAddr::new(local_as, sim_addr.into()))
        {
            std::collections::btree_map::Entry::Occupied(_) => {
                anyhow::bail!(
                    "A network forwarder for AS {} and address {} already exists",
                    local_as,
                    sim_addr
                );
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(NetworkForwarderState {
                    local_as,
                    sim_addr,
                    queue_size,
                    forward_addr,
                });
            }
        }

        Ok(())
    }

    /// Returns a list of all network forwarders in the system state, along with their state.
    pub fn network_forwarders(&self) -> Vec<(ScionAddr, NetworkForwarderState)> {
        self.system_state
            .read()
            .unwrap()
            .network_forwarders
            .iter()
            .map(|(addr, state)| (*addr, state.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::SystemTime};

    use bytes::Bytes;
    use scion_proto::{
        address::{IsdAsn, ScionAddr, SocketAddr},
        packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
        path::DataPlanePath,
        wire_encoding::{WireDecode, WireEncodeVec},
    };
    use tokio::time::{Duration, timeout};

    use super::NetworkForwarder;
    use crate::{
        network::scion::{
            routing::ScionNetworkTime,
            topology::{ScionAs, ScionTopology},
        },
        state::SharedPocketScionState,
    };

    fn setup_state(isd_as: IsdAsn) -> SharedPocketScionState {
        let mut state = SharedPocketScionState::new(SystemTime::now());
        let mut topology = ScionTopology::new();
        topology
            .add_as(ScionAs::new_core(isd_as))
            .expect("failed to add AS");
        state.set_topology(topology);
        state
    }

    #[tokio::test]
    async fn should_forward_sim_packets_to_real_network() {
        let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
        let sender_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let forwarder_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let queue_size = 8;

        let state = setup_state(local_as);

        let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind peer socket");
        let forward_addr = peer_socket.local_addr().expect("peer addr");

        let forwarder = NetworkForwarder::bind(
            state.clone(),
            local_as,
            forwarder_ip,
            queue_size,
            "127.0.0.1:0".parse().unwrap(),
            forward_addr,
        )
        .await
        .expect("bind forwarder");
        let listen_addr = forwarder.listen_addr();

        let forwarder_task = tokio::spawn(forwarder.run());

        let sender_stack = state
            .bind_sim_network_stack(local_as, sender_ip, queue_size)
            .expect("sender stack");
        let sender_socket = sender_stack.bind_udp(0).expect("bind sim udp");

        let payload = Bytes::from_static(b"hello-from-sim");
        let dst = SocketAddr::new(ScionAddr::new(local_as, forwarder_ip.into()), 4242);
        sender_socket
            .try_send(
                dst,
                DataPlanePath::EmptyPath,
                payload,
                ScionNetworkTime::now(),
            )
            .expect("send sim packet");

        let mut buf = [0u8; 2048];
        let (size, addr) = timeout(Duration::from_secs(2), peer_socket.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv packet");

        assert_eq!(addr, listen_addr, "forwarder should send to peer"); // peer receives from forwarder

        let mut pkt_bytes = &buf[..size];
        let pkt = ScionPacketRaw::decode(&mut pkt_bytes).expect("decode packet");
        let dest = pkt.headers.address.destination().expect("dest address");
        let src = pkt.headers.address.source().expect("src address");

        assert_eq!(dest, ScionAddr::new(local_as, forward_addr.ip().into())); // destination translated to forwarder peer IP
        assert_eq!(src, ScionAddr::new(local_as, sender_ip.into())); // source preserved from sim sender

        forwarder_task.abort();
    }

    #[tokio::test]
    async fn should_forward_real_packets_to_sim_network() {
        let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
        let forwarder_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let receiver_ip: IpAddr = "10.0.0.3".parse().unwrap();
        let queue_size = 8;

        let state = setup_state(local_as);

        let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind peer socket");
        let forward_addr = peer_socket.local_addr().expect("peer addr");

        let forwarder = NetworkForwarder::bind(
            state.clone(),
            local_as,
            forwarder_ip,
            queue_size,
            "127.0.0.1:0".parse().unwrap(),
            forward_addr,
        )
        .await
        .expect("bind forwarder");
        let listen_addr = forwarder.listen_addr();

        let forwarder_task = tokio::spawn(forwarder.run());

        let receiver_stack = state
            .bind_sim_network_stack(local_as, receiver_ip, queue_size)
            .expect("receiver stack");
        let receiver_socket = receiver_stack.bind_udp(43000).expect("bind receiver udp");

        let src_ip: IpAddr = "10.0.0.9".parse().unwrap();
        let src_addr = SocketAddr::new(ScionAddr::new(local_as, src_ip.into()), 5555);
        let dst_addr = SocketAddr::new(ScionAddr::new(local_as, receiver_ip.into()), 43000);
        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: src_addr,
                destination: dst_addr,
            },
            DataPlanePath::EmptyPath,
            Bytes::from_static(b"hello-from-real"),
        )
        .expect("build packet");

        peer_socket
            .send_to(&packet.encode_to_bytes_vec().concat(), listen_addr)
            .await
            .expect("send to forwarder");

        let recv = timeout(Duration::from_secs(2), receiver_socket.recv())
            .await
            .expect("recv timeout")
            .expect("recv packet");

        let source = recv.source().expect("source addr");
        let destination = recv.destination().expect("destination addr");

        assert_eq!(destination, dst_addr); // destination preserved for sim receiver
        assert_eq!(
            source,
            SocketAddr::new(ScionAddr::new(local_as, forwarder_ip.into()), 5555)
        ); // source IP rewritten to forwarder sim address

        forwarder_task.abort();
    }
}
