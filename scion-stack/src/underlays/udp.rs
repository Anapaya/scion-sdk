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
//! UDP underlay socket.
use std::{
    io,
    net::{self, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    task::{Poll, ready},
};

use anyhow::Context;
use bytes::BytesMut;
use futures::future::BoxFuture;
use scion_proto::{
    address::SocketAddr,
    datagram::UdpMessage,
    packet::{
        ByEndpoint, PacketClassification, ScionPacketRaw, ScionPacketUdp, classify_scion_packet,
    },
    path::{DataPlanePath, Path, PathInterface},
    scmp::SCMP_PROTOCOL_NUMBER,
    wire_encoding::{WireDecode as _, WireEncodeVec as _},
};
use tokio::{io::ReadBuf, net::UdpSocket};

use crate::{
    scionstack::{
        AsyncUdpUnderlaySocket, NetworkError, ScionSocketSendError, UnderlaySocket,
        udp_polling::UdpPollHelper,
    },
    underlays::discovery::UnderlayDiscovery,
};

const UDP_DATAGRAM_BUFFER_SIZE: usize = 65535;

/// Local IP resolver.
pub trait LocalIpResolver: Send + Sync {
    /// Returns the local IP addresses of the host.
    fn local_ips(&self) -> Vec<net::IpAddr>;
}

impl LocalIpResolver for Vec<net::IpAddr> {
    fn local_ips(&self) -> Vec<net::IpAddr> {
        self.clone()
    }
}

// XXX(uniquefine): This should use impl ToSocketAddrs as argument and
// try to connect to all addresses.
pub(crate) struct TargetAddrLocalIpResolver {
    api_socket_address: net::SocketAddr,
}

impl TargetAddrLocalIpResolver {
    pub fn new(api_address: url::Url) -> anyhow::Result<Self> {
        let socket_addr = api_address
            .socket_addrs(|| None)
            .context("invalid api address")?
            .first()
            .ok_or(anyhow::anyhow!("failed to resolve api socket address"))?
            .to_owned();
        Ok(Self {
            api_socket_address: socket_addr,
        })
    }
}

impl LocalIpResolver for TargetAddrLocalIpResolver {
    /// Binds to Ipv4 and Ipv6 unspecified addresses and returns the local addresses
    /// that can reach the endhost API.
    fn local_ips(&self) -> Vec<net::IpAddr> {
        let mut ips = vec![];
        for ip in [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()] {
            if let Ok(socket) = net::UdpSocket::bind(net::SocketAddr::new(ip, 0))
                && socket.connect(self.api_socket_address).is_ok()
                && let Ok(addr) = socket.local_addr()
            {
                ips.push(addr.ip());
            }
        }
        ips
    }
}

/// A UDP underlay socket.
pub struct UdpUnderlaySocket {
    pub(crate) socket: UdpSocket,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) underlay_discovery: Arc<dyn UnderlayDiscovery>,
}

impl UdpUnderlaySocket {
    pub(crate) fn new(
        socket: UdpSocket,
        bind_addr: SocketAddr,
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
    ) -> Self {
        Self {
            socket,
            bind_addr,
            underlay_discovery,
        }
    }

    /// Dispatch a packet to the local AS network.
    async fn dispatch_local(
        &self,
        packet: ScionPacketRaw,
    ) -> Result<(), crate::scionstack::ScionSocketSendError> {
        let dst_addr = packet
            .headers
            .address
            .destination()
            .ok_or(crate::scionstack::ScionSocketSendError::InvalidPacket(
                "Packet to local endhost has no destination address".into(),
            ))?
            .local_address()
            .ok_or(crate::scionstack::ScionSocketSendError::InvalidPacket(
                "Cannot forward packet to local service address".into(),
            ))?;
        let classification = classify_scion_packet(packet.clone()).map_err(|e| {
            crate::scionstack::ScionSocketSendError::InvalidPacket(
                format!("Cannot classify packet to local endhost: {e:#}").into(),
            )
        })?;
        let dst_port = match classification {
            PacketClassification::Udp(udp_packet) => udp_packet.dst_port(),
            PacketClassification::ScmpWithDestination(port, _) => port,
            PacketClassification::ScmpWithoutDestination(_) | PacketClassification::Other(_) => {
                return Err(crate::scionstack::ScionSocketSendError::InvalidPacket(
                    "Cannot deduce port for packet to local endhost".into(),
                ));
            }
        };
        let packet_bytes = packet.encode_to_bytes_vec().concat();
        let dst_addr = net::SocketAddr::new(dst_addr, dst_port);
        self.socket
            .send_to(&packet_bytes, dst_addr)
            .await
            .map_err(|e| {
                use std::io::ErrorKind::*;
                match e.kind() {
                    HostUnreachable | NetworkUnreachable => {
                        ScionSocketSendError::NetworkUnreachable(
                            NetworkError::DestinationUnreachable(
                                format!("Error sending packet locally to {dst_addr}: {e:?}").into(),
                            ),
                        )
                    }
                    ConnectionAborted | ConnectionReset | BrokenPipe => {
                        ScionSocketSendError::Closed
                    }
                    _ => ScionSocketSendError::IoError(e),
                }
            })?;
        Ok(())
    }
}

impl UnderlaySocket for UdpUnderlaySocket {
    fn send<'a>(
        &'a self,
        packet: ScionPacketRaw,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
        let source_ia = packet.headers.address.ia.source;
        if packet.headers.address.ia.destination == source_ia {
            return Box::pin(async move {
                self.dispatch_local(packet).await?;
                Ok(())
            });
        }

        // Extract the source IA and next hop from the packet.
        let interface_id = if let DataPlanePath::Standard(standard_path) = &packet.headers.path
            && let Some(interface_id) = standard_path.iter_interfaces().next()
        {
            interface_id
        } else {
            return Box::pin(async move {
                Err(ScionSocketSendError::InvalidPacket(
                    "Path does not contain first hop.".into(),
                ))
            });
        };

        let next_hop = match self
            .underlay_discovery
            .resolve_udp_underlay_next_hop(PathInterface {
                isd_asn: source_ia,
                id: interface_id.get(),
            })
            .ok_or(ScionSocketSendError::NetworkUnreachable(
                NetworkError::UnderlayNextHopUnreachable {
                    isd_as: source_ia,
                    interface_id: interface_id.get(),
                    msg: "next hop not found".to_string(),
                },
            )) {
            Ok(next_hop) => next_hop,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            }
        };

        let packet_bytes = packet.encode_to_bytes_vec().concat();
        Box::pin(async move {
            self.socket
                .send_to(&packet_bytes, next_hop)
                .await
                .map_err(|e| {
                    use std::io::ErrorKind::*;
                    match e.kind() {
                        HostUnreachable | NetworkUnreachable => {
                            ScionSocketSendError::NetworkUnreachable(
                                NetworkError::UnderlayNextHopUnreachable {
                                    isd_as: source_ia,
                                    interface_id: interface_id.get(),
                                    msg: e.to_string(),
                                },
                            )
                        }
                        ConnectionAborted | ConnectionReset | BrokenPipe => {
                            ScionSocketSendError::Closed
                        }
                        _ => ScionSocketSendError::IoError(e),
                    }
                })?;
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ScionPacketRaw, crate::scionstack::ScionSocketReceiveError>> {
        Box::pin(async move {
            let mut buf = [0u8; UDP_DATAGRAM_BUFFER_SIZE];
            loop {
                let (n, _src) = self.socket.recv_from(&mut buf).await?;
                let packet = match ScionPacketRaw::decode(&mut BytesMut::from(&buf[..n])) {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to decode SCION packet");
                        continue;
                    }
                };

                // Drop packets that are not addressed to this socket.
                let dst = packet.headers.address.destination();
                if dst.is_none() || dst.unwrap() != self.bind_addr.scion_address() {
                    tracing::debug!(destination = ?dst, assigned_addr = %self.bind_addr.scion_address(), "Packet destination does not match assigned address, skipping");
                    continue;
                }

                match packet.headers.common.next_header {
                    UdpMessage::PROTOCOL_NUMBER => {
                        return Ok(packet);
                    }
                    SCMP_PROTOCOL_NUMBER => {
                        tracing::debug!("SCMP packet received, skipping");
                        continue;
                    }
                    _ => {
                        tracing::debug!(next_header = %packet.headers.common.next_header, "Unknown packet type, skipping");
                        continue;
                    }
                }
            }
        })
    }

    fn local_addr(&self) -> scion_proto::address::SocketAddr {
        self.bind_addr
    }
}

/// An async UDP underlay socket.
pub struct UdpAsyncUdpUnderlaySocket {
    local_addr: SocketAddr,
    discovery: Arc<dyn UnderlayDiscovery>,
    inner: UdpSocket,
}

impl UdpAsyncUdpUnderlaySocket {
    pub(crate) fn new(
        local_addr: SocketAddr,
        discovery: Arc<dyn UnderlayDiscovery>,
        inner: UdpSocket,
    ) -> Self {
        Self {
            local_addr,
            discovery,
            inner,
        }
    }

    /// Dispatch a packet to the local AS network.
    fn try_dispatch_local(&self, packet: ScionPacketRaw) -> io::Result<()> {
        let dst_addr = packet
            .headers
            .address
            .destination()
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Packet to local endhost has no destination address".to_string(),
            ))?
            .local_address()
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot forward packet with service address".to_string(),
            ))?;
        let classification = classify_scion_packet(packet.clone()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot classify packet to local endhost: {e:#}"),
            )
        })?;
        let dst_port = match classification {
            PacketClassification::Udp(udp_packet) => udp_packet.dst_port(),
            PacketClassification::ScmpWithDestination(port, _) => port,
            PacketClassification::ScmpWithoutDestination(_) | PacketClassification::Other(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot deduce port for packet to local endhost",
                ));
            }
        };
        let packet_bytes = packet.encode_to_bytes_vec().concat();
        let dst_addr = net::SocketAddr::new(dst_addr, dst_port);
        self.inner.try_send_to(&packet_bytes, dst_addr)?;
        Ok(())
    }
}

impl AsyncUdpUnderlaySocket for UdpAsyncUdpUnderlaySocket {
    fn create_io_poller(
        self: Arc<Self>,
    ) -> std::pin::Pin<Box<dyn crate::scionstack::udp_polling::UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let self_clone = self.clone();
            async move { self_clone.inner.writable().await }
        }))
    }

    fn try_send(&self, packet: ScionPacketRaw) -> Result<(), std::io::Error> {
        let source_ia = packet.headers.address.ia.source;
        if packet.headers.address.ia.destination == source_ia {
            return self.try_dispatch_local(packet);
        }

        // Extract the source IA and next hop from the packet.
        let interface_id = if let DataPlanePath::Standard(standard_path) = &packet.headers.path
            && let Some(interface_id) = standard_path.iter_interfaces().next()
        {
            interface_id
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path does not contain first hop.".to_string(),
            ));
        };

        let next_hop = self
            .discovery
            .resolve_udp_underlay_next_hop(PathInterface {
                isd_asn: source_ia,
                id: interface_id.get(),
            })
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "could not resolve next hop",
            ))?;

        let packet_bytes = packet.encode_to_bytes_vec().concat();
        // Ignore all errors except for WouldBlock. The sender should try to
        // retransmit.
        match self.inner.try_send_to(&packet_bytes, next_hop) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                tracing::warn!(err = ?e, "Error sending packet");
                Ok(())
            }
        }?;
        Ok(())
    }

    fn poll_recv_from_with_path(
        &self,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<(SocketAddr, bytes::Bytes, scion_proto::path::Path)>> {
        loop {
            let mut raw_buf = [0u8; UDP_DATAGRAM_BUFFER_SIZE];
            let mut buf = ReadBuf::new(&mut raw_buf);
            let _ = ready!(self.inner.poll_recv_from(cx, &mut buf))?;

            let packet = match ScionPacketRaw::decode(&mut BytesMut::from(buf.initialized())) {
                Ok(packet) => packet,
                Err(e) => {
                    tracing::trace!(error = %e, "Received non SCION packet, dropping");
                    continue;
                }
            };
            let src = match packet.headers.address.source() {
                Some(src) => src,
                None => {
                    tracing::trace!("Received packet without source address header, dropping");
                    continue;
                }
            };
            let dst = match packet.headers.address.destination() {
                Some(dst) => dst,
                None => {
                    tracing::trace!("Received packet without destination address header, dropping");
                    continue;
                }
            };

            let path = Path::new(
                packet.headers.path.clone(),
                ByEndpoint {
                    source: src.isd_asn(),
                    destination: dst.isd_asn(),
                },
                None,
            );

            match packet.headers.common.next_header {
                UdpMessage::PROTOCOL_NUMBER => {
                    let packet: ScionPacketUdp = match packet.try_into() {
                        Ok(packet) => packet,
                        Err(e) => {
                            tracing::error!(error = %e, "Received non UDP packet, dropping");
                            continue;
                        }
                    };

                    return Poll::Ready(Ok((
                        SocketAddr::new(src, packet.src_port()),
                        packet.datagram.payload,
                        path,
                    )));
                }
                SCMP_PROTOCOL_NUMBER => {
                    // XXX(uniquefine): We should handle SCMP packets here.
                    tracing::debug!("SCMP packet received, skipping");
                    continue;
                }
                _ => {
                    tracing::debug!(next_header = %packet.headers.common.next_header, "Unknown packet type, dropping");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}
