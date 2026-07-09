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
    net::{self},
    sync::Arc,
};

use futures::future::BoxFuture;
use sciparse::{
    address::ip_socket_addr::ScionSocketIpAddr,
    core::view::View,
    dataplane_path::view::ScionDpPathViewExt,
    identifier::isd_asn::IsdAsn,
    packet::view::{ScionPacketView, ScionRawPacketView},
    path::metadata::path_interface::PathInterface,
};
use tokio::net::UdpSocket;

use crate::{
    scionstack::{ScionSocketSendError, UnderlaySocket},
    underlays::{discovery::UnderlayDiscovery, outbound_ip_towards},
};

const UDP_DATAGRAM_BUFFER_SIZE: usize = 65535;

/// A trait for resolving the local IP addresses for outbound connections.
#[async_trait::async_trait]
pub trait OutboundIpResolver: Send + Sync {
    /// Returns the local IP addresses of the host that can be used to reach the network.
    async fn outbound_ips(&self) -> Vec<net::IpAddr>;
}

#[async_trait::async_trait]
impl OutboundIpResolver for Vec<net::IpAddr> {
    async fn outbound_ips(&self) -> Vec<net::IpAddr> {
        self.clone()
    }
}

/// An outbound IP resolver that resolves the local IP address that can be used to reach a target
/// API address.
///
/// DNS overrides in `host_overrides` take precedence over the OS resolver. This allows
/// the resolver to be used in environments where the OS resolver is not aware of custom
/// hostname-to-IP mappings (e.g. when `ConnectParameters::hosts` is set).
pub struct TargetAddrOutboundIpResolver {
    url: url::Url,
    host_overrides: Vec<(String, net::IpAddr)>,
}

impl TargetAddrOutboundIpResolver {
    /// Create an outbound IP resolver for the given target `url` with a set of hostname-to-IP
    /// overrides.
    ///
    /// When resolving the outbound IP towards `url`, entries in `host_overrides` are checked before
    /// the OS resolver. Pass an empty vec when no overrides are needed.
    pub fn new(url: url::Url, host_overrides: Vec<(String, net::IpAddr)>) -> Self {
        Self {
            url,
            host_overrides,
        }
    }
}

#[async_trait::async_trait]
impl OutboundIpResolver for TargetAddrOutboundIpResolver {
    /// Returns the local IP addresses that can reach the target URL.
    ///
    /// Resolution order:
    /// 1. `host_overrides` map
    /// 2. Literal IP in the URL
    /// 3. OS DNS resolver
    async fn outbound_ips(&self) -> Vec<net::IpAddr> {
        let url = &self.url;
        let host = match url.host_str() {
            Some(h) => h,
            None => return vec![],
        };
        let port = url.port_or_known_default().unwrap_or(0);

        let target = if let Some((_, ip)) = self.host_overrides.iter().find(|(h, _)| h == host) {
            net::SocketAddr::new(*ip, port)
        } else if let Ok(ip) = host.parse::<net::IpAddr>() {
            net::SocketAddr::new(ip, port)
        } else {
            match url
                .socket_addrs(|| None)
                .ok()
                .and_then(|addrs| addrs.into_iter().next())
            {
                Some(addr) => addr,
                None => {
                    tracing::warn!(url = %url, "failed to resolve API URL for local IP detection");
                    return vec![];
                }
            }
        };

        match outbound_ip_towards(target).await {
            Some(ip) => vec![ip],
            None => vec![],
        }
    }
}

/// A UDP underlay socket.
pub struct UdpUnderlaySocket {
    pub(crate) socket: UdpSocket,
    pub(crate) bind_addr: ScionSocketIpAddr,
    pub(crate) underlay_discovery: Arc<dyn UnderlayDiscovery>,
}

impl UdpUnderlaySocket {
    pub(crate) fn new(
        socket: UdpSocket,
        bind_addr: ScionSocketIpAddr,
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
    ) -> Self {
        Self {
            socket,
            bind_addr,
            underlay_discovery,
        }
    }

    /// Dispatch a packet to the local AS network.
    fn resolve_local_dispatch_addr(
        &self,
        packet: &ScionPacketView,
    ) -> Result<net::SocketAddr, ScionSocketSendError> {
        let dst_addr = packet
            .header()
            .dst_host_addr()
            .map_err(|e| {
                crate::scionstack::ScionSocketSendError::InvalidPacket(
                    format!("Packet for local dispatch had invalid destination address: {e}")
                        .into(),
                )
            })?
            .ip()
            .ok_or(crate::scionstack::ScionSocketSendError::InvalidPacket(
                "Packet for local dispatch dst was not an IP address".into(),
            ))?;

        let classified = packet.try_classify().map_err(|e| {
            crate::scionstack::ScionSocketSendError::InvalidPacket(
                format!("Failed to classify packet for local dispatch: {e}").into(),
            )
        })?;

        let dst_port =
            classified
                .dst_port()
                .ok_or(crate::scionstack::ScionSocketSendError::InvalidPacket(
                    "Coulldn't determine destination port in packet for local dispatch".into(),
                ))?;

        Ok(net::SocketAddr::new(dst_addr, dst_port))
    }

    fn try_dispatch_local(&self, packet: &ScionPacketView) -> Result<(), ScionSocketSendError> {
        let dst_addr = self.resolve_local_dispatch_addr(packet)?;
        self.socket
            .try_send_to(packet.as_slice(), dst_addr)
            .map_err(|e| Self::map_send_io_error(e, packet.header().src_ia(), 0, dst_addr))?;
        Ok(())
    }

    /// Dispatch a packet to the local AS network.
    async fn dispatch_local(
        &self,
        packet: &ScionPacketView,
    ) -> Result<(), crate::scionstack::ScionSocketSendError> {
        let dst_addr = self.resolve_local_dispatch_addr(packet)?;
        self.socket
            .send_to(packet.as_slice(), dst_addr)
            .await
            .map_err(|e| Self::map_send_io_error(e, packet.header().src_ia(), 0, dst_addr))?;
        Ok(())
    }

    /// Map a UDP send error to a SCION socket send error.
    fn map_send_io_error(
        e: io::Error,
        src: IsdAsn,
        interface_id: u16,
        next_hop: net::SocketAddr,
    ) -> ScionSocketSendError {
        use std::io::ErrorKind::*;
        match e.kind() {
            HostUnreachable | NetworkUnreachable => {
                ScionSocketSendError::UnderlayNextHopUnreachable {
                    isd_as: src,
                    interface_id,
                    address: Some(next_hop),
                    msg: e.to_string(),
                }
            }
            ConnectionAborted | ConnectionReset | BrokenPipe => ScionSocketSendError::Closed,
            _ => ScionSocketSendError::IoError(e),
        }
    }
}

impl UnderlaySocket for UdpUnderlaySocket {
    fn send<'a>(
        &'a self,
        packet: &'a ScionRawPacketView,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
        let source_ia = packet.header().src_ia();

        // If packet is destined for the local AS, dispatch it locally.
        if packet.header().dst_ia() == source_ia {
            return Box::pin(self.dispatch_local(packet));
        }

        // Get the current egress interface from the path
        let Some(egress_if) = packet.header().path().first_egress_interface() else {
            return Box::pin(async move {
                Err(ScionSocketSendError::InvalidPacket(
                    "Can't determine egress interface for packet.".into(),
                ))
            });
        };

        // Lookup the address of the egress router by the source IA and egress interface.
        let next_hop = match self
            .underlay_discovery
            .resolve_udp_underlay_next_hop(PathInterface {
                isd_asn: source_ia,
                id: egress_if,
            }) {
            Some(next_hop) => next_hop,
            None => {
                return Box::pin(async move {
                    Err(ScionSocketSendError::UnderlayNextHopUnreachable {
                        isd_as: source_ia,
                        interface_id: egress_if,
                        address: None,
                        msg: "next hop not found".to_string(),
                    })
                });
            }
        };

        Box::pin(async move {
            self.socket
                .send_to(packet.as_slice(), next_hop)
                .await
                .map_err(|e| Self::map_send_io_error(e, source_ia, egress_if, next_hop))?;

            Ok(())
        })
    }

    /// Try to send a raw packet immediately. Takes a ScionPacketRaw because it needs to read the
    /// path to resolve the underlay next hop.
    fn try_send(&self, packet: &ScionRawPacketView) -> Result<(), ScionSocketSendError> {
        let source_ia = packet.header().src_ia();

        // If packet is destined for the local AS, dispatch it locally.
        if packet.header().dst_ia() == source_ia {
            return self.try_dispatch_local(packet);
        }

        // Get the current egress interface from the path
        let Some(egress_if) = packet.header().path().first_egress_interface() else {
            return Err(ScionSocketSendError::InvalidPacket(
                "Can't determine egress interface for packet.".into(),
            ));
        };

        // Lookup the address of the egress router by the source IA and egress interface.
        let next_hop = match self
            .underlay_discovery
            .resolve_udp_underlay_next_hop(PathInterface {
                isd_asn: source_ia,
                id: egress_if,
            }) {
            Some(next_hop) => next_hop,
            None => {
                return Err(ScionSocketSendError::UnderlayNextHopUnreachable {
                    isd_as: source_ia,
                    interface_id: egress_if,
                    address: None,
                    msg: "next hop not found".to_string(),
                });
            }
        };

        self.socket
            .try_send_to(packet.as_slice(), next_hop)
            .map_err(|e| Self::map_send_io_error(e, source_ia, egress_if, next_hop))?;

        Ok(())
    }

    fn recv<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Box<ScionRawPacketView>, crate::scionstack::ScionSocketReceiveError>>
    {
        Box::pin(async move {
            let mut buf = [0u8; UDP_DATAGRAM_BUFFER_SIZE];
            loop {
                let (n, _) = self.socket.recv_from(&mut buf).await?;

                let packet = match ScionRawPacketView::try_from_slice(&buf[..n]) {
                    Ok((packet, _rest)) => packet,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to decode SCION packet");
                        continue;
                    }
                };

                let dst = match packet.dst_scion_addr() {
                    Ok(dst) => Some(dst),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to read destination address from packet");
                        continue;
                    }
                };

                // Drop packets that are not addressed to this socket.
                if dst != Some(self.bind_addr.scion_addr()) {
                    tracing::debug!(destination = ?dst, assigned_addr = %self.bind_addr.scion_addr(), "Packet destination does not match assigned address, skipping");
                    continue;
                }

                return Ok(packet.to_boxed());
            }
        })
    }

    fn local_addr(&self) -> ScionSocketIpAddr {
        self.bind_addr
    }

    fn snap_data_plane(&self) -> Option<net::SocketAddr> {
        None
    }
}
