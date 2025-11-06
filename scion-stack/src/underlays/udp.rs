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
//! UDP underlay stack.

use std::{
    net::{self, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

use anyhow::Context as _;
use demultiplexer::Demultiplexer;
use futures::future::BoxFuture;
use scion_proto::address::{EndhostAddr, IsdAsn, ScionAddr, SocketAddr};
use tokio::sync::mpsc;
use underlay_resolver::UdpUnderlayResolver;

use crate::scionstack::{ScionSocketBindError, SocketKind, UnderlayStack};

mod demultiplexer;
mod socket;
pub mod underlay_resolver;

pub use socket::{UdpAsyncUdpUnderlaySocket, UdpUnderlaySocket};

/// Underlay stack that uses UDP as underlay to connect to the SCION network
/// via SCION routers.
/// It can be used when no SNAP dataplane is available.
pub struct UdpUnderlayStack {
    demultiplexer: Demultiplexer,
    /// The size of the receive queue of packets received from the OS UDP sockets.
    receive_channel_size: usize,
    underlay_next_hop_resolver: Arc<UdpUnderlayResolver>,
    local_ip_resolver: Arc<dyn LocalIpResolver>,
}

impl UdpUnderlayStack {
    /// Creates a new UDP underlay stack.
    pub fn new(
        underlay_next_hop_resolver: Arc<UdpUnderlayResolver>,
        local_ip_resolver: Arc<dyn LocalIpResolver>,
        receive_channel_size: usize,
    ) -> Self {
        Self {
            demultiplexer: Demultiplexer::new(),
            receive_channel_size,
            underlay_next_hop_resolver,
            local_ip_resolver,
        }
    }

    fn resolve_bind_addr(
        &self,
        bind_addr: Option<SocketAddr>,
    ) -> Result<SocketAddr, ScionSocketBindError> {
        let bind_addr = match bind_addr {
            Some(addr) => {
                if addr.is_service() {
                    return Err(ScionSocketBindError::InvalidBindAddress(
                        addr,
                        "service addresses can't be bound".to_string(),
                    ));
                }
                addr
            }
            None => {
                let local_address = *self.local_ip_resolver.local_ips().first().ok_or(
                    ScionSocketBindError::InvalidBindAddress(
                        SocketAddr::new(ScionAddr::new(IsdAsn(0), Ipv4Addr::UNSPECIFIED.into()), 0),
                        "no local address found".to_string(),
                    ),
                )?;
                let isd_as = *self
                    .underlay_next_hop_resolver
                    .isd_ases()
                    .iter()
                    .min() // Use min to make it deterministic.
                    .ok_or(ScionSocketBindError::InvalidBindAddress(
                        SocketAddr::new(ScionAddr::new(IsdAsn(0), Ipv4Addr::UNSPECIFIED.into()), 0),
                        "no local ISD-AS found".to_string(),
                    ))?;
                SocketAddr::new(ScionAddr::new(isd_as, local_address.into()), 0)
            }
        };
        Ok(bind_addr)
    }
}

impl UnderlayStack for UdpUnderlayStack {
    type Socket = UdpUnderlaySocket;
    type AsyncUdpSocket = UdpAsyncUdpUnderlaySocket;

    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Self::Socket, ScionSocketBindError>> {
        Box::pin(async move {
            let bind_addr = self.resolve_bind_addr(bind_addr)?;

            let (sender, receiver) = mpsc::channel(self.receive_channel_size);
            let underlay_socket = self.demultiplexer.register(bind_addr, kind, sender).await?;

            // Find the address that was assigned.
            let local_addr = underlay_socket.local_addr().map_err(|e| {
                ScionSocketBindError::InvalidBindAddress(
                    bind_addr,
                    format!("failed to get local address: {e}"),
                )
            })?;
            let bind_addr = SocketAddr::new(
                ScionAddr::new(bind_addr.isd_asn(), local_addr.ip().into()),
                local_addr.port(),
            );

            Ok(UdpUnderlaySocket::new(
                underlay_socket,
                bind_addr,
                self.underlay_next_hop_resolver.clone(),
                receiver,
            ))
        })
    }

    fn bind_socket_with_time(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
        _: Instant,
    ) -> BoxFuture<'_, Result<Self::Socket, ScionSocketBindError>> {
        Box::pin(async move { self.bind_socket(kind, bind_addr).await })
    }

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Self::AsyncUdpSocket, ScionSocketBindError>> {
        Box::pin(async move {
            let bind_addr = self.resolve_bind_addr(bind_addr)?;

            let (sender, receiver) = mpsc::channel(self.receive_channel_size);
            let underlay_socket = self
                .demultiplexer
                .register(bind_addr, SocketKind::Udp, sender)
                .await?;

            // Find the address that was assigned.
            let local_addr = underlay_socket.local_addr().map_err(|e| {
                ScionSocketBindError::InvalidBindAddress(
                    bind_addr,
                    format!("failed to get local address: {e}"),
                )
            })?;
            let bind_addr = SocketAddr::new(
                ScionAddr::new(bind_addr.isd_asn(), local_addr.ip().into()),
                local_addr.port(),
            );

            Ok(UdpAsyncUdpUnderlaySocket::new(
                bind_addr,
                self.underlay_next_hop_resolver.clone(),
                underlay_socket,
                receiver,
            ))
        })
    }

    fn local_addresses(&self) -> Vec<EndhostAddr> {
        let local_ips = self.local_ip_resolver.local_ips();
        if local_ips.is_empty() {
            return vec![];
        }
        let isd_ases = self.underlay_next_hop_resolver.isd_ases();
        isd_ases
            .into_iter()
            .flat_map(|isd_as| {
                local_ips
                    .iter()
                    .map(move |ip| EndhostAddr::new(isd_as, *ip))
            })
            .collect()
    }
}

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
