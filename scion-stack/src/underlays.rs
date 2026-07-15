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
//! SCION stack underlay implementations.

use std::{net, sync::Arc};

use ana_gotatun::packet::PacketBufPool;
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use sciparse::{address::ip_socket_addr::ScionSocketIpAddr, identifier::isd_asn::IsdAsn};
use snap_tun::client::{PACKET_BUF_POOL_SIZE, SnapTunEndpoint};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use url::Url;
use x25519_dalek::StaticSecret;

use crate::{
    scionstack::{
        BoundUnderlaySocket, DynUnderlayStack, InvalidBindAddressError, ScionSocketBindError,
        SnapConnectionError, UnderlaySocket, builder::PreferredUnderlay,
    },
    underlays::{
        discovery::{UnderlayDiscovery, UnderlayInfo},
        udp::{OutboundIpResolver, UdpUnderlaySocket},
    },
};

pub mod discovery;
pub mod snap;
pub mod udp;

/// Configuration needed to create a SNAP socket(s).
pub(crate) struct SnapSocketConfig {
    /// Custom CRPC client for reaching the SNAP control plane.
    pub crpc_client: Option<reqwest::Client>,
    /// Source for SNAP token. If this is None, no SNAP sockets
    /// can be bound.
    pub snap_token_source: Option<Arc<dyn TokenSource>>,
}

/// Underlay stack.
pub(crate) struct UnderlayStack {
    preferred_underlay: PreferredUnderlay,
    underlay_discovery: Arc<dyn UnderlayDiscovery>,
    /// Resolver for the outbound IP address for UDP underlay sockets.
    outbound_ip_resolver: Arc<dyn OutboundIpResolver>,
    snap_socket_config: SnapSocketConfig,
    snap_tunnel_manager: Option<SnapTunEndpoint>,
    pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
}

impl UnderlayStack {
    /// Creates a new underlay stack.
    pub fn new(
        preferred_underlay: PreferredUnderlay,
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
        outbound_ip_resolver: Arc<dyn OutboundIpResolver>,
        static_identity: StaticSecret,
        default_snap_socket_config: SnapSocketConfig,
    ) -> Self {
        let snap_tunnel_manager = default_snap_socket_config
            .snap_token_source
            .as_ref()
            .map(|token_source| SnapTunEndpoint::new(token_source.clone(), static_identity));
        Self {
            preferred_underlay,
            underlay_discovery,
            outbound_ip_resolver,
            snap_socket_config: default_snap_socket_config,
            snap_tunnel_manager,
            pool: PacketBufPool::new(64),
        }
    }

    /// Selects the first underlay that matches the requested isd as. If available, the preferred
    /// underlay type is returned.
    ///
    /// XXX(uniquefine): We only use the ISD-AS to select the underlay, the bind address is ignored.
    /// In the unlikely case that user requests a specific IP, but a wildcard ISD-AS, it could in
    /// theory happen that we select the wrong underlay.
    fn select_underlay(&self, requested_isd_as: IsdAsn) -> Option<(IsdAsn, UnderlayInfo)> {
        let underlays = self.underlay_discovery.underlays(requested_isd_as);
        match self.preferred_underlay {
            PreferredUnderlay::Snap => {
                if let Some(underlay) = underlays
                    .iter()
                    .find(|(_, underlay)| matches!(underlay, UnderlayInfo::Snap(_)))
                {
                    return Some(underlay.clone());
                }
            }
            PreferredUnderlay::Udp => {
                if let Some(underlay) = underlays
                    .iter()
                    .find(|(_, underlay)| matches!(underlay, UnderlayInfo::Udp(_)))
                {
                    return Some(underlay.clone());
                }
            }
        }
        underlays.into_iter().next()
    }

    async fn bind_snap_socket(
        &self,
        requested_addr: Option<ScionSocketIpAddr>,
        isd_as: IsdAsn,
        cp_url: Url,
    ) -> Result<snap::SnapUnderlaySocket, ScionSocketBindError> {
        let (Some(token_source), Some(snap_tunnel_manager)) = (
            self.snap_socket_config.snap_token_source.as_ref(),
            self.snap_tunnel_manager.as_ref(),
        ) else {
            return Err(ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::SnapTokenSourceMissing,
            ))?;
        };

        let local_addr = match requested_addr {
            Some(addr) => addr.socket_addr(),
            None => {
                if let Some(cp_addr) = cp_url
                    .socket_addrs(|| None)
                    .ok()
                    .and_then(|addrs| addrs.first().cloned())
                    && let Some(ip) = outbound_ip_towards(cp_addr).await
                {
                    Ok(net::SocketAddr::new(ip, 0))
                } else {
                    Err(ScionSocketBindError::InvalidBindAddress(
                        InvalidBindAddressError::NoLocalIpAddressFound,
                    ))
                }?
            }
        };

        let bind_addr = ScionSocketIpAddr::new(isd_as, local_addr.ip(), local_addr.port());

        let udp_socket = bind_udp_underlay_socket(local_addr)?;

        let socket = snap::SnapUnderlaySocket::new(
            bind_addr,
            cp_url,
            udp_socket,
            snap_tunnel_manager,
            token_source.clone(),
            1024,
            self.pool.clone(),
            self.snap_socket_config.crpc_client.clone(),
        )
        .await?;

        let assigned_addr = socket.local_addr();

        // If the requested address is specified but does not match the assigned address, return an
        // error.
        if let Some(requested_addr) = requested_addr
                // IsdAsn mismatch
                && requested_addr.isd_asn().matches(assigned_addr.isd_asn())
                // IP mismatch. Note, that both addresses will have ip addresses.
                && let requested_socket_addr = requested_addr.socket_addr()
                && let assigned_socket_addr = assigned_addr.socket_addr()
                && ((!requested_socket_addr.ip().is_unspecified() && assigned_socket_addr.ip() != requested_socket_addr.ip())
                // Port mismatch
                || (requested_socket_addr.port() != 0 && assigned_socket_addr.port() != requested_socket_addr.port()))
        {
            // IsdAsns must match

            return Err(crate::scionstack::ScionSocketBindError::InvalidBindAddress(
                crate::scionstack::InvalidBindAddressError::AddressMismatch {
                    assigned_addr: ScionSocketIpAddr::new(
                        bind_addr.isd_asn(),
                        requested_socket_addr.ip(),
                        requested_socket_addr.port(),
                    ),
                    bind_addr,
                },
            ));
        }

        Ok(socket)
    }

    /// Resolves the bind address for a UDP socket. If an override address is provided, it is used.
    ///
    /// Otherwise tries to determine which interface's ip address can reach the endhost api and uses
    /// that as the bind address
    async fn resolve_udp_bind_addr(
        &self,
        isd_as: IsdAsn,
        override_addr: Option<ScionSocketIpAddr>,
    ) -> Result<ScionSocketIpAddr, ScionSocketBindError> {
        if let Some(addr) = override_addr {
            return Ok(addr);
        }

        // No override address provided, try to determine the local IP address that can reach the
        // control plane.
        let local_address = *self
            .outbound_ip_resolver
            .outbound_ips()
            .await
            .first()
            .ok_or(ScionSocketBindError::InvalidBindAddress(
                InvalidBindAddressError::NoLocalIpAddressFound,
            ))?;

        Ok(ScionSocketIpAddr::new(isd_as, local_address, 0))
    }

    async fn bind_udp_socket(
        &self,
        isd_as: IsdAsn,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<(ScionSocketIpAddr, UdpSocket), ScionSocketBindError> {
        //TODO: the bind address could be a wildcard, in which case it should be handled the same
        // as a None? So this should probably be either disallowed, or the Option removed
        let bind_addr = self.resolve_udp_bind_addr(isd_as, bind_addr).await?;
        let local_addr: net::SocketAddr = bind_addr.socket_addr();

        // Bind the udp socket
        let socket = bind_udp_underlay_socket(local_addr)?;
        let local_addr = socket.local_addr().map_err(|e| {
            ScionSocketBindError::Other(
                anyhow::anyhow!("failed to get local address: {e}").into_boxed_dyn_error(),
            )
        })?;

        // We use the extracted local address to avoid mismatches between the requested bind address
        // and the actual bind address.
        let bind_addr =
            ScionSocketIpAddr::new(bind_addr.isd_asn(), local_addr.ip(), local_addr.port());

        Ok((bind_addr, socket))
    }
}

impl DynUnderlayStack for UnderlayStack {
    fn bind_socket(
        &self,
        _kind: crate::scionstack::SocketKind,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> futures::future::BoxFuture<'_, Result<BoundUnderlaySocket, ScionSocketBindError>> {
        Box::pin(async move {
            let requested_isd_as = bind_addr
                .map(|addr| addr.isd_asn())
                .unwrap_or(IsdAsn::WILDCARD);
            match self.select_underlay(requested_isd_as) {
                Some((isd_as, UnderlayInfo::Snap(cp_url))) => {
                    let socket = self.bind_snap_socket(bind_addr, isd_as, cp_url).await?;
                    Ok(BoundUnderlaySocket {
                        local_addr: socket.local_addr(),
                        snap_data_plane: socket.snap_data_plane(),
                        socket: Box::new(socket) as Box<dyn UnderlaySocket>,
                    })
                }
                Some((isd_as, UnderlayInfo::Udp(_))) => {
                    let (bind_addr, socket) = self.bind_udp_socket(isd_as, bind_addr).await?;
                    Ok(BoundUnderlaySocket {
                        local_addr: bind_addr,
                        snap_data_plane: None,
                        socket: Box::new(UdpUnderlaySocket::new(
                            socket,
                            bind_addr,
                            self.underlay_discovery.clone(),
                        )) as Box<dyn UnderlaySocket>,
                    })
                }
                None => {
                    Err(ScionSocketBindError::NoUnderlayAvailable(
                        requested_isd_as.isd(),
                    ))
                }
            }
        })
    }

    fn local_ases(&self) -> Vec<IsdAsn> {
        let mut isd_ases: Vec<IsdAsn> = self.underlay_discovery.isd_ases().into_iter().collect();
        isd_ases.sort();
        isd_ases
    }
}

#[cfg(windows)]
fn set_exclusive_addr_use(sock: &Socket, enable: bool) -> std::io::Result<()> {
    use std::{mem, os::windows::io::AsRawSocket};

    use windows_sys::Win32::Networking::WinSock;

    // Winsock expects an int/bool-ish value passed by pointer.
    let val: u32 = if enable { 1 } else { 0 };

    let rc = unsafe {
        WinSock::setsockopt(
            sock.as_raw_socket() as usize,
            WinSock::SOL_SOCKET,
            WinSock::SO_EXCLUSIVEADDRUSE,
            &val as *const _ as *const _,
            mem::size_of_val(&val) as _,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// This is equivalent to tokio::net::UdpSocket::bind(addr) but with the exclusive address use set
/// to true on windows.
/// This is because on windows, by default, multiple sockets can bind to the same address:port
/// if one binds to wildcard address.
fn bind_udp_underlay_socket(
    addr: net::SocketAddr,
) -> Result<tokio::net::UdpSocket, ScionSocketBindError> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| ScionSocketBindError::Other(Box::new(e)))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| ScionSocketBindError::Other(Box::new(e)))?;
    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(false)
    {
        tracing::debug!(%e, "unable to make socket dual-stack");
    }

    // XXX(uniquefine): on windows, we need to set the exclusive address use to true to
    // prevent multiple sockets from binding to the same address.
    #[cfg(windows)]
    set_exclusive_addr_use(&socket, true).map_err(|e| ScionSocketBindError::Other(Box::new(e)))?;

    socket.bind(&addr.into()).map_err(|e| {
        match e.kind() {
            std::io::ErrorKind::AddrInUse => ScionSocketBindError::PortAlreadyInUse(addr.port()),
            std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::InvalidInput => {
                ScionSocketBindError::InvalidBindAddress(
                    InvalidBindAddressError::CannotBindToRequestedAddress(
                        ScionSocketIpAddr::new(IsdAsn::WILDCARD, addr.ip(), addr.port()),
                        format!("Failed to bind socket: {e:#}").into(),
                    ),
                )
            }
            #[cfg(windows)]
            // On windows, if a port is already in use the error returned is sometimes
            // code 10013 WSAEACCES.
            // see https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
            std::io::ErrorKind::PermissionDenied => {
                ScionSocketBindError::PortAlreadyInUse(addr.port())
            }
            _ => ScionSocketBindError::Other(Box::new(e)),
        }
    })?;

    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))
        .map_err(|e| ScionSocketBindError::Other(Box::new(e)))
}

/// Returns the outbound IP address that can reach the given destination address.
pub(crate) async fn outbound_ip_towards(dst: net::SocketAddr) -> Option<net::IpAddr> {
    let bind_addr = match dst.ip() {
        net::IpAddr::V4(_) => net::Ipv4Addr::UNSPECIFIED.into(),
        net::IpAddr::V6(_) => net::Ipv6Addr::UNSPECIFIED.into(),
    };
    if let Ok(socket) = tokio::net::UdpSocket::bind(net::SocketAddr::new(bind_addr, 0)).await
        && socket.connect(dst).await.is_ok()
        && let Ok(addr) = socket.local_addr()
    {
        return Some(addr.ip());
    }
    None
}
