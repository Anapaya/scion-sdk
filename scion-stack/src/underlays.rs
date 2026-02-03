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

use scion_proto::address::{Isd, IsdAsn, ScionAddr, SocketAddr};
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use scion_sdk_utils::backoff::ExponentialBackoff;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use url::Url;
use x25519_dalek::StaticSecret;

use crate::{
    scionstack::{
        AsyncUdpUnderlaySocket, DynUnderlayStack, InvalidBindAddressError, ScionSocketBindError,
        SnapConnectionError, UnderlaySocket, builder::PreferredUnderlay, scmp_handler::ScmpHandler,
    },
    underlays::{
        discovery::{UnderlayDiscovery, UnderlayInfo},
        udp::{LocalIpResolver, UdpAsyncUdpUnderlaySocket, UdpUnderlaySocket},
    },
};

pub mod discovery;
pub mod snap_ng;
pub mod udp;

/// Configuration needed to create a SNAP socket(s).
pub struct SnapSocketConfig {
    /// Source for SNAP token. If this is None, no SNAP sockets
    /// can be bound.
    pub snap_token_source: Option<Arc<dyn TokenSource>>,
    /// Backoff for reconnecting a SNAP tunnel.
    pub reconnect_backoff: ExponentialBackoff,
}

/// Underlay stack.
pub struct UnderlayStack {
    preferred_underlay: PreferredUnderlay,
    underlay_discovery: Arc<dyn UnderlayDiscovery>,
    /// Resolver for the local IP address for UDP underlay sockets.
    local_ip_resolver: Arc<dyn LocalIpResolver>,
    snap_socket_config: SnapSocketConfig,
    // TODO(uniquefine): This should be handled by a
    // global identity registration component.
    // https://github.com/Anapaya/scion/issues/27486
    // Generate an register an identity for this socket.
    snap_static_identity: StaticSecret,
}

impl UnderlayStack {
    /// Creates a new underlay stack.
    pub fn new(
        preferred_underlay: PreferredUnderlay,
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
        local_ip_resolver: Arc<dyn LocalIpResolver>,
        snap_socket_config: SnapSocketConfig,
    ) -> Self {
        Self {
            preferred_underlay,
            underlay_discovery,
            local_ip_resolver,
            snap_socket_config,
            snap_static_identity: StaticSecret::random(),
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
        bind_addr: Option<scion_proto::address::SocketAddr>,
        isd_as: IsdAsn,
        cp_url: Url,
        token_source: Option<Arc<dyn TokenSource>>,
    ) -> Result<snap_ng::SnapUnderlaySocket, ScionSocketBindError> {
        let token_source = token_source.ok_or(ScionSocketBindError::SnapConnectionError(
            SnapConnectionError::SnapTokenSourceMissing,
        ))?;

        let local_addr = match bind_addr {
            Some(addr) => {
                addr.local_address()
                    .ok_or(ScionSocketBindError::InvalidBindAddress(
                        InvalidBindAddressError::ServiceAddress(addr),
                    ))?
            }
            None => "0.0.0.0:0".parse().unwrap(),
        };

        let bind_addr = SocketAddr::from_std(isd_as, local_addr);

        let udp_socket = bind_udp_underlay_socket(local_addr)?;

        let socket = snap_ng::SnapUnderlaySocket::new(
            bind_addr,
            cp_url,
            udp_socket,
            token_source,
            self.snap_static_identity.clone(),
            1024,
        )
        .await?;
        Ok(socket)
    }

    fn resolve_udp_bind_addr(
        &self,
        isd_as: IsdAsn,
        bind_addr: Option<SocketAddr>,
    ) -> Result<SocketAddr, ScionSocketBindError> {
        let bind_addr = match bind_addr {
            Some(addr) => {
                if addr.is_service() {
                    return Err(ScionSocketBindError::InvalidBindAddress(
                        InvalidBindAddressError::ServiceAddress(addr),
                    ));
                }
                addr
            }
            None => {
                let local_address = *self.local_ip_resolver.local_ips().first().ok_or(
                    ScionSocketBindError::InvalidBindAddress(
                        InvalidBindAddressError::NoLocalIpAddressFound,
                    ),
                )?;
                SocketAddr::new(ScionAddr::new(isd_as, local_address.into()), 0)
            }
        };
        Ok(bind_addr)
    }

    async fn bind_udp_socket(
        &self,
        isd_as: IsdAsn,
        bind_addr: Option<SocketAddr>,
    ) -> Result<(SocketAddr, UdpSocket), ScionSocketBindError> {
        let bind_addr = self.resolve_udp_bind_addr(isd_as, bind_addr)?;
        let local_addr: net::SocketAddr =
            bind_addr
                .local_address()
                .ok_or(ScionSocketBindError::InvalidBindAddress(
                    InvalidBindAddressError::ServiceAddress(bind_addr),
                ))?;
        let socket = bind_udp_underlay_socket(local_addr)?;
        let local_addr = socket.local_addr().map_err(|e| {
            ScionSocketBindError::Other(
                anyhow::anyhow!("failed to get local address: {e}").into_boxed_dyn_error(),
            )
        })?;
        let bind_addr = SocketAddr::new(
            ScionAddr::new(bind_addr.isd_asn(), local_addr.ip().into()),
            local_addr.port(),
        );
        Ok((bind_addr, socket))
    }
}

impl DynUnderlayStack for UnderlayStack {
    fn bind_socket(
        &self,
        _kind: crate::scionstack::SocketKind,
        bind_addr: Option<scion_proto::address::SocketAddr>,
    ) -> futures::future::BoxFuture<
        '_,
        Result<Box<dyn crate::scionstack::UnderlaySocket>, crate::scionstack::ScionSocketBindError>,
    > {
        Box::pin(async move {
            let requested_isd_as = bind_addr
                .map(|addr| addr.isd_asn())
                .unwrap_or(IsdAsn::WILDCARD);
            match self.select_underlay(requested_isd_as) {
                Some((isd_as, UnderlayInfo::Snap(cp_url))) => {
                    Ok(Box::new(
                        self.bind_snap_socket(
                            bind_addr,
                            isd_as,
                            cp_url,
                            self.snap_socket_config.snap_token_source.clone(),
                        )
                        .await?,
                    ) as Box<dyn UnderlaySocket>)
                }
                Some((isd_as, UnderlayInfo::Udp(_))) => {
                    let (bind_addr, socket) = self.bind_udp_socket(isd_as, bind_addr).await?;
                    Ok(Box::new(UdpUnderlaySocket::new(
                        socket,
                        bind_addr,
                        self.underlay_discovery.clone(),
                    )) as Box<dyn UnderlaySocket>)
                }
                None => {
                    Err(
                        crate::scionstack::ScionSocketBindError::NoUnderlayAvailable(
                            requested_isd_as.isd(),
                        ),
                    )
                }
            }
        })
    }

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<scion_proto::address::SocketAddr>,
        scmp_handlers: Vec<Box<dyn ScmpHandler>>,
    ) -> futures::future::BoxFuture<
        '_,
        Result<
            std::sync::Arc<dyn crate::scionstack::AsyncUdpUnderlaySocket>,
            crate::scionstack::ScionSocketBindError,
        >,
    > {
        Box::pin(async move {
            match self.select_underlay(
                bind_addr
                    .map(|addr| addr.isd_asn())
                    .unwrap_or(IsdAsn::WILDCARD),
            ) {
                Some((isd_as, UnderlayInfo::Snap(cp_url))) => {
                    let socket = self
                        .bind_snap_socket(
                            bind_addr,
                            isd_as,
                            cp_url,
                            self.snap_socket_config.snap_token_source.clone(),
                        )
                        .await?;
                    let async_udp_socket = snap_ng::SnapAsyncUdpSocket::new(socket, scmp_handlers);
                    Ok(Arc::new(async_udp_socket) as Arc<dyn AsyncUdpUnderlaySocket + 'static>)
                }
                Some((isd_as, UnderlayInfo::Udp(_))) => {
                    let (bind_addr, socket) = self.bind_udp_socket(isd_as, bind_addr).await?;
                    let async_udp_socket = UdpAsyncUdpUnderlaySocket::new(
                        bind_addr,
                        self.underlay_discovery.clone(),
                        socket,
                        scmp_handlers,
                    );
                    Ok(Arc::new(async_udp_socket) as Arc<dyn AsyncUdpUnderlaySocket + 'static>)
                }
                None => {
                    Err(
                        crate::scionstack::ScionSocketBindError::NoUnderlayAvailable(
                            bind_addr
                                .map(|addr| addr.isd_asn().isd())
                                .unwrap_or(Isd::WILDCARD),
                        ),
                    )
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
                        SocketAddr::from_std(IsdAsn::WILDCARD, addr),
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
