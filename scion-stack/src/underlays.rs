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

use std::{sync::Arc, time::Duration};

use scion_proto::address::{IsdAsn, ScionAddr, SocketAddr};
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use scion_sdk_utils::backoff::ExponentialBackoff;
use tokio::net::UdpSocket;
use url::Url;

use crate::{
    scionstack::{
        AsyncUdpUnderlaySocket, DynUnderlayStack, ScionSocketBindError, UnderlaySocket,
        builder::PreferredUnderlay,
    },
    underlays::{
        discovery::{UnderlayDiscovery, UnderlayInfo},
        snap::{SnapAsyncUdpSocket, SnapUnderlaySocket},
        udp::{LocalIpResolver, UdpAsyncUdpUnderlaySocket, UdpUnderlaySocket},
    },
};

pub mod discovery;
pub mod snap;
pub mod udp;

/// Configuration needed to create a SNAP socket(s).
pub struct SnapSocketConfig {
    /// Source for SNAP token. If this is None, no SNAP sockets
    /// can be bound.
    pub snap_token_source: Option<Arc<dyn TokenSource>>,
    /// Threshold for waiting before sending a fresh SNAP token to the SNAP data plane.
    pub renewal_wait_threshold: Duration,
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
    ) -> Result<SnapUnderlaySocket, ScionSocketBindError> {
        let token_source = token_source.ok_or(ScionSocketBindError::DataplaneError(
            "cannot bind SNAP socket without SNAP token (source)".into(),
        ))?;

        if let Some(SocketAddr::Svc(_)) = bind_addr {
            return Err(ScionSocketBindError::InvalidBindAddress(
                bind_addr.unwrap(),
                "service addresses can't be bound".to_string(),
            ));
        }

        let socket = SnapUnderlaySocket::new(
            isd_as,
            bind_addr.and_then(|addr| addr.local_address()),
            cp_url,
            "localhost".to_string(),
            self.underlay_discovery.clone(),
            token_source,
            self.snap_socket_config.renewal_wait_threshold,
            self.snap_socket_config.reconnect_backoff,
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
                        addr,
                        "service addresses can't be bound".to_string(),
                    ));
                }
                addr
            }
            None => {
                let local_address = *self.local_ip_resolver.local_ips().first().ok_or(
                    ScionSocketBindError::UnderlayUnavailable("no local IP address found".into()),
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
        let local_addr =
            bind_addr
                .local_address()
                .ok_or(ScionSocketBindError::InvalidBindAddress(
                    bind_addr,
                    "Service addresses can't be bound".to_string(),
                ))?;
        let socket = UdpSocket::bind(local_addr).await.map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::AddrInUse => {
                    ScionSocketBindError::PortAlreadyInUse(local_addr.port())
                }
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::InvalidInput => {
                    ScionSocketBindError::InvalidBindAddress(
                        bind_addr,
                        format!("Failed to bind socket: {e:#}"),
                    )
                }
                _ => ScionSocketBindError::Other(Box::new(e)),
            }
        })?;
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
                None => Err(
                    crate::scionstack::ScionSocketBindError::UnderlayUnavailable(
                        format!(
                            "no underlay available to bind the requested ISD-AS {requested_isd_as}"
                        )
                        .into(),
                    ),
                ),
            }
        })
    }

    // XXX(uniquefine): drop this func once we migrated to v2.
    fn bind_socket_with_time(
        &self,
        kind: crate::scionstack::SocketKind,
        bind_addr: Option<scion_proto::address::SocketAddr>,
        _now: std::time::Instant,
    ) -> futures::future::BoxFuture<
        '_,
        Result<Box<dyn crate::scionstack::UnderlaySocket>, crate::scionstack::ScionSocketBindError>,
    > {
        self.bind_socket(kind, bind_addr)
    }

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<scion_proto::address::SocketAddr>,
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
                    let async_udp_socket = SnapAsyncUdpSocket::new(socket);
                    Ok(Arc::new(async_udp_socket) as Arc<dyn AsyncUdpUnderlaySocket + 'static>)
                }
                Some((isd_as, UnderlayInfo::Udp(_))) => {
                    let (bind_addr, socket) = self.bind_udp_socket(isd_as, bind_addr).await?;
                    let async_udp_socket = UdpAsyncUdpUnderlaySocket::new(
                        bind_addr,
                        self.underlay_discovery.clone(),
                        socket,
                    );
                    Ok(Arc::new(async_udp_socket) as Arc<dyn AsyncUdpUnderlaySocket + 'static>)
                }
                None => {
                    // XXX(uniquefine): use a proper error type here.
                    Err(crate::scionstack::ScionSocketBindError::Other(
                        anyhow::anyhow!("no underlay available").into_boxed_dyn_error(),
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
