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
//! SNAP underlay stack.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use demultiplexer::DemultiplexerHost;
use futures::future::BoxFuture;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::{EndhostAddr, IsdAsn, SocketAddr};
use snap_control::{client::ControlPlaneApi, crpc_api::api_service::model::SessionGrant};
use socket::{SnapAsyncUdpSocket, SnapUnderlaySocket};
use tokio::sync::mpsc;
use tracing::{Instrument, Span, instrument};

use crate::{
    allocation::{self, PortAllocator},
    scionstack::{ScionSocketBindError, ScmpHandler, SocketKind, UnderlayStack},
    snap_tunnel::{SessionRenewal, SnapTunnel, SnapTunnelError, SnapTunnelSender},
    underlays::snap::demultiplexer::DemultiplexerHandle,
};

fn registration_error_to_bind_error(
    error: demultiplexer::RegistrationError,
    port: u16,
) -> ScionSocketBindError {
    match error {
        demultiplexer::RegistrationError::PortAlreadyInUse => {
            ScionSocketBindError::PortAlreadyInUse(port)
        }
        demultiplexer::RegistrationError::ConnectionClosed => {
            ScionSocketBindError::Internal("demultiplexer stopped".to_string())
        }
    }
}

mod demultiplexer;
pub mod socket;

/// SNAP underlay stack.
pub struct SnapUnderlayStack {
    #[expect(unused)]
    snap_cp_client: Arc<dyn ControlPlaneApi>,
    demultiplexer_handle: DemultiplexerHandle,
    tunnel: Arc<SnapTunnel>,
    port_allocator: PortAllocator,
    /// The size of the receive queue of packets received from the snap tunnel.
    receive_channel_size: usize,
}

/// SNAP underlay stack creation error.
#[derive(thiserror::Error, Debug)]
pub enum NewSnapUnderlayStackError {
    /// SNAP tunnel errors.
    #[error("snap tunnel error: {0:#}")]
    SnapTunnelError(#[from] SnapTunnelError),
    /// Session grant missing.
    #[error("no session grants provided")]
    NoSessionGrants,
}

impl SnapUnderlayStack {
    /// Create a new SNAP underlay stack.
    #[instrument(name = "snap_stack", fields(local), skip_all)]
    pub async fn new(
        snap_cp_client: Arc<dyn ControlPlaneApi>,
        session_grants: Vec<SessionGrant>,
        requested_addresses: Vec<EndhostAddr>,
        rng: ChaCha8Rng,
        port_reserved_time: Duration,
        default_scmp_handler_factory: impl FnOnce(SnapTunnelSender) -> Arc<dyn ScmpHandler>,
        receive_channel_size: usize,
        auto_session_renewal: SessionRenewal,
    ) -> Result<Self, NewSnapUnderlayStackError> {
        // Try to establish a tunnel to each dataplane. Return the first successful tunnel or an
        // error.
        let tunnel = async {
            for (i, session_grant) in session_grants.iter().enumerate() {
                match SnapTunnel::new(
                    session_grant,
                    snap_cp_client.clone(),
                    requested_addresses.clone(),
                    auto_session_renewal.clone(),
                )
                .await
                {
                    Ok(tunnel) => return Ok(tunnel),
                    Err(e) => {
                        if i == session_grants.len() - 1 {
                            return Err(NewSnapUnderlayStackError::SnapTunnelError(e));
                        }
                    }
                }
            }
            Err(NewSnapUnderlayStackError::NoSessionGrants)
        }
        .await?;

        let tunnel = Arc::new(tunnel);

        let assigned_addresses = tunnel.assigned_addresses();

        // Record the assigned addresses in the tracing span.
        Span::current().record(
            "local",
            assigned_addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );

        let default_scmp_handler = default_scmp_handler_factory(tunnel.sender());

        let demultiplexer = DemultiplexerHost::new(tunnel.receiver(), default_scmp_handler);
        let demultiplexer_handle = demultiplexer.handle();

        tokio::spawn(demultiplexer.main_loop().in_current_span());
        // A task that logs path statistics on a regular basis (every 10
        // minutes).
        tokio::spawn({
            let tunnel = tunnel.clone();
            async move {
                loop {
                    let path_stats = tunnel.debug_path_stats();
                    tracing::debug!(?path_stats, "Reporting snaptun path stats");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(600)) => {}
                    };
                }
            }
            .in_current_span()
        });

        Ok(Self {
            snap_cp_client,
            demultiplexer_handle,
            tunnel,
            port_allocator: PortAllocator::new(rng, port_reserved_time),
            receive_channel_size,
        })
    }

    fn resolve_bind_addr(
        &self,
        bind_addr: Option<SocketAddr>,
        allocation_kind: allocation::Kind,
        now: Instant,
    ) -> Result<(SocketAddr, allocation::PortGuard), ScionSocketBindError> {
        let scion_addr = match bind_addr {
            Some(addr) => {
                let eh_addr = EndhostAddr::try_from(addr.scion_address()).map_err(|_| {
                    ScionSocketBindError::InvalidBindAddress(
                        addr,
                        "service addresses can't be bound".to_string(),
                    )
                })?;
                if !self.tunnel.assigned_addresses().contains(&eh_addr) {
                    return Err(ScionSocketBindError::InvalidBindAddress(
                        addr,
                        "requested address is not assigned".to_string(),
                    ));
                }
                addr.scion_address().try_into().map_err(|_| {
                    ScionSocketBindError::InvalidBindAddress(
                        bind_addr.unwrap(),
                        "cannot bind to service address".to_string(),
                    )
                })?
            }
            None => {
                *self.tunnel.assigned_addresses().first().ok_or_else(|| {
                    ScionSocketBindError::InvalidBindAddress(
                        bind_addr.unwrap(),
                        "no address assigned".to_string(),
                    )
                })?
            }
        };

        let allocation = self
            .port_allocator
            .allocate(
                allocation_kind,
                scion_addr,
                bind_addr.map(|addr| addr.port()).unwrap_or(0),
                now,
            )
            .map_err(|e| {
                match e {
                    allocation::PortAllocatorError::PortAlreadyInUse => {
                        ScionSocketBindError::PortAlreadyInUse(
                            bind_addr.map(|addr| addr.port()).unwrap_or(0),
                        )
                    }
                    allocation::PortAllocatorError::AddressNotFound => {
                        ScionSocketBindError::InvalidBindAddress(
                            bind_addr.unwrap(),
                            "requested address is not assigned".to_string(),
                        )
                    }
                    allocation::PortAllocatorError::NoAvailablePorts => {
                        ScionSocketBindError::InvalidBindAddress(
                            bind_addr.unwrap(),
                            "no available ports".to_string(),
                        )
                    }
                }
            })?;

        let bind_addr = SocketAddr::new(scion_addr.into(), allocation.port());
        Ok((bind_addr, allocation))
    }
}

impl UnderlayStack for SnapUnderlayStack {
    type Socket = SnapUnderlaySocket;
    type AsyncUdpSocket = SnapAsyncUdpSocket;

    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Self::Socket, ScionSocketBindError>> {
        Box::pin(async move {
            self.bind_socket_with_time(kind, bind_addr, Instant::now())
                .await
        })
    }

    fn bind_socket_with_time(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
        now: Instant,
    ) -> BoxFuture<'_, Result<Self::Socket, ScionSocketBindError>> {
        Box::pin(async move {
            let (bind_addr, allocation) = self.resolve_bind_addr(
                bind_addr,
                match kind {
                    SocketKind::Udp => allocation::Kind::Udp,
                    SocketKind::Scmp => allocation::Kind::ScmpHandler,
                    SocketKind::Raw => allocation::Kind::Raw,
                },
                now,
            )?;

            let (sender, receiver) = mpsc::channel(self.receive_channel_size);
            match kind {
                SocketKind::Udp => {
                    self.demultiplexer_handle
                        .register_udp_receiver(bind_addr, sender)
                        .map_err(|e| registration_error_to_bind_error(e, bind_addr.port()))?
                }
                SocketKind::Scmp => {
                    self.demultiplexer_handle
                        .register_scmp_receiver(bind_addr, sender)
                        .map_err(|e| registration_error_to_bind_error(e, bind_addr.port()))?
                }
                SocketKind::Raw => {
                    self.demultiplexer_handle
                        .register_raw_receiver(bind_addr, sender)
                        .map_err(|e| registration_error_to_bind_error(e, bind_addr.port()))?
                }
            }

            Ok(SnapUnderlaySocket::new(
                self.tunnel.sender(),
                bind_addr,
                allocation,
                receiver,
            ))
        })
    }

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Self::AsyncUdpSocket, ScionSocketBindError>> {
        Box::pin(async move {
            let (bind_addr, allocation) =
                self.resolve_bind_addr(bind_addr, allocation::Kind::Udp, Instant::now())?;

            let (tx, rx) = mpsc::channel(self.receive_channel_size);
            self.demultiplexer_handle
                .register_udp_receiver(bind_addr, tx)
                .map_err(|e| registration_error_to_bind_error(e, bind_addr.port()))?;

            Ok(SnapAsyncUdpSocket::new(
                self.tunnel.sender(),
                bind_addr,
                rx,
                allocation,
            ))
        })
    }

    fn local_ases(&self) -> Vec<IsdAsn> {
        let mut isd_ases: Vec<IsdAsn> = self
            .tunnel
            .assigned_addresses()
            .into_iter()
            .map(|addr| addr.isd_asn())
            .collect();
        isd_ases.sort();
        isd_ases.dedup();
        isd_ases
    }
}
