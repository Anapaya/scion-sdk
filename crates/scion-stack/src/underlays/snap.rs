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
//! SNAP underlay socket.
use std::{io, net, sync::Arc};

use ana_gotatun::packet::PacketBufPool;
use async_trait::async_trait;
use bytes::Bytes;
use reqwest_connect_rpc::token_source::TokenSource;
use sciparse::{
    address::ip_socket_addr::ScionSocketIpAddr, core::view::View, packet::view::ScionRawPacketView,
};
use snap_control::client::{ControlPlaneApi as _, CrpcSnapControlClient};
use snap_tun::client::{PACKET_BUF_POOL_SIZE, SnapTunEndpoint, SnapTunnel};
use tokio::{net::UdpSocket, task::JoinHandle};
use url::Url;

use crate::stack::{
    ScionSocketReceiveError, ScionSocketSendError, SnapConnectionError, UnderlaySocket,
};

/// A handle to the background task that runs the SNAP underlay socket task.
/// Cancels the task when dropped.
struct SnapUnderlaySocketTaskHandle(JoinHandle<()>);

impl Drop for SnapUnderlaySocketTaskHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct SnapUnderlaySocket {
    pub inner: Arc<SnapTunnel>,
    local_addr: ScionSocketIpAddr,
    _task: Arc<SnapUnderlaySocketTaskHandle>,
    pub(crate) pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
    /// A datagram received by [`readable`](UnderlaySocket::readable) but not yet returned by
    /// [`try_recv`](UnderlaySocket::try_recv).
    ///
    /// The SNAP receive queue can only be observed by consuming from it, so `readable` pulls one
    /// datagram into this slot and `try_recv` drains it before pulling further datagrams.
    peeked: tokio::sync::Mutex<Option<Bytes>>,
}

impl SnapUnderlaySocket {
    pub async fn new(
        bind_addr: ScionSocketIpAddr,
        snap_cp: Url,
        socket: UdpSocket,
        snaptunnel_manager: &'_ SnapTunEndpoint,
        snap_token_source: Arc<dyn TokenSource>,
        receive_queue_capacity: usize,
        pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
        crpc_client: Option<reqwest::Client>,
    ) -> Result<Self, crate::stack::ScionSocketBindError> {
        // Establish the initial tunnel.
        let mut snap_cp_client = match crpc_client.clone() {
            Some(client) => {
                CrpcSnapControlClient::new_with_client(&snap_cp, client).map_err(|e| {
                    crate::stack::ScionSocketBindError::SnapConnectionError(
                        SnapConnectionError::ControlPlaneClientCreation(e.into_boxed_dyn_error()),
                    )
                })?
            }
            None => {
                CrpcSnapControlClient::new(&snap_cp).map_err(|e| {
                    crate::stack::ScionSocketBindError::SnapConnectionError(
                        SnapConnectionError::ControlPlaneClientCreation(e.into_boxed_dyn_error()),
                    )
                })?
            }
        };
        snap_cp_client.use_token_source(snap_token_source.clone());

        let data_plane = snap_cp_client.get_data_plane_address().await.map_err(|e| {
            crate::stack::ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::DataPlaneDiscovery(Box::new(e)),
            )
        })?;

        tracing::debug!(%data_plane.address, "Connecting to dataplane");
        let snaptun_cp_addr = data_plane.snap_tun_control_address.ok_or(
            crate::stack::ScionSocketBindError::Other(
                anyhow::anyhow!(
                    "the snap-tun control address is missing, the snap needs to be updated."
                )
                .into_boxed_dyn_error(),
            ),
        )?;
        let mut snaptun_cp_client = match crpc_client {
            Some(client) => {
                CrpcSnapControlClient::new_with_client(&snaptun_cp_addr, client).map_err(|e| {
                    crate::stack::ScionSocketBindError::SnapConnectionError(
                        SnapConnectionError::ControlPlaneClientCreation(e.into_boxed_dyn_error()),
                    )
                })?
            }
            None => {
                CrpcSnapControlClient::new(&snaptun_cp_addr).map_err(|e| {
                    crate::stack::ScionSocketBindError::SnapConnectionError(
                        SnapConnectionError::ControlPlaneClientCreation(e.into_boxed_dyn_error()),
                    )
                })?
            }
        };
        snaptun_cp_client.use_token_source(snap_token_source.clone());

        let tunnel = snaptunnel_manager.connect_tunnel(
            data_plane.snap_static_x25519.ok_or(crate::stack::ScionSocketBindError::Other(
                anyhow::anyhow!(
                    "data plane did not provide static public key, the snap needs to be updated."
                )
                .into_boxed_dyn_error(),
            ))?,
            data_plane.address,
            snaptun_cp_addr,
            Arc::new(snaptun_cp_client),
            Arc::new(socket),
            receive_queue_capacity,
            pool.clone(),
        ).await.map_err(|e| crate::stack::ScionSocketBindError::SnapConnectionError(SnapConnectionError::TunnelEstablishment(Box::new(e))))?;

        let tunnel_addr = tunnel.local_addr();
        let local_addr =
            ScionSocketIpAddr::new(bind_addr.isd_asn(), tunnel_addr.ip(), tunnel_addr.port());

        Ok(Self {
            inner: Arc::new(tunnel),
            local_addr,
            _task: Arc::new(SnapUnderlaySocketTaskHandle(tokio::spawn(async {}))),
            pool,
            peeked: tokio::sync::Mutex::new(None),
        })
    }

    /// The local SCION address the socket is bound to.
    pub(crate) fn local_addr(&self) -> ScionSocketIpAddr {
        self.local_addr
    }

    /// The SNAP data plane the socket is connected to.
    pub(crate) fn snap_data_plane(&self) -> Option<net::SocketAddr> {
        Some(self.inner.data_plane_address())
    }
}

#[async_trait]
impl UnderlaySocket for SnapUnderlaySocket {
    fn try_send(&self, packet: &ScionRawPacketView) -> Result<(), ScionSocketSendError> {
        // TODO: ana gotatun requires ownership of the buffer, so we need to copy the packet into a
        // new buffer. Should be looked into if it's possible to avoid this copy.

        let mut buf = self.pool.get();
        let pkt = packet.as_slice();

        let packet_size = pkt.len();
        {
            let write = buf.buf_mut();
            write.resize(packet_size, 0);
            buf[..packet_size].copy_from_slice(pkt);
        }

        self.inner
            .try_send(buf)
            .map_err(ScionSocketSendError::IoError)
    }

    async fn writeable(&self) {
        // Ignore readiness errors; a subsequent `try_send` surfaces any real error.
        let _ = self.inner.writable().await;
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<usize, ScionSocketReceiveError> {
        loop {
            // Take a datagram staged by `readable`, or pull the next one without blocking.
            let raw: Bytes = {
                let Ok(mut peeked) = self.peeked.try_lock() else {
                    // `readable` is currently staging a datagram; report not-ready for now.
                    return Err(ScionSocketReceiveError::IoError(io::Error::from(
                        io::ErrorKind::WouldBlock,
                    )));
                };
                match peeked.take() {
                    Some(raw) => raw,
                    None => {
                        match self.inner.try_recv() {
                            Ok(Some(raw)) => raw,
                            Ok(None) => {
                                return Err(ScionSocketReceiveError::IoError(io::Error::from(
                                    io::ErrorKind::WouldBlock,
                                )));
                            }
                            // XXX(uniquefine) this error handling is awkward. But this will only
                            // happen when the stack is dropped anyway.
                            Err(_) => {
                                return Err(ScionSocketReceiveError::IoError(io::Error::new(
                                    io::ErrorKind::ConnectionReset,
                                    "SNAP tunnel closed",
                                )));
                            }
                        }
                    }
                }
            };

            let n = raw.len();
            if n > buf.len() {
                tracing::debug!(
                    packet_size = n,
                    buffer_size = buf.len(),
                    "SNAP packet larger than receive buffer, skipping"
                );
                continue;
            }
            buf[..n].copy_from_slice(&raw);

            // Only accept packets that decode and are addressed to this socket; skip the rest.
            match ScionRawPacketView::try_from_slice(&buf[..n]) {
                Ok((packet, _rest)) => {
                    match packet.dst_scion_addr() {
                        Ok(dst) if dst == self.local_addr.scion_addr() => return Ok(n),
                        Ok(_) => {
                            tracing::debug!(
                                "Packet destination does not match assigned address, skipping"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "Received packet with invalid destination address, skipping");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to decode SCION packet, skipping");
                }
            }
        }
    }

    async fn readable(&self) {
        let mut peeked = self.peeked.lock().await;
        if peeked.is_some() {
            return;
        }
        // Consume one datagram and stage it so the subsequent `try_recv` can return it. On error
        // the tunnel is closed; leave the slot empty so `try_recv` surfaces the error.
        if let Ok(raw) = self.inner.recv().await {
            *peeked = Some(raw);
        }
    }
}
