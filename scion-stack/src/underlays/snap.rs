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
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use scion_proto::{
    address::SocketAddr,
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
    path::Path,
    scmp::SCMP_PROTOCOL_NUMBER,
    wire_encoding::{WireDecode as _, WireEncodeVec as _},
};
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use snap_control::client::{ControlPlaneApi as _, CrpcSnapControlClient};
use snap_tun::client::SnapTunNgSocket;
use tokio::{net::UdpSocket, task::JoinHandle};
use url::Url;
use x25519_dalek::StaticSecret;

use crate::scionstack::{
    AsyncUdpUnderlaySocket, ScionSocketReceiveError, ScionSocketSendError, SnapConnectionError,
    UnderlaySocket,
    scmp_handler::ScmpHandler,
    udp_polling::{UdpPollHelper, UdpPoller},
};

/// A handle to the background task that runs the SNAP underlay socket task.
/// Cancels the task when dropped.
struct SnapUnderlaySocketTaskHandle(JoinHandle<()>);

impl Drop for SnapUnderlaySocketTaskHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
pub(crate) struct SnapUnderlaySocket {
    pub inner: Arc<SnapTunNgSocket>,
    local_addr: SocketAddr,
    _task: Arc<SnapUnderlaySocketTaskHandle>,
}

impl SnapUnderlaySocket {
    pub async fn new(
        bind_addr: SocketAddr,
        snap_cp: Url,
        socket: UdpSocket,
        snap_token_source: Arc<dyn TokenSource>,
        static_private: StaticSecret,
        receive_queue_capacity: usize,
    ) -> Result<Self, crate::scionstack::ScionSocketBindError> {
        // Establish the initial tunnel.
        let mut snap_cp_client = CrpcSnapControlClient::new(&snap_cp).map_err(|e| {
            crate::scionstack::ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::ControlPlaneClientCreationError(e),
            )
        })?;
        snap_cp_client.use_token_source(snap_token_source.clone());

        let data_plane = snap_cp_client.get_data_plane_address().await.map_err(|e| {
            crate::scionstack::ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::DataPlaneDiscoveryError(e),
            )
        })?;

        // TODO(uniquefine): we register the identity once here, but this must refactored
        // https://github.com/Anapaya/scion/issues/27486
        // in a followup issue to be handled globally.
        let static_public = x25519_dalek::PublicKey::from(&static_private);
        let mut snap_tun_cp_client = CrpcSnapControlClient::new(
            &data_plane.snap_tun_control_address.ok_or(crate::scionstack::ScionSocketBindError::Other(
                anyhow::anyhow!("data plane did not provide snap tun control address, the snap data plane needs to be updated.").into_boxed_dyn_error(),
                )
            )?,
        )
        .map_err(|e| {
            crate::scionstack::ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::ControlPlaneClientCreationError(e),
            )
        })?;
        snap_tun_cp_client.use_token_source(snap_token_source.clone());
        let _ = snap_tun_cp_client
            .register_snaptun_identity(static_public, None)
            .await
            .map_err(|e| {
                crate::scionstack::ScionSocketBindError::SnapConnectionError(
                    SnapConnectionError::ConnectionEstablishmentError(anyhow::anyhow!(
                        "failed to register SNAP identity: {e:#}"
                    )),
                )
            })?;

        tracing::debug!(%data_plane.address, "Connecting to dataplane");

        let tunnel = SnapTunNgSocket::new(
            static_private,
            data_plane
                .snap_static_x25519
                .ok_or(crate::scionstack::ScionSocketBindError::Other(
                anyhow::anyhow!(
                    "data plane did not provide static public key, the snap data plane needs to be updated."
                )
                .into_boxed_dyn_error(),
            ))?,
            Arc::new(socket),
            data_plane.address,
            receive_queue_capacity,
        )
        .await
        // XXX(uniquefine): This error handling needs to be cleaned up.
        .map_err(|e| {
            crate::scionstack::ScionSocketBindError::SnapConnectionError(
                SnapConnectionError::ConnectionEstablishmentError(e.into()),
            )
        })?;

        let assigned_addr = tunnel.local_addr();

        // If the bind address is specified but does not match the assigned address, return an
        // error.
        if let Some(local_bind_addr) = bind_addr.local_address()
            // IP mismatch
        && ((!local_bind_addr.ip().is_unspecified() && assigned_addr.ip() != local_bind_addr.ip())
            // Port mismatch
                || (local_bind_addr.port() != 0 && assigned_addr.port() != local_bind_addr.port()))
        {
            return Err(crate::scionstack::ScionSocketBindError::InvalidBindAddress(
                crate::scionstack::InvalidBindAddressError::AddressMismatch {
                    assigned_addr: SocketAddr::from_std(bind_addr.isd_asn(), assigned_addr),
                    bind_addr,
                },
            ));
        }

        Ok(Self {
            inner: Arc::new(tunnel),
            local_addr: SocketAddr::from_std(bind_addr.isd_asn(), assigned_addr),
            _task: Arc::new(SnapUnderlaySocketTaskHandle(tokio::spawn(async {}))),
        })
    }
}

impl UnderlaySocket for SnapUnderlaySocket {
    fn try_send(&self, packet: ScionPacketRaw) -> Result<(), ScionSocketSendError> {
        let mut bytes_mut = BytesMut::with_capacity(packet.required_capacity());
        let parts = packet.encode_to_bytes_vec();
        bytes_mut.extend_from_slice(&parts[0]);
        bytes_mut.extend_from_slice(&parts[1]);
        self.inner
            .try_send(bytes_mut)
            .map_err(ScionSocketSendError::IoError)
    }

    fn send<'a>(
        &'a self,
        packet: scion_proto::packet::ScionPacketRaw,
    ) -> futures::future::BoxFuture<'a, Result<(), crate::scionstack::ScionSocketSendError>> {
        let mut bytes_mut = BytesMut::with_capacity(packet.required_capacity());
        let parts = packet.encode_to_bytes_vec();
        bytes_mut.extend_from_slice(&parts[0]);
        bytes_mut.extend_from_slice(&parts[1]);
        Box::pin(async move {
            self.inner
                .send(bytes_mut)
                .await
                .map_err(ScionSocketSendError::IoError)
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> futures::future::BoxFuture<'a, Result<ScionPacketRaw, ScionSocketReceiveError>> {
        Box::pin(async move {
            loop {
                let raw = self
                    .inner
                    .recv()
                    .await
                    // XXX(uniquefine) this error handling is awkward. But this will only happen
                    // when the stack is dropped anyway.
                    .map_err(|_| {
                        ScionSocketReceiveError::IoError(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "SNAP tunnel closed",
                        ))
                    })?;
                let packet = match ScionPacketRaw::decode(&mut raw.clone()) {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Failed to decode SCION packet, skipping");
                        continue;
                    }
                };

                let dst = packet.headers.address.destination();
                if dst.is_none() || dst.unwrap() != self.local_addr.scion_address() {
                    tracing::debug!(destination = ?dst, assigned_addr = %self.local_addr.scion_address(), "Packet destination does not match assigned address, skipping");
                    continue;
                }
                return Ok(packet);
            }
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

pub(crate) struct SnapAsyncUdpSocket {
    socket: SnapUnderlaySocket,
    scmp_handlers: Vec<Box<dyn ScmpHandler>>,
}

impl SnapAsyncUdpSocket {
    pub fn new(socket: SnapUnderlaySocket, scmp_handlers: Vec<Box<dyn ScmpHandler>>) -> Self {
        Self {
            socket,
            scmp_handlers,
        }
    }
}

impl AsyncUdpUnderlaySocket for SnapAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let self_clone = self.clone();
            async move { self_clone.socket.inner.writable().await }
        }))
    }

    fn try_send(&self, raw_packet: ScionPacketRaw) -> Result<(), std::io::Error> {
        let mut bytes_mut = BytesMut::with_capacity(raw_packet.required_capacity());
        let parts = raw_packet.encode_to_bytes_vec();
        bytes_mut.extend_from_slice(&parts[0]);
        bytes_mut.extend_from_slice(&parts[1]);
        self.socket.inner.try_send(bytes_mut)?;
        Ok(())
    }

    fn poll_recv_from_with_path(
        &self,
        cx: &mut Context,
    ) -> Poll<std::io::Result<(SocketAddr, Bytes, Path)>> {
        loop {
            let Ok(mut raw) = ready!(self.socket.inner.poll_recv(cx)) else {
                // XXX(uniquefine) this error handling is awkward. But this will only happen
                // when the stack is dropped anyway.
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "SNAP tunnel closed",
                )));
            };

            let packet = match ScionPacketRaw::decode(&mut raw) {
                Ok(packet) => packet,
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to decode SCION packet, skipping");
                    continue;
                }
            };

            // Handle SCMP packets.
            if packet.headers.common.next_header == SCMP_PROTOCOL_NUMBER {
                tracing::debug!("SCMP packet received, forwarding to SCMP handlers");
                for handler in &self.scmp_handlers {
                    if let Some(reply) = handler.handle(packet.clone())
                        && let Err(e) = self.try_send(reply)
                    {
                        tracing::warn!(error = %e, "failed to send SCMP reply");
                    }
                }
                continue;
            };

            let fallible = || {
                let src = packet
                    .headers
                    .address
                    .source()
                    .context("reading source address")?;
                let dst = packet
                    .headers
                    .address
                    .destination()
                    .context("reading destination address")?;

                let path = Path::new(
                    packet.headers.path.clone(),
                    ByEndpoint {
                        source: src.isd_asn(),
                        destination: dst.isd_asn(),
                    },
                    None,
                );

                let packet: ScionPacketUdp = packet.try_into().context("parsing UDP packet")?;

                anyhow::Ok((
                    SocketAddr::new(src, packet.src_port()),
                    packet.datagram.payload,
                    path,
                ))
            };

            match fallible() {
                Ok(result) => return Poll::Ready(Ok(result)),
                Err(e) => {
                    tracing::warn!(error = %e, "Received invalid packet, skipping");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }
}
