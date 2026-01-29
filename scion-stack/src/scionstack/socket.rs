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
//! SCION socket types.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use chrono::Utc;
use futures::future::BoxFuture;
use scion_proto::{
    address::{ScionAddr, SocketAddr},
    datagram::UdpMessage,
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
    path::Path,
    scmp::{SCMP_PROTOCOL_NUMBER, ScmpMessage},
};

use super::UnderlaySocket;
use crate::{
    path::manager::{MultiPathManager, traits::PathManager},
    scionstack::{
        ScionSocketConnectError, ScionSocketReceiveError, ScionSocketSendError,
        scmp_handler::ScmpHandler,
    },
    types::Subscribers,
};

/// A path unaware UDP SCION socket.
pub struct PathUnawareUdpScionSocket {
    inner: Box<dyn UnderlaySocket + Sync + Send>,
    /// The SCMP handlers.
    scmp_handlers: Vec<Box<dyn ScmpHandler>>,
}

impl std::fmt::Debug for PathUnawareUdpScionSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathUnawareUdpScionSocket")
            .field("local_addr", &self.inner.local_addr())
            .finish()
    }
}

impl PathUnawareUdpScionSocket {
    pub(crate) fn new(
        socket: Box<dyn UnderlaySocket + Sync + Send>,
        scmp_handlers: Vec<Box<dyn ScmpHandler>>,
    ) -> Self {
        Self {
            inner: socket,
            scmp_handlers,
        }
    }

    /// Send a SCION UDP datagram via the given path.
    pub fn send_to_via<'a>(
        &'a self,
        payload: &[u8],
        destination: SocketAddr,
        path: &Path<&[u8]>,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
        let packet = match ScionPacketUdp::new(
            ByEndpoint {
                source: self.inner.local_addr(),
                destination,
            },
            path.data_plane_path.to_bytes_path(),
            Bytes::copy_from_slice(payload),
        ) {
            Ok(packet) => packet,
            Err(e) => {
                return Box::pin(async move {
                    Err(ScionSocketSendError::InvalidPacket(
                        format!("error encoding packet: {e}").into(),
                    ))
                });
            }
        }
        .into();
        self.inner.send(packet)
    }

    /// Receive a SCION packet with the sender and path.
    #[allow(clippy::type_complexity)]
    pub fn recv_from_with_path<'a>(
        &'a self,
        buffer: &'a mut [u8],
        path_buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, SocketAddr, Path<&'a mut [u8]>), ScionSocketReceiveError>>
    {
        Box::pin(async move {
            loop {
                let packet = self.inner.recv().await?;

                let packet = match packet.headers.common.next_header {
                    UdpMessage::PROTOCOL_NUMBER => packet,
                    SCMP_PROTOCOL_NUMBER => {
                        tracing::debug!("SCMP packet received, forwarding to SCMP handlers");
                        for handler in &self.scmp_handlers {
                            if let Some(reply) = handler.handle(packet.clone())
                                && let Err(e) = self.inner.try_send(reply)
                            {
                                tracing::warn!(error = %e, "failed to send SCMP reply");
                            }
                        }
                        continue;
                    }
                    _ => {
                        tracing::debug!(next_header = %packet.headers.common.next_header, "Packet with unknown next layer protocol, skipping");
                        continue;
                    }
                };

                let packet: ScionPacketUdp = match packet.try_into() {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Received invalid UDP packet, skipping");
                        continue;
                    }
                };
                let src_addr = match packet.headers.address.source() {
                    Some(source) => SocketAddr::new(source, packet.src_port()),
                    None => {
                        tracing::debug!("Received packet without source address header, skipping");
                        continue;
                    }
                };
                tracing::trace!(
                    src = %src_addr,
                    length = packet.datagram.payload.len(),
                    "received packet",
                );

                let max_read = std::cmp::min(buffer.len(), packet.datagram.payload.len());
                buffer[..max_read].copy_from_slice(&packet.datagram.payload[..max_read]);

                if path_buffer.len() < packet.headers.path.raw().len() {
                    return Err(ScionSocketReceiveError::PathBufTooSmall);
                }

                let dataplane_path = packet
                    .headers
                    .path
                    .copy_to_slice(&mut path_buffer[..packet.headers.path.raw().len()]);

                // Note, that we do not have the next hop address of the path.
                // A socket that uses more than one tunnel will need to distinguish between
                // packets received on different tunnels.
                let path = Path::new(dataplane_path, packet.headers.address.ia, None);

                return Ok((packet.datagram.payload.len(), src_addr, path));
            }
        })
    }

    /// Receive a SCION packet with the sender.
    pub fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, SocketAddr), ScionSocketReceiveError>> {
        Box::pin(async move {
            loop {
                let packet = self.inner.recv().await?;

                let packet = match packet.headers.common.next_header {
                    UdpMessage::PROTOCOL_NUMBER => packet,
                    SCMP_PROTOCOL_NUMBER => {
                        tracing::debug!("SCMP packet received, forwarding to SCMP handlers");
                        for handler in &self.scmp_handlers {
                            if let Some(reply) = handler.handle(packet.clone())
                                && let Err(e) = self.inner.try_send(reply)
                            {
                                tracing::warn!(error = %e, "failed to send SCMP reply");
                            }
                        }
                        continue;
                    }
                    _ => {
                        tracing::debug!(next_header = %packet.headers.common.next_header, "Packet with unknown next layer protocol, skipping");
                        continue;
                    }
                };

                let packet: ScionPacketUdp = match packet.try_into() {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Received invalid UDP packet, dropping");
                        continue;
                    }
                };
                let src_addr = match packet.headers.address.source() {
                    Some(source) => SocketAddr::new(source, packet.src_port()),
                    None => {
                        tracing::debug!("Received packet without source address header, dropping");
                        continue;
                    }
                };

                tracing::trace!(
                    src = %src_addr,
                    length = packet.datagram.payload.len(),
                    buffer_size = buffer.len(),
                    "received packet",
                );

                let max_read = std::cmp::min(buffer.len(), packet.datagram.payload.len());
                buffer[..max_read].copy_from_slice(&packet.datagram.payload[..max_read]);

                return Ok((packet.datagram.payload.len(), src_addr));
            }
        })
    }

    /// The local address the socket is bound to.
    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }
}

/// A SCMP SCION socket.
pub struct ScmpScionSocket {
    inner: Box<dyn UnderlaySocket + Sync + Send>,
}

impl ScmpScionSocket {
    pub(crate) fn new(socket: Box<dyn UnderlaySocket + Sync + Send>) -> Self {
        Self { inner: socket }
    }
}

impl ScmpScionSocket {
    /// Send a SCMP message to the destination via the given path.
    pub fn send_to_via<'a>(
        &'a self,
        message: ScmpMessage,
        destination: ScionAddr,
        path: &Path<&[u8]>,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
        let packet = match ScionPacketScmp::new(
            ByEndpoint {
                source: self.inner.local_addr().scion_address(),
                destination,
            },
            path.data_plane_path.to_bytes_path(),
            message,
        ) {
            Ok(packet) => packet,
            Err(e) => {
                return Box::pin(async move {
                    Err(ScionSocketSendError::InvalidPacket(
                        format!("error encoding packet: {e}").into(),
                    ))
                });
            }
        };
        let packet = packet.into();
        Box::pin(async move { self.inner.send(packet).await })
    }

    /// Receive a SCMP message with the sender and path.
    #[allow(clippy::type_complexity)]
    pub fn recv_from_with_path<'a>(
        &'a self,
        path_buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(ScmpMessage, ScionAddr, Path<&'a mut [u8]>), ScionSocketReceiveError>>
    {
        Box::pin(async move {
            loop {
                let packet = self.inner.recv().await?;
                let packet: ScionPacketScmp = match packet.try_into() {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Received invalid SCMP packet, dropping");
                        continue;
                    }
                };
                let src_addr = match packet.headers.address.source() {
                    Some(source) => source,
                    None => {
                        tracing::debug!("Received packet without source address header, dropping");
                        continue;
                    }
                };

                if path_buffer.len() < packet.headers.path.raw().len() {
                    return Err(ScionSocketReceiveError::PathBufTooSmall);
                }
                let dataplane_path = packet
                    .headers
                    .path
                    .copy_to_slice(&mut path_buffer[..packet.headers.path.raw().len()]);
                let path = Path::new(dataplane_path, packet.headers.address.ia, None);

                return Ok((packet.message, src_addr, path));
            }
        })
    }

    /// Receive a SCMP message with the sender.
    pub fn recv_from<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<(ScmpMessage, ScionAddr), ScionSocketReceiveError>> {
        Box::pin(async move {
            loop {
                let packet = self.inner.recv().await?;
                let packet: ScionPacketScmp = match packet.try_into() {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Received invalid SCMP packet, skipping");
                        continue;
                    }
                };
                let src_addr = match packet.headers.address.source() {
                    Some(source) => source,
                    None => {
                        tracing::debug!("Received packet without source address header, skipping");
                        continue;
                    }
                };
                return Ok((packet.message, src_addr));
            }
        })
    }

    /// Return the local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }
}

/// A raw SCION socket.
pub struct RawScionSocket {
    inner: Box<dyn UnderlaySocket>,
}

impl RawScionSocket {
    pub(crate) fn new(socket: Box<dyn UnderlaySocket + Sync + Send>) -> Self {
        Self { inner: socket }
    }
}

impl RawScionSocket {
    /// Send a raw SCION packet.
    pub fn send<'a>(
        &'a self,
        packet: ScionPacketRaw,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
        self.inner.send(packet)
    }

    /// Receive a raw SCION packet.
    pub fn recv<'a>(&'a self) -> BoxFuture<'a, Result<ScionPacketRaw, ScionSocketReceiveError>> {
        self.inner.recv()
    }

    /// Return the local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }
}

/// A trait for receiving socket send errors.
pub trait SendErrorReceiver: Send + Sync {
    /// Reports an error when sending a packet.
    /// This function must return immediately and not block.
    fn report_send_error(&self, error: &ScionSocketSendError);
}

/// A path aware UDP socket generic over the underlay socket and path manager.
pub struct UdpScionSocket<P: PathManager = MultiPathManager> {
    socket: PathUnawareUdpScionSocket,
    pather: Arc<P>,
    connect_timeout: Duration,
    remote_addr: Option<SocketAddr>,
    send_error_receivers: Subscribers<dyn SendErrorReceiver>,
}

impl<P: PathManager> std::fmt::Debug for UdpScionSocket<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpScionSocket")
            .field("local_addr", &self.socket.local_addr())
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl<P: PathManager> UdpScionSocket<P> {
    /// Creates a new path aware UDP SCION socket.
    pub fn new(
        socket: PathUnawareUdpScionSocket,
        pather: Arc<P>,
        connect_timeout: Duration,
        send_error_receivers: Subscribers<dyn SendErrorReceiver>,
    ) -> Self {
        Self {
            socket,
            pather,
            connect_timeout,
            remote_addr: None,
            send_error_receivers,
        }
    }

    /// Connects the socket to a remote address.
    ///
    /// Ensures a Path to the Destination exists, returns an error if not.
    ///
    /// Timeouts after configured `connect_timeout`
    pub async fn connect(self, remote_addr: SocketAddr) -> Result<Self, ScionSocketConnectError> {
        // Check that a path exists to destination
        let _path = self
            .pather
            .path_timeout(
                self.socket.local_addr().isd_asn(),
                remote_addr.isd_asn(),
                Utc::now(),
                self.connect_timeout,
            )
            .await?;

        Ok(Self {
            remote_addr: Some(remote_addr),
            ..self
        })
    }

    /// Send a datagram to the connected remote address.
    pub async fn send(&self, payload: &[u8]) -> Result<(), ScionSocketSendError> {
        if let Some(remote_addr) = self.remote_addr {
            self.send_to(payload, remote_addr).await
        } else {
            Err(ScionSocketSendError::NotConnected)
        }
    }

    /// Send a datagram to the specified destination.
    pub async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), ScionSocketSendError> {
        let path = &self
            .pather
            .path_wait(
                self.socket.local_addr().isd_asn(),
                destination.isd_asn(),
                Utc::now(),
            )
            .await?;
        self.socket
            .send_to_via(payload, destination, &path.to_slice_path())
            .await
    }

    /// Send a datagram to the specified destination via the specified path.
    pub async fn send_to_via(
        &self,
        payload: &[u8],
        destination: SocketAddr,
        path: &Path<&[u8]>,
    ) -> Result<(), ScionSocketSendError> {
        self.socket
            .send_to_via(payload, destination, path)
            .await
            .inspect_err(|e| {
                self.send_error_receivers
                    .for_each(|receiver| receiver.report_send_error(e));
            })
    }

    /// Receive a datagram from any address, along with the sender address and path.
    pub async fn recv_from_with_path<'a>(
        &'a self,
        buffer: &'a mut [u8],
        path_buffer: &'a mut [u8],
    ) -> Result<(usize, SocketAddr, Path<&'a mut [u8]>), ScionSocketReceiveError> {
        let (len, sender_addr, path): (usize, SocketAddr, Path<&mut [u8]>) =
            self.socket.recv_from_with_path(buffer, path_buffer).await?;

        match path.to_reversed() {
            Ok(reversed_path) => {
                // Register the path for future use
                self.pather.register_path(
                    self.socket.local_addr().isd_asn(),
                    sender_addr.isd_asn(),
                    Utc::now(),
                    reversed_path,
                );
            }
            Err(e) => {
                tracing::trace!(error = ?e, "Failed to reverse path for registration")
            }
        }

        tracing::trace!(
            src = %self.socket.local_addr(),
            dst = %sender_addr,
            "Registered reverse path",
        );

        Ok((len, sender_addr, path))
    }

    /// Receive a datagram from the connected remote address and write it into the provided buffer.
    pub async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr), ScionSocketReceiveError> {
        // For this method, we need to get the path to register it, but we don't return it
        let mut path_buffer = [0u8; 1024]; // Temporary buffer for path
        let (len, sender_addr, _) = self.recv_from_with_path(buffer, &mut path_buffer).await?;
        Ok((len, sender_addr))
    }

    /// Receive a datagram from the connected remote address.
    ///
    /// Datagrams from other addresses are silently discarded.
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<usize, ScionSocketReceiveError> {
        if self.remote_addr.is_none() {
            return Err(ScionSocketReceiveError::NotConnected);
        }
        loop {
            let (len, sender_addr) = self.recv_from(buffer).await?;
            match self.remote_addr {
                Some(remote_addr) => {
                    if sender_addr == remote_addr {
                        return Ok(len);
                    }
                }
                None => return Err(ScionSocketReceiveError::NotConnected),
            }
        }
    }

    /// Returns the local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }
}
