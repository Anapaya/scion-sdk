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
use scion_sdk_quic_scion::socket::{BoxedSocketError, GenericScionUdpSocket};

use super::UnderlaySocket;
use crate::{
    path::manager::{MultiPathManager, traits::PathManager},
    scionstack::{
        MIN_PATH_BUFFER_SIZE, ScionSocketConnectError, ScionSocketReceiveError,
        ScionSocketSendError, scmp_handler::ScmpHandler,
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped before completion, the packet may
    /// be silently lost, but no socket state is corrupted and the socket remains usable.
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. The only await point is the inner underlay receive. If the
    /// future is dropped while waiting for a packet, no packet data is consumed and `buffer`
    /// and `path_buffer` are left unmodified. If a packet has already been received (i.e., the
    /// future is dropped after data has been written into the buffers), this cannot occur in
    /// practice because those steps run synchronously within a single `poll` invocation.
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped while waiting for a packet, no
    /// packet is consumed and `buffer` is left unmodified. The contents of `buffer` are only
    /// valid after the method returns `Ok`.
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped before completion, the packet may
    /// be silently lost, but no socket state is corrupted and the socket remains usable.
    pub async fn send(&self, payload: &[u8]) -> Result<(), ScionSocketSendError> {
        if let Some(remote_addr) = self.remote_addr {
            self.send_to(payload, remote_addr).await
        } else {
            Err(ScionSocketSendError::NotConnected)
        }
    }

    /// Send a datagram to the specified destination.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. It has two await points: the path lookup and the actual send.
    /// If the future is dropped at either point, no socket state is corrupted and the socket
    /// remains usable. A packet dropped mid-send is silently lost, which is normal for UDP.
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped before completion, the packet may
    /// be silently lost, but no socket state is corrupted and the socket remains usable.
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
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. The only await point is the inner underlay receive. If the
    /// future is dropped while waiting for a packet, no packet data is consumed and `buffer`
    /// and `path_buffer` are left unmodified.
    ///
    /// Path registration via the path manager runs synchronously within the same `poll`
    /// invocation that delivers the received data, so it cannot be independently cancelled.
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
    ///
    /// The path of the received packet is used to register a reverse path with the path manager,
    /// but is not returned to the caller. Use [`recv_from_with_path`](Self::recv_from_with_path)
    /// if the path is needed.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped while waiting for a packet, no
    /// packet is consumed and `buffer` is left unmodified. The contents of `buffer` are only
    /// valid after the method returns `Ok`.
    pub async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr), ScionSocketReceiveError> {
        let mut path_buffer = [0u8; MIN_PATH_BUFFER_SIZE];
        let (len, sender_addr, _) = self.recv_from_with_path(buffer, &mut path_buffer).await?;
        Ok((len, sender_addr))
    }

    /// Receive a datagram from the connected remote address.
    ///
    /// Datagrams from other addresses are silently discarded.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. If the future is dropped while waiting for a packet, no
    /// packet is permanently lost — the underlying receive is cancel-safe and an undelivered
    /// packet remains available for the next call. Note that packets from other senders are
    /// discarded during filtering; those discarded packets are not recoverable regardless of
    /// cancellation. The contents of `buffer` are only valid after the method returns `Ok(n)`.
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

// Allow using `UdpScionSocket` as a `GenericScionUdpSocket` for compatibility with QUIC and HTTP/3
// implementations.
#[async_trait::async_trait]
impl<P: PathManager + Sync + Send + 'static> GenericScionUdpSocket for UdpScionSocket<P> {
    /// Asynchronously sends a Datagram to the specified destination address.
    async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), BoxedSocketError> {
        self.send_to(payload, destination)
            .await
            .map_err(|e| Box::new(e) as BoxedSocketError)
    }

    /// Asynchronously receives a Datagram, writing it into the provided buffer, and returns the
    /// number of bytes read and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), BoxedSocketError> {
        self.recv_from(buf)
            .await
            .map_err(|e| Box::new(e) as BoxedSocketError)
    }

    /// Returns the local socket address of this socket.
    fn local_addr(&self) -> SocketAddr {
        self.local_addr()
    }
}

#[cfg(test)]
mod cancel_safety_tests {
    //! Unit tests verifying that all async methods on [`UdpScionSocket`] and
    //! [`PathUnawareUdpScionSocket`] are cancel-safe.
    //!
    //! The tests use two hand-rolled test doubles rather than the real underlay and path manager:
    //!
    //! - [`ManualUnderlaySocket`]: backed by a bounded `tokio::sync::mpsc` channel. Injecting
    //!   packets is done via the paired `Sender`. The `recv` future is backed by
    //!   `tokio::sync::mpsc::Receiver::recv()`, which IS cancel-safe (the message stays in the
    //!   channel if the future is dropped before returning `Ready`).
    //!
    //! - [`ImmediatePathManager`]: always returns a local (empty) path immediately, so tests do not
    //!   depend on any background task.
    //!
    //! ## What these tests verify
    //!
    //! The tests verify that dropping a future at realistically reachable await points (the inner
    //! underlay `recv`) leaves no corrupted socket state and that unconsumed packets remain
    //! available for the next caller. They also verify that the wrong-sender filtering loop in
    //! [`UdpScionSocket::recv`] can be safely cancelled mid-iteration.
    //!
    //! Because all processing steps after the underlay `recv` resolves run synchronously within
    //! the same `poll()` invocation, there is no intermediate await point between "data received"
    //! and "data returned" that could be independently cancelled. The tests therefore focus on
    //! the cancel points that actually exist at runtime.

    use std::{
        io,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use futures::future::BoxFuture;
    use scion_proto::{
        address::{Asn, Isd, IsdAsn, ScionAddr, SocketAddr},
        packet::ScionPacketRaw,
        path::{Path, test_builder::TestPathBuilder},
    };

    use super::*;
    use crate::{
        path::manager::traits::{PathWaitError, SyncPathManager},
        scionstack::{ScionSocketReceiveError, ScionSocketSendError, UnderlaySocket},
        types::{ResFut, Subscribers},
    };

    struct ManualUnderlaySocket {
        local: SocketAddr,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<ScionPacketRaw>>,
    }

    impl ManualUnderlaySocket {
        fn new(local: SocketAddr) -> (Self, tokio::sync::mpsc::Sender<ScionPacketRaw>) {
            // Use a large bounded channel so tests never block on send.
            let (inject_tx, recv_rx) = tokio::sync::mpsc::channel::<ScionPacketRaw>(64);
            let socket = Self {
                local,
                rx: tokio::sync::Mutex::new(recv_rx),
            };
            (socket, inject_tx)
        }
    }

    impl UnderlaySocket for ManualUnderlaySocket {
        fn send<'a>(
            &'a self,
            _packet: ScionPacketRaw,
        ) -> BoxFuture<'a, Result<(), ScionSocketSendError>> {
            Box::pin(async move { Ok(()) })
        }

        fn try_send(&self, _packet: ScionPacketRaw) -> Result<(), ScionSocketSendError> {
            Ok(())
        }

        fn recv<'a>(&'a self) -> BoxFuture<'a, Result<ScionPacketRaw, ScionSocketReceiveError>> {
            Box::pin(async move {
                let packet = self.rx.lock().await.recv().await.ok_or_else(|| {
                    ScionSocketReceiveError::IoError(io::Error::other("channel closed"))
                })?;
                Ok(packet)
            })
        }

        fn local_addr(&self) -> SocketAddr {
            self.local
        }
    }

    #[derive(Default)]
    struct ImmediatePathManager {
        registered_paths: Mutex<Vec<Path<Bytes>>>,
    }

    impl SyncPathManager for ImmediatePathManager {
        fn register_path(
            &self,
            _src: IsdAsn,
            _dst: IsdAsn,
            _now: DateTime<Utc>,
            path: Path<Bytes>,
        ) {
            self.registered_paths.lock().expect("poisoned").push(path);
        }

        fn try_cached_path(
            &self,
            src: IsdAsn,
            _dst: IsdAsn,
            _now: DateTime<Utc>,
        ) -> io::Result<Option<Path<Bytes>>> {
            Ok(Some(Path::local(src)))
        }
    }

    impl PathManager for ImmediatePathManager {
        fn path_wait(
            &self,
            src: IsdAsn,
            _dst: IsdAsn,
            _now: DateTime<Utc>,
        ) -> impl ResFut<'_, Path<Bytes>, PathWaitError> {
            async move { Ok(Path::local(src)) }
        }
    }

    const LOCAL_ISD_ASN: IsdAsn = IsdAsn::new(Isd(1), Asn(1));
    const REMOTE_ISD_ASN: IsdAsn = IsdAsn::new(Isd(1), Asn(2));
    const OTHER_ISD_ASN: IsdAsn = IsdAsn::new(Isd(1), Asn(3));

    fn local_addr() -> SocketAddr {
        SocketAddr::new(
            ScionAddr::new(LOCAL_ISD_ASN, Ipv4Addr::new(127, 0, 0, 1).into()),
            8080,
        )
    }

    fn remote_addr() -> SocketAddr {
        SocketAddr::new(
            ScionAddr::new(REMOTE_ISD_ASN, Ipv4Addr::new(127, 0, 0, 2).into()),
            9090,
        )
    }

    fn other_addr() -> SocketAddr {
        SocketAddr::new(
            ScionAddr::new(OTHER_ISD_ASN, Ipv4Addr::new(127, 0, 0, 3).into()),
            7070,
        )
    }

    /// Build a [`TestPathContext`] carrying a path from `src` to `dst`.
    fn test_path_ctx(
        src: ScionAddr,
        dst: ScionAddr,
    ) -> scion_proto::path::test_builder::TestPathContext {
        TestPathBuilder::new(src, dst)
            .using_info_timestamp(1_000_000)
            .up()
            .add_hop(0, 1)
            .add_hop(1, 0)
            .build(1_000_000)
    }

    /// Create a valid [`ScionPacketRaw`] that looks like a UDP packet from `src` to `dst`
    /// with `payload`.
    fn make_udp_raw(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> ScionPacketRaw {
        let ctx = test_path_ctx(src.scion_address(), dst.scion_address());
        ctx.scion_packet_udp(payload, src.port(), dst.port()).into()
    }

    /// Build a connected [`UdpScionSocket`] backed by the test doubles.
    /// Returns the socket, the packet injector, and the path manager.
    fn build_socket() -> (
        UdpScionSocket<ImmediatePathManager>,
        tokio::sync::mpsc::Sender<ScionPacketRaw>,
        Arc<ImmediatePathManager>,
    ) {
        let (underlay, inject_tx) = ManualUnderlaySocket::new(local_addr());
        let pather = Arc::new(ImmediatePathManager::default());
        let path_unaware = PathUnawareUdpScionSocket::new(
            Box::new(underlay),
            vec![], // no SCMP handlers needed
        );
        let socket = UdpScionSocket::new(
            path_unaware,
            pather.clone(),
            std::time::Duration::from_secs(5),
            Subscribers::new(),
        );
        (socket, inject_tx, pather)
    }

    // ─── Tests ─────────────────────────────────────────────────────────────────

    /// Dropping a [`recv_from_with_path`] future while it is pending (waiting in the channel)
    /// must not consume the packet. The next call must receive that packet.
    ///
    /// This verifies that the underlay's `recv` future is cancel-safe: the message stays in the
    /// channel when the outer future is dropped before returning `Ready`.
    #[tokio::test]
    async fn recv_from_with_path_cancel_while_pending_does_not_lose_packet() {
        let (socket, inject_tx, _pather) = build_socket();

        // Poll once — returns Pending because the channel is empty.
        {
            let (mut buf, mut pbuf) = ([0u8; 64], [0u8; 1024]);
            let mut fut = std::pin::pin!(socket.recv_from_with_path(&mut buf, &mut pbuf));
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            // The future must be Pending (no packet injected yet).
            assert!(fut.as_mut().poll(&mut cx).is_pending());
            // Drop `fut` here — the future is cancelled while pending.
        }

        // Inject the packet AFTER the first future was dropped.
        let payload = b"cancel-safe";
        inject_tx
            .try_send(make_udp_raw(remote_addr(), local_addr(), payload))
            .unwrap();

        // The packet must be available to the next future.
        let (mut buf2, mut pbuf2) = (vec![0u8; 64], vec![0u8; 1024]);
        let (len, sender, _path) = socket
            .recv_from_with_path(&mut buf2, &mut pbuf2)
            .await
            .unwrap();

        assert_eq!(len, payload.len());
        assert_eq!(&buf2[..len], payload);
        assert_eq!(sender, remote_addr());
    }

    /// `recv` (connected socket) correctly filters wrong-sender packets and returns
    /// the packet from the connected remote address.
    #[tokio::test]
    async fn recv_filters_wrong_sender_and_delivers_correct_packet() {
        let (mut socket, inject_tx, _pather) = build_socket();
        // Connect to remote_addr.
        socket.remote_addr = Some(remote_addr());

        // Inject wrong-sender packet first, then correct-sender packet.
        inject_tx
            .try_send(make_udp_raw(other_addr(), local_addr(), b"wrong"))
            .unwrap();
        inject_tx
            .try_send(make_udp_raw(remote_addr(), local_addr(), b"correct"))
            .unwrap();

        let mut buf = [0u8; 64];
        let len = socket.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"correct");
    }

    /// After cancelling `recv` mid-filtering (a wrong-sender packet was consumed),
    /// the socket must still be usable and must deliver subsequent correct-sender packets.
    #[tokio::test]
    async fn recv_cancel_during_filtering_socket_remains_usable() {
        let (mut socket, inject_tx, _pather) = build_socket();
        socket.remote_addr = Some(remote_addr());

        // Inject only a wrong-sender packet — `recv` will consume it and loop back
        // to await the next packet (Pending at that point).
        inject_tx
            .try_send(make_udp_raw(other_addr(), local_addr(), b"wrong"))
            .unwrap();

        // Poll once with a noop waker: recv processes the wrong-sender packet, finds it does not
        // match the connected address, and loops back to yield on the inner recv (Pending).
        // No Tokio runtime involvement is needed here — the channel already holds the packet.
        {
            let mut filter_buf = [0u8; 64];
            let mut fut = std::pin::pin!(socket.recv(&mut filter_buf));
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(
                fut.as_mut().poll(&mut cx).is_pending(),
                "recv must be Pending after consuming wrong-sender packet"
            );
            // Drop the future here — the wrong-sender packet has been consumed and discarded.
        }

        // Now inject a correct-sender packet and verify the socket is still usable.
        inject_tx
            .try_send(make_udp_raw(remote_addr(), local_addr(), b"after-cancel"))
            .unwrap();

        let mut buf = [0u8; 64];
        let len = socket.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"after-cancel");
    }

    /// Buffer contents are only valid after a successful `Ok` return; after a
    /// cancel and retry the buffer must contain the correct data from the retry.
    #[tokio::test]
    async fn recv_from_buffer_valid_only_after_ok() {
        let (socket, inject_tx, _pather) = build_socket();

        // Pre-fill buffer with sentinel bytes.
        let mut buf = [0xFFu8; 64];

        // Cancel while pending (no packet).
        {
            let mut fut = std::pin::pin!(socket.recv_from(&mut buf));
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut cx).is_pending());
        }

        // Inject a packet with known payload.
        let payload = b"real-data";
        inject_tx
            .try_send(make_udp_raw(remote_addr(), local_addr(), payload))
            .unwrap();

        let (len, _sender) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(
            &buf[..len],
            payload,
            "buffer must contain the real payload after Ok return"
        );
    }
}
