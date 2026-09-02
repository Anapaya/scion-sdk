// Copyright 2026 Anapaya Systems
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

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ana_gotatun::{
    noise::{Tunn, TunnResult, errors::WireGuardError, rate_limiter::RateLimiter},
    packet::{Packet, PacketBufPool, WgKind},
    x25519::{self},
};
use bytes::{Bytes, BytesMut};
use scion_sdk_utils::backoff::ExponentialBackoff;
use tokio::{select, task::JoinHandle, time::Interval};
use tracing::instrument;
use zerocopy::IntoBytes as _;

use super::{PACKET_BUF_POOL_SIZE, TunnelGuard};
use crate::udp_batch::{QueuePacketError, RecvBatchError, UdpBatchReceiver, UdpBatchSender};

const HANDSHAKE_RATE_LIMIT: u64 = 20;
const RECEIVE_BATCH_SIZE: usize = 64;

/// How long the driver tries to re-establish an expired session before it stops.
const REHANDSHAKE_BUDGET: Duration = Duration::from_secs(600);

/// Error when sending or receiving packets on the SNAP tunnel.
#[derive(Debug, thiserror::Error)]
pub enum SnapTunnelDriverError {
    /// I/O error when sending packets on the underlay socket.
    #[error("send i/o error: {0}")]
    SendIoError(#[from] std::io::Error),
    /// I/O error when receiving packets on the underlay socket.
    #[error("receive i/o error: {0}")]
    ReceiveIoError(std::io::Error),
    /// Receive queue closed.
    #[error("receive queue closed")]
    ReceiveQueueClosed,
    /// Connection expired.
    #[error("connection expired")]
    ConnectionExpired,
    /// Error receiving a Wireguard packet.
    /// This will never be WireGuardError::ConnectionExpired.
    #[error("error receiving a Wireguard packet: {0:?}")]
    WireguardError(WireGuardError),
}

impl SnapTunnelDriverError {
    /// Returns whether the failure is transient, so that a retry may help.
    ///
    /// Prefer this over matching the variants: a new variant would silently fall into a caller's
    /// wildcard arm.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            // The underlay socket could not carry the datagram, which is a condition of the local
            // network or of the route to the data plane.
            Self::SendIoError(_) | Self::ReceiveIoError(_) => true,
            // The peer did not complete the handshake within the WireGuard time window, so a new
            // handshake may still succeed.
            Self::ConnectionExpired => true,
            // The consumer of the tunnel is gone; there is nothing left to deliver packets to.
            Self::ReceiveQueueClosed => false,
            // A WireGuard failure describes either the datagram or the configuration, and only
            // the second survives a retry. Ordering, duplication, corruption and replay are all
            // properties of one datagram that a fresh handshake, or simply the next packet,
            // leaves behind. A peer key that does not match, a poisoned lock, and a buffer this
            // side sized too small answer the same way every time.
            //
            // Spelled out rather than reached through a wildcard: `WireGuardError` is not
            // `#[non_exhaustive]`, so naming every variant makes an `ana-gotatun` upgrade a
            // compile error here instead of a silent reclassification.
            Self::WireguardError(error) => {
                match error {
                    WireGuardError::NoCurrentSession
                    | WireGuardError::WrongIndex
                    | WireGuardError::UnexpectedPacket
                    | WireGuardError::WrongPacketType
                    | WireGuardError::IncorrectPacketLength
                    | WireGuardError::InvalidPacket
                    | WireGuardError::InvalidCounter
                    | WireGuardError::DuplicateCounter
                    | WireGuardError::InvalidMac
                    | WireGuardError::InvalidAeadTag
                    | WireGuardError::InvalidTai64nTimestamp
                    | WireGuardError::WrongTai64nTimestamp
                    | WireGuardError::ConnectionExpired => true,
                    WireGuardError::WrongKey
                    | WireGuardError::LockFailed
                    | WireGuardError::DestinationBufferTooSmall => false,
                }
            }
        }
    }
}

struct SnapTunnelDriver {
    pub tunn: Arc<Mutex<Tunn>>,
    pub static_private: x25519::StaticSecret,
    pub peer_public: x25519::PublicKey,
    pub underlay_socket: Arc<tokio::net::UdpSocket>,
    pub dataplane_address: SocketAddr,
    pub persistent_keepalive_seconds: Option<u16>,
    pub update_timers_interval: Interval,
    pub packet_sender: async_channel::Sender<BytesMut>,
    pub local_sockaddr: Option<SocketAddr>,
    pub pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
    pub receiver: UdpBatchReceiver<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>,
    pub sender: UdpBatchSender<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>,
    /// Shared with the [`SnapTunnel`] handle, which exposes it to the application.
    pub discarded_datagrams: Arc<AtomicU64>,
    /// Set when the driver stops. Shared with the [`SnapTunnel`] handle.
    pub closed: Arc<AtomicBool>,
}

impl SnapTunnelDriver {
    fn new(
        static_private: x25519::StaticSecret,
        peer_public: x25519::PublicKey,
        underlay_socket: Arc<tokio::net::UdpSocket>,
        dataplane_address: SocketAddr,
        persistent_keepalive_seconds: Option<u16>,
        packet_sender: async_channel::Sender<BytesMut>,
        pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
    ) -> io::Result<Self> {
        let update_timers_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(250),
            Duration::from_millis(250),
        );
        let receiver = UdpBatchReceiver::<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>::new(
            underlay_socket.as_ref(),
            &pool,
        )?;
        let sender = UdpBatchSender::<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>::new(
            underlay_socket.as_ref(),
        )?;
        Ok(Self {
            tunn: Arc::new(Mutex::new(Self::create_tunn(
                static_private.clone(),
                peer_public,
                dataplane_address,
                persistent_keepalive_seconds,
            ))),
            static_private,
            peer_public,
            underlay_socket,
            dataplane_address,
            persistent_keepalive_seconds,
            update_timers_interval,
            packet_sender,
            local_sockaddr: None,
            receiver,
            sender,
            pool,
            discarded_datagrams: Arc::new(AtomicU64::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Flushes the send queue as far as the socket allows right now.
    ///
    /// Back pressure needs no handling here: the datagrams stay queued and the next flush
    /// picks them up.
    ///
    /// Takes the fields it needs one by one instead of `&mut self` so that it stays callable
    /// from the receive closure, which borrows the driver field by field.
    fn try_flush(
        socket: &tokio::net::UdpSocket,
        sender: &mut UdpBatchSender<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>,
        discarded_datagrams: &AtomicU64,
    ) {
        let _ = sender.try_flush_best_effort(socket);
        Self::account_discarded_datagrams(sender, discarded_datagrams);
    }

    /// Flushes the send queue, waiting for the socket to become writable.
    async fn flush(
        socket: &tokio::net::UdpSocket,
        sender: &mut UdpBatchSender<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>,
        discarded_datagrams: &AtomicU64,
    ) -> io::Result<()> {
        let result = sender.flush(socket).await;
        Self::account_discarded_datagrams(sender, discarded_datagrams);
        result
    }

    /// Publishes the datagrams the sender had to discard to the shared counter.
    ///
    /// Every flush goes through [`Self::try_flush`] or [`Self::flush`] so that no discard
    /// escapes this accounting.
    fn account_discarded_datagrams(
        sender: &mut UdpBatchSender<RECEIVE_BATCH_SIZE, PACKET_BUF_POOL_SIZE>,
        discarded_datagrams: &AtomicU64,
    ) {
        let discarded = sender.take_discarded_datagrams();
        if discarded > 0 {
            discarded_datagrams.fetch_add(discarded, Ordering::Relaxed);
        }
    }

    #[instrument(name = "st-client", skip(self), fields(socket_addr= ?self.local_sockaddr))]
    async fn initiate_connection(&mut self) -> Result<SocketAddr, SnapTunnelDriverError> {
        let handshake_init = self.tunn.lock().unwrap().format_handshake_initiation(false);
        if let Some(wg_init) = handshake_init
            && let Err(e) = self
                .underlay_socket
                .send_to(
                    to_bytes(WgKind::HandshakeInit(wg_init)).as_bytes(),
                    self.dataplane_address,
                )
                .await
        {
            return Err(SnapTunnelDriverError::SendIoError(e));
        }
        // Drive the tunnel until any error occurs or the handshake is completed.
        loop {
            self.drive_once().await?;
            if let Some(sockaddr) = self.tunn.lock().unwrap().get_initiator_remote_sockaddr() {
                if self.local_sockaddr.is_none() {
                    self.local_sockaddr = Some(sockaddr);
                }
                tracing::debug!(local_addr=?sockaddr, "handshake completed, local address assigned");
                return Ok(sockaddr);
            }
        }
    }

    /// Drives the tunnel until it stops, then marks the tunnel closed.
    #[instrument(name = "st-client", skip(self), fields(socket_addr= ?self.local_sockaddr))]
    async fn main_loop(mut self) {
        self.run().await;
        self.closed.store(true, Ordering::Release);
        tracing::info!("snap tunnel driver stopped");
    }

    /// Drives the tunnel. Returns when the consumer of the receive queue is gone or when an
    /// expired session cannot be re-established on this socket.
    async fn run(&mut self) {
        let local_sockaddr = self
            .local_sockaddr
            .expect("local address must be set before main_loop()");
        loop {
            match self.drive_once().await {
                Err(SnapTunnelDriverError::ReceiveQueueClosed) => {
                    tracing::info!("receive queue closed, snap tunnel driver shutting down");
                    return;
                }
                Err(SnapTunnelDriverError::ConnectionExpired) => {
                    if !self.rehandshake(local_sockaddr).await {
                        return;
                    }
                }
                Err(ref e) => tracing::error!(err=?e, "error driving tunnel"),
                _ => {}
            }
        }
    }

    /// Re-establishes an expired session with a fresh handshake.
    ///
    /// Returns `true` when the session is back on the same local address. Returns `false` when the
    /// driver must stop: the data plane assigned a different address, the failure is permanent, or
    /// [`REHANDSHAKE_BUDGET`] is spent.
    async fn rehandshake(&mut self, local_sockaddr: SocketAddr) -> bool {
        let started = Instant::now();
        let mut backoff = BackoffState::new();
        loop {
            *self.tunn.lock().expect("poison") = Self::create_tunn(
                self.static_private.clone(),
                self.peer_public,
                self.dataplane_address,
                self.persistent_keepalive_seconds,
            );
            let result = self.initiate_connection().await;
            match rehandshake_outcome(local_sockaddr, &result, started.elapsed()) {
                Recovery::Recovered => return true,
                Recovery::Retry => {
                    tracing::warn!(?result, "re-handshake failed, retrying");
                }
                Recovery::Stop(reason) => {
                    tracing::error!(
                        ?reason,
                        ?result,
                        "cannot re-establish snap tunnel, stopping driver"
                    );
                    return false;
                }
            }
            backoff.backoff().await;
        }
    }

    /// Drives the tunnel once. Returns Ok(()) if no error occured in the drive, otherwise returns
    /// the error. This method is called periodically by the main loop to update the timers and
    /// receive packets.
    async fn drive_once(&mut self) -> Result<(), SnapTunnelDriverError> {
        select! {
            // bias to ensure that high receive load cannot starve the timer
            biased;
            _ = self.update_timers_interval.tick() => {
                let p = match self.tunn.lock().unwrap().update_timers() {
                    Ok(Some(wg)) => { Some(wg) },
                    Ok(None) => None,
                    Err(WireGuardError::ConnectionExpired) => {
                        return Err(SnapTunnelDriverError::ConnectionExpired);
                    }
                    Err(e) => {
                        // At the time of writing, update_timers does not return any error
                        // other than ConnectionExpired.
                        tracing::error!(err=?e, "unexpected error updating timers on tunnel");
                        None
                    }
                };
                if let Some(wg) = p && let Err(e) = self.underlay_socket.send_to(to_bytes(wg).as_bytes(), self.dataplane_address).await {
                    return Err(SnapTunnelDriverError::SendIoError(e));
                }
            },
            recv = self.receiver.recv_batch(&self.underlay_socket, &self.pool, |buf, sender_addr| {
                if sender_addr != self.dataplane_address {
                    return Ok(());
                }
                let Ok(wg) = buf.try_into_wg() else {
                    tracing::debug!("received packet that is not a valid WireGuard packet, ignoring");
                    return Ok(());
                };
                let result = self.tunn.lock().unwrap().handle_incoming_packet(wg);
                match result {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        return Err(SnapTunnelDriverError::WireguardError(e));
                    }
                    TunnResult::WriteToNetwork(p) => {
                        if let Err(error) = self
                            .sender
                            .try_queue_packet(to_bytes(p), self.dataplane_address)
                        {
                            match error {
                                QueuePacketError::Full { packet, target } => {
                                    Self::try_flush(
                                        &self.underlay_socket,
                                        &mut self.sender,
                                        &self.discarded_datagrams,
                                    );
                                    if self.sender.try_queue_packet(packet, target).is_err() {
                                        tracing::debug!(?target, "dropping outbound packet because batched sender remains full");
                                    }
                                }
                                QueuePacketError::PacketTooLarge {
                                    packet_len,
                                    max_packet_size,
                                    ..
                                } => {
                                    return Err(SnapTunnelDriverError::SendIoError(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        format!(
                                            "outbound packet length {packet_len} exceeds batched sender max of {max_packet_size}"
                                        ),
                                    )));
                                }
                            }
                        }
                        for queued in self.tunn.lock().unwrap().get_queued_packets() {
                            if let Err(error) = self
                                .sender
                                .try_queue_packet(to_bytes(queued), self.dataplane_address)
                            {
                                match error {
                                    QueuePacketError::Full { packet, target } => {
                                        Self::try_flush(
                                            &self.underlay_socket,
                                            &mut self.sender,
                                            &self.discarded_datagrams,
                                        );
                                        if self.sender.try_queue_packet(packet, target).is_err() {
                                            tracing::debug!(?target, "dropping queued outbound packet because batched sender remains full");
                                        }
                                    }
                                    QueuePacketError::PacketTooLarge {
                                        packet_len,
                                        max_packet_size,
                                        ..
                                    } => {
                                        return Err(SnapTunnelDriverError::SendIoError(io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            format!(
                                                "queued outbound packet length {packet_len} exceeds batched sender max of {max_packet_size}"
                                            ),
                                        )));
                                    }
                                }
                            }
                        }
                    }
                    TunnResult::WriteToTunnel(mut p) => {
                        let buf = p.buf_mut().to_owned();
                        if !buf.is_empty() {
                            match self.packet_sender.try_send(buf) {
                                Ok(()) => {}
                                Err(async_channel::TrySendError::Full(_)) => {
                                    tracing::debug!("receive channel is full, dropping packet");
                                }
                                Err(_) => {
                                    return Err(SnapTunnelDriverError::ReceiveQueueClosed);
                                }
                            }
                        }
                    }
                }
                Ok(())
            }) => {
                match recv {
                    Ok(()) => {
                        Self::flush(
                            &self.underlay_socket,
                            &mut self.sender,
                            &self.discarded_datagrams,
                        )
                        .await?;
                    }
                    Err(RecvBatchError::Io(e)) => {
                        return Err(SnapTunnelDriverError::ReceiveIoError(e));
                    }
                    Err(RecvBatchError::Handler(e)) => {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    fn create_tunn(
        static_private: x25519::StaticSecret,
        peer_public: x25519::PublicKey,
        dataplane_address: SocketAddr,
        persistent_keepalive_seconds: Option<u16>,
    ) -> Tunn {
        let local_public = x25519::PublicKey::from(&static_private);
        Tunn::new(
            static_private,
            peer_public,
            None,
            persistent_keepalive_seconds,
            0,
            Arc::new(RateLimiter::new(&local_public, HANDSHAKE_RATE_LIMIT)),
            dataplane_address,
        )
    }
}

/// What the driver does after one re-handshake attempt.
#[derive(Debug, PartialEq, Eq)]
enum Recovery {
    /// The session is back on the same local address.
    Recovered,
    /// Try again after a backoff.
    Retry,
    /// Stop the driver.
    Stop(StopReason),
}

/// Why the driver stops instead of trying the re-handshake again.
#[derive(Debug, PartialEq, Eq)]
enum StopReason {
    /// The data plane assigned a different local address. The data plane derives the address from
    /// the source address it observes, so this socket now speaks for a different SCION address
    /// than the one the application was given.
    AddressChanged { new_addr: SocketAddr },
    /// The failure answers the same way on every attempt.
    PermanentError,
    /// Transient failures lasted longer than [`REHANDSHAKE_BUDGET`].
    BudgetExhausted,
}

/// Decides how the driver continues after a re-handshake attempt that took `elapsed` since the
/// session expired.
fn rehandshake_outcome(
    expected_addr: SocketAddr,
    result: &Result<SocketAddr, SnapTunnelDriverError>,
    elapsed: Duration,
) -> Recovery {
    match result {
        Ok(addr) if *addr == expected_addr => Recovery::Recovered,
        Ok(addr) => Recovery::Stop(StopReason::AddressChanged { new_addr: *addr }),
        Err(e) if !e.is_transient() => Recovery::Stop(StopReason::PermanentError),
        Err(_) if elapsed >= REHANDSHAKE_BUDGET => Recovery::Stop(StopReason::BudgetExhausted),
        Err(_) => Recovery::Retry,
    }
}

/// Error when receiving a packet from the SNAP tunnel connection.
#[derive(Debug, thiserror::Error)]
pub enum SnapTunnelReceiveError {
    /// The receive queue is closed because the tunnel is closed. See [`SnapTunnel::is_closed`].
    #[error("receive queue closed")]
    ReceiveQueueClosed,
}

type RecvFuture = Pin<Box<dyn Future<Output = Result<BytesMut, async_channel::RecvError>> + Send>>;

/// A SNAP tunnel connection.
///
/// A background driver task runs the WireGuard session. Once the driver stops the tunnel is closed
/// for good: receiving fails with [`SnapTunnelReceiveError::ReceiveQueueClosed`] and sending fails
/// with an `io::ErrorKind::ConnectionReset` error. See [`SnapTunnel::is_closed`] for when that
/// happens.
pub struct SnapTunnel {
    _guard: TunnelGuard,
    tunn: Arc<Mutex<Tunn>>,
    underlay_socket: Arc<tokio::net::UdpSocket>,
    dataplane_address: SocketAddr,
    local_sockaddr: SocketAddr,
    receive_queue: async_channel::Receiver<BytesMut>,
    /// Stored receive future for poll_recv. Protected by Mutex for interior mutability.
    recv_future: Mutex<Option<RecvFuture>>,
    /// Tasks that drives the SNAP tunnel.
    /// Cancelled when the socket is dropped.
    driver_task: JoinHandle<()>,
    discarded_datagrams: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl Drop for SnapTunnel {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

impl SnapTunnel {
    /// Creates a new SNAP tunnel and waits for the handshake to complete.
    ///
    /// # Arguments
    ///
    /// * `static_private` - The client's static private key
    /// * `peer_public` - The server's static public key (needed for handshake)
    /// * `rate_limiter` - Rate limiter for the tunnel
    /// * `underlay_socket` - UDP socket for sending/receiving packets
    /// * `dataplane_address` - Address of the remote server
    /// * `receive_queue_capacity` - Capacity of the receive queue
    pub(super) async fn new(
        guard: TunnelGuard,
        static_private: x25519::StaticSecret,
        peer_public: x25519::PublicKey,
        underlay_socket: Arc<tokio::net::UdpSocket>,
        dataplane_address: SocketAddr,
        receive_queue_capacity: usize,
        persistent_keepalive_seconds: Option<u16>,
        pool: PacketBufPool<PACKET_BUF_POOL_SIZE>,
    ) -> Result<Self, SnapTunnelDriverError> {
        let (packet_sender, packet_receiver) = async_channel::bounded(receive_queue_capacity);
        let mut driver = SnapTunnelDriver::new(
            static_private,
            peer_public,
            underlay_socket.clone(),
            dataplane_address,
            persistent_keepalive_seconds,
            packet_sender,
            pool.clone(),
        )?;
        let socket_addr = driver.initiate_connection().await?;
        Ok(Self {
            _guard: guard,
            tunn: driver.tunn.clone(),
            discarded_datagrams: driver.discarded_datagrams.clone(),
            closed: driver.closed.clone(),
            underlay_socket,
            dataplane_address,
            local_sockaddr: socket_addr,
            receive_queue: packet_receiver,
            recv_future: Mutex::new(None),
            driver_task: tokio::spawn(driver.main_loop()),
        })
    }

    /// Send a packet to the remote server.
    ///
    /// While a handshake is in progress the packet is queued and sent when the handshake
    /// completes. Fails with `io::ErrorKind::ConnectionReset` once the tunnel is closed.
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= packet.len()))]
    pub async fn send(&self, packet: Packet) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed_error());
        }
        let encapsulated_packet = self.tunn.lock().unwrap().handle_outgoing_packet(packet);
        match encapsulated_packet {
            Some(wg) => {
                let bytes = match wg {
                    WgKind::HandshakeInit(p) => p.into_bytes(),
                    WgKind::HandshakeResp(p) => p.into_bytes(),
                    WgKind::CookieReply(p) => p.into_bytes(),
                    WgKind::Data(p) => p.into_bytes(),
                };
                tracing::trace!(dataplane_address=?self.dataplane_address, "sending packet");
                self.underlay_socket
                    .send_to(bytes.as_bytes(), self.dataplane_address)
                    .await?;
                Ok(())
            }
            None => {
                // None is returned if a handshake is ongoing but not yet complete.
                // In this case the packet is queued and will be sent when the handshake is
                // complete.
                tracing::trace!("handshake ongoing, queueing packet");
                Ok(())
            }
        }
    }

    /// Try to send a packet to the remote server. Returns error of try_send_to.
    ///
    /// Fails with `io::ErrorKind::ConnectionReset` once the tunnel is closed.
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= packet.len()))]
    pub fn try_send(&self, packet: Packet) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed_error());
        }
        match self.tunn.lock().unwrap().handle_outgoing_packet(packet) {
            Some(wg) => {
                let bytes = match wg {
                    WgKind::HandshakeInit(p) => p.into_bytes(),
                    WgKind::HandshakeResp(p) => p.into_bytes(),
                    WgKind::CookieReply(p) => p.into_bytes(),
                    WgKind::Data(p) => p.into_bytes(),
                };
                tracing::trace!(dataplane_address=?self.dataplane_address, "trying to send packet");
                self.underlay_socket
                    .try_send_to(bytes.as_bytes(), self.dataplane_address)?;
                Ok(())
            }
            None => {
                // None is returned if a handshake is ongoing but not yet complete.
                // In this case the packet is queued and will be sent when the handshake is
                // complete.
                Ok(())
            }
        }
    }

    /// Receive a packet from the remote server.
    ///
    /// Fails with [`SnapTunnelReceiveError::ReceiveQueueClosed`] once the tunnel is closed.
    pub async fn recv(&self) -> Result<Bytes, SnapTunnelReceiveError> {
        match self.receive_queue.recv().await {
            Ok(packet) => Ok(packet.into()),
            Err(_) => Err(SnapTunnelReceiveError::ReceiveQueueClosed),
        }
    }

    /// Try to receive a packet from the remote server without blocking.
    ///
    /// Returns `Ok(None)` if no packet is currently available.
    pub fn try_recv(&self) -> Result<Option<Bytes>, SnapTunnelReceiveError> {
        match self.receive_queue.try_recv() {
            Ok(packet) => Ok(Some(packet.into())),
            Err(async_channel::TryRecvError::Empty) => Ok(None),
            Err(async_channel::TryRecvError::Closed) => {
                Err(SnapTunnelReceiveError::ReceiveQueueClosed)
            }
        }
    }

    /// Poll for a packet from the remote server.
    pub fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Bytes, SnapTunnelReceiveError>> {
        let mut fut_guard = self.recv_future.lock().expect("lock poisoned");

        // Create future if it doesn't exist
        if fut_guard.is_none() {
            // Clone the receiver (cheap with async-channel) to avoid borrowing self
            let receiver = self.receive_queue.clone();
            *fut_guard = Some(Box::pin(async move { receiver.recv().await }));
        }

        // Poll the stored future
        let fut = fut_guard.as_mut().expect("future cannot be none");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(packet)) => {
                // Clear the future so a new one is created on next poll
                *fut_guard = None;
                std::task::Poll::Ready(Ok(packet.into()))
            }
            std::task::Poll::Ready(Err(_)) => {
                tracing::trace!("receive queue closed, returning error");
                *fut_guard = None;
                std::task::Poll::Ready(Err(SnapTunnelReceiveError::ReceiveQueueClosed))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Get the local socket address. Assigned by the remote server.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_sockaddr
    }

    /// Whether the tunnel is closed. A closed tunnel delivers nothing in either direction.
    ///
    /// The tunnel closes when the driver stops. The driver stops when the consumer of the receive
    /// queue is gone, when an expired session cannot be re-established within a fixed budget, when
    /// a re-handshake fails permanently, or when a re-handshake assigns a different local address.
    /// The last case happens after the local network changed, because the data plane derives the
    /// address from the source address it observes. An application that wants to continue then
    /// connects a new tunnel; see the rules on [`super::SnapTunEndpoint`].
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Check if the socket is writable.
    pub async fn writable(&self) -> io::Result<()> {
        self.underlay_socket.writable().await
    }

    /// The data plane the tunnel is connected to.
    pub fn data_plane_address(&self) -> SocketAddr {
        self.dataplane_address
    }

    /// Total number of outbound datagrams the underlay socket refused since the tunnel was
    /// created.
    ///
    /// A refused datagram is dropped rather than retried, because retrying one the socket will
    /// never accept blocks every packet queued behind it. The tunnel therefore stays up when
    /// sending fails persistently, for example because the interface went down or a firewall
    /// answers `EPERM`, and this counter is what tells such a tunnel apart from a healthy one.
    pub fn discarded_datagrams(&self) -> u64 {
        self.discarded_datagrams.load(Ordering::Relaxed)
    }
}

struct BackoffState {
    last: Instant,
    exp_backoff: ExponentialBackoff,
    attempt: usize,
}

impl BackoffState {
    fn new() -> Self {
        Self {
            last: Instant::now(),
            exp_backoff: ExponentialBackoff::new(
                5.0, 180.0, // max 3 mins
                1.3, 0.5,
            ),
            attempt: 0,
        }
    }

    /// The delay before the next attempt or `None` when the next attempt is already due.
    fn next_delay(&mut self) -> Option<Duration> {
        let now = Instant::now();
        let until_next = (self.last + self.exp_backoff.duration(self.attempt as u32))
            .checked_duration_since(now);
        self.attempt += 1;
        self.last = now;
        until_next
    }

    fn backoff(&mut self) -> impl Future<Output = ()> {
        let until_next = self.next_delay();
        async move {
            if let Some(d) = until_next {
                tokio::time::sleep(d).await;
            }
        }
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "SNAP tunnel closed")
}

fn to_bytes(wg: WgKind) -> Packet<[u8]> {
    match wg {
        WgKind::HandshakeInit(p) => p.into_bytes(),
        WgKind::HandshakeResp(p) => p.into_bytes(),
        WgKind::CookieReply(p) => p.into_bytes(),
        WgKind::Data(p) => p.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_error_transient_classification() {
        // The socket or the peer did not carry the handshake through, so a retry may.
        assert!(SnapTunnelDriverError::SendIoError(io::Error::other("boom")).is_transient());
        assert!(SnapTunnelDriverError::ReceiveIoError(io::Error::other("boom")).is_transient());
        assert!(SnapTunnelDriverError::ConnectionExpired.is_transient());
        // Handshake timing and packet ordering: a datagram that arrived late, twice, or for a
        // session that has since rotated. None of them says anything about the next attempt.
        for error in [
            WireGuardError::NoCurrentSession,
            WireGuardError::WrongIndex,
            WireGuardError::UnexpectedPacket,
            WireGuardError::InvalidCounter,
            WireGuardError::DuplicateCounter,
        ] {
            assert!(
                SnapTunnelDriverError::WireguardError(error).is_transient(),
                "a handshake-timing condition was reported as permanent"
            );
        }
        // A peer key that does not match, and a gone consumer, answer the same way on every
        // attempt.
        assert!(!SnapTunnelDriverError::WireguardError(WireGuardError::WrongKey).is_transient());
        assert!(!SnapTunnelDriverError::ReceiveQueueClosed.is_transient());
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rehandshake_recovers_on_the_same_address() {
        let expected = addr("192.0.2.1:4000");
        assert_eq!(
            rehandshake_outcome(expected, &Ok(expected), Duration::ZERO),
            Recovery::Recovered
        );
    }

    #[test]
    fn rehandshake_stops_when_the_address_changed() {
        let expected = addr("192.0.2.1:4000");
        let new_addr = addr("198.51.100.7:4000");
        assert_eq!(
            rehandshake_outcome(expected, &Ok(new_addr), Duration::ZERO),
            Recovery::Stop(StopReason::AddressChanged { new_addr })
        );
    }

    #[test]
    fn rehandshake_retries_transient_errors_within_the_budget() {
        let expected = addr("192.0.2.1:4000");
        let expired = Err(SnapTunnelDriverError::ConnectionExpired);
        assert_eq!(
            rehandshake_outcome(expected, &expired, Duration::ZERO),
            Recovery::Retry
        );
        assert_eq!(
            rehandshake_outcome(
                expected,
                &expired,
                REHANDSHAKE_BUDGET - Duration::from_secs(1)
            ),
            Recovery::Retry
        );
        let send_failed = Err(SnapTunnelDriverError::SendIoError(io::Error::other("down")));
        assert_eq!(
            rehandshake_outcome(expected, &send_failed, Duration::ZERO),
            Recovery::Retry
        );
    }

    #[test]
    fn rehandshake_stops_when_the_budget_is_spent() {
        let expected = addr("192.0.2.1:4000");
        let expired = Err(SnapTunnelDriverError::ConnectionExpired);
        assert_eq!(
            rehandshake_outcome(expected, &expired, REHANDSHAKE_BUDGET),
            Recovery::Stop(StopReason::BudgetExhausted)
        );
    }

    #[test]
    fn rehandshake_stops_on_a_permanent_error() {
        let expected = addr("192.0.2.1:4000");
        let gone = Err(SnapTunnelDriverError::ReceiveQueueClosed);
        assert_eq!(
            rehandshake_outcome(expected, &gone, Duration::ZERO),
            Recovery::Stop(StopReason::PermanentError)
        );
    }

    #[test]
    fn backoff_delay_grows_across_attempts() {
        // The jitter is at most 0.5 s and the base delay grows by at least 1.5 s per attempt, so
        // consecutive delays of one state are strictly increasing.
        let mut backoff = BackoffState::new();
        let first = backoff.next_delay().expect("first attempt waits");
        let second = backoff.next_delay().expect("second attempt waits");
        let third = backoff.next_delay().expect("third attempt waits");
        assert!(
            first < second && second < third,
            "{first:?} {second:?} {third:?}"
        );
    }
}
