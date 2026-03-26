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
    sync::{Arc, Mutex},
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
        })
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

    #[instrument(name = "st-client", skip(self), fields(socket_addr= ?self.local_sockaddr))]
    async fn main_loop(mut self) {
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
                    loop {
                        let mut backoff = BackoffState::new();
                        // reset tunnel
                        *self.tunn.lock().expect("poison") = Self::create_tunn(
                            self.static_private.clone(),
                            self.peer_public,
                            self.dataplane_address,
                            self.persistent_keepalive_seconds,
                        );
                        match self.initiate_connection().await {
                            Ok(addr) if addr == local_sockaddr => break,
                            Ok(addr) => {
                                tracing::error!(expected_addr=?local_sockaddr, new_addr=?addr, "local socket address changed");
                            }
                            Err(err) => {
                                tracing::error!(?err, "error driving tunnel");
                            }
                        }
                        backoff.backoff().await;
                    }
                }
                Err(ref e) => tracing::error!(err=?e, "error driving tunnel"),
                _ => {}
            }
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
                                    let err = self.sender.try_flush_best_effort(&self.underlay_socket);
                                    if let Err(ref flush_err) = err
                                        && flush_err.kind() != io::ErrorKind::WouldBlock
                                    {
                                        return Err(SnapTunnelDriverError::SendIoError(io::Error::new(
                                            flush_err.kind(),
                                            flush_err.to_string(),
                                        )));
                                    }
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
                                        let err = self.sender.try_flush_best_effort(&self.underlay_socket);
                                        if let Err(ref flush_err) = err
                                            && flush_err.kind() != io::ErrorKind::WouldBlock
                                        {
                                            return Err(SnapTunnelDriverError::SendIoError(io::Error::new(
                                                flush_err.kind(),
                                                flush_err.to_string(),
                                            )));
                                        }
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
                        self.sender.flush(&self.underlay_socket).await?;
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

/// Error when receiving a packet from the SNAP tunnel connection.
#[derive(Debug, thiserror::Error)]
pub enum SnapTunnelReceiveError {
    /// The receive queue is closed.
    #[error("receive queue closed")]
    ReceiveQueueClosed,
}

type RecvFuture = Pin<Box<dyn Future<Output = Result<BytesMut, async_channel::RecvError>> + Send>>;

/// A SNAP tunnel connection.
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
            underlay_socket,
            dataplane_address,
            local_sockaddr: socket_addr,
            receive_queue: packet_receiver,
            recv_future: Mutex::new(None),
            driver_task: tokio::spawn(driver.main_loop()),
        })
    }

    /// Send a packet to the remote server.
    // xxx(dsd): during a connection reset, packets will be silently dropped.
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= packet.len()))]
    pub async fn send(&self, packet: Packet) -> io::Result<()> {
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
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= packet.len()))]
    pub fn try_send(&self, packet: Packet) -> io::Result<()> {
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
    pub async fn recv(&self) -> Result<Bytes, SnapTunnelReceiveError> {
        match self.receive_queue.recv().await {
            Ok(packet) => Ok(packet.into()),
            Err(_) => Err(SnapTunnelReceiveError::ReceiveQueueClosed),
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

    /// Check if the socket is writable.
    pub async fn writable(&self) -> io::Result<()> {
        self.underlay_socket.writable().await
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

    fn backoff(&mut self) -> impl Future<Output = ()> {
        let now = Instant::now();
        let until_next = (self.last + self.exp_backoff.duration(self.attempt as u32))
            .checked_duration_since(now);
        self.attempt += 1;
        self.last = now;

        async move {
            if let Some(d) = until_next {
                tokio::time::sleep(d).await;
            }
        }
    }
}

fn to_bytes(wg: WgKind) -> Packet<[u8]> {
    match wg {
        WgKind::HandshakeInit(p) => p.into_bytes(),
        WgKind::HandshakeResp(p) => p.into_bytes(),
        WgKind::CookieReply(p) => p.into_bytes(),
        WgKind::Data(p) => p.into_bytes(),
    }
}
