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
//! SNAP tunnel client.

use std::{
    io,
    net::SocketAddr,
    pin,
    sync::{Arc, Mutex},
    task::ready,
    time::Duration,
};

use ana_gotatun::{
    noise::{Tunn, TunnResult, errors::WireGuardError, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    x25519::{self},
};
use bytes::{Bytes, BytesMut};
use tokio::{
    select,
    sync::mpsc::{self, error::TrySendError},
    task::JoinHandle,
    time::Interval,
};
use tracing::instrument;
use zerocopy::IntoBytes as _;

const UDP_DATAGRAM_BUFFER_SIZE: usize = 65535;
const HANDSHAKE_RATE_LIMIT: u64 = 20;

/// Error when sending or receiving packets on the SNAP tunnel.
#[derive(Debug, thiserror::Error)]
pub enum SnapTunNgSocketError {
    /// I/O error.
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
    /// Receive queue closed.
    #[error("receive queue closed")]
    ReceiveQueueClosed,
    /// Initial handshake timed out.
    #[error("initial handshake timed out")]
    InitialHandshakeTimeout,
    /// Wireguard error.
    #[error("wireguard error: {0:?}")]
    WireguardError(WireGuardError),
}

struct SnapTunNgClientDriver {
    pub tunn: Arc<Mutex<Tunn>>,
    pub underlay_socket: Arc<tokio::net::UdpSocket>,
    pub dataplane_address: SocketAddr,
    pub update_timers_interval: Interval,
    pub packet_sender: mpsc::Sender<BytesMut>,
    pub local_sockaddr: Option<SocketAddr>,
}

fn to_bytes(wg: WgKind) -> Packet<[u8]> {
    match wg {
        WgKind::HandshakeInit(p) => p.into_bytes(),
        WgKind::HandshakeResp(p) => p.into_bytes(),
        WgKind::CookieReply(p) => p.into_bytes(),
        WgKind::Data(p) => p.into_bytes(),
    }
}

impl SnapTunNgClientDriver {
    fn new(
        tunn: Arc<Mutex<Tunn>>,
        underlay_socket: Arc<tokio::net::UdpSocket>,
        dataplane_address: SocketAddr,
        packet_sender: mpsc::Sender<BytesMut>,
    ) -> Self {
        let update_timers_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(250),
            Duration::from_millis(250),
        );
        Self {
            tunn,
            underlay_socket,
            dataplane_address,
            update_timers_interval,
            packet_sender,
            local_sockaddr: None,
        }
    }

    #[instrument(name = "st-client", skip(self), fields(socket_addr= ?self.local_sockaddr))]
    async fn initial_connection(&mut self) -> Result<SocketAddr, SnapTunNgSocketError> {
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
            return Err(SnapTunNgSocketError::IoError(e));
        }
        // Drive the tunnel until any error occurs or the handshake is completed.
        loop {
            self.drive_once().await?;
            if let Some(sockaddr) = self.tunn.lock().unwrap().get_initiator_remote_sockaddr() {
                self.local_sockaddr = Some(sockaddr);
                tracing::debug!(socket_addr=?sockaddr, "handshake completed, socket address assigned");
                return Ok(sockaddr);
            }
        }
    }

    #[instrument(name = "st-client", skip(self), fields(socket_addr= ?self.local_sockaddr))]
    async fn main_loop(mut self) {
        loop {
            let result = self.drive_once().await;
            if let Err(ref e) = result {
                tracing::error!(err=?e, "error driving tunnel");
            }
            if let Err(SnapTunNgSocketError::ReceiveQueueClosed) = result {
                tracing::info!("receive queue closed, snap tunnel driver shutting down");
                return;
            }
        }
    }

    async fn drive_once(&mut self) -> Result<(), SnapTunNgSocketError> {
        let mut buf = BytesMut::zeroed(UDP_DATAGRAM_BUFFER_SIZE);
        select! {
            _ = self.update_timers_interval.tick() => {
                let p = match self.tunn.lock().unwrap().update_timers() {
                    Ok(Some(wg)) => { Some(wg) },
                    Ok(None) => None,
                    Err(WireGuardError::ConnectionExpired) => {
                        return Err(SnapTunNgSocketError::InitialHandshakeTimeout);
                    }
                    Err(e) => {
                        tracing::error!(err=?e, "error updating timers on tunnel");
                        None
                    }
                };
                if let Some(wg) = p && let Err(e) = self.underlay_socket.send_to(to_bytes(wg).as_bytes(), self.dataplane_address).await {
                    return Err(SnapTunNgSocketError::IoError(e));
                }
            },
            recv = self.underlay_socket.recv_from(&mut buf) => {
                let (n, sender_addr) = match recv {
                    Ok((n, sender_addr)) => (n, sender_addr),
                    Err(e) => {
                        return Err(SnapTunNgSocketError::IoError(e));
                    }
                };
                if sender_addr != self.dataplane_address {
                    // Ignore packets that are not from the dataplane address.
                    return Ok(());
                }
                buf.truncate(n);
                let packet: Packet<[u8]> = Packet::from_bytes(buf);
                let wg = packet.try_into_wg().expect("this needs to be handled");
                // Process the packet and release the lock before accessing it again
                let result = self.tunn.lock().unwrap().handle_incoming_packet(wg);
                let ps = match result {
                    TunnResult::Done => None,
                    TunnResult::Err(e) => {
                        return Err(SnapTunNgSocketError::WireguardError(e));
                    }
                    TunnResult::WriteToNetwork(p) => {
                        // Send all queued packets to the network.
                        let queued_packets = self.tunn.lock().unwrap().get_queued_packets().collect::<Vec<_>>();
                        let packets = std::iter::once(p).chain(queued_packets.into_iter());
                        Some(packets)

                    }
                    TunnResult::WriteToTunnel(mut p) => {
                        let buf = p.buf_mut().to_owned();

                        // Ignore empty packets, they are keepalive packets.
                        if !buf.is_empty() {
                            match self.packet_sender.try_send(buf) {
                                Ok(()) => {},
                                Err(TrySendError::Full(_)) => {
                                    tracing::error!("receive channel is full, dropping packet");
                                }
                                Err(_) => {
                                    // The channel is closed. Stop the task.
                                    return Err(SnapTunNgSocketError::ReceiveQueueClosed);
                                }
                            }
                        }
                        None
                    }
                };
                if let Some(packets) = ps {
                    for p in packets {
                        if let Err(e) = self.underlay_socket.send_to(to_bytes(p).as_bytes(), self.dataplane_address).await {
                            return Err(SnapTunNgSocketError::IoError(e));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// A SNAP tun ng socket.
pub struct SnapTunNgSocket {
    tunn: Arc<Mutex<Tunn>>,
    underlay_socket: Arc<tokio::net::UdpSocket>,
    dataplane_address: SocketAddr,
    local_sockaddr: SocketAddr,
    receive_queue: tokio::sync::Mutex<mpsc::Receiver<BytesMut>>,
    /// Tasks that drives the SNAP tunnel.
    /// Cancelled when the socket is dropped.
    driver_task: JoinHandle<()>,
}

impl Drop for SnapTunNgSocket {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

impl SnapTunNgSocket {
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
    pub async fn new(
        static_private: x25519::StaticSecret,
        peer_public: x25519::PublicKey,
        underlay_socket: Arc<tokio::net::UdpSocket>,
        dataplane_address: SocketAddr,
        receive_queue_capacity: usize,
    ) -> Result<Self, SnapTunNgSocketError> {
        let local_public = x25519::PublicKey::from(&static_private);
        let tunn = Arc::new(Mutex::new(Tunn::new(
            static_private,
            peer_public,
            None,
            None,
            0,
            Arc::new(RateLimiter::new(&local_public, HANDSHAKE_RATE_LIMIT)),
            dataplane_address,
        )));
        let (packet_sender, packet_receiver) = mpsc::channel(receive_queue_capacity);
        let mut driver = SnapTunNgClientDriver::new(
            tunn.clone(),
            underlay_socket.clone(),
            dataplane_address,
            packet_sender,
        );
        let socket_addr = driver.initial_connection().await?;
        Ok(Self {
            tunn,
            underlay_socket,
            dataplane_address,
            local_sockaddr: socket_addr,
            // TODO(uniquefine): This should be refactored to use a more efficient receive queue.
            // https://github.com/Anapaya/scion/issues/27487
            receive_queue: tokio::sync::Mutex::new(packet_receiver),
            driver_task: tokio::spawn(driver.main_loop()),
        })
    }

    /// Send a packet to the remote server.
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= payload.len()))]
    pub async fn send(&self, payload: BytesMut) -> io::Result<()> {
        let packet: Packet<[u8]> = Packet::from_bytes(payload);
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
    #[instrument(name = "st-client", skip_all, fields(socket_addr= ?self.local_sockaddr, payload_len= payload.len()))]
    pub fn try_send(&self, payload: BytesMut) -> io::Result<()> {
        let packet: Packet<[u8]> = Packet::from_bytes(payload);
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
    pub async fn recv(&self) -> Result<Bytes, SnapTunNgSocketError> {
        match self.receive_queue.lock().await.recv().await {
            Some(packet) => Ok(packet.into()),
            None => Err(SnapTunNgSocketError::ReceiveQueueClosed),
        }
    }

    /// Poll for a packet from the remote server.
    pub fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Bytes, SnapTunNgSocketError>> {
        let mut receiver = ready!(pin::pin!(self.receive_queue.lock()).poll(cx));
        match receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(packet)) => std::task::Poll::Ready(Ok(packet.into())),
            std::task::Poll::Ready(None) => {
                tracing::trace!("receive queue closed, returning error");
                std::task::Poll::Ready(Err(SnapTunNgSocketError::ReceiveQueueClosed))
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
