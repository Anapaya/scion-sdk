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

//! The EdgeTun WireGuard client drives the data plane I/O loop for a single
//! EdgeTun tunnel over a SCION underlay socket.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ana_gotatun::{
    noise::{TunnResult, errors::WireGuardError},
    packet::{Packet, WgKind},
};
use bytes::{Bytes, BytesMut};
use scion_sdk_quic_scion::socket::{BoxedSocketError, GenericScionUdpSocket};
use sciparse::address::socket_addr::ScionSocketAddr;
use tokio::{select, task::JoinHandle, time::Interval};
use zerocopy::IntoBytes as _;

use super::{
    client_state::{EdgeTunClientConfig, EdgeTunClientState},
    common::EdgePacketBufPool,
};
use crate::fragmenting::metrics::{DefragmentMetrics, FragmentMetrics};

// Minimum interval between logging underlay send I/O errors.
//
// Mirrors quinn's `IO_ERROR_LOG_INTERVAL`: when the underlay is failing, every
// outgoing packet produces the same error, so we rate-limit the log to avoid
// flooding it with one line per dropped packet.
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

// A [`GenericScionUdpSocket`] wrapper that suppresses underlay send I/O
// errors.
//
// Following quinn's approach (see quinn-udp's `log_sendmsg_error`), a failed
// `send_to` is treated as a lost datagram rather than a fatal error.
//
// Errors are logged at most once per [`SEND_ERROR_LOG_INTERVAL`].
struct SendErrorTolerantSocket {
    inner: Arc<dyn GenericScionUdpSocket>,
    /// When the last send error was logged, or `None` if none has been logged
    /// yet. Used to throttle logging to [`SEND_ERROR_LOG_INTERVAL`].
    last_logged_error: Mutex<Option<Instant>>,
}

impl SendErrorTolerantSocket {
    fn new(inner: Arc<dyn GenericScionUdpSocket>) -> Self {
        Self {
            inner,
            last_logged_error: Mutex::new(None),
        }
    }

    /// Logs `err` at most once per [`SEND_ERROR_LOG_INTERVAL`].
    fn log_send_error_throttled(&self, err: &BoxedSocketError, destination: ScionSocketAddr) {
        let now = Instant::now();
        let mut last = self.last_logged_error.lock().expect("lock poisoned");
        let should_log =
            last.is_none_or(|t| now.saturating_duration_since(t) > SEND_ERROR_LOG_INTERVAL);
        if should_log {
            *last = Some(now);
            tracing::warn!(
                error = ?err,
                ?destination,
                "underlay send error; dropping packet (logged at most once per {}s)",
                SEND_ERROR_LOG_INTERVAL.as_secs(),
            );
        }
    }
}

#[async_trait::async_trait]
impl GenericScionUdpSocket for SendErrorTolerantSocket {
    async fn send_to(
        &self,
        payload: &[u8],
        destination: ScionSocketAddr,
    ) -> Result<(), BoxedSocketError> {
        if let Err(e) = self.inner.send_to(payload, destination).await {
            self.log_send_error_throttled(&e, destination);
        }
        // Always report success: a failed send is a dropped datagram, not a fatal
        // error. Reconnect, if needed, is driven by the WireGuard connection timer.
        Ok(())
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketAddr), BoxedSocketError> {
        self.inner.recv_from(buf).await
    }

    fn local_addr(&self) -> ScionSocketAddr {
        self.inner.local_addr()
    }
}

/// Error when driving the edge-tun WireGuard client.
#[derive(Debug, thiserror::Error)]
pub enum ClientDriverError {
    /// I/O error when sending packets on the underlay socket.
    #[error("send i/o error: {0}")]
    SendIoError(BoxedSocketError),
    /// I/O error when receiving packets on the underlay socket.
    #[error("receive i/o error: {0}")]
    ReceiveIoError(BoxedSocketError),
    /// Receive queue closed.
    #[error("receive queue closed")]
    ReceiveQueueClosed,
    /// Connection expired.
    #[error("connection expired")]
    ConnectionExpired,
    /// Error processing a WireGuard packet.
    #[error("wireguard error: {0:?}")]
    WireguardError(WireGuardError),
}

struct ClientDriver {
    state: Arc<Mutex<EdgeTunClientState<ScionSocketAddr>>>,
    socket: Arc<dyn GenericScionUdpSocket>,
    dataplane_address: ScionSocketAddr,
    update_timers_interval: Interval,
    packet_sender: async_channel::Sender<BytesMut>,
    pool: EdgePacketBufPool,
}

impl ClientDriver {
    fn new(
        state: Arc<Mutex<EdgeTunClientState<ScionSocketAddr>>>,
        socket: Arc<dyn GenericScionUdpSocket>,
        dataplane_address: ScionSocketAddr,
        packet_sender: async_channel::Sender<BytesMut>,
        pool: EdgePacketBufPool,
    ) -> Self {
        let update_timers_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(250),
            Duration::from_millis(250),
        );
        Self {
            state,
            socket,
            dataplane_address,
            update_timers_interval,
            packet_sender,
            pool,
        }
    }

    async fn main_loop(mut self) -> ClientDriverError {
        loop {
            match self.drive_once().await {
                Ok(()) => {}
                Err(e) => return e,
            }
        }
    }

    async fn drive_once(&mut self) -> Result<(), ClientDriverError> {
        let mut buf_packet = self.pool.get();
        let buf = buf_packet.buf_mut();
        buf.resize(buf.capacity(), 0);

        select! {
            biased;
            _ = self.update_timers_interval.tick() => {
                let wg = {
                    let mut state = self.state.lock().expect("lock poisoned");
                    match state.update_timers() {
                        Ok(Some(wg)) => Some(wg),
                        Ok(None) => None,
                        Err(WireGuardError::ConnectionExpired) => {
                            return Err(ClientDriverError::ConnectionExpired);
                        }
                        Err(e) => {
                            tracing::error!(err=?e, "unexpected error updating timers");
                            None
                        }
                    }
                };
                if let Some(wg) = wg {
                    self.send_wg_to_network(wg).await?;
                }
            },
            recv = self.socket.recv_from(buf) => {
                let (n, sender_addr) = recv.map_err(ClientDriverError::ReceiveIoError)?;
                buf_packet.buf_mut().truncate(n);
                let packet = buf_packet;

                if sender_addr != self.dataplane_address {
                    tracing::trace!(?sender_addr, expected=?self.dataplane_address, "dropping packet from unexpected source");
                    return Ok(());
                }
                let mut send_to_network = VecDeque::new();
                let result = {
                    let mut state = self.state.lock().expect("lock poisoned");
                    state.handle_incoming_packet(sender_addr, packet, &mut send_to_network)
                };
                // Send any queued outgoing frames.
                for wg_out in send_to_network {
                    self.send_wg_to_network(wg_out).await?;
                }
                match result {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        return Err(ClientDriverError::WireguardError(e));
                    }
                    TunnResult::WriteToTunnel(mut p) => {
                        let buf = p.buf_mut().split();
                        if !buf.is_empty() {
                            match self.packet_sender.try_send(buf) {
                                Ok(()) => {}
                                Err(async_channel::TrySendError::Full(_)) => {
                                    tracing::debug!("receive channel is full, dropping packet");
                                }
                                Err(_) => {
                                    return Err(ClientDriverError::ReceiveQueueClosed);
                                }
                            }
                        }
                    }
                    TunnResult::WriteToNetwork(_) => {
                        // Per EdgeTunClientState contract, handle_incoming_packet never
                        // returns WriteToNetwork. Outgoing frames are in send_to_network.
                        tracing::warn!("unexpected WriteToNetwork from handle_incoming_packet");
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_wg_to_network(&self, wg: WgKind) -> Result<(), ClientDriverError> {
        let bytes = wg_to_bytes(wg);
        self.socket
            .send_to(bytes.as_bytes(), self.dataplane_address)
            .await
            .map_err(ClientDriverError::SendIoError)
    }
}

/// Error when sending on the [`EdgeTunClient`].
#[derive(Debug, thiserror::Error)]
pub enum EdgeTunClientSendError {
    /// I/O error when sending packets on the underlay socket.
    #[error("send i/o error: {0}")]
    SendIoError(BoxedSocketError),
}

/// Error when receiving on the [`EdgeTunClient`].
#[derive(Debug, thiserror::Error)]
pub enum EdgeTunClientRecvError {
    /// The receive queue is closed (driver exited).
    #[error("receive queue closed")]
    ReceiveQueueClosed,
}

/// A WireGuard-based edge-tun data plane client.
///
/// The client handle communicates with a background driver task.
/// - **Send**: directly locks the shared `EdgeTunClientState` and sends frames on the SCION socket.
/// - **Recv**: reads decrypted IP packets from a channel fed by the driver.
///
/// Dropping the client aborts the driver task.
pub struct EdgeTunClient {
    state: Arc<Mutex<EdgeTunClientState<ScionSocketAddr>>>,
    socket: Arc<dyn GenericScionUdpSocket>,
    dataplane_address: ScionSocketAddr,
    receive_queue: async_channel::Receiver<BytesMut>,
    driver_task: JoinHandle<ClientDriverError>,
}

impl Drop for EdgeTunClient {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

impl EdgeTunClient {
    /// Create and start a new edge-tun WireGuard client.
    ///
    /// This spawns the background driver task immediately. The WireGuard
    /// handshake will be initiated asynchronously by timer-driven retransmits;
    /// `send` may be called before the handshake completes (packets are queued).
    pub fn new(
        config: EdgeTunClientConfig,
        socket: Arc<dyn GenericScionUdpSocket>,
        dataplane_address: ScionSocketAddr,
        receive_queue_capacity: usize,
        pool: EdgePacketBufPool,
        fragmenter_metrics: FragmentMetrics,
        defragmenter_metrics: DefragmentMetrics,
    ) -> Self {
        let state = Arc::new(Mutex::new(EdgeTunClientState::new(
            pool.clone(),
            config,
            fragmenter_metrics,
            defragmenter_metrics,
        )));
        // Wrap the underlay socket to log but not forward send errors. Send IO
        // errors on UDP sockets are transient. E.g. on Windows an interface
        // flapping results in an error AddrNotAvailable.
        let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(SendErrorTolerantSocket::new(socket));
        let (packet_sender, packet_receiver) = async_channel::bounded(receive_queue_capacity);
        let driver = ClientDriver::new(
            state.clone(),
            socket.clone(),
            dataplane_address,
            packet_sender,
            pool,
        );
        let driver_task = tokio::spawn(driver.main_loop());
        Self {
            state,
            socket,
            dataplane_address,
            receive_queue: packet_receiver,
            driver_task,
        }
    }

    /// Send an IP packet through the tunnel.
    ///
    /// The packet is fragmented and encrypted via the shared
    /// `EdgeTunClientState`, then each resulting WireGuard frame is sent on the
    /// SCION socket. If the handshake is not yet complete, the packet is queued in the shared state
    /// and flushed by the driver once the handshake completes.
    pub async fn send(&self, packet: Packet) -> Result<(), EdgeTunClientSendError> {
        let mut send_to_network = VecDeque::new();
        {
            let mut state = self.state.lock().expect("lock poisoned");
            state.handle_outgoing_packet(packet, &mut send_to_network);
        }
        for wg in send_to_network {
            let bytes = wg_to_bytes(wg);
            self.socket
                .send_to(bytes.as_bytes(), self.dataplane_address)
                .await
                .map_err(EdgeTunClientSendError::SendIoError)?
        }
        Ok(())
    }

    /// Receive the next decrypted and reassembled IP packet from the tunnel.
    pub async fn recv(&self) -> Result<Bytes, EdgeTunClientRecvError> {
        match self.receive_queue.recv().await {
            Ok(packet) => Ok(packet.into()),
            Err(_) => Err(EdgeTunClientRecvError::ReceiveQueueClosed),
        }
    }

    /// The data plane address the client is connected to.
    pub fn dataplane_address(&self) -> ScionSocketAddr {
        self.dataplane_address
    }
}

fn wg_to_bytes(wg: WgKind) -> Packet<[u8]> {
    match wg {
        WgKind::HandshakeInit(p) => p.into_bytes(),
        WgKind::HandshakeResp(p) => p.into_bytes(),
        WgKind::CookieReply(p) => p.into_bytes(),
        WgKind::Data(p) => p.into_bytes(),
    }
}
