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

use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};

use ana_gotatun::{
    noise::TunnResult,
    packet::{Packet, WgKind},
};
use bytes::BytesMut;
use snap_tun::server::{SnapTunAuthorization, SnapTunNgServer};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const UDP_BUFFER_SIZE: usize = 65535;

/// Server harness that drives the SnapTunNgServer state machine
/// Uses real UDP socket for client-server communication and channels for tunnel interface
pub struct ServerHarness<T: SnapTunAuthorization> {
    server: Arc<tokio::sync::Mutex<SnapTunNgServer<T>>>,
    /// Real UDP socket for client-server network communication
    network_socket: Arc<tokio::net::UdpSocket>,
    /// Channel to send decrypted packets FROM server TO test
    tunnel_from_server_tx: mpsc::UnboundedSender<(BytesMut, SocketAddr)>,
    /// Channel to receive decrypted packets FROM server (for test to read)
    tunnel_from_server_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(BytesMut, SocketAddr)>>>,
    /// Channel to receive packets FROM test TO server
    tunnel_to_server_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(BytesMut, SocketAddr)>>>,
    /// Channel to send packets TO server tunnel (for test to write)
    tunnel_to_server_tx: mpsc::UnboundedSender<(BytesMut, SocketAddr)>,
    /// Cancellation token for shutdown
    cancel_token: CancellationToken,
}

impl<T: SnapTunAuthorization + 'static> ServerHarness<T> {
    /// Create a new server harness (does not start the I/O loop)
    pub async fn new(server: SnapTunNgServer<T>, bind_addr: SocketAddr) -> std::io::Result<Self> {
        let network_socket = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
        // Channel for packets FROM server TO test (decrypted)
        // Unbounded channels are acceptable in test infrastructure for simplicity
        #[allow(clippy::disallowed_methods)]
        let (from_server_tx, from_server_rx) = mpsc::unbounded_channel();
        // Channel for packets FROM test TO server (to be encrypted and sent)
        #[allow(clippy::disallowed_methods)]
        let (to_server_tx, to_server_rx) = mpsc::unbounded_channel();

        Ok(Self {
            server: Arc::new(tokio::sync::Mutex::new(server)),
            network_socket,
            tunnel_from_server_tx: from_server_tx,
            tunnel_from_server_rx: Arc::new(tokio::sync::Mutex::new(from_server_rx)),
            tunnel_to_server_rx: Arc::new(tokio::sync::Mutex::new(to_server_rx)),
            tunnel_to_server_tx: to_server_tx,
            cancel_token: CancellationToken::new(),
        })
    }

    /// Run the server I/O loop until cancelled
    pub async fn run(&self) {
        let mut send_queue = VecDeque::<WgKind>::new();
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut to_server_rx = self.tunnel_to_server_rx.lock().await;

        loop {
            let mut buf = BytesMut::zeroed(UDP_BUFFER_SIZE);

            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    tracing::debug!("Server harness shutting down");
                    break;
                }

                // Handle incoming network packets
                result = self.network_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            buf.truncate(n);
                            let packet = Packet::from_bytes(buf);

                            let mut server = self.server.lock().await;
                            let result = server.handle_incoming_packet(packet, from, &mut send_queue);

                            // If packet should go to tunnel, send it to the test
                            if let TunnResult::WriteToTunnel(mut p) = result {
                                let buf = p.buf_mut().to_owned();
                                if !buf.is_empty() {
                                    // Send decrypted packet to test
                                    let _ = self.tunnel_from_server_tx.send((buf, from));
                                }
                            }

                            // Send all queued packets back to the sender
                            use zerocopy::IntoBytes as _;
                            while let Some(wg_packet) = send_queue.pop_front() {
                                let bytes = match wg_packet {
                                    WgKind::HandshakeInit(p) => p.into_bytes(),
                                    WgKind::HandshakeResp(p) => p.into_bytes(),
                                    WgKind::CookieReply(p) => p.into_bytes(),
                                    WgKind::Data(p) => p.into_bytes(),
                                };
                                let _ = self.network_socket.send_to(bytes.as_bytes(), from).await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving from network socket: {}", e);
                        }
                    }
                }

                // Handle outgoing tunnel packets (from test to server)
                Some((packet, target_addr)) = to_server_rx.recv() => {
                    use zerocopy::IntoBytes as _;
                    let packet = Packet::from_bytes(packet);
                    let mut server = self.server.lock().await;

                    if let Some(wg_packet) = server.handle_outgoing_packet(packet, target_addr) {
                        let bytes = match wg_packet {
                            WgKind::HandshakeInit(p) => p.into_bytes(),
                            WgKind::HandshakeResp(p) => p.into_bytes(),
                            WgKind::CookieReply(p) => p.into_bytes(),
                            WgKind::Data(p) => p.into_bytes(),
                        };
                        let _ = self.network_socket.send_to(bytes.as_bytes(), target_addr).await;
                    }
                }

                // Timer tick for keepalive/handshake
                _ = timer.tick() => {
                    use zerocopy::IntoBytes as _;
                    let mut server = self.server.lock().await;
                    let packets = server.update_timers();
                    for (target_addr, wg_packet) in packets {
                        let bytes = match wg_packet {
                            WgKind::HandshakeInit(p) => p.into_bytes(),
                            WgKind::HandshakeResp(p) => p.into_bytes(),
                            WgKind::CookieReply(p) => p.into_bytes(),
                            WgKind::Data(p) => p.into_bytes(),
                        };
                        let _ = self.network_socket.send_to(bytes.as_bytes(), target_addr).await;
                    }
                }
            }
        }
    }

    /// Get cancellation token for shutdown
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Get the network socket address (for client to connect to)
    pub fn socket_addr(&self) -> SocketAddr {
        self.network_socket.local_addr().unwrap()
    }

    /// Send a packet to the tunnel (packets to send through server)
    pub fn send_to_tunnel(&self, packet: BytesMut, target_addr: SocketAddr) {
        let _ = self.tunnel_to_server_tx.send((packet, target_addr));
    }

    /// Receive a decrypted packet from the tunnel with timeout
    pub async fn recv_from_tunnel(&self, timeout: Duration) -> Option<(BytesMut, SocketAddr)> {
        tokio::time::timeout(timeout, async {
            self.tunnel_from_server_rx.lock().await.recv().await
        })
        .await
        .ok()
        .flatten()
    }
}
