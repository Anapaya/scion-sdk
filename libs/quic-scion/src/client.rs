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

//! QUIC client module for establishing connections over SCION transport.

use std::{sync::Arc, time::Duration};

use ring::{
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use scion_proto::address::{IsdAsn, SocketAddr};
use scion_stack::scionstack::UdpScionSocket;
use thiserror::Error;
use tokio::sync::Mutex;

// ============================================================================
// Configuration
// ============================================================================

/// Default handshake timeout.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default idle timeout for connections.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default max UDP payload size.
const DEFAULT_MAX_UDP_PAYLOAD_SIZE: usize = 1200;

/// UDP packet buffer size.
const UDP_PACKET_BUFFER_SIZE: usize = 65535;

/// QUIC client configuration.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Timeout for QUIC handshake completion.
    pub handshake_timeout: Duration,
    /// Idle timeout for connections.
    pub idle_timeout: Duration,
    /// Maximum UDP payload size.
    pub max_udp_payload_size: usize,
    /// Application protocols to advertise (ALPN).
    pub application_protos: Vec<Vec<u8>>,
    /// Whether to verify the server certificate.
    pub verify_peer: bool,
    /// Optional path to CA certificates file.
    pub ca_certs_path: Option<String>,
    /// Initial max data.
    pub initial_max_data: u64,
    /// Initial max stream data for bidirectional local streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial max stream data for bidirectional remote streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial max stream data for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Initial max bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// Initial max unidirectional streams.
    pub initial_max_streams_uni: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            application_protos: vec![b"h3".to_vec()],
            verify_peer: true,
            ca_certs_path: None,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
        }
    }
}

impl QuicConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> QuicConfigBuilder {
        QuicConfigBuilder::default()
    }

    /// Creates a squiche::Config from this configuration.
    pub fn to_quiche_config(&self) -> Result<squiche::Config, squiche::Error> {
        let mut config = squiche::Config::new(squiche::SCION_PROTOCOL_VERSION)?;

        config.set_application_protos(
            &self
                .application_protos
                .iter()
                .map(|p| p.as_slice())
                .collect::<Vec<_>>(),
        )?;

        config.set_max_idle_timeout(self.idle_timeout.as_millis() as u64);
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size);
        config.set_max_send_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_disable_active_migration(true);

        config.verify_peer(self.verify_peer);

        Ok(config)
    }
}

/// Builder for [`QuicConfig`].
#[derive(Debug, Default)]
pub struct QuicConfigBuilder {
    config: QuicConfig,
}

impl QuicConfigBuilder {
    /// Sets the handshake timeout.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout = timeout;
        self
    }

    /// Sets the idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Sets the maximum UDP payload size.
    pub fn max_udp_payload_size(mut self, size: usize) -> Self {
        self.config.max_udp_payload_size = size;
        self
    }

    /// Sets the application protocols (ALPN).
    pub fn application_protos(mut self, protos: Vec<Vec<u8>>) -> Self {
        self.config.application_protos = protos;
        self
    }

    /// Sets whether to verify the peer's certificate.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.verify_peer = verify;
        self
    }

    /// Sets the path to CA certificates file for verification.
    pub fn ca_certs_path(mut self, path: impl Into<String>) -> Self {
        self.config.ca_certs_path = Some(path.into());
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> QuicConfig {
        self.config
    }
}

/// A QUIC connection over SCION.
#[derive(Clone)]
pub struct QuicConnection {
    /// The underlying squiche connection.
    pub conn: Arc<Mutex<squiche::Connection>>,
    /// Waiter for connection events.
    pub waiter: Arc<tokio::sync::Notify>,
}

/// QUIC connection error.
#[derive(Debug, Error)]
pub enum QuicConnectionError {
    /// Connection ID generation error.
    #[error("Failed to generate connection ID: {0}")]
    ConnectionIdError(#[from] Unspecified),
    /// Invalid socket local address.
    #[error("Invalid socket local address")]
    InvalidSocketLocalAddress,
    /// Invalid remote address.
    #[error("Invalid remote address")]
    InvalidRemoteAddress,
    /// QUIC connection error.
    #[error("QUIC connection error: {0}")]
    ConnectError(#[from] squiche::Error),
}

impl QuicConnection {
    /// Creates a new QUIC connection over SCION.
    pub async fn new(
        server_name: Option<String>,
        remote: SocketAddr,
        socket: Arc<UdpScionSocket>,
        mut quiche_config: squiche::Config,
    ) -> Result<Self, QuicConnectionError> {
        let scid = generate_connection_id()?;

        let local_addr = socket
            .local_addr()
            .local_address()
            .ok_or(QuicConnectionError::InvalidSocketLocalAddress)?;
        let remote_addr = remote
            .local_address()
            .ok_or(QuicConnectionError::InvalidRemoteAddress)?;

        let notifier = Arc::new(tokio::sync::Notify::new());
        let waiter = notifier.clone();

        let conn = squiche::connect(
            server_name.as_deref(),
            &scid,
            local_addr,
            remote_addr,
            &mut quiche_config,
        )?;

        let conn = Arc::new(tokio::sync::Mutex::new(conn));

        let driver =
            QuicConnectionDriver::new(conn.clone(), socket.clone(), remote.isd_asn(), notifier)
                .await;
        tokio::spawn(driver.run());

        while !conn.lock().await.is_established() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        tracing::info!("QUIC connection established to {}", remote);

        Ok(Self { conn, waiter })
    }
}

/// Driver for a QUIC connection. Dispatches packets between the [UdpScionSocket] and the
/// [squiche::Connection].
pub struct QuicConnectionDriver {
    conn: Arc<tokio::sync::Mutex<squiche::Connection>>,
    socket: Arc<UdpScionSocket>,
    remote_isd_as: IsdAsn,
    notifier: Arc<tokio::sync::Notify>,
}

impl QuicConnectionDriver {
    /// Creates a new QUIC connection driver.
    pub async fn new(
        conn: Arc<Mutex<squiche::Connection>>,
        socket: Arc<UdpScionSocket>,
        remote_isd_as: IsdAsn,
        notifier: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            conn,
            socket,
            remote_isd_as,
            notifier,
        }
    }

    /// Runs the QUIC connection driver event loop.
    pub async fn run(self) {
        tracing::info!("QuicConnectionDriver started");

        let mut recv_buffer = [0; UDP_PACKET_BUFFER_SIZE];

        let mut send_buffer = [0; DEFAULT_MAX_UDP_PAYLOAD_SIZE];

        // Bookkeeping variables for the next packet to send.
        let mut send_size;
        let mut target_address;

        // Send initial packet
        {
            let mut conn = self.conn.lock().await;
            match conn.send(&mut send_buffer) {
                Ok((len, send_info)) => {
                    send_size = len;
                    target_address = send_info.to;
                }
                Err(err) => {
                    match err {
                        squiche::Error::Done => {
                            tracing::error!(
                                "expected the initial QUIC packet to send, but QUIC connection indicated there are no packets to send"
                            )
                        }
                        _ => tracing::error!(?err, "failed to send the initial QUIC packet"),
                    }
                    // Close connection if sending the initial packet failed.
                    if let Err(err) = conn.close(true, 0x00, b"Failed to generate Initial packet") {
                        tracing::warn!(?err, "Error closing connection");
                    }
                    return;
                }
            }
        }

        // Main loop
        loop {
            // Determine timeout based on QUIC state
            let timeout = self
                .conn
                .lock()
                .await
                .timeout()
                .unwrap_or(Duration::from_secs(60));

            // I/O future to send packets on the socket
            let send = async {
                let dst = SocketAddr::from_std(self.remote_isd_as, target_address);
                self.socket.send_to(&send_buffer[..send_size], dst).await
            };

            tokio::select! {
                biased;

                // Handle QUIC Timers.
                _ = tokio::time::sleep(timeout) => {
                    tracing::debug!("QUIC timeout elapsed");
                    let mut conn = self.conn.lock().await;
                    conn.on_timeout();
                }


                // Receive packets on the socket.
                res = self.socket.recv_from(&mut recv_buffer) => {
                    let (len, src) = match res {
                        Ok(res) => res,
                        Err(err) => {
                            tracing::warn!(?err, "Error receiving packet");
                            return
                        }
                    };

                    if let (Some(from), Some(to)) = (src.local_address(), self.socket.local_addr().local_address()) {
                        let recv_info = squiche::RecvInfo { from, to };
                        let mut conn = self.conn.lock().await;
                        if let Err(err) = conn.recv(&mut recv_buffer[..len], recv_info) {
                            tracing::warn!(
                                ?err,
                                "failed to dispatch packet from transport to QUIC connection"
                            );
                            return
                        }

                        // Notify waiter about potential new data on the QUIC connection.
                        self.notifier.notify_waiters();
                    } else {
                        tracing::warn!(?src, "packet with invalid addresses ignored");
                    }
                }

                // Send packets on the socket.
                res = send, if send_size >0 => {
                    match res {
                        Ok(()) => {
                            send_size = 0;
                        },
                        Err(err) => {
                            tracing::info!(?err, "Error sending packet");
                        }
                    }
                }
            }

            // Check if there is data to send if nothing is outstanding.
            if send_size == 0 {
                let mut conn = self.conn.lock().await;
                match conn.send(&mut send_buffer) {
                    Ok((len, send_info)) => {
                        send_size = len;
                        target_address = send_info.to;
                    }
                    Err(squiche::Error::Done) => {} // No more packets to send
                    Err(err) => tracing::info!(?err, "Error checking if there are packets to send"),
                }
            }

            // Exit driver if connection is closed.
            {
                let conn = self.conn.lock().await;
                if conn.is_closed() {
                    tracing::info!(stats=?conn.stats(),"Connection closed, shutting down driver");
                    break;
                }
            }
        }

        tracing::info!("QUIC connection driver shutting down");
    }
}

/// Generate a random QUIC connection ID.
fn generate_connection_id() -> Result<squiche::ConnectionId<'static>, Unspecified> {
    let mut scid = [0; squiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid)?;
    Ok(squiche::ConnectionId::from_vec(scid.to_vec()))
}
