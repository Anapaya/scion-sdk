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

use std::{pin::Pin, sync::Arc, time::Duration};

use ring::{
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use scion_proto::address::{IsdAsn, SocketAddr};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    buf_factory::{BufFactory, PooledBuf},
    socket::{BoxedSocketError, GenericScionUdpSocket},
};

/// A QUIC connection over SCION.
#[derive(Clone)]
pub struct QuicConnection {
    /// The underlying squiche connection.
    pub conn: Arc<Mutex<squiche::Connection>>,
    /// Waker for connection events.
    pub tx_notifier: Arc<tokio::sync::Notify>,
}

/// QUIC connection error.
#[derive(Debug, Error)]
pub enum QuicConnectionError {
    /// Connection ID generation error.
    #[error("Failed to generate connection ID: {0}")]
    ConnectionIdError(Unspecified),
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
        socket: Arc<dyn GenericScionUdpSocket>,
        mut quiche_config: squiche::Config,
    ) -> Result<Self, QuicConnectionError> {
        let scid = generate_connection_id().map_err(QuicConnectionError::ConnectionIdError)?;

        let local_addr = socket
            .local_addr()
            .local_address()
            .ok_or(QuicConnectionError::InvalidSocketLocalAddress)?;
        let remote_addr = remote
            .local_address()
            .ok_or(QuicConnectionError::InvalidRemoteAddress)?;

        let quic_tx_notifier = Arc::new(tokio::sync::Notify::new());

        let conn = squiche::connect(
            server_name.as_deref(),
            &scid,
            local_addr,
            remote_addr,
            &mut quiche_config,
        )?;

        let conn = Arc::new(tokio::sync::Mutex::new(conn));

        let driver = QuicConnectionDriver::new(
            conn.clone(),
            socket.clone(),
            remote.isd_asn(),
            quic_tx_notifier.clone(),
        )
        .await;
        tokio::spawn(driver.run());

        while !conn.lock().await.is_established() {
            tokio::task::yield_now().await;
        }

        tracing::debug!(?remote, "QUIC connection established");

        Ok(Self {
            conn,
            tx_notifier: quic_tx_notifier,
        })
    }

    /// Sends data on a stream.
    pub async fn stream_send(
        &self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), squiche::Error> {
        let mut conn = self.conn.lock().await;
        conn.stream_send(stream_id, data, fin)?;

        // Notify the QuicConnectionDriver that there is data to send. Otherwise this can lead to a
        // delay until the QUIC connection timer fires.
        self.tx_notifier.notify_one();
        Ok(())
    }

    /// Receives data from a stream.
    pub async fn stream_recv(
        &self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), squiche::Error> {
        loop {
            let mut conn = self.conn.lock().await;

            match conn.stream_recv(stream_id, buf) {
                Ok(v) => return Ok(v),
                Err(squiche::Error::Done) => {}
                Err(e) => return Err(e),
            };
        }
    }

    /// Returns a list of streams that have data to be read.
    pub async fn readable_streams(&self) -> Vec<u64> {
        let conn = self.conn.lock().await;
        conn.readable().collect()
    }

    /// Waits until the connection is established.
    pub async fn wait_established(&self) {
        while !self.conn.lock().await.is_established() {
            tokio::task::yield_now().await;
        }
    }
}

/// Driver for a QUIC connection. Dispatches packets between the [GenericScionUdpSocket] and the
/// [squiche::Connection].
pub struct QuicConnectionDriver {
    conn: Arc<tokio::sync::Mutex<squiche::Connection>>,
    socket: Arc<dyn GenericScionUdpSocket>,
    remote_isd_as: IsdAsn,
    /// Notifier to hint that there are new packets to send on the socket.
    quic_tx_notifier: Arc<tokio::sync::Notify>,
    /// Buffer pool for incoming packets.
    incoming_buf: PooledBuf,
}

impl QuicConnectionDriver {
    /// Creates a new QUIC connection driver.
    pub async fn new(
        conn: Arc<Mutex<squiche::Connection>>,
        socket: Arc<dyn GenericScionUdpSocket>,
        remote_isd_as: IsdAsn,
        quic_tx_notifier: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            conn,
            socket,
            remote_isd_as,
            quic_tx_notifier,
            incoming_buf: BufFactory::get_max_buf(),
        }
    }

    /// Runs the QUIC connection driver event loop.
    pub async fn run(mut self) {
        tracing::debug!("QUIC connection driver started");

        let mut send_buffer = [0; DEFAULT_MAX_UDP_PAYLOAD_SIZE];

        // Bookkeeping variables for the next packet to send.
        let mut send_size;
        let mut target_address;
        // Option to store the pending send future. This ensures cancel safety in the select! loop.
        //
        // XXX(bunert): Once the UdpScionSocket::send_to is cancel safe, remove this and have the
        // send future directly in the select! branch.
        #[allow(clippy::type_complexity)]
        let mut pending_send: Option<
            Pin<Box<dyn Future<Output = Result<(), BoxedSocketError>> + Send>>,
        > = None;

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

            // Prepare the send future if there is data to send and no pending send.
            if pending_send.is_none() && send_size > 0 {
                let dst = SocketAddr::from_std(self.remote_isd_as, target_address);
                let socket = self.socket.clone();
                pending_send = Some(Box::pin(async move {
                    socket.send_to(&send_buffer[..send_size], dst).await
                }));
            }

            tokio::select! {
                biased;

                // Handle QUIC Timers.
                _ = tokio::time::sleep(timeout) => {
                    tracing::trace!("QUIC timeout elapsed");
                    let mut conn = self.conn.lock().await;
                    conn.on_timeout();
                }

                _ = self.quic_tx_notifier.notified() => {}

                // Receive packets on the socket.
                res = self.socket.recv_from(&mut self.incoming_buf) => {
                    let (len, src) = match res {
                        Ok(res) => res,
                        Err(err) => {
                            tracing::warn!(?err, "Error receiving packet");
                            return
                        }
                    };

                    let mut body = std::mem::replace(
                        &mut self.incoming_buf,
                        BufFactory::get_max_buf(),
                    );
                    body.truncate(len);

                    if let (Some(from), Some(to)) = (src.local_address(), self.socket.local_addr().local_address()) {
                        let recv_info = squiche::RecvInfo { from, to };
                        let mut conn = self.conn.lock().await;
                        if let Err(err) = conn.recv(&mut body, recv_info) {
                            tracing::warn!(
                                ?err,
                                "failed to dispatch packet from transport to QUIC connection"
                            );
                            return
                        }
                    } else {
                        tracing::warn!(?src, "packet with invalid addresses ignored");
                    }
                }

                // Send packets on the socket.
                res = async {
                    if let Some(fut) = pending_send.as_mut() {
                        fut.await
                    } else {
                        std::future::pending().await
                    }
                }, if pending_send.is_some() => {
                    pending_send = None;
                    match res {
                        Ok(()) => send_size = 0,
                        Err(err) => tracing::warn!(?err, "Failed to send on the underlying socket"),
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
                    tracing::debug!(stats=?conn.stats(),"Connection closed, shutting down driver");
                    break;
                }
            }
        }

        tracing::debug!("QUIC connection driver shutting down");
    }
}

/// Generate a random QUIC connection ID.
fn generate_connection_id() -> Result<squiche::ConnectionId<'static>, Unspecified> {
    let mut scid = [0; squiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid)?;
    Ok(squiche::ConnectionId::from_vec(scid.to_vec()))
}
