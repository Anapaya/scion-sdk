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

//! QUIC server module to handle incoming connections.

use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};

use ring::rand::SystemRandom;
use scion_proto::address::SocketAddr;
use squiche::ConnectionId;
use thiserror::Error;
use tokio::sync::{Mutex, Notify, mpsc};

use crate::{
    DEFAULT_MAX_UDP_PAYLOAD_SIZE, UDP_PACKET_BUFFER_SIZE,
    buf_factory::{BufFactory, PooledBuf},
    quic::addr_validation_token::{AddrValidationTokenManager, TokenError},
    socket::{BoxedSocketError, GenericScionUdpSocket},
};

/// Server error.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Socket error.
    #[error("Socket error")]
    SocketError,
    /// Connection error.
    #[error("Connection error: {0}")]
    ConnectionError(#[from] squiche::Error),
    /// Internal error.
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// A QUIC server that listens on a SCION socket.
pub struct QuicServer {
    /// Channel to receive new connections from the connection acceptor.
    new_connections: mpsc::Receiver<QuicServerConnection>,
}

impl QuicServer {
    /// Creates a new QUIC server.
    pub fn new(
        socket: Arc<dyn GenericScionUdpSocket>,
        config: squiche::Config,
    ) -> Result<Self, ServerError> {
        // XXX(bunert): Would be nice to get rid of this channel. The connection manager dispatches
        // packages from the underlying socket to existing QUIC connections. The channels basically
        // enables the accept API for the caller to retrieve a newly established connection.
        let (new_connections_tx, new_connections_rx) = mpsc::channel(100);
        let connections = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the socket listener task
        let connection_acceptor = ConnectionManager {
            token_manager: AddrValidationTokenManager::default(),
            socket: socket.clone(),
            config,
            new_connections_tx,
            connection_map: connections,
            incoming_buf: BufFactory::get_max_buf(),
            rng: SystemRandom::new(),
        };
        tokio::spawn(connection_acceptor.run());

        Ok(Self {
            new_connections: new_connections_rx,
        })
    }

    /// Accepts the next incoming connection.
    pub async fn accept(&mut self) -> Option<QuicServerConnection> {
        self.new_connections.recv().await
    }
}

type ConnectionMap = HashMap<ConnectionId<'static>, Arc<Mutex<squiche::Connection>>>;

/// Active component that listens for incoming packets on the socket, demultiplexes them to the
/// correct connection based on the DCID, and creates new connections for incoming Initial packets
/// that do not match an existing connection.
struct ConnectionManager {
    token_manager: AddrValidationTokenManager,
    socket: Arc<dyn GenericScionUdpSocket>,
    config: squiche::Config,
    new_connections_tx: mpsc::Sender<QuicServerConnection>,
    connection_map: Arc<Mutex<ConnectionMap>>,
    incoming_buf: PooledBuf,
    rng: SystemRandom,
}

#[derive(Debug, Error)]
enum PacketProcessError {
    #[error("failed to parse local/remote address")]
    InvalidAddress,
    #[error("expected initial packet: {0:?}")]
    ExpectedInitialPacket(ConnectionId<'static>),
    #[error("missing token in initial packet")]
    MissingToken,
    #[error("invalid address validation token: {0}")]
    InvalidToken(#[from] TokenError),
    #[error("invalid destination connection ID")]
    InvalidDestinationConnectionId,

    // squiche errors
    #[error("invalid header: {0}")]
    InvalidHeader(squiche::Error),
    #[error("failed to negotiate version: {0}")]
    VersionNegotiationError(squiche::Error),
    #[error("failed to accept connection: {0}")]
    AcceptError(squiche::Error),
}

impl ConnectionManager {
    async fn run(mut self) {
        let mut send_buffer = vec![0u8; UDP_PACKET_BUFFER_SIZE];

        tracing::debug!("QUIC connection acceptor started");

        loop {
            let (len, from) = match self.socket.recv_from(&mut self.incoming_buf).await {
                Ok(res) => res,
                Err(err) => {
                    tracing::warn!(?err, "Server failed to receive on the underlying socket");
                    continue;
                }
            };
            tracing::debug!(
                ?from,
                ?len,
                "Server received packet on the underlying socket"
            );
            let mut body = std::mem::replace(&mut self.incoming_buf, BufFactory::get_max_buf());
            body.truncate(len);

            let out_len = match self.process_pkt(&mut body, from, &mut send_buffer).await {
                Ok(len) => len,
                Err(err) => {
                    tracing::warn!(?err, "Failed to process incoming packet");
                    continue;
                }
            };

            // Send version negotiation or retry packet if needed.
            if out_len > 0
                && let Err(err) = self.socket.send_to(&send_buffer[..out_len], from).await
            {
                tracing::warn!(
                    ?err,
                    "Failed to send response packet on the underlying socket"
                );
            }
        }
    }

    async fn process_pkt(
        &mut self,
        pkt: &mut [u8],
        from: SocketAddr,
        out: &mut [u8],
    ) -> Result<usize, PacketProcessError> {
        // Parse QUIC header
        let hdr = squiche::Header::from_slice(pkt, squiche::MAX_CONN_ID_LEN)
            .map_err(PacketProcessError::InvalidHeader)?;

        tracing::debug!(?hdr.scid, ?hdr.dcid, ?from, "Received QUIC packet");

        let (remote_addr, local_addr) = match (
            from.local_address(),
            self.socket.local_addr().local_address(),
        ) {
            (Some(from), Some(to)) => (from, to),
            _ => return Err(PacketProcessError::InvalidAddress),
        };

        let recv_info = squiche::RecvInfo {
            from: remote_addr,
            to: local_addr,
        };

        // Dispatch packet to existing connection.
        if let Some(conn) = self.connection_map.lock().await.get(&hdr.dcid) {
            let mut conn = conn.lock().await;
            if let Err(err) = conn.recv(pkt, recv_info) {
                tracing::debug!(?err, "Connection recv error");
            }

            return Ok(0);
        }

        // Handle initial packet and create new connection if valid.

        // Ignore non-initial packets
        if hdr.ty != squiche::Type::Initial {
            return Err(PacketProcessError::ExpectedInitialPacket(hdr.dcid));
        }

        // Check version support
        if !squiche::version_is_supported(hdr.version) {
            let len = squiche::negotiate_version(&hdr.scid, &hdr.dcid, out)
                .map_err(PacketProcessError::VersionNegotiationError)?;

            return Ok(len);
        }

        // Check token
        //
        // Generate new SCID for the server (this will be the new source CID)
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &self.rng).expect("no fail");
        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..squiche::MAX_CONN_ID_LEN];
        let scid: squiche::ConnectionId<'_> = conn_id.to_vec().into();

        let token = match hdr.token.as_ref() {
            Some(token) => token,
            None => {
                // The token is always set (even if it's empty) when the header of an
                // initial packet is parsed.
                return Err(PacketProcessError::MissingToken);
            }
        };

        // Do stateless retry if the client didn't send a token.
        if token.is_empty() {
            tracing::debug!("Doing stateless retry");
            let new_token = self.token_manager.generate(&hdr.dcid, remote_addr);

            let len =
                squiche::retry(&hdr.scid, &hdr.dcid, &scid, &new_token, hdr.version, out).unwrap();

            return Ok(len);
        }

        let odcid = self
            .token_manager
            .validate_and_extract_original_dcid(token, remote_addr)?;

        if scid.len() != hdr.dcid.len() {
            return Err(PacketProcessError::InvalidDestinationConnectionId);
        }

        // Reuse the source connection ID we sent in the Retry packet, instead of changing
        // it again.
        let scid = hdr.dcid.clone();

        // Generate new SCID for server (this will be our Source CID)
        // dcid refers to destination CID from the packet header.
        let mut conn = squiche::accept(
            &scid,
            Some(&odcid),
            local_addr,
            remote_addr,
            &mut self.config,
        )
        .map_err(PacketProcessError::AcceptError)?;

        tracing::debug!(?remote_addr, "Accepted new quic connection");

        // Dispatch the initial packet to the new connection so that the handshake can be
        // processed.

        if let Err(err) = conn.recv(pkt, recv_info) {
            tracing::debug!(?err, "Connection recv error");
        }

        let conn = Arc::new(Mutex::new(conn));

        // Add to connection map using the server SCID as key, so that incoming packets with
        // this SCID as DCID can be routed to this connection.
        {
            let mut conns = self.connection_map.lock().await;
            tracing::debug!(?scid, "Adding new connection to connection map");
            conns.insert(scid.clone(), conn.clone());
        }

        let quic_rx_notifier = Arc::new(Notify::new());
        let server_conn = QuicServerConnection {
            conn: conn.clone(),
            quic_rx_notifier: quic_rx_notifier.clone(),
        };

        // Start send driver
        let driver = SendDriver {
            conn: conn.clone(),
            socket: self.socket.clone(),
            send_notifier: quic_rx_notifier.clone(),
            remote_isd_as: from.isd_asn(),
            server_scid: scid,
            connections_map: self.connection_map.clone(),
        };
        tokio::spawn(driver.run());

        quic_rx_notifier.notify_one();

        if let Err(err) = self.new_connections_tx.send(server_conn).await {
            tracing::error!(?err, "Failed to send new connection to server listener");
        }

        Ok(0)
    }
}

/// A QUIC connection on the server side.
#[derive(Clone)]
pub struct QuicServerConnection {
    /// The underlying squiche connection.
    pub conn: Arc<Mutex<squiche::Connection>>,
    /// Notifier that gets notified if new packets arrived on the socket.
    pub quic_rx_notifier: Arc<Notify>,
}

impl QuicServerConnection {
    /// Sends data on a stream.
    pub async fn stream_send(
        &self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), squiche::Error> {
        let mut conn = self.conn.lock().await;
        conn.stream_send(stream_id, data, fin)?;

        self.quic_rx_notifier.notify_one();
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

// XXX(bunert): Would it be cleaner to have a single sender driver for the socket for all
// connections? Would need to manage all the connection timeouts and then remove them from the
// connection map.
struct SendDriver {
    conn: Arc<Mutex<squiche::Connection>>,
    socket: Arc<dyn GenericScionUdpSocket>,
    send_notifier: Arc<Notify>,
    remote_isd_as: scion_proto::address::IsdAsn,

    // For connection map cleanup once the send driver exits.
    server_scid: ConnectionId<'static>,
    connections_map: Arc<Mutex<ConnectionMap>>,
}

impl SendDriver {
    async fn run(self) {
        let mut send_buffer = vec![0u8; DEFAULT_MAX_UDP_PAYLOAD_SIZE];

        // Bookkeeping variables for the next packet to send.
        let mut send_size = 0;
        let mut target_address = "127.0.0.1:0".parse().unwrap();

        // Option to store the pending send future. This ensures cancel safety in the select! loop.
        //
        // XXX(bunert): Once the UdpScionSocket::send_to is cancel safe, remove this and have the
        // send future directly in the select! branch.
        #[allow(clippy::type_complexity)]
        let mut pending_send: Option<
            Pin<Box<dyn Future<Output = (Result<(), BoxedSocketError>, Vec<u8>)> + Send>>,
        > = None;

        loop {
            // Determine timeout
            let timeout = self
                .conn
                .lock()
                .await
                .timeout()
                .unwrap_or(Duration::from_secs(60));

            // Prepare the send future if there is data to send and no pending send.
            if pending_send.is_none() && send_size > 0 {
                let dst = SocketAddr::from_std(self.remote_isd_as, target_address);

                // We need to move the send buffer into the future, once the future completes,
                // return the original buffer so that it can be reused for the next send.
                //
                // We need to replace the send buffer with an empty one temporaryly. We know it's
                // not used before the future completes.
                let buffer = send_buffer;
                send_buffer = vec![];

                let socket = self.socket.clone();
                pending_send = Some(Box::pin(async move {
                    let res = socket.send_to(&buffer[..send_size], dst).await;
                    (res, buffer)
                }));
            }

            tokio::select! {
                biased;

                _ = tokio::time::sleep(timeout) => {
                     let mut conn = self.conn.lock().await;
                     conn.on_timeout();
                }

                // Indicator that new packets are ready to be sent on the underlying socket.
                _ = self.send_notifier.notified() => {}

                // Send packets on the socket.
                (res, buff) = async {
                    if let Some(fut) = pending_send.as_mut() {
                        fut.await
                    } else {
                        std::future::pending().await
                    }
                }, if pending_send.is_some() => {
                    pending_send = None;
                    send_buffer = buff; // Reuse the buffer for the next send.
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
                    Err(squiche::Error::Done) => {}
                    Err(err) => tracing::warn!(?err, "Error checking if there are packets to send"),
                }
            }

            {
                let conn = self.conn.lock().await;
                if conn.is_closed() {
                    break;
                }
            }
        }

        // Remove from map
        let mut conns = self.connections_map.lock().await;
        conns.remove(&self.server_scid);
    }
}
