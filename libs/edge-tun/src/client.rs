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

use std::{
    borrow::Cow,
    collections::VecDeque,
    convert::TryInto,
    net::IpAddr,
    ops::Deref,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use anapaya_quinn::{ConnectionStats, RecvStream, SendStream};
use bytes::Bytes;
use ipnet::IpNet;
use prost::Message;
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use thiserror::Error;

use crate::{
    fragmenting::{
        Defragmenter, Fragmenter, FragmenterSendError,
        metrics::{DefragmentMetrics, FragmentMetrics},
    },
    ip::IpPacketValidator,
    requests::{
        AddressAssignResponse, IpAddrError, RouteAdvertisementResponse, SessionRenewalResponse,
        system_time_from_unix_epoch_secs,
    },
    server::PATH_SESSION_RENEWAL,
};

/// All control requests issued by the client MUST NOT exceed
/// `CTRL_REQUEST_BUF_SIZE` bytes.
pub const CTRL_RESPONSE_BUF_SIZE: usize = 4096;
/// Default number of reassembly queues used by the defragmenter.
pub const DEFAULT_DEFRAG_QUEUE_COUNT: usize = 8;

/// Builder for a QUIC-based edge-tun client connection.
#[derive(Default, Debug)]
pub struct ClientBuilder {
    mtu: u16,
    auth_token: String,
    metrics_registry: Option<MetricsRegistry>,
    defrag_queues: Option<usize>,
}

impl ClientBuilder {
    /// Set the initial MTU for this tunnel. Packets that are larger than this
    /// MTU will be segmented.
    pub fn with_initial_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the number of reassembly queues used by the defragmenter.
    pub fn with_defragmenting_queues(mut self, count: usize) -> Self {
        self.defrag_queues = Some(count);
        self
    }

    /// Set the authentication token to be used to authenticate requests.
    pub fn with_initial_auth_token<S: AsRef<str>>(mut self, auth_token: S) -> Self {
        self.auth_token = auth_token.as_ref().into();
        self
    }

    /// Set the metrics registry to be used for this client.
    pub fn with_metrics_registry(mut self, metrics: MetricsRegistry) -> Self {
        self.metrics_registry = Some(metrics);
        self
    }

    /// Establish an edgetun tunnel using the `conn` QUIC-connection.
    pub async fn connect(
        self,
        conn: anapaya_quinn::Connection,
    ) -> Result<(Incoming, Outgoing, Control), EdgeTunError> {
        // xxx: this should be parallelized at some point

        // Local metrics for the defragmenter that are not exposed outside of this module.
        let conn_state = SharedConnState::new(ConnState::default());
        let mut ctrl = Control {
            conn: conn.clone(),
            state: conn_state.clone(),
        };

        ctrl.renew_session(&self.auth_token).await?;
        ctrl.request_address(&self.auth_token).await?;
        ctrl.request_routes(&self.auth_token).await?;

        let metrics_registry = self.metrics_registry.unwrap_or_default();
        let defrag_queues = self.defrag_queues.unwrap_or(DEFAULT_DEFRAG_QUEUE_COUNT);

        Ok((
            Incoming {
                conn: conn.clone(),
                conn_state: conn_state.clone(),
                defrag: Defragmenter::new(defrag_queues, DefragmentMetrics::new(&metrics_registry)),
            },
            Outgoing::new(
                conn.clone(),
                self.mtu,
                conn_state.clone(),
                FragmentMetrics::new(&metrics_registry),
            ),
            ctrl,
        ))
    }
}

/// Control can be used to send control messages to the server
#[derive(Clone)]
pub struct Control {
    conn: anapaya_quinn::Connection,
    state: SharedConnState,
}

impl Control {
    /// Return the IP addresses currently assigned to this connection.
    pub fn assigned_addresses(&self) -> Vec<IpAddr> {
        self.state
            .read()
            .expect("no fail")
            .assigned_addresses
            .clone()
    }

    /// Return the IP routes currently advertised by the server for this connection.
    pub fn advertised_routes(&self) -> Vec<IpNet> {
        self.state
            .read()
            .expect("no fail")
            .advertised_routes
            .clone()
    }

    /// Return the session expiry time for this connection.
    pub fn session_expiry(&self) -> SystemTime {
        self.state.read().expect("no fail").session_expiry
    }

    /// Return QUIC connection statistics.
    pub fn stats(&self) -> ConnectionStats {
        self.conn.stats()
    }

    /// Sends an address assign request to the edgetun server.
    ///
    /// In addition, this also extends the session validity based on the token validity.
    ///
    /// # Arguments
    /// * `token` - The authentication token to use for the request.
    async fn request_address(&mut self, token: &str) -> Result<(), EdgeTunError> {
        tracing::debug!("Requesting address assignment");

        let (mut snd, mut rcv) = self.conn.open_bi().await?;

        write_http_header(&mut snd, crate::server::PATH_ADDR_ASSIGNMENT, token, true).await?;

        let mut resp_buf = [0u8; CTRL_RESPONSE_BUF_SIZE];
        let response = recv_response::<AddressAssignResponse>(&mut resp_buf[..], &mut rcv).await?;

        if response.assigned_addresses.is_empty() {
            return Err(EdgeTunError::AddressAssignmentFailed(
                AddrAssignError::NoAddressAssigned,
            ));
        }

        self.state.write().expect("no fail").assigned_addresses = response
            .assigned_addresses
            .iter()
            .map(|address_range| {
                TryInto::<IpAddr>::try_into(address_range).map_err(|e| {
                    EdgeTunError::AddressAssignmentFailed(AddrAssignError::InvalidAddr(e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    /// Sends a route request to the edgetun server.
    ///
    /// In addition, this also extends the session validity based on the token validity.
    ///
    /// # Arguments
    /// * `token` - The authentication token to use for the request.
    async fn request_routes(&mut self, token: &str) -> Result<(), EdgeTunError> {
        let (mut snd, mut rcv) = self.conn.open_bi().await?;
        write_http_header(&mut snd, crate::server::PATH_ROUTES_REQUEST, token, true).await?;
        let mut resp_buf = [0u8; CTRL_RESPONSE_BUF_SIZE];
        let response: RouteAdvertisementResponse =
            recv_response(&mut resp_buf[..], &mut rcv).await?;

        if response.routes.is_empty() {
            return Err(EdgeTunError::RouteRequestFailed(
                RoutesError::NoRoutesAdvertised,
            ));
        }

        self.state.write().expect("no fail").advertised_routes = response
            .routes
            .into_iter()
            .map(|address_range| {
                TryInto::<IpNet>::try_into(&address_range)
                    .map_err(|e| EdgeTunError::RouteRequestFailed(RoutesError::InvalidAddr(e)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    /// Sends a session renewal request to the edgetun server.
    ///
    /// # Arguments
    /// * `token` - The authentication token to use for the request.
    pub async fn renew_session(&mut self, token: &str) -> Result<(), EdgeTunError> {
        let (mut snd, mut rcv) = self.conn.open_bi().await?;

        write_http_header(&mut snd, PATH_SESSION_RENEWAL, token, true).await?;
        let mut resp_buf = [0u8; CTRL_RESPONSE_BUF_SIZE];
        let response: SessionRenewalResponse = recv_response(&mut resp_buf[..], &mut rcv).await?;
        self.state.write().expect("no fail").session_expiry =
            system_time_from_unix_epoch_secs(response.valid_until);
        Ok(())
    }
}

/// Receive incoming packets from the tunnel.
///
/// # Error conditions
///
/// From the client's perspective the control state of the connection remains
/// unchanged for the duration of the connection. Further, some errors, that are
/// recoverable per QUIC-spec (e.g. enabling/disabling datagram support), are
/// treated as non-recoverable, connection-aborting errors. To prevent
/// [Incoming::receive] and [Outgoing::send_wait] from returning different
/// errors under exceptional circumstances, connection errors are returned
/// _only_ from the [Incoming::receive]-call, and never from
/// [Outgoing::send_wait]-call.
pub struct Incoming {
    conn: anapaya_quinn::Connection,
    conn_state: SharedConnState,
    defrag: Defragmenter,
}

impl Incoming {
    /// Tries to receive a packet
    ///
    /// Returns an error if the connection is broken and should be shut down
    #[tracing::instrument(skip_all, fields(conn_id = self.conn.stable_id()))]
    pub async fn receive(&mut self) -> Result<Bytes, ConnError> {
        // immediately fail if we have deferred error in the sate
        self.conn_state.check_error_state()?;

        loop {
            // read bytes from network
            let p = match self.conn.read_datagram().await {
                Ok(p) => p,
                Err(e) => return Err(self.conn_state.get_or_set_error_state(e.into())),
            };

            // reassemble bytes
            match self.defrag.recv(&p) {
                // reconstructed packet
                Ok(Some(packet)) => {
                    // check that it is a valid ip packet
                    match IpPacketValidator::check(packet.payload) {
                        Ok(()) => {
                            return Ok(Bytes::copy_from_slice(packet.payload));
                        }
                        Err(e) => {
                            tracing::warn!(error=?e, "received invalid IP packet");
                        }
                    }
                }
                // packet is not fully received, continue waiting
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error=?e, "packet was rejected");
                }
            }
        }
    }
}

/// Send outgoing packets to the tunnel server.
pub struct Outgoing {
    conn: anapaya_quinn::Connection,
    conn_state: SharedConnState,
    fragmenter: Fragmenter,
    frame_send_queue: VecDeque<Bytes>,
}

impl Outgoing {
    fn new(
        conn: anapaya_quinn::Connection,
        mtu: u16,
        conn_state: SharedConnState,
        fragment_metrics: FragmentMetrics,
    ) -> Self {
        Self {
            conn,
            conn_state,
            fragmenter: Fragmenter::new(mtu as usize, fragment_metrics),
            frame_send_queue: Default::default(),
        }
    }

    /// Tries to send a packet
    ///
    /// Returns an error if the connection is broken and should be shut down
    pub async fn send_wait(&mut self, packet: Bytes) -> Result<(), SendError> {
        self.conn_state.check_error_state()?;
        // Update our MTU
        let new = self.conn.max_datagram_size().ok_or_else(|| {
            self.conn_state
                .get_or_set_error_state(ConnError::DatagramDisabled)
        })?;

        let curr = self.fragmenter.mtu();

        if new != curr {
            tracing::debug!(curr, new, "Updating max frame size");
            self.fragmenter.set_mtu(new);
        }

        // Split packet into multiple frames
        self.fragmenter.send(&packet, |p| {
            self.frame_send_queue
                .push_back(Bytes::from_owner(p.to_vec()))
        })?;

        // Send all frames
        while let Some(p) = self.frame_send_queue.pop_front() {
            let current_frame_size = p.len();

            if let Err(e) = self.conn.send_datagram_wait(p).await {
                use anapaya_quinn::SendDatagramError::*;

                match e {
                    // Return immediately, can't use this connection
                    UnsupportedByPeer => {
                        return Err(self
                            .conn_state
                            .get_or_set_error_state(ConnError::DatagramUnsupportedByPeer)
                            .into());
                    }
                    Disabled => {
                        return Err(self
                            .conn_state
                            .get_or_set_error_state(ConnError::DatagramDisabled)
                            .into());
                    }
                    ConnectionLost(err) => {
                        return Err(self.conn_state.get_or_set_error_state(err.into()).into());
                    }
                    // Our current fragment size must have been too large
                    TooLarge => {
                        let new = self
                            .conn
                            .max_datagram_size()
                            .expect("Only returns none when datagrams are not supported");

                        if new == curr {
                            tracing::warn!(
                                new,
                                curr,
                                size = current_frame_size,
                                "Frame was too large, but MTU was set correctly, dropping"
                            )
                        } else {
                            tracing::debug!(
                                new,
                                curr,
                                size = current_frame_size,
                                "Frame was too large, dropping"
                            );
                        }

                        // Clear queued frames - can't be assembled on receiving side anymore
                        self.frame_send_queue.clear();
                    }
                }
            }
        }

        Ok(())
    }
}

/// Error returned when sending a packet over the tunnel fails.
#[derive(Debug, Clone, Error)]
pub enum SendError {
    /// The underlying connection is broken.
    #[error(transparent)]
    ConnError(#[from] ConnError),
    /// The packet could not be fragmented.
    #[error("could not fragment packet: {0}")]
    FragmenterSendError(#[from] FragmenterSendError),
}

/// Connection state.
#[derive(Debug, Clone)]
struct ConnState {
    /// Set if the Connection is irreperably broken and needs to be shut down
    error: Option<ConnError>,
    /// The addresses assigned to this connection.
    assigned_addresses: Vec<IpAddr>,
    /// The routes advertised by this connection.
    advertised_routes: Vec<IpNet>,
    /// The expiry time of the session.
    session_expiry: SystemTime,
}

impl Default for ConnState {
    fn default() -> Self {
        Self {
            error: None,
            assigned_addresses: Vec::new(),
            advertised_routes: Vec::new(),
            session_expiry: SystemTime::UNIX_EPOCH,
        }
    }
}

#[derive(Debug, Clone)]
struct SharedConnState(Arc<RwLock<ConnState>>);

impl SharedConnState {
    fn new(conn_state: ConnState) -> Self {
        Self(Arc::new(RwLock::new(conn_state)))
    }
}

impl Deref for SharedConnState {
    type Target = Arc<RwLock<ConnState>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SharedConnState {
    /// Checks if the connection has an error.
    ///
    /// Every operation should use this to check the error state before executing.
    fn check_error_state(&self) -> Result<(), ConnError> {
        let guard = self.read().unwrap();
        match &guard.error {
            Some(err) => Err(err.clone()),
            None => Ok(()),
        }
    }

    /// Gets the current error or sets a new error and returns it.
    ///
    /// Every operation should use [Self::check_error_state] to receive this error before executing.
    fn get_or_set_error_state(&self, error: ConnError) -> ConnError {
        let mut guard = self.write().unwrap();
        guard.error.get_or_insert(error).clone()
    }
}

/// Edge tun client connection errors
#[derive(Debug, Clone, Error)]
pub enum ConnError {
    /// The QUIC connection has datagrams disabled.
    #[error("datagrams are disabled on this connection")]
    DatagramDisabled,
    /// The remote peer does not support QUIC datagrams.
    #[error("connection peer does not support datagrams")]
    DatagramUnsupportedByPeer,
    /// The underlying QUIC connection was lost.
    #[error(transparent)]
    ConnectionLost(#[from] anapaya_quinn::ConnectionError),
}

/// The control state associated with this connection.
#[derive(Debug)]
pub struct StaticControlState {
    /// The IP addresses assigned to this connection.
    pub assigned_addresses: Vec<IpAddr>,

    /// The IP routes advertised by the server for this connection.
    pub routes: Vec<IpNet>,
}

impl std::fmt::Display for StaticControlState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let assigned_addresses = self
            .assigned_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let routes = self
            .routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "EdgeTunClient {{ assigned_addresses: [{assigned_addresses}], routes: [{routes}] }}"
        )
    }
}

async fn recv_response<M: Message + Default>(
    buf: &mut [u8],
    rcv: &mut RecvStream,
) -> Result<M, EdgeTunError> {
    let mut cursor = 0;
    let mut body_offset = 0;
    let mut code = 0;

    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&buf[..cursor])? {
            httparse::Status::Partial => {}
            httparse::Status::Complete(n) => {
                body_offset = n;
                code = resp.code.unwrap_or(0);
                break;
            }
        };

        // Only keep reading if we have enough space in buffer
        if cursor >= buf.len() {
            return Err(EdgeTunError::ResponseError("response too large".into()));
        }
    }

    // We only have a single message on the stream, so the rest we expect to be the body.
    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;
        if cursor >= buf.len() {
            return Err(EdgeTunError::ResponseError("response too large".into()));
        }
    }

    // If the response code is not 200, return an error with the response body as message.
    if code != 200 {
        let msg = String::from_utf8_lossy(&buf[body_offset..cursor]).to_string();
        return Err(EdgeTunError::ResponseError(msg.into()));
    }

    let m = M::decode(&buf[body_offset..cursor])?;

    Ok(m)
}

/// Send a control request to the server using `snd` as the request-stream.
async fn write_http_header(
    snd: &mut SendStream,
    method: &str,
    token: &str,
    finish_stream: bool,
) -> Result<(), EdgeTunError> {
    write_all(
        snd,
        format!(
            "POST {method} HTTP/1.1\r\n\
content-type: application/proto\r\n\
connect-protocol-version: 1\r\n\
content-encoding: identity\r\n\
accept-encoding: identity\r\n\
Authorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;

    if finish_stream {
        snd.finish()?;
    }
    Ok(())
}

// write_all is not cancel-safe, so we use loops instead.
async fn write_all(stream: &mut SendStream, data: &[u8]) -> std::io::Result<()> {
    let mut cursor = 0;
    while cursor < data.len() {
        cursor += stream.write(&data[cursor..]).await?;
    }
    Ok(())
}

/// Error returned by client operations when the QUIC connection fails.
#[derive(Debug, Error)]
pub enum EdgeTunError {
    /// A stream read failed.
    #[error("Read error: {0}")]
    ReadError(#[from] anapaya_quinn::ReadError),
    /// A stream was closed before all data was written.
    #[error("stream was prematurely closed: {0}")]
    SendError(#[from] anapaya_quinn::ClosedStream),
    /// The QUIC connection was lost.
    #[error("connection error: {0}")]
    ConnectionError(#[from] anapaya_quinn::ConnectionError),
    /// Parsing the HTTP envelope of a control response failed.
    #[error("parsing HTTP envelope failed: {0}")]
    HTTParseError(#[from] httparse::Error),
    /// Decoding a protobuf control message failed.
    #[error("parsing control message failed: {0}")]
    ParseError(#[from] prost::DecodeError),
    /// The server returned a non-200 response.
    #[error("received bad response: {0}")]
    ResponseError(Cow<'static, str>),
    /// The address assignment request failed.
    #[error("address assignment failed: {0}")]
    AddressAssignmentFailed(#[from] AddrAssignError),
    /// The route advertisement request failed.
    #[error("route request failed: {0}")]
    RouteRequestFailed(#[from] RoutesError),
    /// An I/O error occurred.
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Error returned when address assignment fails.
#[derive(Debug, thiserror::Error)]
pub enum AddrAssignError {
    /// The server returned an address that could not be parsed.
    #[error("invalid addr: {0}")]
    InvalidAddr(#[from] IpAddrError),
    /// The server did not assign any address.
    #[error("no address assigned")]
    NoAddressAssigned,
}

/// Error returned when the route advertisement request fails.
#[derive(Debug, thiserror::Error)]
pub enum RoutesError {
    /// The server returned a route that could not be parsed.
    #[error("invalid addr: {0}")]
    InvalidAddr(#[from] IpAddrError),
    /// The server did not advertise any routes.
    #[error("no routes advertised")]
    NoRoutesAdvertised,
}
