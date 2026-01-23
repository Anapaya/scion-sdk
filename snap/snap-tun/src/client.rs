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
    borrow::Cow,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use bytes::Bytes;
use prost::Message;
use quinn::{ConnectionError, RecvStream, SendStream};
use scion_sdk_reqwest_connect_rpc::token_source::{self, TokenSource};
use scion_sdk_utils::backoff::ExponentialBackoff;
use tokio::{select, task::JoinHandle};

use crate::requests::{
    AddrError, SocketAddrAssignmentRequest, SocketAddrAssignmentResponse, TokenUpdateResponse,
    system_time_from_unix_epoch_secs,
};

/// Maximum size of a control message, both request and response.
pub const MAX_CTRL_MESSAGE_SIZE: usize = 4096;

/// SNAP tunnel client builder.
pub struct ClientBuilder {
    token_source: Arc<dyn TokenSource>,
}

impl ClientBuilder {
    /// Client builder with an initial SNAP token to be used to authenticate requests.
    pub fn new(token_source: Arc<dyn TokenSource>) -> Self {
        ClientBuilder { token_source }
    }

    /// Establish a SNAP tunnel using the provided QUIC connection using the builder's settings.
    pub async fn connect(
        self,
        conn: quinn::Connection,
    ) -> Result<(Sender, Receiver, Control), SnapTunError> {
        let conn_state = SharedConnState::new(ConnState::new());
        let mut ctrl = Control {
            conn: conn.clone(),
            state: conn_state.clone(),
            token_renewal_task: None,
        };

        let mut token_watch = self.token_source.watch();

        // Try to get the current token
        let mut initial_token = match token_watch.borrow_and_update().as_ref() {
            Some(Ok(token)) => Some(token.clone()),
            Some(Err(e)) => return Err(SnapTunError::InitialTokenError(e.to_string())),
            None => None,
        };

        // Wait for the initial token if not already available.
        if initial_token.is_none() {
            token_watch
                .changed()
                .await
                .map_err(|e| SnapTunError::InitialTokenError(e.to_string()))?;

            initial_token = match token_watch.borrow().as_ref() {
                Some(Ok(token)) => Some(token.clone()),
                Some(Err(e)) => return Err(SnapTunError::InitialTokenError(e.to_string())),
                None => None,
            };
        }

        let initial_token = initial_token.ok_or_else(|| {
            SnapTunError::InitialTokenError("failed to obtain initial token".into())
        })?;

        ctrl.state.write().unwrap().snap_token = initial_token;
        ctrl.update_token().await?;
        ctrl.request_socket_addr().await?;

        // If our token source supports notifications for new tokens, spawn a task to
        // inform the server whenever the token is updated.
        tracing::trace!("Starting token update task");
        ctrl.session_token_update_task(token_watch);

        Ok((Sender::new(conn.clone()), Receiver { conn }, ctrl))
    }
}

/// Control can be used to send control messages to the server
pub struct Control {
    conn: quinn::Connection,
    state: SharedConnState,
    token_renewal_task: Option<JoinHandle<Result<(), RenewTaskError>>>,
}

impl Control {
    /// Returns the socket address assigned by the server. This typically
    /// corresponds to the client's _remote_ socket address; i.e. the possibly
    /// NAT'ed address of the client visible to the server.
    ///
    /// It is up to the client to use the correct ISD-AS for this tunnel.
    pub fn assigned_sock_addr(&self) -> Option<SocketAddr> {
        self.state.read().expect("no fail").assigned_sock_addr
    }

    /// Returns the token expiry time.
    pub fn token_expiry(&self) -> SystemTime {
        self.state.read().expect("no fail").token_expiry
    }

    /// Returns the current SNAP token.
    pub fn snap_token(&self) -> String {
        self.state.read().expect("no fail").snap_token.clone()
    }

    /// Sends a socket address assign request to the snaptun server.
    async fn request_socket_addr(&mut self) -> Result<(), ControlError> {
        tracing::debug!("Requesting socket address assignment");
        let (mut snd, mut rcv) = self.conn.open_bi().await?;

        let request = SocketAddrAssignmentRequest {};

        let body = request.encode_to_vec();
        let token = self.state.read().expect("no fail").snap_token.clone();
        send_control_request(
            &mut snd,
            crate::PATH_SOCK_ADDR_ASSIGNMENT,
            body.as_ref(),
            &token,
        )
        .await?;

        // Parse address assignment response
        let mut resp_buf = [0u8; MAX_CTRL_MESSAGE_SIZE];
        let response =
            recv_response::<SocketAddrAssignmentResponse>(&mut resp_buf[..], &mut rcv).await?;

        let sock_addr = response
            .socket_addr()
            .map_err(|e| ControlError::AddressAssignmentFailed(AddrAssignError::InvalidAddr(e)))?;

        let mut sstate = self.state.0.write().expect("no fail");
        sstate.assigned_sock_addr = Some(sock_addr);

        Ok(())
    }

    /// Sends a new SNAP token to keep the snaptun connection with the server established.
    pub async fn update_token(&mut self) -> Result<(), ControlError> {
        let token = self.state.read().unwrap().snap_token.clone();
        self.set_token_expiry(update_token(&self.conn.clone(), &token).await?);
        Ok(())
    }

    /// Spawns a task which informs the server whenever the client's token was updated.
    fn session_token_update_task(&mut self, mut token_watch: token_source::TokenSourceWatch) {
        let conn = self.conn.clone();
        let conn_state = self.state.clone();

        self.token_renewal_task = Some(tokio::spawn(async move {
            loop {
                let expiry = conn_state.read().expect("no fail").token_expiry;
                let now = SystemTime::now();
                let dur_until_expiry = expiry
                    .duration_since(now)
                    .unwrap_or_else(|_| std::time::Duration::from_secs(0));

                let expiry_timeout = tokio::time::Instant::now() + dur_until_expiry;

                select! {
                    // A new token is available.
                    _ = token_watch.changed() => {}
                    // Our token has expired.
                    _ = tokio::time::sleep_until(expiry_timeout) => {
                        tracing::error!("SNAP token has expired but no new token was received from the token source");
                        return Err(RenewTaskError::TokenExpired);
                    },
                }

                // Try to get a new token from the token source. Can fail if the token source
                // expired and failed fetching a new token in time
                let new_token = token_watch
                    .borrow_and_update()
                    .as_ref()
                    .ok_or_else(|| {
                        RenewTaskError::TokenSourceError(
                            "token source watch channel has no value".into(),
                        )
                    })?
                    .as_ref()
                    .map_err(|e| RenewTaskError::TokenSourceError(e.to_string().into()))?
                    .clone();

                // Try to update the token on the server.
                let mut attempt = 0;
                // Maximum number of retries for token renewal.
                const MAX_RETRIES: u32 = 5;
                // Update backoff
                const BACKOFF: ExponentialBackoff = ExponentialBackoff::new(3.0, 30.0, 2.0, 1.0);

                tracing::info!("Updating SNAP token on server");
                // Note: Unlikely edgecase - If the token lifetime is very short, we might run into
                // the situation where the token expires before we could successfully update it on
                // the server.
                loop {
                    match update_token(&conn, &new_token).await {
                        Ok(new_expiry) => {
                            tracing::info!("Successfully updated SNAP token on server");
                            // Update the token in the connection state.
                            {
                                let mut conn_state = conn_state.write().unwrap();
                                conn_state.token_expiry = new_expiry;
                                conn_state.snap_token = new_token.clone();
                            }
                            break;
                        }
                        Err(err) if attempt > MAX_RETRIES => {
                            attempt += 1;
                            tracing::error!(
                                %attempt,
                                %err,
                                "Failed to update SNAP token on server, max retries reached",
                            );

                            return Err(RenewTaskError::MaxRetriesReached);
                        }
                        Err(err) => {
                            attempt += 1;

                            let delay = BACKOFF.duration(attempt);
                            let next_try = delay.as_secs();
                            tracing::warn!(
                                %attempt,
                                %err,
                                %next_try,
                                "Failed to update SNAP token on server",
                            );

                            if expiry_timeout <= tokio::time::Instant::now() + delay {
                                tracing::error!(
                                    "SNAP token has expired before it could be renewed"
                                );
                                return Err(RenewTaskError::TokenExpired);
                            }

                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }));
    }

    fn set_token_expiry(&mut self, expiry: SystemTime) {
        self.state.write().expect("no fail").token_expiry = expiry;
    }

    /// An async function that returns when the underlying connection is closed.
    pub async fn closed(&self) -> ConnectionError {
        self.conn.closed().await
    }

    /// Returns the underlying QUIC connection.
    pub fn inner_conn(&self) -> quinn::Connection {
        self.conn.clone()
    }

    /// This is a helper function that returns a debug-printable object
    /// containing metrics about the underlying QUIC-connection.
    // XXX(dsd): We are overcautious here and do not want to commit to an
    // implementation-specific type.
    pub fn debug_path_stats(&self) -> impl std::fmt::Debug + 'static + use<> {
        self.conn.stats().path
    }
}

/// Token renew task error.
#[derive(Debug, thiserror::Error)]
pub enum RenewTaskError {
    /// Token expired.
    #[error("token expired")]
    TokenExpired,
    /// Maximum number of retries reached.
    #[error("maximum number of retries reached")]
    MaxRetriesReached,
    /// Token source error.
    #[error("token source failed: {0}")]
    TokenSourceError(#[from] token_source::TokenSourceError),
}

/// Update SNAP token.
///
/// This opens a new bi-directional stream to the server, sends a update SNAP token request, and
/// waits for the response. On success, it returns the new token expiry time.
pub async fn update_token(
    conn: &quinn::Connection,
    token: &str,
) -> Result<SystemTime, ControlError> {
    let (mut snd, mut rcv) = conn.open_bi().await?;

    let body = vec![];
    send_control_request(&mut snd, crate::PATH_UPDATE_TOKEN, &body, token).await?;
    let mut resp_buf = [0u8; MAX_CTRL_MESSAGE_SIZE];
    let response: TokenUpdateResponse = recv_response(&mut resp_buf[..], &mut rcv).await?;

    Ok(system_time_from_unix_epoch_secs(response.valid_until))
}

impl Drop for Control {
    fn drop(&mut self) {
        if let Some(task) = self.token_renewal_task.take() {
            // Cancel the token renewal task
            task.abort();
        }
    }
}

/// Connection state.
#[derive(Debug, Clone)]
struct ConnState {
    snap_token: String,
    token_expiry: SystemTime,
    // The socket address that is assigned by the remote and should be used as
    // the endhost socket address for this tunnel.
    assigned_sock_addr: Option<SocketAddr>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            snap_token: String::new(),
            token_expiry: SystemTime::UNIX_EPOCH,
            assigned_sock_addr: None,
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

/// SNAP tunnel sender.
#[derive(Debug, Clone)]
pub struct Sender {
    conn: quinn::Connection,
}

impl Sender {
    /// Creates a new sender.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Sends a datagram to the connection.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.conn.send_datagram(data)
    }

    /// Sends a datagram to the connection and waits for the datagram to be sent.
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.conn.send_datagram_wait(data).await
    }
}

/// SNAP tunnel receiver.
#[derive(Debug, Clone)]
pub struct Receiver {
    conn: quinn::Connection,
}

impl Receiver {
    /// Reads a datagram from the connection.
    pub async fn read_datagram(&self) -> Result<Bytes, quinn::ConnectionError> {
        self.conn.read_datagram().await
    }
}

/// Parse response error.
#[derive(Debug, thiserror::Error)]
pub enum ParseResponseError {
    /// Parsing HTTP envelope failed.
    #[error("parsing HTTP envelope failed: {0}")]
    HTTParseError(#[from] httparse::Error),
    /// QUIC read error.
    #[error("read error: {0}")]
    ReadError(#[from] quinn::ReadError),
    /// Protobuf decode error.
    #[error("parsing control message failed: {0}")]
    ParseError(#[from] prost::DecodeError),
    /// Received a bad response.
    #[error("received bad response: {0}")]
    ResponseError(Cow<'static, str>),
}

async fn recv_response<M: prost::Message + Default>(
    buf: &mut [u8],
    rcv: &mut RecvStream,
) -> Result<M, ParseResponseError> {
    let mut cursor = 0;
    let mut body_offset = 0;
    let mut code = 0;

    // Parse HTTP response headers.
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
            return Err(ParseResponseError::ResponseError(
                "response too large".into(),
            ));
        }
    }

    // We only have a single message on the stream, so the rest we expect to be the body.
    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;
        if cursor >= buf.len() {
            return Err(ParseResponseError::ResponseError(
                "response too large".into(),
            ));
        }
    }

    // If the response code is not 200, return an error with the response body as message.
    if code != 200 {
        let msg = String::from_utf8_lossy(&buf[body_offset..cursor]).to_string();
        return Err(ParseResponseError::ResponseError(msg.into()));
    }

    // Otherwise, parse the body as protobuf message.
    let m = M::decode(&buf[body_offset..cursor])?;

    Ok(m)
}

/// Send control request error.
#[derive(Debug, thiserror::Error)]
pub enum SendControlRequestError {
    /// I/O error.
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
    /// QUIC closed stream error.
    #[error("stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
}

/// Send a control request to the server using `snd` as the request-stream.
async fn send_control_request(
    snd: &mut SendStream,
    method: &str,
    body: &[u8],
    token: &str,
) -> Result<(), SendControlRequestError> {
    write_all(
        snd,
        format!(
            "POST {method} HTTP/1.1\r\n\
content-type: application/proto\r\n\
connect-protocol-version: 1\r\n\
content-encoding: identity\r\n\
accept-encoding: identity\r\n\
content-length: {}\r\n\
Authorization: Bearer {token}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await?;
    write_all(snd, body).await?;
    snd.finish()?;
    Ok(())
}

// SendStream::write_all is not cancel-safe, so we use loops instead.
async fn write_all(stream: &mut SendStream, data: &[u8]) -> std::io::Result<()> {
    let mut cursor = 0;
    while cursor < data.len() {
        cursor += stream.write(&data[cursor..]).await?;
    }
    Ok(())
}

/// SNAP tunnel errors.
#[derive(Debug, thiserror::Error)]
pub enum SnapTunError {
    /// Initial token error.
    #[error("initial token error: {0}")]
    InitialTokenError(String),
    /// Control error.
    #[error("control error: {0}")]
    ControlError(#[from] ControlError),
}

/// SNAP tunnel control errors.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// QUIC connection error.
    #[error("quinn connection error: {0}")]
    ConnectionError(#[from] quinn::ConnectionError),
    /// Address assignment failed.
    #[error("address assignment failed: {0}")]
    AddressAssignmentFailed(#[from] AddrAssignError),
    /// Parse control request response error.
    #[error("parse control request response: {0}")]
    ParseResponse(#[from] ParseResponseError),
    /// Send control request error.
    #[error("send control request error: {0}")]
    SendRequestError(#[from] SendControlRequestError),
}

/// Address assignment error.
#[derive(Debug, thiserror::Error)]
pub enum AddrAssignError {
    /// Invalid address.
    #[error("invalid addr: {0}")]
    InvalidAddr(#[from] AddrError),
    /// No address assigned.
    #[error("no address assigned")]
    NoAddressAssigned,
}
