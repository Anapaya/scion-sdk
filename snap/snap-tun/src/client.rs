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
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use prost::Message;
use quinn::{ConnectionError, RecvStream, SendStream};
use tokio::{sync::watch, task::JoinHandle};

use crate::requests::{
    AddrError, SocketAddrAssignmentRequest, SocketAddrAssignmentResponse, TokenUpdateResponse,
    system_time_from_unix_epoch_secs,
};

/// Maximum size of a control message, both request and response.
pub const MAX_CTRL_MESSAGE_SIZE: usize = 4096;

/// Lead time for SNAP token renewal. Renewal is triggered when the current time is later than the
/// token expiry minus the lead time.
pub const DEFAULT_RENEWAL_WAIT_THRESHOLD: Duration = Duration::from_secs(300); // 5min

/// Token renewal error.
pub type TokenRenewError = Box<dyn std::error::Error + Sync + Send>;

/// Function type for renewing tokens.
pub type TokenRenewFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<String, TokenRenewError>> + Send>> + Send + Sync,
>;

/// Automatic SNAP token renewal configuration.
#[derive(Clone)]
pub struct AutoTokenRenewal {
    /// Function to fetch a new SNAP token.
    pub token_renewer: TokenRenewFn,
    renew_wait_threshold: Duration,
}

impl AutoTokenRenewal {
    /// Create a new automatic SNAP token renewal configuration.
    ///
    /// # Arguments
    /// * `renew_wait_threshold` - Duration before SNAP token expiry to wait before attempting
    ///   renewal.
    /// * `token_renewer` - Function to renew the SNAP token.
    pub fn new(renew_wait_threshold: Duration, token_renewer: TokenRenewFn) -> Self {
        AutoTokenRenewal {
            token_renewer,
            renew_wait_threshold,
        }
    }
}

/// SNAP tunnel client builder.
pub struct ClientBuilder {
    initial_snap_token: String,
    auto_token_renewal: Option<AutoTokenRenewal>,
}

impl ClientBuilder {
    /// Client builder with an initial SNAP token to be used to authenticate requests.
    pub fn new<S: AsRef<str>>(initial_snap_token: S) -> Self {
        ClientBuilder {
            initial_snap_token: initial_snap_token.as_ref().into(),
            auto_token_renewal: None,
        }
    }

    /// Enable automatic SNAP token renewal.
    pub fn with_auto_token_renewal(mut self, token_renewal: AutoTokenRenewal) -> Self {
        self.auto_token_renewal = Some(token_renewal);
        self
    }

    /// Establish a SNAP tunnel using the provided QUIC connection using the builder's settings.
    pub async fn connect(
        self,
        conn: quinn::Connection,
    ) -> Result<(Sender, Receiver, Control), SnapTunError> {
        let (expiry_sender, expiry_receiver) = watch::channel(());
        let conn_state = SharedConnState::new(ConnState::new(expiry_sender.clone()));
        let mut ctrl = Control {
            conn: conn.clone(),
            state: conn_state.clone(),
            token_renewal_task: None,
        };

        ctrl.state.write().expect("no fail").snap_token = self.initial_snap_token;
        ctrl.update_token().await?;
        ctrl.request_socket_addr().await?;

        if let Some(auto_token_renewal) = self.auto_token_renewal.clone() {
            ctrl.start_auto_token_renewal(auto_token_renewal, expiry_receiver);
        }

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
        let token = self.state.read().expect("no fail").snap_token.clone();
        self.set_token_expiry(update_token(&self.conn.clone(), &token).await?);
        Ok(())
    }

    fn start_auto_token_renewal(
        &mut self,
        config: AutoTokenRenewal,
        mut expiry_notifier: watch::Receiver<()>,
    ) {
        let conn = self.conn.clone();
        let conn_state = self.state.clone();

        self.token_renewal_task = Some(tokio::spawn(async move {
            // Maximum number of retries for token renewal.
            const MAX_RETRIES: u32 = 5;
            // Base retry delay used for exponential backoff.
            const BASE_RETRY_DELAY_SECS: u64 = 3;
            // Fraction of the remaining time to sleep before retrying.
            const SLEEP_FRACTION: f32 = 0.75; // Sleep for 3/4 of the remaining time

            let mut retries: u32 = 0;
            loop {
                let secs_until_expiry = {
                    let expiry = conn_state.read().expect("no fail").token_expiry;
                    // Calculate how long until the token expires
                    match expiry.duration_since(SystemTime::now()) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            // As long as the auto token renewal works correctly, this should
                            // never happen.
                            tracing::error!("Token expiry already passed, stopping auto-renewal");
                            return Err(RenewTaskError::TokenExpired);
                        }
                    }
                };

                // Renew immediately if the remaining seconds are less than the wait threshold.
                let sleep_secs = if secs_until_expiry < config.renew_wait_threshold.as_secs() {
                    0
                } else {
                    (secs_until_expiry as f32 * SLEEP_FRACTION) as u64
                };
                tracing::debug!("Next token renewal in {sleep_secs} seconds");

                tokio::select! {
                    _ = expiry_notifier.changed() => continue,
                    _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {
                        tracing::debug!("Renewing snaptun token");

                        // renew token
                        let token = match (config.token_renewer)().await {
                            Ok(token) => token,
                            Err(err) => {
                                tracing::warn!(%err, "Failed to renew token, retrying");
                                retries += 1;
                                if retries >= MAX_RETRIES {
                                    return Err(RenewTaskError::MaxRetriesReached);
                                }
                                tokio::time::sleep(Duration::from_secs(BASE_RETRY_DELAY_SECS.pow(retries))).await;
                                continue;
                            },
                        };

                        // update token
                        let new_expiry = match update_token(&conn, &token).await {
                            Ok(exp) => exp,
                            Err(err) => {
                                tracing::warn!(%err, "Failed to update token, retrying");
                                retries += 1;
                                if retries >= MAX_RETRIES {
                                    return Err(RenewTaskError::MaxRetriesReached);
                                }
                                tokio::time::sleep(Duration::from_secs(BASE_RETRY_DELAY_SECS.pow(retries))).await;
                                continue;
                            }
                        };

                        tracing::info!(new_expiry=%chrono::DateTime::<chrono::Utc>::from(new_expiry).to_rfc3339(), "Auto token renewal successful");
                        conn_state.write().expect("no fail").token_expiry = new_expiry;
                        retries = 0;
                    }
                }
            }
        }));
    }

    fn set_token_expiry(&mut self, expiry: SystemTime) {
        self.state.write().expect("no fail").token_expiry = expiry;
        if self
            .state
            .read()
            .expect("no fail")
            .expiry_notifier
            .send(())
            .is_err()
        {
            // This happens only if the channel is closed, which means that the token has
            // expired and the receiver is no longer interested in updates.
            tracing::debug!("Failed to notify token expiry update");
        }
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
    expiry_notifier: watch::Sender<()>,
}

impl ConnState {
    fn new(expiry_notifier: watch::Sender<()>) -> Self {
        Self {
            snap_token: String::new(),
            token_expiry: SystemTime::UNIX_EPOCH,
            assigned_sock_addr: None,
            expiry_notifier,
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
    InitialTokenError(#[from] TokenRenewError),
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
