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
    net::IpAddr,
    ops::Deref,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use prost::Message;
use quinn::{RecvStream, SendStream};
use scion_proto::address::EndhostAddr;
use tokio::{sync::watch, task::JoinHandle};
use tracing::debug;

use crate::requests::{
    AddrError, AddressAssignRequest, AddressAssignResponse, AddressRange, SessionRenewalResponse,
    system_time_from_unix_epoch_secs,
};

/// All control requests issued by the client MUST NOT exceed
/// `CTRL_REQUEST_BUF_SIZE` bytes.
pub const CTRL_RESPONSE_BUF_SIZE: usize = 4096;

/// Lead time for session renewal. Renewal is triggered when the current time is later than the
/// token expiry minus the lead time.
pub const DEFAULT_RENEWAL_WAIT_THRESHOLD: Duration = Duration::from_secs(300); // 5min

/// Token renewal error.
pub type TokenRenewError = Box<dyn std::error::Error + Sync + Send>;

/// Function type for renewing tokens.
pub type TokenRenewFn = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<String, TokenRenewError>> + Send>> + Send + Sync,
>;

/// Automatic session renewal configuration.
pub struct AutoSessionRenewal {
    token_renewer: TokenRenewFn,
    renew_wait_threshold: Duration,
}

impl AutoSessionRenewal {
    /// Create a new automatic session renewal configuration.
    ///
    /// # Arguments
    /// * `renew_wait_threshold` - Duration before session expiry to wait before attempting renewal.
    /// * `token_renewer` - Function to renew the session token.
    pub fn new(renew_wait_threshold: Duration, token_renewer: TokenRenewFn) -> Self {
        AutoSessionRenewal {
            token_renewer,
            renew_wait_threshold,
        }
    }
}

/// SNAP tunnel client builder.
pub struct ClientBuilder {
    desired_addresses: Vec<EndhostAddr>,
    initial_session_token: String,
    auto_session_renewal: Option<AutoSessionRenewal>,
}

impl ClientBuilder {
    /// Client builder with an initial session token to be used to authenticate requests.
    pub fn new<S: AsRef<str>>(initial_session_token: S) -> Self {
        ClientBuilder {
            desired_addresses: Vec::new(),
            initial_session_token: initial_session_token.as_ref().into(),
            auto_session_renewal: None,
        }
    }

    /// Set the desired addresses to be requested from the SNAP. If empty, the SNAP server will
    /// assign an address.
    pub fn with_desired_addresses(mut self, desired_addresses: Vec<EndhostAddr>) -> Self {
        self.desired_addresses = desired_addresses;
        self
    }

    /// Enable automatic session renewal.
    pub fn with_auto_session_renewal(mut self, session_renewal: AutoSessionRenewal) -> Self {
        self.auto_session_renewal = Some(session_renewal);
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
            session_renewal_task: None,
        };

        ctrl.state.write().expect("no fail").session_token = self.initial_session_token;
        ctrl.renew_session().await?;
        ctrl.request_address(self.desired_addresses).await?;

        if let Some(auto_session_renewal) = self.auto_session_renewal {
            ctrl.start_auto_session_renewal(auto_session_renewal, expiry_receiver);
        }

        Ok((Sender::new(conn.clone()), Receiver { conn }, ctrl))
    }
}

/// Control can be used to send control messages to the server
pub struct Control {
    conn: quinn::Connection,
    state: SharedConnState,
    session_renewal_task: Option<JoinHandle<Result<(), RenewTaskError>>>,
}

impl Control {
    /// Returns the currently assigned addresses.
    pub fn assigned_addresses(&self) -> Vec<EndhostAddr> {
        self.state
            .read()
            .expect("no fail")
            .assigned_addresses
            .clone()
    }

    /// Returns the session expiry time.
    pub fn session_expiry(&self) -> SystemTime {
        self.state.read().expect("no fail").session_expiry
    }

    /// Sends an address assign request to the snaptun server.
    ///
    /// In addition, this also extends the session validity based on the token validity.
    ///
    /// # Arguments
    /// * `desired_addresses` - Client can request specific [EndhostAddr] from the server.
    async fn request_address(
        &mut self,
        desired_addresses: Vec<EndhostAddr>,
    ) -> Result<(), ControlError> {
        debug!(?desired_addresses, "Requesting address assignment");
        let (mut snd, mut rcv) = self.conn.open_bi().await?;
        let request = AddressAssignRequest {
            requested_addresses: desired_addresses
                .into_iter()
                .map(|addr| {
                    let (version, prefix_length, octets) = match addr.local_address() {
                        IpAddr::V4(a) => (4, 32, a.octets().to_vec()),
                        IpAddr::V6(a) => (6, 128, a.octets().to_vec()),
                    };
                    AddressRange {
                        isd_as: addr.isd_asn().into(),
                        ip_version: version as u32,
                        prefix_length: prefix_length as u32,
                        address: octets,
                    }
                })
                .collect::<Vec<_>>(),
        };
        let body = request.encode_to_vec();
        let token = self.state.read().expect("no fail").session_token.clone();
        send_control_request(&mut snd, crate::PATH_ADDR_ASSIGNMENT, body.as_ref(), &token).await?;
        let mut resp_buf = [0u8; CTRL_RESPONSE_BUF_SIZE];
        let response: AddressAssignResponse =
            parse_http_response(&mut resp_buf[..], &mut rcv).await?;

        if response.assigned_addresses.is_empty() {
            return Err(ControlError::AddressAssignmentFailed(
                AddrAssignError::NoAddressAssigned,
            ));
        }
        let assigned_addresses = response
            .assigned_addresses
            .iter()
            .map(|address_range| {
                TryInto::<EndhostAddr>::try_into(address_range).map_err(|e| {
                    ControlError::AddressAssignmentFailed(AddrAssignError::InvalidAddr(e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        debug!(?assigned_addresses, "Got address assignment");

        self.state.write().expect("no fail").assigned_addresses = assigned_addresses;
        Ok(())
    }

    /// Sends a session renewal request to the snaptun server.
    pub async fn renew_session(&mut self) -> Result<(), ControlError> {
        let token = self.state.read().expect("no fail").session_token.clone();
        self.set_session_expiry(renew_session(&self.conn.clone(), &token).await?);
        Ok(())
    }

    fn start_auto_session_renewal(
        &mut self,
        config: AutoSessionRenewal,
        mut expiry_notifier: watch::Receiver<()>,
    ) {
        let conn = self.conn.clone();
        let conn_state = self.state.clone();

        self.session_renewal_task = Some(tokio::spawn(async move {
            // Maximum number of retries for session renewal.
            const MAX_RETRIES: u32 = 5;
            // Base retry delay used for exponential backoff.
            const BASE_RETRY_DELAY_SECS: u64 = 3;
            // Fraction of the remaining time to sleep before retrying.
            const SLEEP_FRACTION: f32 = 0.75; // Sleep for 3/4 of the remaining time

            let mut retries: u32 = 0;
            loop {
                let secs_until_expiry = {
                    let expiry = conn_state.read().expect("no fail").session_expiry;
                    // Calculate how long until the session expires
                    match expiry.duration_since(SystemTime::now()) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            // As long as the auto session renewal works correctly, this should
                            // never happen.
                            tracing::error!("Session expiry already passed, stopping auto-renewal");
                            return Err(RenewTaskError::SessionExpired);
                        }
                    }
                };

                // Renew immediately if the remaining seconds are less than the wait threshold.
                let sleep_secs = if secs_until_expiry < config.renew_wait_threshold.as_secs() {
                    0
                } else {
                    (secs_until_expiry as f32 * SLEEP_FRACTION) as u64
                };
                debug!("Next session renewal in {sleep_secs} seconds");

                tokio::select! {
                    _ = expiry_notifier.changed() => continue,
                    _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {
                        debug!("Renewing token and snaptun session");

                        // renew token
                        let token = match (config.token_renewer)().await {
                            Ok(token) => token,
                            Err(err) => {
                                debug!(%err, "Failed to renew token, retry");
                                retries += 1;
                                if retries >= MAX_RETRIES {
                                    return Err(RenewTaskError::MaxRetriesReached);
                                }
                                tokio::time::sleep(Duration::from_secs(BASE_RETRY_DELAY_SECS.pow(retries))).await;
                                continue;
                            },
                        };

                        // renew session
                        let new_expiry = match renew_session(&conn, &token).await {
                            Ok(exp) => exp,
                            Err(err) => {
                                debug!(%err, "Failed to renew session, retry");
                                retries += 1;
                                if retries >= MAX_RETRIES {
                                    return Err(RenewTaskError::MaxRetriesReached);
                                }
                                tokio::time::sleep(Duration::from_secs(BASE_RETRY_DELAY_SECS.pow(retries))).await;
                                continue;
                            }
                        };

                        debug!(new_expiry=%chrono::DateTime::<chrono::Utc>::from(new_expiry).to_rfc3339(), "auto session renewal successful");
                        conn_state.write().expect("no fail").session_expiry = new_expiry;
                        retries = 0;
                    }
                }
            }
        }));
    }

    fn set_session_expiry(&mut self, expiry: SystemTime) {
        self.state.write().expect("no fail").session_expiry = expiry;
        if self
            .state
            .read()
            .expect("no fail")
            .expiry_notifier
            .send(())
            .is_err()
        {
            // This happens only if the channel is closed, which means that the session has
            // expired and the receiver is no longer interested in updates.
            debug!("Failed to notify session expiry update");
        }
    }

    /// An async function that returns when the underlying connection is closed.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }

    /// This is a helper function that returns a debug-printable object
    /// containing metrics about the underlying QUIC-connection.
    // XXX(dsd): We are overcautious here and do not want to commit to an
    // implementation-specific type.
    pub fn debug_path_stats(&self) -> impl std::fmt::Debug {
        self.conn.stats().path
    }
}

/// Token renew task error.
#[derive(Debug, thiserror::Error)]
pub enum RenewTaskError {
    /// Session expired.
    #[error("session expired")]
    SessionExpired,
    /// Maximum number of retries reached.
    #[error("maximum number of retries reached")]
    MaxRetriesReached,
}

/// Renew SNAP tunnel session.
///
/// This opens a new bi-directional stream to the server, sends a session renewal request, and waits
/// for the response. On success, it returns the new session expiry time.
pub async fn renew_session(
    conn: &quinn::Connection,
    token: &str,
) -> Result<SystemTime, ControlError> {
    let (mut snd, mut rcv) = conn.open_bi().await?;

    let body = vec![];
    send_control_request(&mut snd, crate::PATH_SESSION_RENEWAL, &body, token).await?;
    let mut resp_buf = [0u8; CTRL_RESPONSE_BUF_SIZE];
    let response: SessionRenewalResponse = parse_http_response(&mut resp_buf[..], &mut rcv).await?;

    Ok(system_time_from_unix_epoch_secs(response.valid_until))
}

impl Drop for Control {
    fn drop(&mut self) {
        if let Some(task) = self.session_renewal_task.take() {
            // Cancel the session renewal task
            task.abort();
        }
    }
}

/// Connection state.
#[derive(Debug, Clone)]
struct ConnState {
    session_token: String,
    session_expiry: SystemTime,
    assigned_addresses: Vec<EndhostAddr>,
    expiry_notifier: watch::Sender<()>,
}

impl ConnState {
    fn new(expiry_notifier: watch::Sender<()>) -> Self {
        Self {
            session_token: String::new(),
            session_expiry: SystemTime::UNIX_EPOCH,
            assigned_addresses: Vec::new(),
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
        self.conn.send_datagram(data)?;
        Ok(())
    }

    /// Sends a datagram to the connection and waits for the datagram to be sent.
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.conn.send_datagram_wait(data).await?;
        Ok(())
    }
}

/// SNAP tunnel receiver.
pub struct Receiver {
    conn: quinn::Connection,
}

impl Receiver {
    /// Reads a datagram from the connection.
    pub async fn read_datagram(&self) -> Result<Bytes, quinn::ConnectionError> {
        let packet = self.conn.read_datagram().await?;
        Ok(packet)
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
}

async fn parse_http_response<M: prost::Message + Default>(
    buf: &mut [u8],
    rcv: &mut RecvStream,
) -> Result<M, ParseResponseError> {
    let mut cursor = 0usize;
    let mut body_offset = 0usize;
    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        body_offset = match resp.parse(&buf[..cursor]) {
            Ok(httparse::Status::Partial) => continue,
            Ok(httparse::Status::Complete(n)) => n,
            Err(e) => return Err(ParseResponseError::HTTParseError(e)),
        };
    }
    // we want to keep this method cancel-safe, so we use repeated reads.
    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;
    }
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
