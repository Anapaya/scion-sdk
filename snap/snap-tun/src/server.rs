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
//! # The snaptun server.
//!
//! This module contains the snaptun-[Server]. The QUIC-connection handling is left to the caller.
//! That is, after accepting a QUIC-connection, [Server::accept_with_timeout] will establish an
//! snaptun with a client, provided the peer behaves as expected and sends the required control
//! requests.
//!
//! The [Server::accept_with_timeout] method produces three different objects: [Receiver], [Sender],
//! and [Control]. The first is used to receive packets from the peer, the second to send packets to
//! the peer. The third is used to _drive_ the control state of the connection.
//!
//! [Server::accept_with_timeout] expects the client to first send a update token request followed
//! by an address assignment request. If the client doesn't do so within [ACCEPT_TIMEOUT], a
//! [AcceptError::Timeout] error is returned and the connection closed. The rationale behind this is
//! that bogus client connections should be closed as quickly as possible.
//!
//! ## Synopsis
//!
//! ```no_exec
//! loop {
//!   let quic_conn = endpoint.accept().await?;
//!
//!   let (sender, receiver, control) = snaptun_server.accept(quic_conn)?;
//!   let _ = tokio::spawn(control); // drive control state
//!
//!   let _ = tokio::spawn(async move {
//!     while Ok(p) = receiver.receive().await {
//!       // process incoming packet
//!     }
//!   });
//!
//!   // send an outgoing packet
//!   sender.send(p);
//! }
//! ```

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::SystemTime,
    vec,
};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::StatusCode;
use prost::Message;
use quinn::{RecvStream, SendStream, VarInt};
use scion_proto::address::EndhostAddr;
use scion_sdk_token_validator::validator::{Token, TokenValidator, TokenValidatorError};
use serde::Deserialize;
use tokio::sync::watch;

use crate::{
    AUTH_HEADER, PATH_SOCK_ADDR_ASSIGNMENT, PATH_UPDATE_TOKEN,
    metrics::{Metrics, ReceiverMetrics, SenderMetrics},
    requests::{SocketAddrAssignmentResponse, TokenUpdateResponse, unix_epoch_from_system_time},
};

/// SNAP tunnel connection errors.
#[derive(Copy, Clone)]
pub enum SnaptunConnErrors {
    /// Invalid control request error.
    InvalidRequest = 1,
    /// Timeout error.
    Timeout = 2,
    /// Unauthenticated error.
    Unauthenticated = 3,
    /// Token expired error.
    TokenExpired = 4,
    /// Internal error.
    InternalError = 5,
}

impl From<SnaptunConnErrors> for quinn::VarInt {
    fn from(e: SnaptunConnErrors) -> Self {
        VarInt::from_u32(e as u32)
    }
}

/// Deserializable SNAP token trait.
pub trait SnapTunToken: for<'de> Deserialize<'de> + Token + Clone {}
impl<T> SnapTunToken for T where T: for<'de> Deserialize<'de> + Token + Clone {}

/// A client MUST first send a token update request, followed by an address assignment request
/// within the `ACCEPT_TIMEOUT`.
pub const ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Sending a control response to the client may take no longer than
/// `SEND_TIMEOUT`.
pub const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Maximum size of a control message, both request and response.
const MAX_CTRL_MESSAGE_SIZE: usize = 4096;

/// The snaptun server accepts connections from clients and provides them with an address
/// assignment.
pub struct Server<T> {
    metrics: Metrics,
    validator: Arc<dyn TokenValidator<T>>,
}

/// Accept errors.
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    /// Timeout reached.
    #[error("timeout reached.")]
    Timeout,
    /// QUIC connection error.
    #[error("quinn connection error: {0}")]
    ConnectionError(#[from] quinn::ConnectionError),
    /// Parse control request error.
    #[error("parse control request error: {0}")]
    ParseControlRequestError(#[from] ParseControlRequestError),
    /// Send control response error.
    #[error("send control response error: {0}")]
    SendControlResponseError(#[from] SendControlResponseError),
    /// Unexpected control request.
    #[error("unexpected control request")]
    UnexpectedControlRequest,
}

impl<T: SnapTunToken> Server<T> {
    /// Create a new server that can accept QUIC connections and turn them into
    /// snap tunnels.
    pub fn new(validator: Arc<dyn TokenValidator<T>>, metrics: Metrics) -> Self {
        Self { validator, metrics }
    }

    /// Accept a connection and establish a tunnel.
    ///
    /// ## Tunnel initialization
    ///
    /// The client is expected to first send a token update request, followed by an address
    /// assignment request. The connection is closed with a [SnaptunConnErrors::Timeout] if the
    /// client does not send the requests within [ACCEPT_TIMEOUT].
    pub async fn accept_with_timeout(
        &self,
        conn: quinn::Connection,
    ) -> Result<(Sender<T>, Receiver<T>, Control), AcceptError> {
        match tokio::time::timeout(ACCEPT_TIMEOUT, self.accept(conn.clone())).await {
            Ok(res) => res,
            Err(_elapsed) => {
                conn.close(
                    SnaptunConnErrors::Timeout.into(),
                    b"timeout establishing snaptun",
                );
                Err(AcceptError::Timeout)
            }
        }
    }

    /// Accept a connection and establish a snaptun.
    ///
    /// ## Tunnel initialization
    ///
    /// The client is expected to first send a token update request, followed by an address
    /// assignment request.
    async fn accept(
        &self,
        conn: quinn::Connection,
    ) -> Result<(Sender<T>, Receiver<T>, Control), AcceptError> {
        let state_machine = Arc::new(TunnelStateMachine::new(
            conn.remote_address(),
            self.validator.clone(),
        ));

        //
        // First request MUST be a token update request.
        let (token_update_req, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |r| matches!(r, ControlRequest::TokenUpdate(_)),
            b"expected token update request",
        )
        .await?;

        let now = SystemTime::now();
        tracing::debug!(?now, request=?token_update_req, "Got token update request");

        let (code, body) = state_machine.process_control_request(now, token_update_req);
        let send_res = send_http_response(&mut snd, code, &body).await;
        if !code.is_success() {
            conn.close(SnaptunConnErrors::InvalidRequest.into(), &body);
            return Err(AcceptError::UnexpectedControlRequest);
        }
        if let Err(e) = send_res {
            conn.close(
                SnaptunConnErrors::InternalError.into(),
                b"failed to send control response",
            );
            return Err(AcceptError::SendControlResponseError(e));
        }

        // Second request MUST be a socket address assignment request.
        let (address_assign_request, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |r| matches!(r, ControlRequest::SocketAddrAssignment { .. }),
            b"expected socket addr assignment request",
        )
        .await?;

        let now = SystemTime::now();

        tracing::debug!(?now, request=?address_assign_request, "Got address assignment request");

        let (code, body) = state_machine.process_control_request(now, address_assign_request);
        let send_res = send_http_response(&mut snd, code, &body).await;
        if !code.is_success() {
            conn.close(SnaptunConnErrors::InvalidRequest.into(), &body);
            return Err(AcceptError::UnexpectedControlRequest);
        }
        if let Err(e) = send_res {
            conn.close(
                SnaptunConnErrors::InternalError.into(),
                b"failed to send control response",
            );
            return Err(AcceptError::SendControlResponseError(e));
        }

        let initial_state_version = state_machine.state_version();
        Ok((
            Sender::new(
                state_machine.get_socket_addr(),
                state_machine.get_addresses().expect("assigned state"),
                conn.clone(),
                state_machine.clone(),
                initial_state_version,
                self.metrics.sender_metrics.clone(),
            ),
            Receiver::new(
                conn.clone(),
                state_machine.clone(),
                initial_state_version,
                self.metrics.receiver_metrics.clone(),
            ),
            Control::new(conn, state_machine.clone()),
        ))
    }
}

async fn receive_expected_control_request(
    conn: &quinn::Connection,
    expected: fn(&ControlRequest) -> bool,
    wrong_request_conn_close_reason: &'static [u8],
) -> Result<(ControlRequest, SendStream, RecvStream), AcceptError> {
    let (snd, mut rcv) = conn
        .accept_bi()
        .await
        .map_err(AcceptError::ConnectionError)?;
    let mut buf = vec![0u8; MAX_CTRL_MESSAGE_SIZE];
    let req = match recv_request(&mut buf, &mut rcv).await {
        Ok(req) if expected(&req) => req,
        Ok(_) => {
            conn.close(
                SnaptunConnErrors::InvalidRequest.into(),
                wrong_request_conn_close_reason,
            );
            return Err(AcceptError::UnexpectedControlRequest);
        }
        Err(err) => {
            handle_invalid_request(conn, &err);
            return Err(err.into());
        }
    };
    Ok((req, snd, rcv))
}

/// Sender can be used to send packets to the client. It is returned by
/// [Server::accept_with_timeout].
///
/// Sender offers a synchronous and an asychronous API to send packets to the client.
pub struct Sender<T: SnapTunToken> {
    assigned_socket_addr: Option<SocketAddr>,
    metrics: SenderMetrics,
    addresses: Vec<EndhostAddr>,
    conn: quinn::Connection,
    state_machine: Arc<TunnelStateMachine<T>>,
    last_state_version: AtomicUsize,
    is_closed: AtomicBool,
}

impl<T: SnapTunToken> Sender<T> {
    fn new(
        assigned_socket_addr: Option<SocketAddr>,
        addresses: Vec<EndhostAddr>,
        conn: quinn::Connection,
        state_machine: Arc<TunnelStateMachine<T>>,
        initial_state_version: usize,
        metrics: SenderMetrics,
    ) -> Self {
        Self {
            assigned_socket_addr,
            addresses,
            conn,
            state_machine,
            last_state_version: AtomicUsize::new(initial_state_version),
            is_closed: AtomicBool::new(false),
            metrics,
        }
    }

    /// Returns the addresses assigned to this sender.
    pub fn assigned_addresses(&self) -> Vec<EndhostAddr> {
        self.addresses.clone()
    }

    /// Returns the endhost socket address assigned to the endhost.
    pub fn assigned_socket_addr(&self) -> Option<SocketAddr> {
        self.assigned_socket_addr
    }

    /// Returns the remote address of the underlying QUIC connection.
    pub fn remote_underlay_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Send a packet to the client. The packet needs to fit entirely into a QUIC datagram.
    ///
    /// ## Errors
    ///
    /// The function returns an error if either the connection is in an
    /// erroneous state (non-recoverable), or the address assignment has
    /// changed. In the latter case, [SendPacketError::NewAssignedAddress] is
    /// returned with a new [Sender] object that is assigned the new address.
    /// The old object will return a [SendPacketError::ConnectionClosed] error.
    pub fn send(&self, pkt: Bytes) -> Result<(), SendPacketError<T>> {
        let pkt = self.validate_tun(pkt)?;
        self.conn.send_datagram(pkt)?;
        self.metrics.datagrams_sent_total.inc();
        Ok(())
    }

    /// Send a packet to the client. The packet needs to fit entirely into a QUIC datagram.
    ///
    /// Unlike [Self::send], this method will wait for buffer space during congestion
    /// conditions, which effectively prioritizes old datagrams over new datagrams.
    pub async fn send_wait(&self, pkt: Bytes) -> Result<(), SendPacketError<T>> {
        let pkt = self.validate_tun(pkt)?;
        self.conn.send_datagram_wait(pkt).await?;
        Ok(())
    }

    /// Immediately closes the underlying connection with the given code and reason.
    ///
    /// All other methods on this Sender will return ConnectionClosed after this is called.
    pub fn close(&self, error_code: SnaptunConnErrors, reason: &[u8]) {
        self.conn.close(error_code.into(), reason)
    }

    fn validate_tun(&self, pkt: Bytes) -> Result<Bytes, SendPacketError<T>> {
        // if the connection is closed, immediately return an error
        if self.is_closed.load(Ordering::Acquire) {
            return Err(SendPacketError::ConnectionClosed);
        }
        // check if something changed in the state machine
        let current_state_version = self.state_machine.state_version();
        if self
            .last_state_version
            .compare_exchange(
                current_state_version - 1,
                current_state_version,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // state has been updated
            // check if the state machine is closed
            if self.state_machine.is_closed() {
                self.is_closed.store(true, Ordering::Release);
                return Err(SendPacketError::ConnectionClosed);
            }
            // if the state machine has changed, we need to re-fetch the addresses from it
            let addresses = self.state_machine.get_addresses()?;

            // Return the new sender with the updated addresses
            return Err(SendPacketError::NewAssignedAddress((
                Box::new(Sender::new(
                    self.state_machine.get_socket_addr(),
                    addresses,
                    self.conn.clone(),
                    self.state_machine.clone(),
                    current_state_version,
                    self.metrics.clone(),
                )),
                pkt,
            )));
        }

        Ok(pkt)
    }
}

impl<T: SnapTunToken> std::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("addresses", &self.addresses)
            .field("conn", &self.conn.stable_id())
            .field("last_state_version", &self.last_state_version)
            .finish()
    }
}

/// Send packet error.
#[derive(Debug, thiserror::Error)]
pub enum SendPacketError<T: SnapTunToken> {
    /// Connection closed.
    #[error("connection closed")]
    ConnectionClosed,
    /// New address assigned.
    #[error("address was re-assigned")]
    NewAssignedAddress((Box<Sender<T>>, Bytes)),
    /// Address assignment error.
    #[error("address assignment error: {0}")]
    AddressAssignmentError(#[from] AddressAssignmentError),
    /// QUIC send data gram error.
    #[error("underlying send error")]
    SendDatagramError(#[from] quinn::SendDatagramError),
}

/// Receiver can be used to receive packets from the client. It is returned by
/// [Server::accept_with_timeout].
pub struct Receiver<T: SnapTunToken> {
    metrics: ReceiverMetrics,
    conn: quinn::Connection,
    state_machine: Arc<TunnelStateMachine<T>>,
    last_state_version: AtomicUsize,
    is_closed: AtomicBool,
}

/// Packet receive error.
#[derive(Debug, thiserror::Error)]
pub enum ReceivePacketError {
    /// QUIC connection error.
    #[error("quinn error: {0}")]
    ConnectionError(#[from] quinn::ConnectionError),
    /// Connection closed.
    #[error("connection closed")]
    ConnectionClosed,
}

impl<T: SnapTunToken> Receiver<T> {
    fn new(
        conn: quinn::Connection,
        state_machine: Arc<TunnelStateMachine<T>>,
        initial_state_version: usize,
        metrics: ReceiverMetrics,
    ) -> Self {
        Self {
            conn,
            state_machine,
            last_state_version: AtomicUsize::new(initial_state_version),
            is_closed: AtomicBool::new(false),
            metrics,
        }
    }

    /// Receive a packet from the client.
    pub async fn receive(&self) -> Result<Bytes, ReceivePacketError> {
        // if the state machine changed, check whether the connection is still valid
        let current_state_version = self.state_machine.state_version();
        if self
            .last_state_version
            .compare_exchange(
                current_state_version - 1,
                current_state_version,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // state has been updated, check if the state machine is closed
            if self.state_machine.is_closed() {
                self.is_closed.store(true, Ordering::Release);
            }
        }
        if self.is_closed.load(Ordering::Acquire) {
            return Err(ReceivePacketError::ConnectionClosed);
        }
        let p = self.conn.read_datagram().await?;
        self.metrics.datagrams_received_total.inc();
        Ok(p)
    }
}

/// Control errors.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Parse control request error.
    #[error("parse control request error: {0}")]
    ParseError(#[from] ParseControlRequestError),
    /// Send control response error.
    #[error("send control response error: {0}")]
    SendError(#[from] SendControlResponseError),
    /// QUIC stopped error.
    #[error("wait for completion error: {0}")]
    StoppedError(#[from] quinn::StoppedError),
    /// Token expired.
    #[error("token expired")]
    TokenExpired,
    /// Connection closed prematurely.
    #[error("connection closed prematurely")]
    ClosedPrematurely,
}

/// Control is used to handle control requests from the client. It is returned by
/// [Server::accept_with_timeout] and must be polled to process control requests.
pub struct Control {
    driver_fut: Pin<Box<dyn Future<Output = Result<(), ControlError>> + Send>>,
}

impl Control {
    fn new<T>(conn: quinn::Connection, tunnel_state: Arc<TunnelStateMachine<T>>) -> Self
    where
        T: for<'de> Deserialize<'de> + Token + Clone,
    {
        let fut = async move {
            loop {
                tokio::select! {
                    _ = tunnel_state.await_token_expiry() => {
                        // token expired, close the connection
                        tunnel_state.shutdown();
                        conn.close(SnaptunConnErrors::TokenExpired.into(), b"token expired");
                        return Err(ControlError::TokenExpired)
                    }
                    res = conn.accept_bi() => {
                        let (mut snd, mut rcv) = match res {
                            Ok(v) => v,
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                tunnel_state.shutdown();
                                return Ok(());
                            }
                            Err(_) => {
                                tunnel_state.shutdown();
                                return Err(ControlError::ClosedPrematurely);
                            }
                        };

                        let mut buf = vec![0u8; MAX_CTRL_MESSAGE_SIZE];
                        let control_request  = recv_request(&mut buf, &mut rcv).await.inspect_err(|err| {
                            handle_invalid_request(&conn, err);
                            tunnel_state.shutdown();
                        })?;

                        let (code, body) = tunnel_state.process_control_request(SystemTime::now(), control_request);
                        send_http_response(&mut snd, code, &body).await
                            .inspect_err(|_| {
                                tunnel_state.shutdown();
                                conn.close(SnaptunConnErrors::InternalError.into(), b"send control response error");
                            })?;

                        snd.stopped().await?;
                    }
                }
            }
        };
        let driver_fut = Box::pin(fut);
        Self { driver_fut }
    }
}

impl Future for Control {
    type Output = Result<(), ControlError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.driver_fut.as_mut().poll(cx)
    }
}

/// Address assignment error.
#[derive(Debug, thiserror::Error)]
pub enum AddressAssignmentError {
    /// No address assigned.
    #[error("no address assigned")]
    NoAddressAssigned,
}

/// The state transitions of an snap-tun connection.
///
/// ```text
/// Unassigned --> Assigend --> Closed
/// ```
///
/// Once the connection is closed, it remains closed.
/// The state machine has an internal state version that is incremented whenever the state changes.
/// This can be used to cheaply detect changes in the state machine from the outside.
pub struct TunnelStateMachine<T: SnapTunToken> {
    remote_sock_addr: SocketAddr,
    validator: Arc<dyn TokenValidator<T>>,
    inner_state: RwLock<TunnelState>,
    state_version: AtomicUsize,
    // channel to notify the token termination about token expiry updates
    sender: watch::Sender<()>,
    receiver: watch::Receiver<()>,
}

impl<T: SnapTunToken> Drop for TunnelStateMachine<T> {
    fn drop(&mut self) {
        // Make sure that the state is closed and address is released
        self.shutdown();
    }
}

impl<T: SnapTunToken> TunnelStateMachine<T> {
    pub(crate) fn new(remote_sock_addr: SocketAddr, validator: Arc<dyn TokenValidator<T>>) -> Self {
        let (sender, receiver) = watch::channel(());

        Self {
            remote_sock_addr,
            validator,
            inner_state: Default::default(),
            state_version: AtomicUsize::new(0),
            sender,
            receiver,
        }
    }

    /// Processes an address assignment request, updates the internal protocol
    /// state and returns the response that should be sent back to the client.
    fn process_control_request(
        &self,
        now: SystemTime,
        control_request: ControlRequest,
    ) -> (http::StatusCode, Vec<u8>) {
        let mut inner_state = self.inner_state.write().expect("no fail");

        if let TunnelState::Closed = *inner_state {
            return (http::StatusCode::BAD_REQUEST, "tunnel is closed".into());
        }
        match control_request {
            ControlRequest::SocketAddrAssignment(token) => {
                self.locked_process_socket_addr_assignment_request(&mut inner_state, now, token)
            }
            ControlRequest::TokenUpdate(token) => {
                self.locked_process_token_update(&mut inner_state, now, token)
            }
        }
    }

    fn locked_process_token_update(
        &self,
        inner_state: &mut TunnelState,
        now: SystemTime,
        token: String,
    ) -> (http::StatusCode, Vec<u8>) {
        match self.validator.validate(now, &token) {
            Ok(claims) => {
                let token_expiry = claims.exp_time();

                // update internal state
                self.locked_update_tunnel_expiry(inner_state, token_expiry);

                let resp = TokenUpdateResponse {
                    valid_until: unix_epoch_from_system_time(token_expiry),
                };

                let mut resp_body = vec![];
                resp.encode(&mut resp_body).expect("no fail");
                (StatusCode::OK, resp_body)
            }
            Err(e) => map_token_validation_err_to_response(e),
        }
    }

    fn locked_process_socket_addr_assignment_request(
        &self,
        inner_state: &mut TunnelState,
        now: SystemTime,
        token: String,
    ) -> (http::StatusCode, Vec<u8>) {
        // XXX: assuming well-behaved clients, we should never encounter
        // a situation where a client did not authenticate before requesting a
        // socket addr.
        let token_expiry = match inner_state.token_validity() {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(
                    ?err,
                    "Failed to get token validity when processing address assignment request"
                );
                // this should, in principle, never happen assuming well-behaved
                // clients.
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid state transition".into(),
                );
            }
        };
        match self.validator.validate(now, &token) {
            Ok(_claims) => {
                self.locked_update_state(
                    inner_state,
                    TunnelState::SockAddrAssigned { token_expiry },
                );
                let resp = SocketAddrAssignmentResponse::from(self.remote_sock_addr);

                let mut resp_body = vec![];
                resp.encode(&mut resp_body).expect("no fail");
                (StatusCode::OK, resp_body)
            }
            Err(e) => map_token_validation_err_to_response(e),
        }
    }

    fn locked_update_tunnel_expiry(&self, inner_state: &mut TunnelState, token_expiry: SystemTime) {
        match inner_state {
            TunnelState::Unassigned => {
                *inner_state = TunnelState::SessionEstablished { token_expiry };
            }
            TunnelState::SessionEstablished { .. } => {
                *inner_state = TunnelState::SessionEstablished { token_expiry };
            }
            TunnelState::SockAddrAssigned { .. } => {
                *inner_state = TunnelState::SockAddrAssigned { token_expiry }
            }
            TunnelState::Closed => {
                tracing::error!("Updating tunnel token expiry but in closed state")
            }
        };
    }

    fn locked_update_state(&self, inner_state: &mut TunnelState, new_state: TunnelState) {
        tracing::debug!(%new_state, "Updating tunnel state");
        *inner_state = new_state;

        self.state_version.fetch_add(1, Ordering::AcqRel);

        if self.sender.send(()).is_err() {
            // This happens only if the channel is closed, which means that the token has
            // expired and the receiver is no longer interested in updates.
            tracing::debug!("Failed to notify token expiry update");
        }
    }

    fn get_addresses(&self) -> Result<Vec<EndhostAddr>, AddressAssignmentError> {
        let guard = self.inner_state.read().expect("no fail");

        match &*guard {
            TunnelState::SockAddrAssigned { .. } => Ok(vec![]),
            _ => Err(AddressAssignmentError::NoAddressAssigned),
        }
    }

    fn get_socket_addr(&self) -> Option<SocketAddr> {
        let guard = self.inner_state.read().expect("no fail");
        if let TunnelState::SockAddrAssigned { .. } = &*guard {
            return Some(self.remote_sock_addr);
        }
        None
    }

    async fn await_token_expiry(&self) {
        let mut expiry_notifier = self.receiver.clone();
        loop {
            let valid_duration = {
                let res = {
                    let guard = self.inner_state.read().expect("no fail");
                    guard.token_validity()
                };
                match res {
                    Ok(token_validity) => {
                        match token_validity.duration_since(SystemTime::now()) {
                            Ok(dur) => dur,
                            Err(_) => return, // token already expired
                        }
                    }
                    Err(err) => {
                        // Tunnel in an invalid state, should only happen if the tunnel is closed
                        // (e.g. token already expired).
                        tracing::warn!(%err, "Tunnel in an invalid state");
                        return;
                    }
                }
            };

            tokio::select! {
                _ = expiry_notifier.changed() => {
                    // token expiry updated
                    continue;
                }
                _ = tokio::time::sleep(valid_duration) => {
                    // Sleep until the token expires
                    return;
                }
            }
        }
    }

    fn state_version(&self) -> usize {
        self.state_version.load(Ordering::Acquire)
    }

    fn is_closed(&self) -> bool {
        if let TunnelState::Closed = *self.inner_state.read().expect("no fail") {
            return true;
        }
        false
    }

    fn shutdown(&self) {
        let mut inner_state = self.inner_state.write().expect("no fail");
        self.locked_update_state(&mut inner_state, TunnelState::Closed);
    }
}

fn map_token_validation_err_to_response(value: TokenValidatorError) -> (StatusCode, Vec<u8>) {
    match value {
        TokenValidatorError::JwtSignatureInvalid() => {
            tracing::info!("Invalid JWT Signature");
            (StatusCode::UNAUTHORIZED, "unauthorized".into())
        }
        TokenValidatorError::JwtError(err) => {
            tracing::info!(?err, "Token validation failed");
            (StatusCode::UNAUTHORIZED, "unauthorized".into())
        }
        TokenValidatorError::TokenExpired(err) => {
            tracing::info!(?err, "Token validation failed: token expired");
            (StatusCode::UNAUTHORIZED, "unauthorized".into())
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum TunnelStateError {
    #[error("invalid state: {0}")]
    InvalidState(TunnelState),
}

#[derive(Debug, Clone, Default)]
enum TunnelState {
    #[default]
    Unassigned,
    SessionEstablished {
        token_expiry: SystemTime,
    },
    SockAddrAssigned {
        token_expiry: SystemTime,
    },
    Closed,
}

impl TunnelState {
    fn token_validity(&self) -> Result<SystemTime, TunnelStateError> {
        match self {
            TunnelState::SessionEstablished { token_expiry } => Ok(*token_expiry),
            TunnelState::SockAddrAssigned { token_expiry, .. } => Ok(*token_expiry),
            _ => Err(TunnelStateError::InvalidState(self.clone())),
        }
    }
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Unassigned => write!(f, "Unassigned"),
            TunnelState::SessionEstablished { token_expiry } => {
                write!(
                    f,
                    "SessionEstablished ({})",
                    DateTime::<Utc>::from(*token_expiry)
                )
            }
            TunnelState::Closed => write!(f, "Closed"),
            TunnelState::SockAddrAssigned { token_expiry } => {
                write!(
                    f,
                    "Remote socket address assigned (valid until: {}).",
                    DateTime::<Utc>::from(*token_expiry),
                )
            }
        }
    }
}

#[derive(Debug)]
enum ControlRequest {
    SocketAddrAssignment(String),
    TokenUpdate(String),
}

fn handle_invalid_request(conn: &quinn::Connection, err: &ParseControlRequestError) {
    match err {
        ParseControlRequestError::ClosedPrematurely => {
            conn.close(
                SnaptunConnErrors::InternalError.into(),
                b"closed prematurely",
            );
        }
        ParseControlRequestError::ReadError(_) => {
            conn.close(SnaptunConnErrors::InternalError.into(), b"read error");
        }
        ParseControlRequestError::InvalidRequest(reason) => {
            conn.close(SnaptunConnErrors::InvalidRequest.into(), reason.as_bytes());
        }
        ParseControlRequestError::Unauthenticated(reason) => {
            conn.close(SnaptunConnErrors::Unauthenticated.into(), reason.as_bytes());
        }
    }
}

/// Error parsing control request.
#[derive(Debug, thiserror::Error)]
pub enum ParseControlRequestError {
    /// Invalid request.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Failed to read from QUIC stream.
    #[error("read error: {0}")]
    ReadError(#[from] quinn::ReadError),
    /// Unauthenticated request.
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
    /// Connection closed prematurely.
    #[error("closed prematurely")]
    ClosedPrematurely,
}

// We serialize the request/responses as actual http/1.1 requests. This is an
// arbitrary choice, as what matters is the semantics. However, we require so
// little flexibility in this matter that this is actually simpler than
// specifying a (protobuf) encoding for http-headers.
//
// We are liberal in what we accept:
// * The request MUST be a POST request.
// * The request MUST specify an Authorization-header of Bearer-type.
// * The request MUST have a correct path.
//
// All other headers are ignored.
async fn recv_request(
    buf: &mut [u8],
    rcv: &mut RecvStream,
) -> Result<ControlRequest, ParseControlRequestError> {
    use ParseControlRequestError::*;
    let mut cursor = 0;

    // Keep reading into the buffer
    while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
        cursor += n;
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        // Try to parse the request
        let Ok(httparse::Status::Complete(_body_offset)) = req.parse(&buf[..cursor]) else {
            // Check if we can keep reading
            if cursor >= buf.len() {
                return Err(InvalidRequest("request too big".into()));
            }
            continue;
        };

        // Parsed full request
        if !matches!(req.method, Some("POST")) {
            return Err(InvalidRequest("invalid method".into()));
        }

        // A first defensive check that the path is correct before we
        // actually act on it. (1)
        match req.path {
            Some(PATH_SOCK_ADDR_ASSIGNMENT) => {}
            Some(PATH_UPDATE_TOKEN) => {}
            Some(_) | None => return Err(InvalidRequest("invalid path".into())),
        }

        // Expect auth header
        let Some(auth_header) = req.headers.iter().find(|h| h.name == AUTH_HEADER) else {
            return Err(Unauthenticated("no auth header".into()));
        };
        let bearer_token = auth_header
            .value
            .strip_prefix(b"Bearer ")
            .ok_or(Unauthenticated(
                "bearer not found in authorization header".into(),
            ))
            .map(|x| String::from_utf8_lossy(x).to_string())?;

        // assert: req.path.is_some() and is valid, see (1)
        let path = req.path.unwrap();
        match path {
            PATH_SOCK_ADDR_ASSIGNMENT => {
                return Ok(ControlRequest::SocketAddrAssignment(bearer_token));
            }
            PATH_UPDATE_TOKEN => return Ok(ControlRequest::TokenUpdate(bearer_token)),
            path => unreachable!("invalid path: {path}"),
        }
    }

    Err(ClosedPrematurely)
}

/// Error when sending a control response.
#[derive(Debug, thiserror::Error)]
pub enum SendControlResponseError {
    /// I/O error.
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
    /// Stream was closed.
    #[error("stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
}

// todo: refine these response headers to be in line with the spec.
async fn send_http_response(
    stream: &mut SendStream,
    code: http::StatusCode,
    body: &[u8],
) -> Result<(), SendControlResponseError> {
    // write_all is not cancel-safe, so we use loops instead.
    async fn write_all(stream: &mut SendStream, data: &[u8]) -> std::io::Result<()> {
        let mut cursor = 0;
        while cursor < data.len() {
            cursor += stream.write(&data[cursor..]).await?;
        }
        Ok(())
    }

    write_all(
        stream,
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n",
            code.as_str(),
            code.canonical_reason().unwrap_or(""),
            body.len(),
        )
        .as_bytes(),
    )
    .await?;
    write_all(stream, body).await?;

    // Gracefully terminate the stream.
    stream.finish()?;
    Ok(())
}
