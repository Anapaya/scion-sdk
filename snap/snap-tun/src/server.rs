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
//! [Server::accept_with_timeout] expects the client to first send a session renew request followed
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
use ipnet::IpNet;
use prost::Message;
use quinn::{RecvStream, SendStream, VarInt};
use scion_proto::address::{EndhostAddr, IsdAsn};
use scion_sdk_token_validator::validator::{Token, TokenValidator, TokenValidatorError};
use serde::Deserialize;
use tokio::sync::watch;

use crate::{
    AUTH_HEADER, AddressAllocation, AddressAllocator, IPV4_WILDCARD, IPV6_WILDCARD,
    PATH_ADDR_ASSIGNMENT, PATH_SESSION_RENEWAL,
    metrics::{Metrics, ReceiverMetrics, SenderMetrics},
    requests::{
        AddrError, AddressAssignRequest, AddressAssignResponse, SessionRenewalResponse,
        unix_epoch_from_system_time,
    },
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
    /// Session expired error.
    SessionExpired = 4,
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

/// A client MUST first send a session renew request, followed by an address assignment request
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
    allocator: Arc<dyn AddressAllocator<T>>,
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
    pub fn new(
        allocator: Arc<dyn AddressAllocator<T>>,
        validator: Arc<dyn TokenValidator<T>>,
        metrics: Metrics,
    ) -> Self {
        Self {
            allocator,
            validator,
            metrics,
        }
    }

    /// Accept a connection and establish a tunnel.
    ///
    /// ## Tunnel initialization
    ///
    /// The client is expected to first send a session renew request, followed by an address
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
    /// The client is expected to first send a session renew request, followed by an address
    /// assignment request.
    async fn accept(
        &self,
        conn: quinn::Connection,
    ) -> Result<(Sender<T>, Receiver<T>, Control), AcceptError> {
        let state_machine = Arc::new(TunnelStateMachine::new(
            self.validator.clone(),
            self.allocator.clone(),
        ));

        //
        // First request MUST be a session renew request.
        let (session_renew_req, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |r| matches!(r, ControlRequest::SessionRenewal(_)),
            b"expected session renewal request",
        )
        .await?;

        let now = SystemTime::now();
        tracing::debug!(?now, request=?session_renew_req, "Got session renewal request");

        let (code, body) = state_machine.process_control_request(now, session_renew_req);
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

        //
        // Second request MUST be an address assignment request.
        let (address_assign_request, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |r| matches!(r, ControlRequest::AddressAssignment { .. }),
            b"expected address assignment request",
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
    metrics: SenderMetrics,
    addresses: Vec<EndhostAddr>,
    conn: quinn::Connection,
    state_machine: Arc<TunnelStateMachine<T>>,
    last_state_version: AtomicUsize,
    is_closed: AtomicBool,
}

impl<T: SnapTunToken> Sender<T> {
    fn new(
        addresses: Vec<EndhostAddr>,
        conn: quinn::Connection,
        state_machine: Arc<TunnelStateMachine<T>>,
        initial_state_version: usize,
        metrics: SenderMetrics,
    ) -> Self {
        Self {
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

    /// Returns the remote address of the underling QUIC connection.
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
    pub fn close(&self, code: u32, reason: &'static [u8]) {
        self.conn.close(code.into(), reason);
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
    /// Session expired.
    #[error("session expired")]
    SessionExpired,
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
                    _ = tunnel_state.await_session_expiry() => {
                        // session expired, close the connection
                        tunnel_state.shutdown();
                        conn.close(SnaptunConnErrors::SessionExpired.into(), b"session expired");
                        return Err(ControlError::SessionExpired)
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

/// The state transitions of an edgetun connection.
///
/// ```text
/// Unassigned --> Assigend --> Closed
/// ```
///
/// Once the connection is closed, it remains closed.
/// The state machine has an internal state version that is incremented whenever the state changes.
/// This can be used to cheaply detect changes in the state machine from the outside.
pub struct TunnelStateMachine<T: SnapTunToken> {
    validator: Arc<dyn TokenValidator<T>>,
    allocator: Arc<dyn AddressAllocator<T>>,
    inner_state: RwLock<TunnelState>,
    state_version: AtomicUsize,
    // channel to notify the session termination about session expiry updates
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
    pub(crate) fn new(
        validator: Arc<dyn TokenValidator<T>>,
        allocator: Arc<dyn AddressAllocator<T>>,
    ) -> Self {
        let (sender, receiver) = watch::channel(());

        Self {
            validator,
            allocator,
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
            ControlRequest::AddressAssignment(token, address_assign_request) => {
                self.locked_process_addr_assignment_request(
                    &mut inner_state,
                    now,
                    token,
                    address_assign_request,
                )
            }
            ControlRequest::SessionRenewal(token) => {
                self.locked_process_session_renewal(&mut inner_state, now, token)
            }
        }
    }

    fn locked_process_session_renewal(
        &self,
        inner_state: &mut TunnelState,
        now: SystemTime,
        token: String,
    ) -> (http::StatusCode, Vec<u8>) {
        match self.validator.validate(now, &token) {
            Ok(claims) => {
                let token_expiry = claims.exp_time();

                // update internal state
                self.locked_update_tunnel_session(inner_state, token_expiry);

                let resp = SessionRenewalResponse {
                    valid_until: unix_epoch_from_system_time(token_expiry),
                };

                let mut resp_body = vec![];
                resp.encode(&mut resp_body).expect("no fail");
                (StatusCode::OK, resp_body)
            }
            Err(TokenValidatorError::JwtSignatureInvalid()) => {
                tracing::info!("Invalid signature");
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
            Err(TokenValidatorError::JwtError(err)) => {
                tracing::info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
            Err(TokenValidatorError::TokenExpired(err)) => {
                tracing::info!(?err, "Token validation failed: token expired");
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
        }
    }

    /// Processes an address assignment request, updates the internal protocol
    /// state and returns the response that should be sent back to the client.
    fn locked_process_addr_assignment_request(
        &self,
        inner_state: &mut TunnelState,
        now: SystemTime,
        token: String,
        addr_assignments: AddressAssignRequest,
    ) -> (http::StatusCode, Vec<u8>) {
        match self.validator.validate(now, &token) {
            Ok(claims) => {
                if addr_assignments.requested_addresses.len() > 1 {
                    // We only implement single address assignments at the moment
                    tracing::warn!(
                        "Address assignment failed, multiple address assignments not supported"
                    );
                    return (
                        StatusCode::NOT_IMPLEMENTED,
                        "multiple address assignments are not supported".into(),
                    );
                }

                let mut requests: Vec<(IsdAsn, IpNet)> = match addr_assignments
                    .requested_addresses
                    .iter()
                    .map(|range| range.try_into())
                    .collect::<Result<Vec<_>, AddrError>>()
                {
                    Ok(reqs) => reqs,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "a requested address assignment contained an invalid address range"
                                .into(),
                        );
                    }
                };

                // We only implement single address assignments at the moment
                if requests
                    .iter()
                    .any(|(_, net)| net.prefix_len() != net.max_prefix_len())
                {
                    tracing::warn!(
                        "Address assignment failed, prefix assignments are not supported"
                    );
                    return (
                        StatusCode::NOT_IMPLEMENTED,
                        "prefix assignments are not supported".into(),
                    );
                }

                // If no addresses are requested, try allocating either a IPv4 or IPv6 address.
                if requests.is_empty() {
                    requests.push((IsdAsn::WILDCARD, IPV4_WILDCARD));
                    requests.push((IsdAsn::WILDCARD, IPV6_WILDCARD));
                }

                // check that our current state is valid
                let session_expiry = match inner_state.session_validity() {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::error!(
                            ?err,
                            "Failed to get session validity when processing address assignment request"
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "session state invalid".into(),
                        );
                    }
                };

                // We return the first successfully allocated address.
                let mut assigned_address: Option<AddressAllocation> = None;
                for (requested_isd_as, requested_net) in requests.iter() {
                    match self
                        .allocator
                        .allocate(*requested_isd_as, *requested_net, claims.clone())
                    {
                        Ok(allocation) => {
                            assigned_address = Some(allocation);
                            break;
                        }
                        Err(err) => {
                            tracing::debug!(
                                ?err,
                                "Address allocation failed for ISD-AS {requested_isd_as} and net {requested_net}"
                            );
                        }
                    }
                }

                // Only return an error if no addresses were assigned.
                let Some(assigned_address) = assigned_address else {
                    tracing::warn!(
                        "Address assignment failed - no available addresses for: {requests:?}",
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        "either requested address is unavailable, or no addresses are available"
                            .into(),
                    );
                };

                self.locked_update_state(
                    inner_state,
                    TunnelState::Assigned {
                        session_expiry,
                        address: assigned_address.clone(),
                    },
                );

                let resp = AddressAssignResponse {
                    assigned_addresses: vec![(&assigned_address.address).into()],
                };

                let mut resp_body = vec![];
                resp.encode(&mut resp_body).expect("no fail");
                (StatusCode::OK, resp_body)
            }
            Err(TokenValidatorError::JwtSignatureInvalid()) => {
                tracing::info!("Invalid JWT Signature");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::JwtError(err)) => {
                tracing::info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::TokenExpired(err)) => {
                tracing::info!(?err, "Token validation failed: token expired");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
        }
    }

    fn locked_update_tunnel_session(
        &self,
        inner_state: &mut TunnelState,
        session_expiry: SystemTime,
    ) {
        match inner_state {
            TunnelState::Unassigned => {
                *inner_state = TunnelState::SessionEstablished { session_expiry };
            }
            TunnelState::SessionEstablished { .. } => {
                *inner_state = TunnelState::SessionEstablished { session_expiry };
            }
            TunnelState::Assigned { address, .. } => {
                *inner_state = TunnelState::Assigned {
                    session_expiry,
                    address: address.clone(),
                };
            }
            // XXX(bunert): Should not happen as we error out before updating the state.
            TunnelState::Closed => tracing::error!("Updating tunnel session but in closed state"),
        };
    }

    fn locked_update_state(&self, inner_state: &mut TunnelState, new_state: TunnelState) {
        tracing::debug!(%new_state, "Updating tunnel state");
        *inner_state = new_state;

        self.state_version.fetch_add(1, Ordering::AcqRel);

        if self.sender.send(()).is_err() {
            // This happens only if the channel is closed, which means that the session has
            // expired and the receiver is no longer interested in updates.
            tracing::debug!("Failed to notify session expiry update");
        }
    }

    fn get_addresses(&self) -> Result<Vec<EndhostAddr>, AddressAssignmentError> {
        let guard = self.inner_state.read().expect("no fail");
        if let TunnelState::Assigned {
            address,
            session_expiry: _,
        } = &*guard
        {
            return Ok(vec![address.address]);
        }
        Err(AddressAssignmentError::NoAddressAssigned)
    }

    async fn await_session_expiry(&self) {
        let mut expiry_notifier = self.receiver.clone();
        loop {
            let valid_duration = {
                let res = {
                    let guard = self.inner_state.read().expect("no fail");
                    guard.session_validity()
                };
                match res {
                    Ok(session_validity) => {
                        match session_validity.duration_since(SystemTime::now()) {
                            Ok(dur) => dur,
                            Err(_) => return, // session already expired
                        }
                    }
                    Err(err) => {
                        // Tunnel in an invalid state, should only happen if the tunnel is closed
                        // (e.g. session already expired).
                        tracing::warn!(%err, "Tunnel in an invalid state");
                        return;
                    }
                }
            };

            tokio::select! {
                _ = expiry_notifier.changed() => {
                    // session expiry updated
                    continue;
                }
                _ = tokio::time::sleep(valid_duration) => {
                    // Sleep until the session expires
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

        // Put address grant on hold
        if let TunnelState::Assigned {
            session_expiry: _,
            address,
        } = &*inner_state
        {
            if !self.allocator.put_on_hold(address.id.clone()) {
                tracing::error!(addr=?address.address, "Could not set address to hold during shutdown - address was released while tunnel was still assigned");
            }
        }

        self.locked_update_state(&mut inner_state, TunnelState::Closed);
    }
}

#[derive(Debug, thiserror::Error)]
enum TunnelStateError {
    #[error("invalid state: {0}")]
    InvalidState(TunnelState),
}

#[derive(Debug, Clone)]
enum TunnelState {
    Unassigned,
    SessionEstablished {
        session_expiry: SystemTime,
    },
    Assigned {
        session_expiry: SystemTime,
        address: AddressAllocation,
    },
    Closed,
}

impl TunnelState {
    fn session_validity(&self) -> Result<SystemTime, TunnelStateError> {
        match self {
            TunnelState::SessionEstablished { session_expiry } => Ok(*session_expiry),
            TunnelState::Assigned { session_expiry, .. } => Ok(*session_expiry),
            _ => Err(TunnelStateError::InvalidState(self.clone())),
        }
    }
}

impl Default for TunnelState {
    fn default() -> Self {
        Self::Unassigned
    }
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Unassigned => write!(f, "Unassigned"),
            TunnelState::SessionEstablished { session_expiry } => {
                write!(
                    f,
                    "SessionEstablished ({})",
                    DateTime::<Utc>::from(*session_expiry)
                )
            }
            TunnelState::Assigned {
                session_expiry,
                address,
            } => {
                write!(
                    f,
                    "Assigned (valid until: {}, addresses: [{}])",
                    DateTime::<Utc>::from(*session_expiry),
                    address.address
                )
            }
            TunnelState::Closed => write!(f, "Closed"),
        }
    }
}

#[derive(Debug)]
enum ControlRequest {
    AddressAssignment(String, AddressAssignRequest),
    SessionRenewal(String),
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
        let Ok(httparse::Status::Complete(body_offset)) = req.parse(&buf[..cursor]) else {
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
            Some(PATH_ADDR_ASSIGNMENT) => {}
            Some(PATH_SESSION_RENEWAL) => {}
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
            PATH_ADDR_ASSIGNMENT => {
                // Read rest of the stream, we expect a body
                while let Some(n) = rcv.read(&mut buf[cursor..]).await? {
                    cursor += n;
                    if cursor >= buf.len() {
                        return Err(InvalidRequest("request too big".into()));
                    }
                }

                // parse address assignment request
                let Ok(addr_req) = AddressAssignRequest::decode(&buf[body_offset..cursor]) else {
                    return Err(InvalidRequest(
                        "error when parsing address assignment request".into(),
                    ));
                };
                return Ok(ControlRequest::AddressAssignment(bearer_token, addr_req));
            }
            PATH_SESSION_RENEWAL => return Ok(ControlRequest::SessionRenewal(bearer_token)),
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use snap_tokens::{Pssid, snap_token::SnapTokenClaims};

    use super::*;

    mod address_allocation {

        fn setup() -> (TunnelStateMachine<SnapTokenClaims>, Arc<MockAllocator>) {
            let alloc = Arc::new(MockAllocator {
                is_allocated: AtomicBool::new(false),
                is_on_hold: AtomicBool::new(false),
            });

            let tun = TunnelStateMachine::new(Arc::new(MockValidator), alloc.clone());
            // Prepare the state machine by doing a session renewal first
            let (status, body) = tun.process_control_request(
                SystemTime::now(),
                ControlRequest::SessionRenewal("valid_token".into()),
            );
            assert_eq!(
                status,
                http::StatusCode::OK,
                "failed to renew session - body: {body:?}"
            );

            (tun, alloc)
        }

        use snap_tokens::snap_token::SnapTokenClaims;

        use super::*;

        #[test]
        fn should_put_on_hold_after_shutdown() {
            let (tun, alloc) = setup();

            let (status, body) = tun.process_control_request(
                SystemTime::now(),
                ControlRequest::AddressAssignment(
                    "valid_token".into(),
                    AddressAssignRequest {
                        requested_addresses: vec![],
                    },
                ),
            );
            assert_eq!(status, http::StatusCode::OK, "failed - body: {body:?}");
            assert!(alloc.is_allocated.load(Ordering::Acquire));
            tun.shutdown();
            assert!(alloc.is_on_hold.load(Ordering::Acquire));
        }

        #[test]
        fn should_put_on_hold_after_drop() {
            let (tun, alloc) = setup();

            let (status, body) = tun.process_control_request(
                SystemTime::now(),
                ControlRequest::AddressAssignment(
                    "valid_token".into(),
                    AddressAssignRequest {
                        requested_addresses: vec![],
                    },
                ),
            );
            assert_eq!(status, http::StatusCode::OK, "failed - body: {body:?}");
            assert!(alloc.is_allocated.load(Ordering::Acquire));
            drop(tun);
            assert!(alloc.is_on_hold.load(Ordering::Acquire));
        }
    }

    struct MockValidator;
    impl TokenValidator<SnapTokenClaims> for MockValidator {
        fn validate(
            &self,
            now: SystemTime,
            _: &str,
        ) -> Result<SnapTokenClaims, TokenValidatorError> {
            Ok(SnapTokenClaims {
                pssid: Pssid::new(),
                exp: (now.duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600))
                    .as_secs(),
            })
        }
    }

    struct MockAllocator {
        is_allocated: AtomicBool,
        is_on_hold: AtomicBool,
    }
    impl AddressAllocator<SnapTokenClaims> for MockAllocator {
        fn allocate(
            &self,
            isd_as: IsdAsn,
            prefix: IpNet,
            claims: SnapTokenClaims,
        ) -> Result<AddressAllocation, crate::AddressAllocationError> {
            if self.is_allocated.load(Ordering::Acquire) {
                return Err(crate::AddressAllocationError::NoAddressesAvailable);
            }
            self.is_allocated.store(true, Ordering::Release);

            Ok(AddressAllocation {
                id: crate::AddressAllocationId {
                    registry_id: 0,
                    alloc_id: claims.id(),
                },
                address: EndhostAddr::new(isd_as, prefix.addr()),
            })
        }

        fn put_on_hold(&self, _id: crate::AddressAllocationId) -> bool {
            self.is_on_hold.store(true, Ordering::Release);
            true
        }

        fn deallocate(&self, _id: crate::AddressAllocationId) -> bool {
            false
        }
    }
}
