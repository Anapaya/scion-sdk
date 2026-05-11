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
//! # The edgetun server.
//!
//! This module contains the edgetun-[crate::server::Server]. The
//! QUIC-connection handling is left to the caller. That is, after accepting a
//! QUIC-connection, [crate::server::Server::accept_with_timeout] will establish
//! an edgetun with a client, provided the peer behaves as expected and sends
//! the required control requests.
//!
//! The [crate::server::Server::accept_with_timeout] method produces three
//! different objects: [crate::server::Incoming], [crate::server::Outgoing], and
//! [crate::server::Control]. The first is used to receive packets from the
//! peer, the second to send packets to the peer, possibly segmenting them to
//! fit them into the underlying MTU. The third is used to _drive_ the control
//! state of the connection.
//!
//! [crate::server::Server::accept_with_timeout] expects the client to first
//! send a session renew request followed by an address assignment request. If
//! the client doesn't do so within [crate::server::ACCEPT_TIMEOUT], a
//! [crate::server::AcceptError::Timeout] error is returned and the connection
//! closed. The rationale behind this is that bogus client connections should be
//! closed as quickly as possible.
//!
//! ## Synopsis
//!
//! ```no_exec
//! loop {
//!   let quic_conn = endpoint.accept().await?;
//!
//!   let (incoming, outgoing, control) = edgetun_server.accept(quic_conn)?;
//!   let _ = tokio::spawn(control); // drive control state
//!
//!   let _ = tokio::spawn(async move {
//!     while Ok(p) = incoming.receive().await {
//!       // process incoming packet
//!     }
//!   });
//!
//!   // send an outgoing packet
//!   outgoing.send(p).await;
//! }
//! ```
//!
//! ## Future work
//!
//! * Currently, online-updates of route advertisements is not supported.
//! * The MTU cannot be dynamically adjusted.
//! * No traffic policies are applied at the moment. In particular, incoming packets that have an
//!   invalid source address are not dropped. This is left to the caller.
//!
//! ## Deviations and refinements vis-à-vis the specification
//!
//! * The client MUST send an address assignment request as the first course of action. Otherwise,
//!   the tunnel cannot be established.
//!
//! ## Known issues
//!
//! * The validity period of the address assignment is currently bound to the token expiration. This
//!   should be changed so that the address assignment reports the actual validity period of the
//!   assignment itself.
//!
//! ## Refinements
//!
//! * In case of (unexpected) connection closure, the errors returned by [crate::server::Incoming],
//!   [crate::server::Outgoing], and [crate::server::Control] might be inconsistent; though all of
//!   them are guaranteed to return an error eventually.
//!
//! ## Implementation guidelines
//!
//! Currently, edgetun only supports three types of control requests and this is likely to remain
//! unchanged for some time to come. We keep tight constraints on the buffer allocations that are
//! under the control of the client. I.e., the total buffer size for a client request is
//! [crate::server::CTRL_REQUEST_BUF_SIZE] and strict timeouts are enforced when
//! receiving and parsing requests.

use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, RwLock},
    time::SystemTime,
    vec,
};

use anapaya_quinn::{RecvStream, SendStream, VarInt};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::StatusCode;
use ipnet::IpNet;
use prost::Message;
use scion_sdk_token_validator::validator::{Token, TokenValidator, TokenValidatorError};
use scion_stack::quic::QuinnConn;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    address_allocation::{AddressAllocation, AddressAllocator},
    fragmenting::{Defragmenter, Fragmenter, FragmenterSendError},
    ip::IpPacketValidator,
    metrics::{EdgeTunMetrics, IncomingMetrics, OutgoingMetrics},
    requests::{
        AddressAssignRequest, AddressAssignResponse, IpAddrError, IpAddressRange,
        RouteAdvertisementResponse, SessionRenewalResponse, unix_epoch_from_system_time,
    },
};

/// Well-defined edgetun connection error codes.
// Well defined edgetun connection error codes.
#[derive(Copy, Clone)]
pub enum EdgetunConnErrors {
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

impl From<EdgetunConnErrors> for anapaya_quinn::VarInt {
    fn from(e: EdgetunConnErrors) -> Self {
        VarInt::from_u32(e as u32)
    }
}
/// Trait alias for tokens that can be used to authenticate edge-tun connections.
pub trait EdgeTunToken: for<'de> Deserialize<'de> + Token + Clone {}
impl<T: for<'de> Deserialize<'de> + Token + Clone> EdgeTunToken for T {}

/// A client MUST first send a session renew request, followed by an address assignment request
/// within the `ACCEPT_TIMEOUT`.
pub const ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// All control requests issued by the client MUST NOT exceed
/// `CTRL_REQUEST_BUF_SIZE` bytes.
pub const CTRL_REQUEST_BUF_SIZE: usize = 4096;

// todo(dsd): correct with actual paths
/// Control-protocol path for address assignment requests.
pub const PATH_ADDR_ASSIGNMENT: &str = "/connectrpc.v1.edgetun/assign_addresses";
/// Control-protocol path for session renewal requests.
pub const PATH_SESSION_RENEWAL: &str = "/connectrpc.v1.edgetun/renew_session";
/// Control-protocol path for route advertisement requests.
pub const PATH_ROUTES_REQUEST: &str = "/connectrpc.v1.edgetun/get_routes";
/// HTTP header name used to carry the bearer token.
pub const AUTH_HEADER: &str = "Authorization";

/// Build a server that accepts connection from clients.
///
/// # Implementation notes
///
/// We use dynamic dispatch (e.g., `Arc<dyn AddressAllocator<C>>`) for methods that are
/// involved in control signals and static dispatch for calls that are on the
/// critical path for data traffic (`P: TunneledPacket`). The rationale is that
/// the ratio between control signals and data packets is very small.
pub struct Server<C> {
    metrics: EdgeTunMetrics,
    validator: Arc<dyn TokenValidator<C>>,
    allocator: Arc<dyn AddressAllocator<C>>,
    advertisements: Vec<IpAddressRange>,
    mtu: u16,
    /// Number of defragmentation queues to use per connection.
    defrag_queues: usize,
}

/// Error returned when a connection cannot be accepted as an edge-tun tunnel.
#[derive(Debug, Error)]
pub enum AcceptError {
    /// The client did not complete the handshake within [`ACCEPT_TIMEOUT`].
    #[error("Timeout reached.")]
    Timeout,
    /// The underlying QUIC connection was lost.
    #[error("Quinn connection error: {0}")]
    ConnectionError(#[from] anapaya_quinn::ConnectionError),
    /// Parsing a control request from the client failed.
    #[error("Parse control request error: {0}")]
    ParseControlRequestError(#[from] ParseControlRequestError),
    /// Sending a control response to the client failed.
    #[error("Send control response error: {0}")]
    SendControlResponseError(#[from] SendControlResponseError),
    /// The client sent an unexpected control request.
    #[error("Unexpected control request")]
    UnexpectedControlRequest,
}

impl<T> Server<T>
where
    T: EdgeTunToken,
{
    /// Create a new server that can accept QUIC connections and turn them into
    /// edge tunnels.
    ///
    /// ## Limitations
    ///
    /// * Currently only individual addresses can be requested and assigned.
    /// * The advertised routes are statically configured.
    pub fn new(
        validator: Arc<dyn TokenValidator<T>>,
        allocator: Arc<dyn AddressAllocator<T>>,
        routes: Vec<IpNet>,
        mtu: u16,
        defrag_queues: usize,
        metrics: EdgeTunMetrics,
    ) -> Self {
        Self {
            metrics,
            validator,
            allocator,
            advertisements: routes.into_iter().map(IpAddressRange::from).collect(),
            mtu,
            defrag_queues,
        }
    }

    /// Accept a connection and establish a tunnel.
    ///
    /// ## Tunnel initialization
    ///
    /// The client is expected to first send a session renew request, followed by an address
    /// assignment request. The connection is closed with a [EdgetunConnErrors::Timeout] if the
    /// client does not send the requests within [ACCEPT_TIMEOUT].
    pub async fn accept_with_timeout<Q: QuinnConn + 'static>(
        &self,
        conn: Q,
    ) -> Result<(Incoming<T, Q>, Outgoing<T, Q>, Control), AcceptError> {
        match tokio::time::timeout(ACCEPT_TIMEOUT, self.accept(conn.clone())).await {
            Ok(res) => res,
            Err(_elapsed) => {
                conn.close(
                    EdgetunConnErrors::Timeout.into(),
                    b"timeout establishing edgetun",
                );
                Err(AcceptError::Timeout)
            }
        }
    }

    /// Accept a connection and establish a tunnel.
    ///
    /// ## Tunnel initialization
    ///
    /// The client is expected to first send a session renew request, followed by an address
    /// assignment request.
    #[instrument(skip_all, fields(conn_id = conn.stable_id()))]
    #[allow(clippy::type_complexity)]
    async fn accept<Q: QuinnConn + 'static>(
        &self,
        conn: Q,
    ) -> Result<(Incoming<T, Q>, Outgoing<T, Q>, Control), AcceptError> {
        let state_machine = Arc::new(TunnelStateMachine::new(
            self.validator.clone(),
            self.allocator.clone(),
            self.advertisements.clone(),
        ));

        //
        // First request MUST be a session renew request.
        let (session_renewal_request, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |req| matches!(req, ControlRequest::SessionRenewal(..)),
            b"expected session renew request",
        )
        .await?;

        let now = SystemTime::now();
        debug!(?now, request=?session_renewal_request, "process expected session renewal request");

        let (code, body) = state_machine.process_control_request(now, session_renewal_request);
        let send_res = send_http_response(&mut snd, code, &body).await;
        if !code.is_success() {
            conn.close(EdgetunConnErrors::InvalidRequest.into(), &body);
            return Err(AcceptError::UnexpectedControlRequest);
        }
        if let Err(e) = send_res {
            conn.close(
                EdgetunConnErrors::InternalError.into(),
                b"failed to send control response",
            );
            return Err(AcceptError::SendControlResponseError(e));
        }

        //
        // Second request MUST be an address assignment request.
        let (address_assign_request, mut snd, _rcv) = receive_expected_control_request(
            &conn,
            |req| matches!(req, ControlRequest::AddressAssignment(..)),
            b"expected address assignment request",
        )
        .await?;

        let now = SystemTime::now();
        debug!(?now, request=?address_assign_request, "process expected address assignment request");
        let (code, body) = state_machine.process_control_request(now, address_assign_request);
        let send_res = send_http_response(&mut snd, code, &body).await;
        if !code.is_success() {
            conn.close(EdgetunConnErrors::InvalidRequest.into(), &body);
            return Err(AcceptError::UnexpectedControlRequest);
        }
        if let Err(e) = send_res {
            conn.close(
                EdgetunConnErrors::InternalError.into(),
                b"failed to send control response",
            );
            return Err(AcceptError::SendControlResponseError(e));
        }

        let incoming = Incoming::<T, Q> {
            metrics: self.metrics.incoming.clone(),
            state: state_machine.clone(),
            conn: conn.clone(),
            defrag: Defragmenter::new(self.defrag_queues, self.metrics.defrag.clone()),
        };

        let outgoing = Outgoing::<T, Q> {
            metrics: self.metrics.outgoing.clone(),
            addresses: state_machine.get_addresses(),
            conn: conn.clone(),
            con_state: state_machine.clone(),
            fragmenter: Fragmenter::new(self.mtu as usize, self.metrics.fragment.clone()),
            send_queue: Default::default(),
        };

        let ctr = Control::new(conn, state_machine);
        Ok((incoming, outgoing, ctr))
    }
}

async fn receive_expected_control_request<Q: QuinnConn + 'static>(
    conn: &Q,
    expected: fn(&ControlRequest) -> bool,
    wrong_request_conn_close_reason: &'static [u8],
) -> Result<(ControlRequest, SendStream, RecvStream), AcceptError> {
    let (snd, mut rcv) = conn
        .accept_bi()
        .await
        .map_err(AcceptError::ConnectionError)?;
    let mut buf = vec![0u8; CTRL_REQUEST_BUF_SIZE];
    let req = match parse_http_request(&mut buf, &mut rcv).await {
        Ok(req) if expected(&req) => req,
        Ok(_) => {
            conn.close(
                EdgetunConnErrors::InvalidRequest.into(),
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

/// Receive packets from the client.
pub struct Incoming<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    metrics: IncomingMetrics,
    state: Arc<TunnelStateMachine<C>>,
    conn: Q,
    defrag: Defragmenter,
}

impl<C, Q> Incoming<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    /// Receive a packet. If the connection is closed for any reason, this
    /// method returns [ReceivePacketError::ConnectionClosed]. Note that if the
    /// connection was closed due to an underlying connection error, the
    /// corresponding error is returned by the [Control] future.
    pub async fn receive(&mut self) -> Result<Bytes, ReceivePacketError> {
        loop {
            if self.state.is_closed() {
                return Err(ReceivePacketError::ConnectionClosed);
            }

            let data = match self.conn.read_datagram().await {
                Ok(data) => data,
                Err(e) => {
                    self.metrics.stream_receive_errors_total.inc();
                    return Err(e.into());
                }
            };

            self.metrics.datagrams_received_total.inc();

            // feed the data into the defragmenter
            match self.defrag.recv(&data) {
                // we have a complete packet
                Ok(Some(p)) => {
                    // check that it's actually an IP packet
                    if let Err(e) = IpPacketValidator::check(p.payload) {
                        warn!(conn_id=self.conn.stable_id(), error=?e, "received invalid ip packet");
                        self.metrics.stream_receive_errors_total.inc();
                        continue;
                    }

                    self.metrics.packets_received_total.inc();
                    return Ok(Bytes::copy_from_slice(p.payload));
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(conn_id=self.conn.stable_id(), error=?e, "defragment frame rejected");
                }
            }
        }
    }
}

/// Error returned by [`Incoming::receive`].
#[derive(Debug, Error)]
pub enum ReceivePacketError {
    /// The connection was closed (either cleanly or due to an error).
    #[error("connection closed")]
    ConnectionClosed,
}

impl From<anapaya_quinn::ConnectionError> for ReceivePacketError {
    fn from(_value: anapaya_quinn::ConnectionError) -> Self {
        ReceivePacketError::ConnectionClosed
    }
}

/// Send packets to the client.
///
/// The assumption is that this object is owned by a single (kernel) thread. The
/// provided `send_wait()`-method awaits the underlying congestion control to
/// make room for the packet to be sent.
pub struct Outgoing<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    metrics: OutgoingMetrics,
    addresses: Vec<IpAddr>,
    conn: Q,
    con_state: Arc<TunnelStateMachine<C>>,
    fragmenter: Fragmenter,
    send_queue: VecDeque<Bytes>,
}

impl<C, Q> Outgoing<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    /// Return the assigned client endhost address.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.addresses.clone()
    }

    /// Send a packet to the client, possibly segmenting it. Awaits all segments
    /// to be delivered, possibly awaiting underlying congestion.
    ///
    /// The outgoing part of the connection is assumed to be owned by a _single_
    /// kernel thread. Therefore, the `send()`-function accepts an exclusive
    /// reference `&mut self`.
    ///
    /// ## Errors
    ///
    /// The function returns an error if either the connection is in an
    /// erroneous state (non-recoverable), or the address assignment has
    /// changed. In the latter case, [SendPacketError::NewAssignedAddress] is
    /// returned with a new [Outgoing] object that is assigned the new address.
    /// The old object will return a [SendPacketError::ConnectionClosed] error.
    ///
    /// ## Future extensions
    ///
    /// In a future extension, this method might accept the stream id to be used
    /// for this packet.
    pub async fn send_wait(&mut self, packet: Bytes) -> Result<(), SendPacketError<C, Q>> {
        let now = SystemTime::now();
        let addresses = self.con_state.get_address_check_valid_until(now);
        if addresses.is_empty() {
            // no addresses assigned, we cannot send
            return Err(SendPacketError::ConnectionClosed);
        }

        // addresses changed - return a new tunnel to replace the current one
        if self.addresses.ne(&addresses) {
            return Err(SendPacketError::NewAssignedAddress((
                Box::new(Self {
                    metrics: self.metrics.clone(),
                    addresses,
                    conn: self.conn.clone(),
                    con_state: self.con_state.clone(),
                    fragmenter: self.fragmenter.clone(),
                    send_queue: Default::default(),
                }),
                packet,
            )));
        }

        // Update our MTU
        let new = self
            .conn
            .max_datagram_size()
            .ok_or(SendPacketError::SendDatagramError(
                anapaya_quinn::SendDatagramError::UnsupportedByPeer,
            ))?;

        let curr = self.fragmenter.mtu();

        if new != curr {
            tracing::info!(curr, new, "Updating max frame size");
            self.fragmenter.set_mtu(new);
        }

        // fragment the packet
        self.fragmenter.send(&packet, |p| {
            self.send_queue.push_back(Bytes::from_owner(p.to_vec()))
        })?;

        self.metrics.datagrams_sent_total.inc();
        while let Some(p) = self.send_queue.pop_front() {
            self.conn.send_datagram_wait(p).await?;
            self.metrics.packets_sent_total.inc();
        }

        Ok(())
    }
}

impl<C, Q> std::fmt::Debug for Outgoing<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outgoing")
            .field("addresses", &self.addresses)
            .finish()
    }
}

/// Error returned by [`Outgoing::send_wait`].
#[derive(Debug, Error)]
pub enum SendPacketError<C, Q>
where
    C: EdgeTunToken,
    Q: QuinnConn,
{
    /// The connection was closed.
    #[error("connection closed")]
    ConnectionClosed,
    /// Tunnel address was re-assigned, returns a new tunnel to use for the new address
    #[error("address was re-assigned")]
    NewAssignedAddress((Box<Outgoing<C, Q>>, Bytes)),
    /// The underlying QUIC datagram send failed.
    #[error("underlying send error")]
    SendDatagramError(#[from] anapaya_quinn::SendDatagramError),
    /// Packet fragmentation failed.
    #[error("fragmentation error: {0}")]
    FragmentError(#[from] FragmenterSendError),
}

/// Error returned while driving the control state of a tunnel connection.
#[derive(Debug, Error)]
pub enum ControlError {
    /// Parsing a control request failed.
    #[error("parse control request error: {0}")]
    ParseError(#[from] ParseControlRequestError),
    /// Sending a control response failed.
    #[error("send control response error: {0}")]
    SendError(#[from] SendControlResponseError),
    /// Waiting for stream completion failed.
    #[error("wait for completion error: {0}")]
    StoppedError(#[from] anapaya_quinn::StoppedError),
    /// The client's session expired.
    #[error("session expired")]
    SessionExpired,
    /// The connection was closed before the tunnel was fully established.
    #[error("connection closed prematurely")]
    ClosedPrematurely,
}

/// Drive the control state of the tunnel connection.
///
/// ## Error states
///
/// All connection error states (with the exception of recoverable send-errors)
/// are returned from [Control]. When reporting an error, configuration error
/// take precedence; i.e., if a configuration error occurs (e.g., the peer
/// disabled datagram support), it is reported even though an underlying
/// connection error happened at the same time.
pub struct Control {
    driver_fut: Pin<Box<dyn Future<Output = Result<(), ControlError>> + Send>>,
}

impl Control {
    /// Create a new [`Control`] that drives `tunnel_state` over `conn`.
    pub fn new<C, Q>(conn: Q, tunnel_state: Arc<TunnelStateMachine<C>>) -> Self
    where
        C: EdgeTunToken,
        Q: QuinnConn + 'static,
    {
        let fut = async move {
            loop {
                tokio::select! {
                    _ = tunnel_state.await_session_expiry() => {
                        // session expired, close the connection
                        tunnel_state.shutdown();
                        conn.close(EdgetunConnErrors::SessionExpired.into(), b"session expired");
                        return Err(ControlError::SessionExpired);
                    }
                    res = conn.accept_bi() => {
                        let (mut snd, mut rcv) = match res {
                            Ok(v) => v,
                            Err(anapaya_quinn::ConnectionError::ApplicationClosed { .. }) => {
                                tunnel_state.shutdown();
                                return Err(ControlError::ClosedPrematurely);
                            }
                            Err(_) => {
                                tunnel_state.shutdown();
                                return Err(ControlError::ClosedPrematurely);
                            }
                        };

                        let mut buf = vec![0u8; CTRL_REQUEST_BUF_SIZE];
                        let control_request  = parse_http_request(&mut buf, &mut rcv).await.inspect_err(|err| {
                            handle_invalid_request(&conn, err);
                            tunnel_state.shutdown();
                        })?;

                        let (code, body) = tunnel_state.process_control_request(SystemTime::now(), control_request);
                        send_http_response(&mut snd, code, &body).await
                            .inspect_err(|_| {
                                tunnel_state.shutdown();
                                conn.close(EdgetunConnErrors::InternalError.into(), b"send control response error");
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

/// The state transitions of an edgetun connection.
///
/// ```text
/// Unassigned --> Assigned --> Closed
/// ```
///
/// Once the connection is closed, it remains closed.
pub struct TunnelStateMachine<T: EdgeTunToken> {
    validator: Arc<dyn TokenValidator<T>>,
    allocator: Arc<dyn AddressAllocator<T>>,
    advertisements: Vec<IpAddressRange>,
    inner_state: RwLock<TunnelState>,
}

impl<T: EdgeTunToken> Drop for TunnelStateMachine<T> {
    fn drop(&mut self) {
        // Make sure that the state is closed and address is released
        self.shutdown();
    }
}

impl<T: EdgeTunToken> TunnelStateMachine<T> {
    pub(crate) fn new(
        validator: Arc<dyn TokenValidator<T>>,
        allocator: Arc<dyn AddressAllocator<T>>,
        advertisements: Vec<IpAddressRange>,
    ) -> Self {
        Self {
            validator,
            allocator,
            advertisements,
            inner_state: Default::default(),
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
            ControlRequest::GetAdvertisement(token) => {
                self.process_get_route_adv_request(now, token)
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
                info!("JWT signature validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::JwtError(err)) => {
                info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::TokenExpired(err)) => {
                info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
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
    ) -> (StatusCode, Vec<u8>) {
        // xxx(dsd): Potential optimization for later: We could save an
        // allocation here by passing through the slice pointing into the
        // original request buffer. I.e. the http parsing should just pass
        // return a Cow<'a, str> for the respective header parser.
        match self.validator.validate(now, &token) {
            Ok(claims) => {
                // We only implement single address assignments at the moment
                if addr_assignments.requested_addresses.len() > 1 {
                    warn!(
                        "Address assignment failed, multiple address assignments are not supported"
                    );
                    return (
                        StatusCode::NOT_IMPLEMENTED,
                        "multiple address assignments are not supported".into(),
                    );
                }

                let mut requests: Vec<IpNet> = match addr_assignments
                    .requested_addresses
                    .iter()
                    .map(|range| range.try_into())
                    .collect::<Result<Vec<_>, IpAddrError>>()
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
                    .any(|net| net.prefix_len() != net.max_prefix_len())
                {
                    warn!("Address assignment failed, prefix assignments are not supported");
                    return (
                        StatusCode::NOT_IMPLEMENTED,
                        "prefix assignments are not supported".into(),
                    );
                }

                // If no addresses are requested, try allocating an IPv4 or IPv6 address.
                if requests.is_empty() {
                    requests.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into());
                    requests.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED).into());
                }

                // Get current tunnel validity time
                let tunnel_validity = match inner_state.session_validity() {
                    Ok(v) => v,
                    Err(err) => {
                        error!(
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
                for requested_net in &requests {
                    match self.allocator.allocate(*requested_net, claims.clone()) {
                        Ok(allocation) => {
                            assigned_address = Some(allocation);
                            break;
                        }
                        Err(err) => {
                            debug!(?err, "Address allocation failed for {requested_net}");
                        }
                    }
                }

                // Only return an error if no addresses were assigned.
                let Some(assigned_address) = assigned_address else {
                    warn!("Address assignment failed - no available addresses for: {requests:?}",);
                    return (
                        StatusCode::BAD_REQUEST,
                        "either requested address is unavailable, or no addresses are available"
                            .into(),
                    );
                };

                // Update state
                self.locked_update_state(
                    inner_state,
                    TunnelState::Assigned {
                        valid_until: tunnel_validity,
                        address: assigned_address.clone(),
                    },
                );

                let resp = AddressAssignResponse {
                    assigned_addresses: vec![assigned_address.address.into()],
                };

                let mut resp_body = vec![];
                resp.encode(&mut resp_body)
                    .expect("Buffer grows, can't fail");

                (StatusCode::OK, resp_body)
            }
            Err(TokenValidatorError::JwtError(err)) => {
                info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::JwtSignatureInvalid()) => {
                info!("JWT signature validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::TokenExpired(err)) => {
                info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
        }
    }

    fn process_get_route_adv_request(
        &self,
        now: SystemTime,
        token: String,
    ) -> (StatusCode, Vec<u8>) {
        match self.validator.validate(now, &token) {
            Ok(_claims) => {
                let resp = RouteAdvertisementResponse {
                    routes: self.advertisements.clone(),
                };
                let mut resp_body = vec![];
                resp.encode(&mut resp_body).expect("no fail");
                (StatusCode::OK, resp_body)
            }
            Err(TokenValidatorError::JwtError(err)) => {
                info!(?err, "Token validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::JwtSignatureInvalid()) => {
                info!("JWT signature validation failed");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
            Err(TokenValidatorError::TokenExpired(err)) => {
                info!(?err, "Token validation failed: token expired");
                (StatusCode::UNAUTHORIZED, "unauthorized".into())
            }
        }
    }

    fn locked_update_state(&self, inner_state: &mut TunnelState, new_state: TunnelState) {
        tracing::debug!(%new_state, "Updating tunnel state");
        *inner_state = new_state;
    }

    fn locked_update_tunnel_session(&self, inner_state: &mut TunnelState, valid_until: SystemTime) {
        match inner_state {
            TunnelState::Unassigned => {
                *inner_state = TunnelState::SessionEstablished { valid_until };
            }
            TunnelState::SessionEstablished { .. } => {
                *inner_state = TunnelState::SessionEstablished { valid_until };
            }
            TunnelState::Assigned { address, .. } => {
                *inner_state = TunnelState::Assigned {
                    valid_until,
                    address: address.clone(),
                };
            }
            // XXX(bunert): Should not happen as we error out before updating the state.
            TunnelState::Closed => tracing::error!("Updating tunnel session but in closed state"),
        };
    }

    fn get_address_check_valid_until(&self, now: SystemTime) -> Vec<IpAddr> {
        let guard = self.inner_state.read().expect("no fail");
        match &*guard {
            TunnelState::Assigned {
                address,
                valid_until,
            } if now < *valid_until => vec![address.address],
            _ => vec![],
        }
    }

    fn get_addresses(&self) -> Vec<IpAddr> {
        let guard = self.inner_state.read().expect("no fail");
        match &*guard {
            TunnelState::Assigned { address, .. } => vec![address.address],
            _ => vec![],
        }
    }

    async fn await_session_expiry(&self) {
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
                        // tunnel in a invalid state, should only happen if the tunnel is closed
                        // (e.g. session already expired).
                        tracing::warn!(%err, "Tunnel in a invalid state");
                        return;
                    }
                }
            };

            // Sleep until the session expires
            tokio::time::sleep(valid_duration).await;
        }
    }

    fn is_closed(&self) -> bool {
        if let TunnelState::Closed = *self.inner_state.read().expect("no fail") {
            return true;
        }
        false
    }

    fn shutdown(&self) {
        let mut guard = self.inner_state.write().expect("no fail");

        // Put address grant on hold
        if let TunnelState::Assigned {
            valid_until: _,
            address,
        } = &*guard
            && !self.allocator.put_on_hold(address.id.clone())
        {
            error!(addr=?address.address, "Could not set address to hold during shutdown - address was released while tunnel was still assigned");
        }

        *guard = TunnelState::Closed;
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
        valid_until: SystemTime,
    },
    Assigned {
        valid_until: SystemTime,
        address: AddressAllocation,
    },
    Closed,
}

impl TunnelState {
    fn session_validity(&self) -> Result<SystemTime, TunnelStateError> {
        match self {
            TunnelState::SessionEstablished { valid_until } => Ok(*valid_until),
            TunnelState::Assigned { valid_until, .. } => Ok(*valid_until),
            _ => Err(TunnelStateError::InvalidState(self.clone())),
        }
    }
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Unassigned => write!(f, "Unassigned"),
            TunnelState::SessionEstablished { valid_until } => {
                write!(
                    f,
                    "SessionEstablished ({})",
                    DateTime::<Utc>::from(*valid_until)
                )
            }
            TunnelState::Assigned {
                valid_until,
                address,
            } => {
                write!(
                    f,
                    "Assigned (valid until: {}, addresses: [{}])",
                    DateTime::<Utc>::from(*valid_until),
                    address.address
                )
            }
            TunnelState::Closed => write!(f, "Closed"),
        }
    }
}

/// Error returned when parsing an edge-tun control request fails.
#[derive(Debug, Error)]
pub enum ParseControlRequestError {
    /// The request was syntactically or semantically invalid.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A stream read error occurred while reading the request.
    #[error("read error: {0}")]
    ReadError(#[from] anapaya_quinn::ReadError),
    /// The request did not carry a valid authentication token.
    #[error("authentication error: {0}")]
    Unauthenticated(String),
    /// The stream was closed before the request was fully received.
    #[error("closed prematurely")]
    ClosedPrematurely,
}

/// Close the underlying connection with an appropriate error code and reason if parsing the control
/// request failed.
fn handle_invalid_request<Q: QuinnConn + 'static>(conn: &Q, err: &ParseControlRequestError) {
    match err {
        ParseControlRequestError::ClosedPrematurely => {
            conn.close(
                EdgetunConnErrors::InternalError.into(),
                b"closed prematurely",
            );
        }
        ParseControlRequestError::ReadError(_) => {
            conn.close(EdgetunConnErrors::InternalError.into(), b"read error");
        }
        ParseControlRequestError::InvalidRequest(reason) => {
            conn.close(EdgetunConnErrors::InvalidRequest.into(), reason.as_bytes());
        }
        ParseControlRequestError::Unauthenticated(reason) => {
            conn.close(EdgetunConnErrors::Unauthenticated.into(), reason.as_bytes());
        }
    }
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
// * Depending on the PATH, we parse the content.
//
// All other headers are ignored.
async fn parse_http_request(
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
            Some(PATH_ADDR_ASSIGNMENT) | Some(PATH_ROUTES_REQUEST) | Some(PATH_SESSION_RENEWAL) => {
            }
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
            PATH_ROUTES_REQUEST => {
                return Ok(ControlRequest::GetAdvertisement(bearer_token));
            }
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
                    return Err(InvalidRequest("parsing address assignment request".into()));
                };
                return Ok(ControlRequest::AddressAssignment(bearer_token, addr_req));
            }
            PATH_SESSION_RENEWAL => return Ok(ControlRequest::SessionRenewal(bearer_token)),
            _ => unreachable!("invalid path"),
        }
    }
    Err(ClosedPrematurely)
}

/// Error returned when sending an edge-tun control response fails.
#[derive(Debug, Error)]
pub enum SendControlResponseError {
    /// An I/O error occurred while writing the response.
    #[error("i/o error {0}")]
    IoError(#[from] std::io::Error),
    /// The stream was closed before the response was fully written.
    #[error("stream closed")]
    ClosedStream(#[from] anapaya_quinn::ClosedStream),
}

// todo: refine these response headers to be in line with the spec.
async fn send_http_response(
    stream: &mut SendStream,
    code: StatusCode,
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

#[derive(Debug)]
enum ControlRequest {
    AddressAssignment(String, AddressAssignRequest),
    GetAdvertisement(String),
    SessionRenewal(String),
}
