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
//! The server of the SNAPtun protocol.
//!
//! As the underlying protocol is symmetric (both peers can act as
//! initiator/responders that establish a session), technically, there is no
//! server. The term "server" here just refers to and endpoint that manages
//! multiple peers.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use ana_gotatun::{
    noise::{Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    x25519,
};

/// The [SnapTunServer] manages one [Tunn] per remote socket address.
///
/// The main structural difference between WireGuard (R) and snaptun-ng is that
/// there is a one-to-one relation between a remote socket address (of the
/// initiator) and a tunnel. The [SnapTunServer] manages that relation.
///
/// ## Scaling
///
/// The main methods [SnapTunServer::handle_incoming_packet],
/// [SnapTunServer::handle_outgoing_packet], and
/// [SnapTunServer::update_timers] all require an exclusive reference to the
/// internal state. The reason is that processing both, incoming and outgoing
/// packets requires access to the session state.
///
/// One simple way to achieve load distribution across different cores/threads
/// is to shard over multiple [SnapTunServer]-instances based on a hash of the
/// remote socket address.
///
/// ## Future improvements
///
/// * Separate incoming and outgoing code paths and optimistically lock the session state.
///
/// ## How to use
///
/// The [SnapTunServer] is i/o-free; i.e. it only manages state. The following
/// is a pseudo-code like description of the simplest i/o-layer integration:
///
/// ```text
/// let mut server = SnapTunServer::new(/*...*/);
/// let mut send_to_network = VecDequeue::new();
/// let mut current_sockaddr = ;
/// loop {
///   switch {
///     (network_packet, sockaddr) = network_socket => {
///       server.handle_incoming_packet(/*...*/);
///       /* dispatch packets to tunnel if necessary */
///     }
///     tunnel_packet = tunnel_socket => {
///       server.handle_outgoing_packet(/*...*/);
///     }
///     timer = tick(250ms) => {
///       server.update_timers();
///     }
///   }
///   // dispatch packets to network
///   for p in send_to_network {
///     network_socket.send(sockaddr, p);
///   }
/// }
/// ```
pub struct SnapTunServer<T: SnapTunAuthorization> {
    static_private: x25519::StaticSecret,
    static_public: x25519::PublicKey,
    active_tunnels: HashMap<SocketAddr, ActiveTunnel>,
    rate_limiter: Arc<RateLimiter>,
    authz: Arc<T>,
}

struct ActiveTunnel {
    peer_static: x25519::PublicKey,
    tunn: Tunn,
}

/// Packet-processing output for callers that also need the resolved tunnel session.
///
/// This is an opt-in extension of the original `TunnResult`-based API so the
/// dataplane can reuse the resolved session without forcing existing snap-tun
/// callers to change their control flow.
pub enum HandleIncomingPacketResult<S> {
    /// The result returned by the underlying WireGuard tunnel state machine
    /// when no tunneled SCION payload was forwarded.
    Result {
        /// The result returned by the underlying WireGuard tunnel state
        /// machine.
        result: TunnResult,
    },
    /// A forwarded tunneled SCION payload together with the processing
    /// metadata captured while the tunnel entry was already borrowed.
    Forwarded {
        /// The packet forwarded to the caller.
        packet: Packet,
        /// The timestamp captured after rate-limiter verification.
        processed_at: Instant,
        /// The active session data resolved while processing the packet.
        session_data: Arc<S>,
    },
}

impl<S> HandleIncomingPacketResult<S> {
    /// Converts the result back into the underlying WireGuard tunnel result.
    pub fn into_result(self) -> TunnResult {
        match self {
            HandleIncomingPacketResult::Result { result } => result,
            HandleIncomingPacketResult::Forwarded { packet, .. } => {
                TunnResult::WriteToTunnel(packet)
            }
        }
    }
}

/// Packet-processing output for callers that need the active session once an
/// outbound payload is accepted into the tunnel pipeline.
pub struct HandleOutgoingPacketResult<S> {
    /// The WireGuard packet to send to the network, if the tunnel emitted one
    /// immediately.
    pub network_packet: Option<WgKind>,
    /// The timestamp captured for the authorization check that gated this
    /// outgoing packet.
    pub processed_at: Instant,
    /// The session data resolved for the tunneled SCION payload.
    pub session_data: Arc<S>,
}

impl<S> HandleOutgoingPacketResult<S> {
    /// Converts the result into the immediate network packet, if one exists.
    pub fn into_packet(self) -> Option<WgKind> {
        self.network_packet
    }
}

impl<T: SnapTunAuthorization> SnapTunServer<T> {
    // The caller captures this timestamp after rate-limiter verification and
    // reuses it for both authorization and forwarded-packet metadata.
    fn incoming_packet_result(
        result: TunnResult,
        session_data: Arc<T::SessionData>,
        now: Instant,
    ) -> HandleIncomingPacketResult<T::SessionData> {
        match result {
            TunnResult::WriteToTunnel(packet) => {
                HandleIncomingPacketResult::Forwarded {
                    packet,
                    processed_at: now,
                    session_data,
                }
            }
            result => HandleIncomingPacketResult::Result { result },
        }
    }

    fn outgoing_packet_result(
        network_packet: Option<WgKind>,
        now: Instant,
        session_data: Arc<T::SessionData>,
    ) -> HandleOutgoingPacketResult<T::SessionData> {
        HandleOutgoingPacketResult {
            network_packet,
            processed_at: now,
            session_data,
        }
    }

    /// Creates a new [SnapTunServer] instance.
    pub fn new(
        static_private: x25519::StaticSecret,
        rate_limiter: Arc<RateLimiter>,
        authz: Arc<T>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);
        Self {
            static_private,
            static_public,
            active_tunnels: Default::default(),
            rate_limiter,
            authz,
        }
    }

    /// Handle incoming packet for a tunnel assocated with remote socket address
    /// `from`.
    ///
    /// This method _never_ returns [TunnResult::WriteToNetwork]. Instead,
    /// it codifies the expected protocol behavior which is that, upon receiving
    /// a packet from the remote, the queue of outgoing packets is completely
    /// drained.
    ///
    /// If the rate limiter signals that the server is under load, at most one
    /// packet is added to the queue.
    ///
    /// This compatibility wrapper preserves the original public API for callers
    /// that only care about the tunnel result.
    pub fn handle_incoming_packet(
        &mut self,
        packet: Packet,
        from: SocketAddr,
        send_to_network: &mut VecDeque<WgKind>,
    ) -> TunnResult {
        self.handle_incoming_packet_with_session(packet, from, send_to_network)
            .into_result()
    }

    /// Handles an incoming packet and also returns the active session when one
    /// was resolved while processing the packet.
    ///
    /// Callers on the dataplane hot path can use this to observe forwarded
    /// packets without re-hashing `from` for a second active-tunnel lookup,
    /// while existing callers can keep using [`SnapTunServer::handle_incoming_packet`].
    #[tracing::instrument(skip_all, fields(remote = %from))]
    pub fn handle_incoming_packet_with_session(
        &mut self,
        packet: Packet,
        from: SocketAddr,
        send_to_network: &mut VecDeque<WgKind>,
    ) -> HandleIncomingPacketResult<T::SessionData> {
        let parsed_packet = match self.rate_limiter.verify_packet(from.ip(), packet) {
            Ok(p) => p,
            Err(TunnResult::WriteToNetwork(c)) => {
                tracing::debug!(remote = ?from, "rate limiter issued cookie reply");
                send_to_network.push_back(c);
                return HandleIncomingPacketResult::Result {
                    result: TunnResult::Done,
                };
            }
            Err(e) => {
                tracing::debug!(remote = ?from, err = ?e, "rate limiter rejected packet");
                return HandleIncomingPacketResult::Result { result: e };
            }
        };
        // Capture one shared timestamp after rate-limiter verification so the
        // authorization decision and any forwarded-packet metadata use the same
        // instant without an extra clock read on the hot path.
        let packet_now = Instant::now();

        use std::collections::hash_map::Entry;

        use ana_gotatun::noise::errors::WireGuardError;
        match (self.active_tunnels.entry(from), parsed_packet) {
            (Entry::Occupied(mut occupied_entry), p) => {
                let active_tunnel = occupied_entry.get_mut();
                // TODO(dsd): At the moment, this keeps a tunnel alive even
                // though the processing might fail, but gives the authorization
                // layer a chance to block incomding packets in case an identity
                // is unauthorized.
                //
                // Will fix later.
                let Some(session_data) = self
                    .authz
                    .is_authorized(packet_now, active_tunnel.peer_static.as_bytes())
                else {
                    tracing::debug!(remote = ?from, peer_static = ?active_tunnel.peer_static, "rejected packet from unauthorized peer");
                    return HandleIncomingPacketResult::Result {
                        result: TunnResult::Err(WireGuardError::UnexpectedPacket),
                    };
                };
                let result = Self::handle_incoming_and_drain_queue(
                    send_to_network,
                    p,
                    &mut active_tunnel.tunn,
                );
                Self::incoming_packet_result(result, session_data, packet_now)
            }
            (e, WgKind::HandshakeInit(wg_init)) => {
                let peer = match parse_handshake_anon(
                    &self.static_private,
                    &self.static_public,
                    &wg_init,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(remote = ?from, err = ?e, "failed to parse handshake init");
                        return HandleIncomingPacketResult::Result {
                            result: TunnResult::from(e),
                        };
                    }
                };

                // TODO(dsd): if the socket is occupied, and tunnel.identity !=
                // peer.identity, then send a cookie and abort

                // TODO(dsd): extend ana-gotatun::Tunn such that peer static
                // identity can be retrieved
                let Some(session_data) = self
                    .authz
                    .is_authorized(packet_now, &peer.peer_static_public)
                else {
                    tracing::debug!(remote = ?from, "rejected handshake from unauthorized peer");
                    return HandleIncomingPacketResult::Result {
                        result: TunnResult::Err(WireGuardError::UnexpectedPacket),
                    };
                };
                tracing::debug!(remote = ?from, "accepted new handshake, inserting tunnel");
                let peer_static = x25519::PublicKey::from(peer.peer_static_public);
                let mut tunn = Tunn::new(
                    self.static_private.clone(),
                    peer_static,
                    None,
                    None,
                    0,
                    self.rate_limiter.clone(),
                    from,
                );
                let res = Self::handle_incoming_and_drain_queue(
                    send_to_network,
                    WgKind::HandshakeInit(wg_init),
                    &mut tunn,
                );
                // Derive the caller-visible forwarded-packet result before
                // moving `session_data` into the active-tunnel entry below.
                let handled = Self::incoming_packet_result(res, session_data.clone(), packet_now);
                e.insert_entry(ActiveTunnel { peer_static, tunn });
                handled
            }
            (_, _p) => {
                tracing::debug!(remote = ?from, "received unexpected packet kind for new entry");
                HandleIncomingPacketResult::Result {
                    result: TunnResult::Err(WireGuardError::InvalidPacket),
                }
            }
        }
    }

    /// Handles an outgoing packet sent through the tunnel identified by the
    /// remote socket address `to`.
    pub fn handle_outgoing_packet(&mut self, packet: Packet, to: SocketAddr) -> Option<WgKind> {
        self.handle_outgoing_packet_with_session(packet, to)
            .and_then(HandleOutgoingPacketResult::into_packet)
    }

    /// Handles an outgoing packet and returns the active tunnel session used to
    /// admit the payload into the tunnel pipeline.
    ///
    /// This re-checks authorization on the outgoing path. If the active tunnel
    /// no longer has current authorization, the packet is dropped and `None` is
    /// returned even when the tunnel state itself still exists.
    #[tracing::instrument(skip_all, fields(remote = %to))]
    pub fn handle_outgoing_packet_with_session(
        &mut self,
        packet: Packet,
        to: SocketAddr,
    ) -> Option<HandleOutgoingPacketResult<T::SessionData>> {
        let Some(active_tunnel) = self.active_tunnels.get_mut(&to) else {
            tracing::error!(to=?to, "No tunnel for outgoing packet found.");
            return None;
        };
        let packet_now = Instant::now();
        let Some(session_data) = self
            .authz
            .is_authorized(packet_now, active_tunnel.peer_static.as_bytes())
        else {
            tracing::debug!(remote = ?to, peer_static = ?active_tunnel.peer_static, "dropping outgoing packet for unauthorized peer");
            return None;
        };
        Some(Self::outgoing_packet_result(
            active_tunnel
                .tunn
                .handle_outgoing_packet(packet.into_bytes()),
            packet_now,
            session_data,
        ))
    }

    /// Update timers of all tunnels. Generate corresponding keepalive or
    /// session handshake initializations.
    ///
    /// As a result of this call, all expired tunnels are removed. Note that
    /// this is not the same as unauthorized tunnels.
    pub fn update_timers(&mut self) -> Vec<(SocketAddr, WgKind)> {
        let mut res = vec![];
        self.active_tunnels.retain(|k, active_tunnel| {
            match active_tunnel.tunn.update_timers() {
                Ok(Some(wg)) => res.push((*k, wg)),
                Ok(None) => {},
                Err(e) => tracing::error!(err=?e, remote_sockaddr=?k, "error when updating timers on tunnel"),
            }

            !active_tunnel.tunn.is_expired()
        });
        res
    }

    fn handle_incoming_and_drain_queue(
        q: &mut VecDeque<WgKind>,
        p: WgKind,
        tunn: &mut Tunn,
    ) -> TunnResult {
        let r = match tunn.handle_incoming_packet(p) {
            TunnResult::WriteToNetwork(p) => {
                q.push_back(p);
                TunnResult::Done
            }
            // keep alive
            TunnResult::WriteToTunnel(p) if p.is_empty() => TunnResult::Done,
            r => r,
        };
        for p in tunn.get_queued_packets() {
            q.push_back(p);
        }
        r
    }
}

/// Authorization layer for the snaptun server.
pub trait SnapTunAuthorization: Send + Sync {
    /// Immutable session data that downstream dataplane consumers may read.
    type SessionData: Clone + Send + Sync + 'static;

    /// Returns the current session data iff the peer is allowed to send traffic.
    fn is_authorized(&self, now: Instant, identity: &[u8; 32]) -> Option<Arc<Self::SessionData>>;
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        net::SocketAddr,
        sync::{Arc, Mutex},
    };

    use ana_gotatun::{
        noise::{Tunn, TunnResult, rate_limiter::RateLimiter},
        packet::{IpNextProtocol, Packet, WgKind},
        x25519,
    };
    use zerocopy::IntoBytes;

    use crate::{
        scion_packet::{Scion, ScionHeader},
        server::{
            HandleIncomingPacketResult, HandleOutgoingPacketResult, SnapTunAuthorization,
            SnapTunServer,
        },
    };

    type ResultT = Result<(), Box<dyn std::error::Error>>;

    struct TrivialAuthz;

    impl SnapTunAuthorization for TrivialAuthz {
        type SessionData = ();

        fn is_authorized(
            &self,
            _now: std::time::Instant,
            _ident: &[u8; 32],
        ) -> Option<Arc<Self::SessionData>> {
            Some(Arc::new(()))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MutableSessionData {
        jti: &'static str,
        pssid: &'static str,
        tags: Vec<(&'static str, &'static str)>,
    }

    #[derive(Default)]
    struct MutableAuthz {
        sessions: Mutex<HashMap<[u8; 32], Arc<MutableSessionData>>>,
    }

    impl MutableAuthz {
        fn set_session_data(&self, identity: [u8; 32], session_data: MutableSessionData) {
            self.sessions
                .lock()
                .unwrap()
                .insert(identity, Arc::new(session_data));
        }
    }

    impl SnapTunAuthorization for MutableAuthz {
        type SessionData = MutableSessionData;

        fn is_authorized(
            &self,
            _now: std::time::Instant,
            ident: &[u8; 32],
        ) -> Option<Arc<Self::SessionData>> {
            self.sessions.lock().unwrap().get(ident).cloned()
        }
    }

    fn test_packet<const N: usize>(payload: [u8; N]) -> Packet {
        let packet = Scion {
            header: ScionHeader::new(
                0,
                0xAA,
                0xABCDE,
                payload.len() as _,
                IpNextProtocol::Udp,
                7,
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
            ),
            payload,
        };
        Packet::copy_from(packet.as_bytes())
    }

    fn establish_tunnel<T: SnapTunAuthorization>(
        snaptun_server: &mut SnapTunServer<T>,
        tunn_client: &mut Tunn,
        packet: &Packet,
        sockaddr_client: SocketAddr,
        send_to_network: &mut VecDeque<WgKind>,
    ) {
        let Some(WgKind::HandshakeInit(hs_init)) =
            tunn_client.handle_outgoing_packet(Packet::copy_from(packet))
        else {
            panic!("expected handshake init")
        };

        snaptun_server.handle_incoming_packet(
            Packet::copy_from(hs_init.as_bytes()),
            sockaddr_client,
            send_to_network,
        );
        dispatch_one(tunn_client, send_to_network);
    }

    #[test]
    fn connect_with_multiple_clients() -> ResultT {
        let sockaddr_client0: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let static_client0 = x25519::StaticSecret::from([0u8; 32]);
        let sockaddr_client1: SocketAddr = "192.168.1.2:4321".parse().unwrap();
        let static_client1 = x25519::StaticSecret::from([1u8; 32]);
        let sockaddr_server: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);

        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut snaptun_server =
            SnapTunServer::new(static_server, rate_limiter.clone(), Arc::new(TrivialAuthz));

        let mut send_to_network = VecDeque::<WgKind>::new();

        let test_packet0 = test_packet([b'T', b'E', b'S', b'T', b'0']);
        let test_packet1 = test_packet([b'T', b'E', b'S', b'T', b'1']);

        let mut tunn_client0 = Tunn::new(
            static_client0,
            static_server_public,
            None,
            None,
            0,
            rate_limiter.clone(),
            sockaddr_server,
        );

        let mut tunn_client1 = Tunn::new(
            static_client1,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            sockaddr_server,
        );

        /* handshake 0 */
        establish_tunnel(
            &mut snaptun_server,
            &mut tunn_client0,
            &test_packet0,
            sockaddr_client0,
            &mut send_to_network,
        );
        assert_eq!(
            tunn_client0.get_initiator_remote_sockaddr(),
            Some(sockaddr_client0)
        );

        /* handshake 1 */
        establish_tunnel(
            &mut snaptun_server,
            &mut tunn_client1,
            &test_packet1,
            sockaddr_client1,
            &mut send_to_network,
        );
        assert_eq!(
            tunn_client1.get_initiator_remote_sockaddr(),
            Some(sockaddr_client1)
        );

        /* send C0 -> S */
        let Some(WgKind::Data(p)) = tunn_client0.get_queued_packets().next() else {
            panic!("expected packet to be queued");
        };

        let TunnResult::WriteToTunnel(p) = snaptun_server.handle_incoming_packet(
            Packet::copy_from(p.as_bytes()),
            sockaddr_client0,
            &mut send_to_network,
        ) else {
            panic!("Expected packet to be processed")
        };
        assert_eq!(p.as_bytes(), test_packet0.as_bytes());

        /* send C1 -> S */
        // before we can send a packet to client1, we need to send a packet from
        // client1 so the server starts using the session.
        let Some(WgKind::Data(p1)) = tunn_client1.get_queued_packets().next() else {
            panic!("expected packet to be queued");
        };

        let TunnResult::WriteToTunnel(p1) = snaptun_server.handle_incoming_packet(
            Packet::copy_from(p1.as_bytes()),
            sockaddr_client1,
            &mut send_to_network,
        ) else {
            panic!("expected packet to be received on server side");
        };
        assert_eq!(p1.as_bytes(), test_packet1.as_bytes());

        /* send S -> C1 */
        let res = snaptun_server.handle_outgoing_packet(p, sockaddr_client1);
        let Some(p @ WgKind::Data(_)) = res else {
            panic!("expected packet to be sent back to client")
        };

        let TunnResult::WriteToTunnel(p) = tunn_client1.handle_incoming_packet(p) else {
            panic!("expected packet to be sent back to client")
        };

        assert_eq!(p.as_bytes(), test_packet0.as_bytes());

        Ok(())
    }

    #[test]
    fn outgoing_packet_with_session_returns_active_session() {
        let sockaddr_client: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let static_client = x25519::StaticSecret::from([0u8; 32]);
        let sockaddr_server: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);

        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut snaptun_server =
            SnapTunServer::new(static_server, rate_limiter.clone(), Arc::new(TrivialAuthz));
        let mut send_to_network = VecDeque::<WgKind>::new();

        let test_packet = test_packet([b'T', b'E', b'S', b'T']);

        let mut tunn_client = Tunn::new(
            static_client,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            sockaddr_server,
        );

        establish_tunnel(
            &mut snaptun_server,
            &mut tunn_client,
            &test_packet,
            sockaddr_client,
            &mut send_to_network,
        );

        let Some(WgKind::Data(client_data)) = tunn_client.get_queued_packets().next() else {
            panic!("expected packet to be queued");
        };
        let TunnResult::WriteToTunnel(server_plaintext) = snaptun_server.handle_incoming_packet(
            Packet::copy_from(client_data.as_bytes()),
            sockaddr_client,
            &mut send_to_network,
        ) else {
            panic!("expected packet to be processed")
        };

        let handled = snaptun_server
            .handle_outgoing_packet_with_session(server_plaintext, sockaddr_client)
            .expect("expected packet to be encapsulated");
        let HandleOutgoingPacketResult {
            network_packet: Some(WgKind::Data(encapsulated)),
            processed_at: _,
            session_data,
        } = handled
        else {
            panic!("expected encapsulated data packet")
        };
        assert_eq!(session_data.as_ref(), &());

        let TunnResult::WriteToTunnel(plaintext) =
            tunn_client.handle_incoming_packet(WgKind::Data(encapsulated))
        else {
            panic!("expected packet to be delivered back to client")
        };
        assert_eq!(plaintext.as_bytes(), test_packet.as_bytes());
    }

    #[test]
    fn established_tunnel_refreshes_session_data_for_later_packets() {
        let sockaddr_client: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let static_client = x25519::StaticSecret::from([0u8; 32]);
        let client_identity = x25519::PublicKey::from(&static_client);
        let sockaddr_server: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let authz = Arc::new(MutableAuthz::default());
        let original_session = MutableSessionData {
            jti: "original-jti",
            pssid: "original-pssid",
            tags: vec![("subject_id", "subject-1"), ("scope", "basic")],
        };
        authz.set_session_data(*client_identity.as_bytes(), original_session);

        let mut snaptun_server =
            SnapTunServer::new(static_server, rate_limiter.clone(), authz.clone());
        let mut send_to_network = VecDeque::<WgKind>::new();
        let test_packet = test_packet([b'T', b'E', b'S', b'T']);

        let mut tunn_client = Tunn::new(
            static_client,
            static_server_public,
            None,
            None,
            0,
            rate_limiter,
            sockaddr_server,
        );

        establish_tunnel(
            &mut snaptun_server,
            &mut tunn_client,
            &test_packet,
            sockaddr_client,
            &mut send_to_network,
        );

        let refreshed_session = MutableSessionData {
            jti: "refreshed-jti",
            pssid: "refreshed-pssid",
            tags: vec![("subject_id", "subject-2"), ("scope", "premium")],
        };
        authz.set_session_data(*client_identity.as_bytes(), refreshed_session.clone());

        let Some(WgKind::Data(client_data)) = tunn_client.get_queued_packets().next() else {
            panic!("expected packet to be queued");
        };
        let HandleIncomingPacketResult::Forwarded {
            packet: server_plaintext,
            session_data,
            ..
        } = snaptun_server.handle_incoming_packet_with_session(
            Packet::copy_from(client_data.as_bytes()),
            sockaddr_client,
            &mut send_to_network,
        )
        else {
            panic!("expected forwarded packet with refreshed session data")
        };
        assert_eq!(session_data.as_ref(), &refreshed_session);

        let Some(HandleOutgoingPacketResult {
            network_packet: Some(WgKind::Data(encapsulated)),
            processed_at: _,
            session_data,
        }) = snaptun_server.handle_outgoing_packet_with_session(server_plaintext, sockaddr_client)
        else {
            panic!("expected encapsulated data packet with refreshed session data")
        };
        assert_eq!(session_data.as_ref(), &refreshed_session);

        let TunnResult::WriteToTunnel(plaintext) =
            tunn_client.handle_incoming_packet(WgKind::Data(encapsulated))
        else {
            panic!("expected packet to be delivered back to client")
        };
        assert_eq!(plaintext.as_bytes(), test_packet.as_bytes());
    }

    #[test]
    fn outgoing_packet_with_session_returns_none_without_tunnel() {
        let sockaddr_client: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let static_server = x25519::StaticSecret::from([2u8; 32]);
        let static_server_public = x25519::PublicKey::from(&static_server);
        let rate_limiter = Arc::new(RateLimiter::new(&static_server_public, 100));
        let mut snaptun_server =
            SnapTunServer::new(static_server, rate_limiter, Arc::new(TrivialAuthz));

        let payload = [b'T', b'E', b'S', b'T'];
        let test_packet = Scion {
            header: ScionHeader::new(
                0,
                0xAA,
                0xABCDE,
                payload.len() as _,
                IpNextProtocol::Udp,
                7,
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
            ),
            payload,
        };

        assert!(
            snaptun_server
                .handle_outgoing_packet_with_session(
                    Packet::copy_from(test_packet.as_bytes()),
                    sockaddr_client
                )
                .is_none()
        );
    }

    fn dispatch_one(tunn: &mut Tunn, packets: &mut VecDeque<WgKind>) -> TunnResult {
        if let Some(packet) = packets.pop_front() {
            return tunn.handle_incoming_packet(packet);
        }
        TunnResult::Done
    }
}
