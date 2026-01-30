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

/// The [SnapTunNgServer] manages one [Tunn] per remote socket address.
///
/// The main structural difference between WireGuard (R) and snaptun-ng is that
/// there is a one-to-one relation between a remote socket address (of the
/// initiator) and a tunnel. The [SnapTunNgServer] manages that relation.
///
/// ## Scaling
///
/// The main methods [SnapTunNgServer::handle_incoming_packet],
/// [SnapTunNgServer::handle_outgoing_packet], and
/// [SnapTunNgServer::update_timers] all require an exclusive reference to the
/// internal state. The reason is that processing both, incoming and outgoing
/// packets requires access to the session state.
///
/// One simple way to achieve load distribution across different cores/threads
/// is to shard over multiple [SnapTunNgServer]-instances based on a hash of the
/// remote socket address.
///
/// ## Future improvements
///
/// * Separate incoming and outgoing code paths and optimistically lock the session state.
///
/// ## How to use
///
/// The [SnapTunNgServer] is i/o-free; i.e. it only manages state. The following
/// is a pseudo-code like description of the simplest i/o-layer integration:
///
/// ```text
/// let mut server = SnapTunNgServer::new(/*...*/);
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
pub struct SnapTunNgServer<T> {
    static_private: x25519::StaticSecret,
    static_public: x25519::PublicKey,
    active_tunnels: HashMap<SocketAddr, (x25519::PublicKey, Tunn)>,
    rate_limiter: Arc<RateLimiter>,
    authz: Arc<T>,
}

impl<T: SnapTunAuthorization> SnapTunNgServer<T> {
    /// Creates a new [SnapTunNgServer] instance.
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
    pub fn handle_incoming_packet(
        &mut self,
        packet: Packet,
        from: SocketAddr,
        send_to_network: &mut VecDeque<WgKind>,
    ) -> TunnResult {
        let now = Instant::now();

        let parsed_packet = match self.rate_limiter.verify_packet(from.ip(), packet) {
            Ok(p) => p,
            Err(TunnResult::WriteToNetwork(c)) => {
                send_to_network.push_back(c);
                return TunnResult::Done;
            }
            Err(e) => return e,
        };

        use std::collections::hash_map::Entry;

        use ana_gotatun::noise::errors::WireGuardError;
        match (self.active_tunnels.entry(from), parsed_packet) {
            (Entry::Occupied(mut occupied_entry), p) => {
                let (peer_static, tunn) = occupied_entry.get_mut();
                // TODO(dsd): At the moment, this keeps a tunnel alive even
                // though the processing might fail, but gives the authorization
                // layer a chance to block incomding packets in case an identity
                // is unauthorized.
                //
                // Will fix later.
                if !self.authz.is_authorized(now, peer_static.as_bytes()) {
                    return TunnResult::Err(WireGuardError::UnexpectedPacket);
                }
                Self::handle_incoming_and_drain_queue(send_to_network, p, tunn)
            }
            (e, WgKind::HandshakeInit(wg_init)) => {
                let peer =
                    match parse_handshake_anon(&self.static_private, &self.static_public, &wg_init)
                    {
                        Ok(v) => v,
                        Err(e) => return TunnResult::from(e),
                    };

                // TODO(dsd): if the socket is occupied, and tunnel.identity !=
                // peer.identity, then send a cookie and abort

                // TODO(dsd): extend ana-gotatun::Tunn such that peer static
                // identity can be retrieved
                if !self.authz.is_authorized(now, &peer.peer_static_public) {
                    return TunnResult::Err(WireGuardError::UnexpectedPacket);
                }
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
                e.insert_entry((peer_static, tunn));
                res
            }
            (_, _p) => TunnResult::Err(WireGuardError::InvalidPacket),
        }
    }

    /// Handles an outgoing packet sent through the tunnel identified by the
    /// remote socket address `to`.
    pub fn handle_outgoing_packet(&mut self, packet: Packet, to: SocketAddr) -> Option<WgKind> {
        let Some((_, tunn)) = self.active_tunnels.get_mut(&to) else {
            tracing::error!(to=?to, "No tunnel for outgoing packet found.");
            return None;
        };
        tunn.handle_outgoing_packet(packet.into_bytes())
    }

    /// Update timers of all tunnels. Generate corresponding keepalive or
    /// session handshake initializations.
    ///
    /// As a result of this call, all expired tunnels are removed. Note that
    /// this is not the same as unauthorized tunnels.
    pub fn update_timers(&mut self) -> Vec<(SocketAddr, WgKind)> {
        let mut res = vec![];
        self.active_tunnels.retain(|k, (_, tunn)| {
            match tunn.update_timers() {
                Ok(Some(wg)) => res.push((*k, wg)),
                Ok(None) => {},
                Err(e) => tracing::error!(err=?e, remote_sockaddr=?k, "error when updating timers on tunnel"),
            }

            !tunn.is_expired()
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
    /// Returns true iff the peer is allowed to send traffic to the server.
    fn is_authorized(&self, now: Instant, identity: &[u8; 32]) -> bool;
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::SocketAddr, sync::Arc};

    use ana_gotatun::{
        noise::{Tunn, TunnResult, rate_limiter::RateLimiter},
        packet::{IpNextProtocol, Packet, WgKind},
        x25519,
    };
    use zerocopy::IntoBytes;

    use crate::{
        scion_packet::{Scion, ScionHeader},
        server::{SnapTunAuthorization, SnapTunNgServer},
    };

    type ResultT = Result<(), Box<dyn std::error::Error>>;

    struct TrivialAuthz;

    impl SnapTunAuthorization for TrivialAuthz {
        fn is_authorized(&self, _now: std::time::Instant, _ident: &[u8; 32]) -> bool {
            true
        }
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
            SnapTunNgServer::new(static_server, rate_limiter.clone(), Arc::new(TrivialAuthz));

        let mut send_to_network = VecDeque::<WgKind>::new();

        let test_payload0 = [b'T', b'E', b'S', b'T', b'0'];
        let test_payload1 = [b'T', b'E', b'S', b'T', b'1'];
        let test_packet0 = Scion {
            header: ScionHeader::new(
                0,                        // version
                0xAA,                     // traffic_class
                0xABCDE,                  // flow_id (20 bits)
                test_payload0.len() as _, // payload_len
                IpNextProtocol::Udp,
                7, // hop_count
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
            ),
            payload: test_payload0,
        };
        let test_packet1 = Scion {
            header: test_packet0.header,
            payload: test_payload1,
        };
        let test_packet0 = Packet::copy_from(test_packet0.as_bytes());
        let test_packet1 = Packet::copy_from(test_packet1.as_bytes());

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
        let Some(WgKind::HandshakeInit(hs_init)) =
            tunn_client0.handle_outgoing_packet(Packet::copy_from(&test_packet0))
        else {
            panic!("expected handshake init")
        };

        snaptun_server.handle_incoming_packet(
            Packet::copy_from(hs_init.as_bytes()),
            sockaddr_client0,
            &mut send_to_network,
        );

        dispatch_one(&mut tunn_client0, &mut send_to_network);
        assert_eq!(
            tunn_client0.get_initiator_remote_sockaddr(),
            Some(sockaddr_client0)
        );

        /* handshake 1 */
        let Some(WgKind::HandshakeInit(hs_init)) =
            tunn_client1.handle_outgoing_packet(Packet::copy_from(&test_packet1))
        else {
            panic!("expected handshake init")
        };

        snaptun_server.handle_incoming_packet(
            Packet::copy_from(hs_init.as_bytes()),
            sockaddr_client1,
            &mut send_to_network,
        );

        dispatch_one(&mut tunn_client1, &mut send_to_network);
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

    fn dispatch_one(tunn: &mut Tunn, packets: &mut VecDeque<WgKind>) -> TunnResult {
        if let Some(p) = packets.pop_front() {
            return tunn.handle_incoming_packet(p);
        }
        TunnResult::Done
    }
}
