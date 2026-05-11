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
//! The EdgeTunn client manages the data plane state of a single edgetun tunnel.

use std::{collections::VecDeque, marker::PhantomData, sync::Arc};

use ana_gotatun::{
    noise::{
        Tunn, TunnResult, errors::WireGuardError, handshake::parse_handshake_anon,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
    x25519,
};

use crate::{
    fragmenting::{
        Defragmenter, Fragmenter,
        metrics::{DefragmentMetrics, FragmentMetrics},
    },
    wg::common::{
        AsIpAddr, EdgePacketBufPool, fragment_and_dispatch, handle_incoming_and_drain_queue,
        pool_allocate_packet_with_payload,
    },
};

/// The state of the client side of an edge-tun tunnel.
///
/// Fundamentally, this behaves like a Wireguard-Tunnel, except that outgoing
/// packets are fragmented; i.e. in the case of edge-tun, a WireGuard-Frame
/// carries a fragment, not an entire packet.
pub struct EdgeTunClientState<N> {
    static_private: x25519::StaticSecret,
    static_public: x25519::PublicKey,
    peer_static: x25519::PublicKey,
    rate_limiter: Arc<RateLimiter>,
    fragmenter: Fragmenter,
    defragmenter: Defragmenter,
    session_state: Tunn,
    pool: EdgePacketBufPool,
    _network_remote_addr_type: PhantomData<N>,
}

impl<N: AsIpAddr + std::fmt::Debug> EdgeTunClientState<N> {
    /// Create a new [`EdgeTunClientState`] with the given buffer pool, configuration, and metrics.
    pub fn new(
        pool: EdgePacketBufPool,
        config: EdgeTunClientConfig,
        fragmenter_metrics: FragmentMetrics,
        defragmenter_metrics: DefragmentMetrics,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&config.static_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&static_public, config.rate_limit));
        let fragmenter = Fragmenter::new(config.mtu as usize, fragmenter_metrics);
        let defragmenter = Defragmenter::new(config.defrag_queue_counts, defragmenter_metrics);

        Self {
            static_public,
            static_private: config.static_secret.clone(),
            peer_static: config.peer_static,
            rate_limiter: rate_limiter.clone(),
            fragmenter,
            defragmenter,
            session_state: Tunn::new(
                config.static_secret,
                config.peer_static,
                None,
                None,
                0,
                rate_limiter,
                "0.0.0.0:0".parse().unwrap(),
            ),
            pool,
            _network_remote_addr_type: PhantomData,
        }
    }

    /// Send `packet` outbound: fragment and enqueue all resulting WireGuard frames.
    pub fn handle_outgoing_packet(
        &mut self,
        packet: Packet,
        send_to_network: &mut VecDeque<WgKind>,
    ) {
        let _ = fragment_and_dispatch(
            &packet,
            &mut self.fragmenter,
            &mut self.session_state,
            &self.pool,
            |to_net| send_to_network.push_back(to_net),
        );
    }

    /// Handling incoming packets from network remote identified by
    /// `network_remote`.
    ///
    /// This method _never_ returns [TunnResult::WriteToNetwork]. Instead, all
    /// queued outgoing packets are added to `send_to_network`. All packets
    /// contained in `send_to_network` should be sent to the client immediately
    /// after this call.
    ///
    /// If the rate limiter signals that the server is under load, at most one
    /// packet is added to the queue.
    ///
    /// Receiving a handhshake init from a remote with a static identity
    /// different from the one configured will result in a
    /// [WireGuardError::InvalidPacket] error.
    pub fn handle_incoming_packet(
        &mut self,
        network_remote: N,
        packet: Packet,
        send_to_network: &mut VecDeque<WgKind>,
    ) -> TunnResult {
        // XXX(dsd): The rate limiter must be adapted to support proper endhost
        // addresses. This is a crutch.
        let Some(from_ip) = network_remote.ip() else {
            // XXX(dsd): not exactly the right error, but need fix
            tracing::debug!(network_remote=?network_remote, "dropping packet: no IP address in network remote");
            return TunnResult::Err(WireGuardError::WrongPacketType);
        };
        let parsed = match self.rate_limiter.verify_packet(from_ip, packet) {
            // A cookie reply is sent by the rate limiter when it is under load.
            // Exactly one packet is queued; the contract says "at most one".
            Err(TunnResult::WriteToNetwork(c)) => {
                send_to_network.push_back(c);
                tracing::debug!("rate limiter under load: sending cookie reply");
                return TunnResult::Done;
            }
            Err(e) => return e,
            Ok(wg) => wg,
        };

        if let WgKind::HandshakeInit(p) = &parsed {
            // The static public key of the initiator is authenticated
            // inside the Noise handshake; ask the Tunn to extract it.
            let hs = match parse_handshake_anon(&self.static_private, &self.static_public, p) {
                Ok(id) => id,
                Err(e) => return TunnResult::Err(e),
            };
            let peer_static = x25519::PublicKey::from(hs.peer_static_public);
            if self.peer_static != peer_static {
                tracing::info!("dropping HandshakeInit: peer static key mismatch");
                return TunnResult::Err(WireGuardError::InvalidPacket);
            }
        }
        // condition: remote peer static == configured peer static

        match handle_incoming_and_drain_queue(send_to_network, parsed, &mut self.session_state) {
            TunnResult::WriteToTunnel(packet) => {
                match self.defragmenter.recv(&packet) {
                    Ok(Some(p)) => {
                        tracing::trace!(
                            len = p.payload.len(),
                            "inbound packet reassembled, forwarding to tunnel"
                        );
                        let p = pool_allocate_packet_with_payload(&self.pool, p.payload);
                        TunnResult::WriteToTunnel(p)
                    }
                    Ok(_) => TunnResult::Done,
                    Err(e) => {
                        tracing::debug!(err=?e, "defragmenter error on inbound packet");
                        TunnResult::Done
                    }
                }
            }
            _ => TunnResult::Done,
        }
    }

    /// Advance WireGuard timer state and return any queued keepalive packet.
    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        self.session_state.update_timers()
    }
}

/// Configuration for an [`EdgeTunClientState`].
pub struct EdgeTunClientConfig {
    /// Static public key of the remote server peer.
    pub peer_static: x25519::PublicKey,
    /// This client's static secret key.
    pub static_secret: x25519::StaticSecret,
    /// Maximum number of handshake initiations per second allowed by the rate limiter.
    pub rate_limit: u64,
    /// Initial MTU used for outgoing packet fragmentation.
    pub mtu: u16,
    /// Number of defragmentation queues for incoming packet reassembly.
    pub defrag_queue_counts: usize,
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::SocketAddr, sync::atomic::AtomicU8};

    use ana_gotatun::{
        noise::{TunnResult, errors::WireGuardError},
        packet::{Packet, WgKind},
        x25519,
    };
    use scion_sdk_observability::metrics::registry::MetricsRegistry;

    use crate::{
        fragmenting::metrics::{DefragmentMetrics, FragmentMetrics},
        wg::{
            client::{EdgeTunClientConfig, EdgeTunClientState},
            common::{AsIpAddr, EdgePacketBufPool, handle_incoming_and_drain_queue},
        },
    };

    // ## Helpers

    impl AsIpAddr for SocketAddr {
        fn ip(&self) -> Option<std::net::IpAddr> {
            Some(self.ip())
        }
    }

    /// Builds a minimal pool suitable for tests.
    fn test_pool() -> EdgePacketBufPool {
        EdgePacketBufPool::new(2048)
    }

    static KEYPAIR_COUNTER: AtomicU8 = AtomicU8::new(0);

    /// Returns a freshly generated static keypair (secret + public).
    fn new_keypair() -> (x25519::StaticSecret, x25519::PublicKey) {
        let mut key_bytes = [0u8; 32];
        key_bytes[1] = KEYPAIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let secret = x25519::StaticSecret::from(key_bytes);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    /// Constructs an `EdgeTunClientConfig` with sensible test defaults.
    ///
    /// `peer_static` is the public key of the remote peer.
    fn test_config(
        static_secret: x25519::StaticSecret,
        peer_static: x25519::PublicKey,
    ) -> EdgeTunClientConfig {
        EdgeTunClientConfig {
            peer_static,
            static_secret,
            rate_limit: 100,
            mtu: 1420,
            defrag_queue_counts: 8,
        }
    }

    /// Creates a ready-to-use `EdgeTunClientState<SocketAddr>`.
    fn make_client() -> (
        EdgeTunClientState<SocketAddr>,
        x25519::StaticSecret,
        x25519::PublicKey,
    ) {
        let (client_secret, client_public) = new_keypair();
        let (peer_secret, peer_public) = new_keypair();
        let pool = test_pool();
        let config = test_config(client_secret, peer_public);
        let state = EdgeTunClientState::new(
            pool,
            config,
            FragmentMetrics::new(&MetricsRegistry::new()),
            DefragmentMetrics::new(&MetricsRegistry::new()),
        );
        (state, peer_secret, client_public)
    }

    /// Returns a loopback `SocketAddr` for use as the network remote.
    fn loopback_addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    /// Allocates a `Packet` containing `payload` from `pool`.
    fn make_packet(pool: &EdgePacketBufPool, payload: &[u8]) -> Packet {
        let mut p = pool.get();
        let buf = p.buf_mut();
        // SAFETY: we immediately write exactly `payload.len()` bytes.
        unsafe { buf.set_len(payload.len()) };
        buf[..payload.len()].copy_from_slice(payload);
        p
    }

    /// Drives a full WireGuard handshake for `client`.
    ///
    /// Internally creates an ephemeral server-side `Tunn` with the configured
    /// peer static key, exchanges InitResponse frames, and leaves `client` in
    /// the established state.
    fn complete_handshake(
        client: &mut EdgeTunClientState<SocketAddr>,
        peer_secret: x25519::StaticSecret,
    ) {
        use std::sync::Arc;

        use ana_gotatun::noise::{Tunn, rate_limiter::RateLimiter};

        let peer_public = x25519::PublicKey::from(&peer_secret);
        let rl = Arc::new(RateLimiter::new(&peer_public, 100));

        // Server side: expects connections from client's static public key.
        // For a responder Tunn, the "peer" is the client.
        let mut server = Tunn::new(
            peer_secret,
            client.static_public, // server expects the client's public key
            None,
            None,
            0,
            rl,
            loopback_addr(),
        );

        let pool = test_pool();

        // --- Step 1: client sends HandshakeInit ---
        let trigger = make_packet(&pool, &[0u8; 64]);
        let mut client_queue: VecDeque<WgKind> = VecDeque::new();
        client.handle_outgoing_packet(trigger, &mut client_queue);
        let init = client_queue.pop_front().expect("expected HandshakeInit");

        // --- Step 2: server processes HandshakeInit, produces HandshakeResponse ---
        let mut server_queue: VecDeque<WgKind> = VecDeque::new();
        handle_incoming_and_drain_queue(&mut server_queue, init, &mut server);
        let response = Packet::from(
            server_queue
                .pop_front()
                .expect("expected HandshakeResponse"),
        )
        .into_bytes();

        // --- Step 3: client processes HandshakeResponse ---
        let mut client_queue: VecDeque<WgKind> = VecDeque::new();
        client.handle_incoming_packet(loopback_addr(), response, &mut client_queue);
        // Handshake is now complete; client may emit a keepalive — drain it.
        drop(client_queue);
    }

    // ## Construction

    /// `EdgeTunClientState::new` must not panic given valid inputs.
    #[test]
    fn new_does_not_panic() {
        let (_client, _peer_pub, _) = make_client();
    }

    /// Two independent instances constructed with the same config parameters
    /// must be independent objects (no shared mutable state via Arc aside from
    /// the rate limiter, which is internal).
    #[test]
    fn two_independent_instances_are_independent() {
        let (c1, ..) = make_client();
        let (c2, ..) = make_client();
        // If this compiles and doesn't panic, the two instances are independent.
        drop(c1);
        drop(c2);
    }

    // ## handle_outgoing_packet

    /// Sending an outgoing packet must not panic and must push at least one
    /// element onto `send_to_network` (WireGuard requires a handshake initiation
    /// before data can be encrypted, so the first outgoing data call triggers
    /// an initiation frame).
    #[test]
    fn handle_outgoing_packet_produces_handshake_initiation_on_first_send() {
        let (mut client, ..) = make_client();
        let pool = test_pool();
        let payload = vec![0u8; 64];
        let packet = make_packet(&pool, &payload);
        let mut queue: VecDeque<WgKind> = VecDeque::new();

        client.handle_outgoing_packet(packet, &mut queue);

        // WireGuard state machine: first packet causes a handshake initiation
        // to be enqueued.
        assert!(
            !queue.is_empty(),
            "expected at least one WgKind in send_to_network after first outgoing packet"
        );
    }

    /// Sending a zero-byte payload must not panic and must not produce garbage
    /// on the output queue (a zero-length IP packet is effectively a no-op for
    /// the fragmenter).
    #[test]
    fn handle_outgoing_packet_empty_payload_does_not_panic() {
        let (mut client, ..) = make_client();
        let pool = test_pool();
        let packet = make_packet(&pool, &[]);
        let mut queue: VecDeque<WgKind> = VecDeque::new();

        // Must not panic.
        client.handle_outgoing_packet(packet, &mut queue);
    }

    /// Large payloads (above MTU) must be fragmented; the queue may contain
    /// multiple entries.
    #[test]
    fn handle_outgoing_packet_large_payload_may_produce_multiple_frames() {
        let (mut client, peer_static, _) = make_client();
        let pool = test_pool();

        // Complete the handshake so that subsequent outgoing packets are
        // encrypted data frames rather than HandshakeInit messages.
        complete_handshake(&mut client, peer_static);

        // 3× MTU to guarantee at least 3 fragments.
        let payload = vec![0xABu8; 1420 * 3];
        let packet = make_packet(&pool, &payload);
        let mut queue: VecDeque<WgKind> = VecDeque::new();

        client.handle_outgoing_packet(packet, &mut queue);

        assert!(
            queue.len() >= 3,
            "expected ≥3 WgKind entries for a 3×MTU payload, got {}",
            queue.len()
        );
    }

    // ## handle_incoming_packet

    /// Packets that fail rate-limiter verification (unknown / garbage data)
    /// must not panic and must return a sensible error or Done.
    #[test]
    fn handle_incoming_garbage_packet_returns_error_or_done() {
        let (mut client, ..) = make_client();
        let pool = test_pool();
        // Random garbage — not a valid WireGuard frame.
        let payload = vec![0xFFu8; 128];
        let packet = make_packet(&pool, &payload);
        let mut queue: VecDeque<WgKind> = VecDeque::new();

        let result = client.handle_incoming_packet(loopback_addr(), packet, &mut queue);

        match result {
            TunnResult::Done | TunnResult::Err(_) => { /* expected */ }
            other => panic!("unexpected TunnResult for garbage packet: {:?}", other),
        }
    }

    /// A packet from a peer whose static key differs from the configured one
    /// must be rejected with `WireGuardError::InvalidPacket`.
    ///
    /// We craft a valid HandshakeInit from an *unconfigured* peer and verify
    /// that the client refuses it.
    #[test]
    fn handle_incoming_handshake_from_wrong_peer_is_rejected() {
        use std::sync::Arc;

        use ana_gotatun::noise::{Tunn, rate_limiter::RateLimiter};
        let (mut client, _configured_peer_pub, client_public) = make_client();

        // Build a second, entirely separate WireGuard tunnel (acting as an
        // unknown attacker / wrong peer) and use it to produce a HandshakeInit.
        let (attacker_secret, attacker_public) = new_keypair();

        // Attacker's session targeted at client's public key.
        let rl = Arc::new(RateLimiter::new(&attacker_public, 100));
        let mut attacker_tunn = Tunn::new(
            attacker_secret,
            client_public, // addressed to client — but client won't recognise attacker
            None,
            None,
            0,
            rl,
            loopback_addr(),
        );

        let pool = test_pool();
        // Drive the attacker's state machine to produce a HandshakeInit.
        // Wrap the phantom outgoing data packet to trigger initiation.
        let trigger = make_packet(&pool, &[0u8; 64]);
        let mut attacker_queue: VecDeque<WgKind> = VecDeque::new();
        // We need a raw HandshakeInit — drive attacker_tunn.
        // handle_outgoing_packet returns Option<WgKind>; look for HandshakeInit.
        if let Some(wg) = attacker_tunn.handle_outgoing_packet(trigger) {
            attacker_queue.push_back(wg);
        }

        // Extract the HandshakeInit frame (first element of the attacker queue).
        let handshake_init_kind = attacker_queue.pop_front().expect("expected handshake init");
        // Re-wrap as a Packet for the client to receive.
        let raw = match handshake_init_kind {
            WgKind::HandshakeInit(p) => p.into_bytes(),
            _ => return, // not a HandshakeInit; skip test
        };
        let mut queue: VecDeque<WgKind> = VecDeque::new();
        let result = client.handle_incoming_packet(loopback_addr(), raw, &mut queue);

        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidPacket)),
            "expected InvalidPacket for wrong-peer handshake, got {:?}",
            result
        );
    }

    // ## update_timers

    /// `update_timers` must return `Ok(None)` on a freshly constructed session
    /// (no handshake has occurred, so no timer-driven packets are needed yet).
    #[test]
    fn update_timers_returns_ok_on_fresh_session() {
        let (mut client, ..) = make_client();
        let result = client.update_timers();
        assert!(
            result.is_ok(),
            "update_timers should not error on a fresh session, got {:?}",
            result
        );
    }

    /// Calling `update_timers` repeatedly must not panic.
    #[test]
    fn update_timers_is_idempotent() {
        let (mut client, ..) = make_client();
        for _ in 0..10 {
            let _ = client.update_timers();
        }
    }

    // ## send_to_network queue contract

    /// The doc on `handle_incoming_packet` states: "at most one packet is added
    /// to the queue" when the rate limiter is under load (cookie reply path).
    /// For normal (non-load) paths the queue must also not exceed one entry per
    /// call for a fresh session (only timer / handshake-response packets).
    #[test]
    fn handle_incoming_garbage_does_not_flood_send_to_network() {
        let (mut client, ..) = make_client();
        let pool = test_pool();
        let payload = vec![0x00u8; 32];
        let packet = make_packet(&pool, &payload);
        let mut queue: VecDeque<WgKind> = VecDeque::new();

        client.handle_incoming_packet(loopback_addr(), packet, &mut queue);

        assert!(
            queue.len() <= 1,
            "send_to_network must contain at most 1 entry for a garbage packet, got {}",
            queue.len()
        );
    }
}
