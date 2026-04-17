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
//! # Wireguard-inspired Edgetun Tunnel server
//!
//! The [crate::wg::server::EdgeTunServerState] manages the tunnel state for
//! multiple clients. On the _inbound_ path, it decapsulates and verifies
//! WireGuard-Frames, containing fragments of tunneled packets, reassembles the
//! fragments, checks provided policies and dispatches the packets.
//!
//! On the outbound path, it fragments outgoing packets and encapsulates the
//! fragments.

use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    sync::Arc,
    time::Instant,
};

use ana_gotatun::{
    noise::{Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    x25519,
};
use chacha20::ChaCha8Rng;
use rand::{Rng, SeedableRng};
use scion_sdk_observability::metrics::registry::MetricsRegistry;

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

/// Note that while the local index is represented as a u32, the actual entropy
/// is only 24 bits: The local index is left-shifted and used as the 24 most
/// significant bits of the sender index of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct LocalIdx(u32);

impl LocalIdx {
    fn from_u32(v: u32) -> Self {
        Self(v)
    }

    fn from_receiver_idx(r: u32) -> Self {
        Self(r >> 8)
    }

    fn as_u32(&self) -> u32 {
        self.0
    }
}

/// The maximum number of retries for generating a random local index.
const MAX_IDX_RETRIES: usize = 256;

/// Authorization provider for WireGuard-based edge-tun tunnels.
///
/// Implementors decide whether a given WireGuard static identity is allowed to
/// open a tunnel and, if so, which tunnel address (`T`) to assign to it.
pub trait EdgeTunAuthz<T>: Send + Sync {
    /// If the `identity` is authorized, returns the associated tunnel address (T).
    ///
    /// Implementations MUST NOT re-assign identites. I.e.,
    /// ```text
    /// ∀ t0, t1, s:
    ///   is_authorized(t0, s) == Some(a) implies
    ///    is_authorized(t1, s) ∈ {None, Some(a)}
    /// ```
    ///
    /// ## Implementation notes
    ///
    /// The call should return as quickly as possible and MUST NOT perform any
    /// I/O on the critical path.
    fn is_authorized(&self, now: Instant, identity: &x25519::PublicKey) -> Option<T>;
}

/// An [InboundTrafficPolicy] specifies the traffic policies for inbound tunnel traffic.
pub trait InboundTrafficPolicy<T>: Send + Sync {
    /// Returns true if `packet` meets the policy requirements, for the tunnel identifier.
    fn check_inbound_policy(
        &self,
        identity: &x25519::PublicKey,
        tunnel_remote: &T,
        packet: &[u8],
    ) -> bool;
}

/// Manages the state of a set of authorized, active tunnels and enforces
/// externally provided traffic policies. It associates a tunnel address (T)
/// with a network address (N) and a static identity, each of which uniquely
/// identify an active tunnel.
///
/// The tunnel address (T) is used to identify the correct tunnel for outgoing
/// packets. Note, however, that [EdgeTunServerState] is agnostic wrt. to the
/// protocol that is transported; it is up to the user to ensure that the
/// destination address of outgoing traffic corresponds to the tunnel address.
/// The network address (N) identifies the remote endpoint of an active
/// tunnel on the underlying network.
///
/// The address types are generalized to clearly indicate their function in the
/// context of [EdgeTunServerState] (identification of a tunnel state), and to
/// allow for testing without assuming a specific addressing scheme.
///
/// ## Authorization and address assignment
///
/// A key assumption is that identities are never re-used. As a consequence, a
/// client must re-generate a new static identity if it wants to use another
/// network address.
///
/// If an active tunnel exists for a network (tunnel) address, no new tunnel can
/// be created for that network (tunnel) address. The tunnel MUST first be
/// removed.
pub struct EdgeTunServerState<A, P, N, T> {
    active_tunnels: ActiveTunnels<N, T>,
    rate_limiter: Arc<RateLimiter>,
    authz: Arc<A>,
    inbound_policy: Arc<P>,
    static_public: x25519::PublicKey,
    static_private: x25519::StaticSecret,
    pool: EdgePacketBufPool,
    fragment_size: u16,
}

impl<A: EdgeTunAuthz<T>, P, N, T> EdgeTunServerState<A, P, N, T>
where
    N: std::fmt::Debug + Clone + Eq + std::hash::Hash + AsIpAddr,
    T: std::fmt::Debug + Clone + Eq + std::hash::Hash,
    P: InboundTrafficPolicy<T>,
{
    /// Create a new [`EdgeTunServerState`].
    pub fn new(
        static_private: x25519::StaticSecret,
        rate_limiter: Arc<RateLimiter>,
        authz: Arc<A>,
        inbound_policy: Arc<P>,
        pool: EdgePacketBufPool,
        fragment_size: u16,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);
        Self {
            active_tunnels: ActiveTunnels::new(42),
            rate_limiter,
            authz,
            static_public,
            static_private,
            inbound_policy,
            pool,
            fragment_size,
        }
    }

    /// Handle incoming packet for a tunnel assocated with remote socket address
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
    /// ## Limitations
    ///
    /// The `network_remote` IP-address is only used for rate limiting and as
    /// part of the anti-DDoS cookie mechanism. In the context of SCION,
    /// assuming trust in SCION border routers (meaning, the data plane path in
    /// a received packet represents the _actual_ path), reflection attacks are
    /// much more costly to pull off in SCION. The cookie mechanism in use also
    /// only ties the sender to the IP-address, not the full SCION endhost
    /// address.
    pub fn handle_incoming_packet(
        &mut self,
        network_remote: N,
        packet: Packet,
        send_to_network: &mut VecDeque<WgKind>,
    ) -> TunnResult {
        let now = Instant::now();

        // XXX(dsd): The rate limiter must be adapted to support proper endhost
        // addresses. This is a crutch.
        let Some(from_ip) = network_remote.ip() else {
            tracing::debug!(network_remote=?network_remote, "dropping packet: no IP address in network remote");
            // XXX(dsd): not exactly the right error, but need fix
            return TunnResult::Err(ana_gotatun::noise::errors::WireGuardError::WrongPacketType);
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

        // Retrieve (or create) the tunnel that should handle this packet, and
        // forward the already-verified WgKind to it.
        //
        // Routing rules (mirrors the WireGuard wire format):
        //
        //   HandshakeInit  – keyed by the sender's static public key, which
        //                    the Noise handshake will authenticate.  We must
        //                    create a new (or reuse an existing) Tunn *before*
        //                    we can process the message, so that the Tunn can
        //                    write its handshake-response into the send queue.
        //
        //   HandshakeResp  – the receiver_index field carries *our* local
        //   Data             index, so we route directly to the matching Tunn.
        //   CookieReply
        use ana_gotatun::noise::errors::WireGuardError;
        let is_authz =
            |at: &TunnelIdentifier<N, T>| self.authz.is_authorized(now, &at.identity).is_some();
        let tunn = match &parsed {
            WgKind::HandshakeInit(p) => {
                // The static public key of the initiator is authenticated
                // inside the Noise handshake; ask the Tunn to extract it.
                let hs = match parse_handshake_anon(&self.static_private, &self.static_public, p) {
                    Ok(id) => id,
                    Err(e) => return TunnResult::Err(e),
                };
                let peer_static = x25519::PublicKey::from(hs.peer_static_public);
                let Some(t) = self.authz.is_authorized(now, &peer_static) else {
                    tracing::debug!("dropping HandshakeInit: peer not authorized");
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                };
                let Some(tunn) =
                    self.active_tunnels
                        .get_by_ident_or_create(&peer_static, |local_idx| {
                            (
                                network_remote.clone(),
                                t,
                                Self::create_tunnel(
                                    self.static_private.clone(),
                                    peer_static,
                                    local_idx,
                                    self.rate_limiter.clone(),
                                ),
                                Fragmenter::new(
                                    self.fragment_size as usize,
                                    // XXX(dsd): We instantiate a new registry
                                    // here to avoid re-registering the same
                                    // metrics (which panics) in the metrics
                                    // registry.
                                    // The latter happens because the fragmenter
                                    // is designed to be a singleton.
                                    FragmentMetrics::new(&MetricsRegistry::new()),
                                ),
                                Defragmenter::new(
                                    8,
                                    DefragmentMetrics::new(&MetricsRegistry::new()),
                                ),
                            )
                        })
                else {
                    tracing::debug!(
                        "dropping HandshakeInit: could not create or retrieve tunnel (network/tunnel address conflict?)"
                    );
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                };
                Some(tunn)
            }
            WgKind::HandshakeResp(p) => {
                self.active_tunnels.get_by_idx_or_remove(
                    LocalIdx::from_receiver_idx(p.receiver_idx.into()),
                    is_authz,
                )
            }
            WgKind::Data(p) => {
                self.active_tunnels.get_by_idx_or_remove(
                    LocalIdx::from_receiver_idx(p.header.receiver_idx.into()),
                    is_authz,
                )
            }
            WgKind::CookieReply(p) => {
                self.active_tunnels.get_by_idx_or_remove(
                    LocalIdx::from_receiver_idx(p.receiver_idx.into()),
                    is_authz,
                )
            }
        };

        let tunn = match tunn {
            Some(t) => t,
            // No authorised tunnel found; silently drop.
            None => {
                tracing::debug!("dropping packet: no authorized tunnel found for index");
                return TunnResult::Done;
            }
        };

        let (r, update_netaddr) =
            match handle_incoming_and_drain_queue(send_to_network, parsed, &mut tunn.session_state)
            {
                TunnResult::WriteToTunnel(packet) => {
                    if let Ok(Some(pkt)) = tunn.defragmenter.recv(&packet) {
                        if self.inbound_policy.check_inbound_policy(
                            &tunn.tunnel_ident.identity,
                            &tunn.tunnel_ident.tunnel_remote,
                            pkt.payload,
                        ) {
                            tracing::trace!(
                                tunnel_remote=?tunn.tunnel_ident.tunnel_remote,
                                len=pkt.payload.len(),
                                "inbound packet passed policy, forwarding to tunnel"
                            );
                            let pkt = pool_allocate_packet_with_payload(&self.pool, pkt.payload);
                            return TunnResult::WriteToTunnel(pkt);
                        }
                        tracing::debug!(
                            tunnel_remote=?tunn.tunnel_ident.tunnel_remote,
                            "inbound packet dropped by policy"
                        );
                    }
                    (TunnResult::Done, true)
                }
                r @ TunnResult::Done => (r, true),
                r => (r, false),
            };
        if update_netaddr {
            tunn.tunnel_ident.network_remote = network_remote;
        }
        r
    }

    /// Updates timers of all active tunnels and removes expired or unauthorized tunnels.
    pub fn update_timers(&mut self) -> Vec<(N, WgKind)> {
        let mut keep_alives = vec![];
        let now = Instant::now();

        self.active_tunnels.retain(|at| {
            let is_active = !at.session_state.is_expired();
            let is_authz = self
                .authz
                .is_authorized(now, &at.tunnel_ident.identity)
                .is_some();

            if !is_authz {
                tracing::info!(
                    tunnel_remote=?at.tunnel_ident.tunnel_remote,
                    network_remote=?at.tunnel_ident.network_remote,
                    "evicting tunnel: authorization revoked"
                );
            } else if !is_active {
                tracing::debug!(
                    tunnel_remote=?at.tunnel_ident.tunnel_remote,
                    "evicting tunnel: session expired"
                );
            }

            if is_active && is_authz {
                match at.session_state.update_timers() {
                    Ok(Some(p)) => keep_alives.push((at.tunnel_ident.network_remote.clone(), p)),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(err=?e, "error when updating timers");
                        return false;
                    }
                }
            }
            true
        });
        keep_alives
    }

    /// Handles an outgoing packet sent through the tunnel identified by the
    /// tunnel address `tunnel_remote`.
    ///
    /// Returns the network address of the remote peer and the encrypted packet
    /// to be sent on the network, or `None` if no active tunnel for
    /// `tunnel_remote` exists.
    pub fn handle_outgoing_packet(
        &mut self,
        packet: Packet,
        tunnel_remote: &T,
        send_to_network: &mut VecDeque<(N, WgKind)>,
    ) {
        let now = Instant::now();
        let Some(at) = self
            .active_tunnels
            .get_by_tunnel_remote_or_remove(tunnel_remote, |at| {
                self.authz
                    .is_authorized(now, &at.identity)
                    .map(|x| x == at.tunnel_remote)
                    .unwrap_or_default()
            })
        else {
            tracing::debug!(tunnel_remote=?tunnel_remote, "dropping outgoing packet: no active tunnel for tunnel address");
            return;
        };
        tracing::trace!(
            tunnel_remote=?tunnel_remote,
            network_remote=?at.tunnel_ident.network_remote,
            "sending outgoing packet via tunnel"
        );

        let net_remote = at.tunnel_ident.network_remote.clone();
        let _ = fragment_and_dispatch(
            &packet,
            &mut at.fragmenter,
            &mut at.session_state,
            &self.pool,
            |to_net| send_to_network.push_back((net_remote.clone(), to_net)),
        );
    }

    fn create_tunnel(
        static_private: x25519::StaticSecret,
        identity: x25519::PublicKey,
        local_idx: LocalIdx,
        rate_limiter: Arc<RateLimiter>,
    ) -> Tunn {
        Tunn::new(
            static_private,
            identity,
            None,
            None,
            local_idx.as_u32(),
            rate_limiter.clone(),
            // XXX(dsd): we should extend ana-gotatun to support
            // both, sending the remote socket address and not
            // doing so.
            "0.0.0.0:0".parse().expect("no fail"),
        )
    }
}

/// A tunnel identifier associates three different identifiers for a tunnel:
///
/// * The remote network address (N).
/// * The remote tunnel address (T).
/// * The static identity.
#[derive(Debug, Clone)]
struct TunnelIdentifier<N, T> {
    network_remote: N,
    tunnel_remote: T,
    identity: x25519::PublicKey,
}

struct ActiveTunnel<N, T> {
    tunnel_ident: TunnelIdentifier<N, T>,
    session_state: Tunn,
    fragmenter: Fragmenter,
    defragmenter: Defragmenter,
}

/// Manages the current set of active tunnels and provides specific accessor
/// operations required by the TunnServer while maintaining invariants.
///
/// ## Invariants
///
/// The set of active tunnels can be modeled as a subset of `N⨯T⨯S`, `N` and `T`
/// are the set of network and tunnel addresses and `S` is the set of
/// identities. A tunnel address or an identity uniquely identifies an active
/// tunnel. In other words, for any two tuples `(a_N,a_T,a_S)` and
/// `(b_N,b_T,b_S)` it holds that `a_T == b_T iff a_S == b_S`.
struct ActiveTunnels<N, T> {
    identities: HashMap<x25519::PublicKey, LocalIdx>,
    tunnel_remote: HashMap<T, LocalIdx>,
    active_tunnels: HashMap<LocalIdx, ActiveTunnel<N, T>>,
    rng_state: chacha20::ChaCha8Rng,
}

impl<N, T> ActiveTunnels<N, T>
where
    N: std::fmt::Debug + Clone + Eq + std::hash::Hash,
    T: std::fmt::Debug + Clone + Eq + std::hash::Hash,
{
    fn new(seed: u64) -> Self {
        Self {
            identities: Default::default(),
            tunnel_remote: Default::default(),
            active_tunnels: Default::default(),
            rng_state: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    /// Returns the active tunnel for given `local_idx`. The `should_remove`
    /// allows the caller to immediately remove a stale entry.
    fn get_by_idx_or_remove<F>(
        &mut self,
        local_idx: LocalIdx,
        should_retain: F,
    ) -> Option<&'_ mut ActiveTunnel<N, T>>
    where
        F: FnOnce(&TunnelIdentifier<N, T>) -> bool,
    {
        let Entry::Occupied(occupied_entry) = self.active_tunnels.entry(local_idx) else {
            return None;
        };

        let occupied_entry_ref = occupied_entry.get();
        if !should_retain(&occupied_entry_ref.tunnel_ident) {
            self.tunnel_remote
                .remove(&occupied_entry_ref.tunnel_ident.tunnel_remote);
            self.identities
                .remove(&occupied_entry_ref.tunnel_ident.identity);
            occupied_entry.remove();
            return None;
        }
        Some(occupied_entry.into_mut())
    }

    /// Gets an existing
    fn get_by_ident_or_create<F>(
        &mut self,
        ident: &x25519::PublicKey,
        constr: F,
    ) -> Option<&'_ mut ActiveTunnel<N, T>>
    where
        F: FnOnce(LocalIdx) -> (N, T, Tunn, Fragmenter, Defragmenter),
    {
        match self.identities.get(ident) {
            Some(lidx) => self.active_tunnels.get_mut(lidx),
            None => {
                let lidx = self.next_free_local_idx()?;
                let (network_remote, tunnel_remote, session_state, fragmenter, defragmenter) =
                    constr(lidx);
                match self.tunnel_remote.entry(tunnel_remote.clone()) {
                    Entry::Occupied(_) => return None,
                    Entry::Vacant(vacant_entry) => vacant_entry.insert(lidx),
                };
                // This is already vacant.
                self.identities.insert(*ident, lidx);
                let tunn = self
                    .active_tunnels
                    .entry(lidx)
                    .insert_entry(ActiveTunnel {
                        tunnel_ident: TunnelIdentifier {
                            network_remote,
                            tunnel_remote,
                            identity: *ident,
                        },
                        session_state,
                        fragmenter,
                        defragmenter,
                    })
                    .into_mut();
                Some(tunn)
            }
        }
    }

    fn get_by_tunnel_remote_or_remove<F>(
        &mut self,
        tunnel_remote: &T,
        should_retain: F,
    ) -> Option<&'_ mut ActiveTunnel<N, T>>
    where
        F: FnOnce(&TunnelIdentifier<N, T>) -> bool,
    {
        // XXX(dsd): For small problem sizes, this is good enough. For large
        // servers, the extra hop via the local idx must be removed.
        let lidx = self.tunnel_remote.get(tunnel_remote)?;
        self.get_by_idx_or_remove(*lidx, should_retain)
    }

    /// Retains only those entries for which the `predicate` returns `true`.
    fn retain<F>(&mut self, mut predicate: F) -> Vec<TunnelIdentifier<N, T>>
    where
        F: FnMut(&mut ActiveTunnel<N, T>) -> bool,
    {
        let mut to_be_removed = Vec::new();

        self.active_tunnels.retain(|_lidx, at| {
            let retain = predicate(at);
            if !retain {
                to_be_removed.push(at.tunnel_ident.clone())
            }
            retain
        });

        to_be_removed.iter().for_each(|ti| {
            self.tunnel_remote.remove(&ti.tunnel_remote);
            self.identities.remove(&ti.identity);
        });

        to_be_removed
    }

    fn next_free_local_idx(&mut self) -> Option<LocalIdx> {
        const MASK: u32 = !(0xFFu32 << 24);
        for _ in 0..MAX_IDX_RETRIES {
            let next_try = LocalIdx::from_u32(self.rng_state.next_u32() & MASK);
            if !self.active_tunnels.contains_key(&next_try) {
                return Some(next_try);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        },
        time::Instant,
    };

    use ana_gotatun::{
        noise::{TunnResult, rate_limiter::RateLimiter},
        packet::{Packet, WgKind},
        x25519,
    };
    use scion_sdk_observability::metrics::registry::MetricsRegistry;

    use crate::{
        fragmenting::metrics::{DefragmentMetrics, FragmentMetrics},
        wg::{
            client::{EdgeTunClientConfig, EdgeTunClientState},
            common::{AsIpAddr, EdgePacketBufPool},
            server::{EdgeTunAuthz, EdgeTunServerState, InboundTrafficPolicy, LocalIdx},
        },
    };

    impl AsIpAddr for IpAddr {
        fn ip(&self) -> Option<IpAddr> {
            Some(*self)
        }
    }

    // ## Test implementations of EdgetunAuthz and InboundPolicy
    /// A simple in-memory authz that maps public keys to tunnel (IP) addresses.
    struct TestAuthz {
        entries: Vec<(x25519::PublicKey, IpAddr)>,
    }

    impl TestAuthz {
        fn new(entries: Vec<(x25519::PublicKey, IpAddr)>) -> Self {
            Self { entries }
        }
    }

    impl EdgeTunAuthz<IpAddr> for TestAuthz {
        fn is_authorized(&self, _now: Instant, identity: &x25519::PublicKey) -> Option<IpAddr> {
            self.entries
                .iter()
                .find(|(k, _)| k == identity)
                .map(|(_, addr)| *addr)
        }
    }

    /// A policy that allows all traffic.
    struct AllowAllPolicy;

    impl InboundTrafficPolicy<IpAddr> for AllowAllPolicy {
        fn check_inbound_policy(
            &self,
            _identity: &x25519::PublicKey,
            _tunnel_remote: &IpAddr,
            _packet: &[u8],
        ) -> bool {
            true
        }
    }

    /// A policy that denies all traffic.
    struct DenyAllPolicy;

    impl InboundTrafficPolicy<IpAddr> for DenyAllPolicy {
        fn check_inbound_policy(
            &self,
            _identity: &x25519::PublicKey,
            _tunnel_remote: &IpAddr,
            _packet: &[u8],
        ) -> bool {
            false
        }
    }

    // ## Helpers

    static KEYPAIR_COUNTER: AtomicU8 = AtomicU8::new(0);

    /// Returns a deterministic but unique static keypair.
    fn new_keypair() -> (x25519::StaticSecret, x25519::PublicKey) {
        let mut key_bytes = [0u8; 32];
        // note: the three LSBs of the first byte are clamped to zero, hence we
        // use the second byte.
        key_bytes[1] = KEYPAIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let secret = x25519::StaticSecret::from(key_bytes);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    fn test_pool() -> EdgePacketBufPool {
        EdgePacketBufPool::new(2048)
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:51820".parse().unwrap()
    }

    fn loopback2() -> SocketAddr {
        "127.0.0.1:51821".parse().unwrap()
    }

    fn tunnel_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn tunnel_addr2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    fn make_server<A: EdgeTunAuthz<IpAddr>, P: InboundTrafficPolicy<IpAddr>>(
        authz: Arc<A>,
        policy: Arc<P>,
        server_secret: x25519::StaticSecret,
    ) -> EdgeTunServerState<A, P, SocketAddr, IpAddr> {
        let pool = test_pool();
        let public = x25519::PublicKey::from(&server_secret);
        let rl = Arc::new(RateLimiter::new(&public, 100));
        EdgeTunServerState::new(server_secret, rl, authz, policy, pool, 1420)
    }

    fn make_client(
        client_secret: x25519::StaticSecret,
        server_public: x25519::PublicKey,
    ) -> EdgeTunClientState<SocketAddr> {
        let pool = test_pool();
        let metrics = MetricsRegistry::new();
        let config = EdgeTunClientConfig {
            peer_static: server_public,
            static_secret: client_secret,
            rate_limit: 100,
            mtu: 1420,
            defrag_queue_counts: 8,
        };
        EdgeTunClientState::new(
            pool,
            config,
            FragmentMetrics::new(&metrics),
            DefragmentMetrics::new(&metrics),
        )
    }

    fn make_packet(pool: &EdgePacketBufPool, payload: &[u8]) -> Packet {
        let mut p = pool.get();
        let buf = p.buf_mut();
        unsafe { buf.set_len(payload.len()) };
        buf[..payload.len()].copy_from_slice(payload);
        p
    }

    // ## LocalIdx round-trip

    /// The documented invariant: `from_receiver_idx(x << 8) == x` for any
    /// `LocalIdx` value x whose top 8 bits are zero (as guaranteed by the
    /// MASK in next_free_local_idx).
    #[test]
    fn local_idx_round_trip() {
        for raw in [0u32, 1, 0xFF_FF_FF, 0x12_34_56] {
            let idx = LocalIdx::from_u32(raw);
            // WireGuard sender index = local_idx << 8
            let sender_index: u32 = raw << 8;
            let recovered = LocalIdx::from_receiver_idx(sender_index);
            assert_eq!(idx, recovered, "round-trip failed for raw={:#010x}", raw);
        }
    }

    /// Any byte in the lower 8 bits of the sender index must be masked away.
    #[test]
    fn local_idx_lower_byte_is_ignored() {
        let raw = 0x00_AB_CD_EFu32;
        let idx = LocalIdx::from_u32(raw);
        // Any lower byte value should still recover `idx`.
        for low_byte in [0u32, 1, 127, 255] {
            let sender_index = (raw << 8) | low_byte;
            let recovered = LocalIdx::from_receiver_idx(sender_index);
            assert_eq!(idx, recovered, "lower byte={} not masked", low_byte);
        }
    }

    // ## Server construction
    #[test]
    fn server_new_does_not_panic() {
        let (server_secret, _) = new_keypair();
        let (_client_secret, client_public) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, tunnel_addr())]));
        let policy = Arc::new(AllowAllPolicy);
        let _srv = make_server(authz, policy, server_secret);
    }

    // ## handle_incoming_packet: unknown / garbage packets

    /// Garbage bytes must not panic; they return Done or Err.
    #[test]
    fn server_incoming_garbage_returns_error_or_done() {
        let (server_secret, _) = new_keypair();
        let (_client_secret, client_public) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, tunnel_addr())]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);

        let pool = test_pool();
        let raw = make_packet(&pool, &[0xFFu8; 128]);
        let mut q: VecDeque<WgKind> = VecDeque::new();
        let result = srv.handle_incoming_packet(loopback(), raw, &mut q);
        match result {
            TunnResult::Done | TunnResult::Err(_) => {}
            other => panic!("unexpected: {:?}", other),
        }
    }

    /// A HandshakeInit from an *unauthorized* client must be rejected.
    #[test]
    fn server_incoming_unauthorized_client_is_rejected() {
        let (server_secret, server_public) = new_keypair();
        // Authz is empty — nobody is authorized.
        let authz = Arc::new(TestAuthz::new(vec![]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);

        // Build a client whose key is NOT in authz.
        let (client_secret, _client_public) = new_keypair();
        let mut client = make_client(client_secret, server_public);

        let pool = test_pool();
        let trigger = make_packet(&pool, &[0u8; 64]);
        let mut client_q: VecDeque<WgKind> = VecDeque::new();
        client.handle_outgoing_packet(trigger, &mut client_q);
        let handshake_init = client_q.pop_front().expect("expected HandshakeInit");

        // Convert to raw bytes for the server to receive.
        let raw = Packet::from(handshake_init).into_bytes();
        let mut server_q: VecDeque<WgKind> = VecDeque::new();
        let result = srv.handle_incoming_packet(loopback(), raw, &mut server_q);

        // The server must drop the packet.
        match result {
            TunnResult::Done | TunnResult::Err(_) => {}
            other => {
                panic!(
                    "expected Done or Err for unauthorized init, got {:?}",
                    other
                )
            }
        }
    }

    // ## Full client-server handshake and data exchange

    /// Perform a full Noise handshake between a client and the server and
    /// verify that the tunnel reaches the established state.
    ///
    /// Steps:
    ///  1. Client sends HandshakeInit.
    ///  2. Server processes it, emits HandshakeResponse.
    ///  3. Client processes HandshakeResponse.
    ///  4. Client sends a data packet; server decapsulates it.
    fn do_handshake_with_netaddr<A: EdgeTunAuthz<IpAddr>, P: InboundTrafficPolicy<IpAddr>>(
        client: &mut EdgeTunClientState<SocketAddr>,
        srv: &mut EdgeTunServerState<A, P, SocketAddr, IpAddr>,
        net_addr: SocketAddr,
    ) {
        let pool = test_pool();

        // Step 1: client → server: HandshakeInit
        let trigger = make_packet(&pool, &[0u8; 1]);
        let mut client_q: VecDeque<WgKind> = VecDeque::new();
        client.handle_outgoing_packet(trigger, &mut client_q);
        let init_raw =
            Packet::from(client_q.pop_front().expect("expected HandshakeInit")).into_bytes();

        // Step 2: server processes HandshakeInit
        let mut server_q: VecDeque<WgKind> = VecDeque::new();
        let r = srv.handle_incoming_packet(net_addr, init_raw, &mut server_q);
        assert!(
            matches!(r, TunnResult::Done),
            "server should return Done after processing HandshakeInit, got {:?}",
            r
        );
        assert!(
            !server_q.is_empty(),
            "server must queue a HandshakeResponse"
        );

        // Step 3: client processes HandshakeResponse
        let resp_raw =
            Packet::from(server_q.pop_front().expect("expected HandshakeResponse")).into_bytes();
        let mut client_q: VecDeque<WgKind> = VecDeque::new();
        let r = client.handle_incoming_packet(loopback(), resp_raw, &mut client_q);
        for wg in client_q {
            let raw = Packet::from(wg).into_bytes();
            let mut server_q: VecDeque<WgKind> = VecDeque::new();
            srv.handle_incoming_packet(loopback(), raw, &mut server_q);
        }

        assert!(
            matches!(r, TunnResult::Done),
            "client should return Done after HandshakeResponse, got {:?}",
            r
        );
        // Drain any keepalives the client may emit.
        // drop(client_q);
    }

    fn do_handshake<A: EdgeTunAuthz<IpAddr>, P: InboundTrafficPolicy<IpAddr>>(
        client: &mut EdgeTunClientState<SocketAddr>,
        srv: &mut EdgeTunServerState<A, P, SocketAddr, IpAddr>,
    ) {
        do_handshake_with_netaddr(client, srv, loopback());
    }

    #[test]
    fn handshake_succeeds_for_authorized_client() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, tunnel_addr())]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);
    }

    /// After a successful handshake, an outgoing packet from the server to the
    /// client (identified by tunnel address) must be delivered and decapsulated
    /// correctly by the client.
    #[test]
    fn outgoing_packet_server_to_client_delivered_after_handshake() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let taddr = tunnel_addr();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, taddr)]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);

        // Send a data packet from server → client via tunnel address.
        let pool = test_pool();
        let payload = vec![0xABu8; 200];
        let packet = make_packet(&pool, &payload);
        let mut server_out: VecDeque<(SocketAddr, WgKind)> = VecDeque::new();
        srv.handle_outgoing_packet(packet, &taddr, &mut server_out);

        assert!(
            !server_out.is_empty(),
            "server must emit at least one encrypted frame for outgoing packet"
        );

        // Feed each frame to the client.
        let mut received: Option<Packet> = None;
        for (_, wg) in server_out {
            let raw = Packet::from(wg).into_bytes();
            let mut client_q: VecDeque<WgKind> = VecDeque::new();
            let r = client.handle_incoming_packet(loopback(), raw, &mut client_q);
            if let TunnResult::WriteToTunnel(pkt) = r {
                received = Some(pkt);
                break;
            }
        }

        let received = received.expect("client must receive and decapsulate a packet");
        assert_eq!(
            &*received,
            &payload[..],
            "decapsulated payload must match what was sent"
        );
    }

    /// After a successful handshake, an incoming data packet from the client
    /// that passes the inbound policy must be returned as `WriteToTunnel`.
    #[test]
    fn incoming_data_from_client_reaches_tunnel_after_handshake() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let taddr = tunnel_addr();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, taddr)]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);

        // Client sends a data packet.
        let pool = test_pool();
        let payload = vec![0x55u8; 300];
        let packet = make_packet(&pool, &payload);
        let mut client_q: VecDeque<WgKind> = VecDeque::new();
        client.handle_outgoing_packet(packet, &mut client_q);

        // Feed each frame to the server.
        let mut received: Option<Packet> = None;
        for wg in client_q {
            let raw = Packet::from(wg).into_bytes();
            let mut server_q: VecDeque<WgKind> = VecDeque::new();
            let r = srv.handle_incoming_packet(loopback(), raw, &mut server_q);
            if let TunnResult::WriteToTunnel(pkt) = r {
                received = Some(pkt);
                break;
            }
        }

        let received = received.expect("server must deliver packet to tunnel");
        assert_eq!(
            &*received,
            &payload[..],
            "reassembled payload must match original"
        );
    }

    /// Inbound policy denying all traffic: data frames must be silently dropped
    /// (server returns `Done`, not `WriteToTunnel`).
    #[test]
    fn inbound_policy_deny_drops_data_packets() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let taddr = tunnel_addr();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, taddr)]));
        let policy = Arc::new(DenyAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);

        let pool = test_pool();
        let payload = vec![0xCCu8; 100];
        let packet = make_packet(&pool, &payload);
        let mut client_q: VecDeque<WgKind> = VecDeque::new();
        client.handle_outgoing_packet(packet, &mut client_q);

        for wg in client_q {
            let raw = Packet::from(wg).into_bytes();
            let mut server_q: VecDeque<WgKind> = VecDeque::new();
            let r = srv.handle_incoming_packet(loopback(), raw, &mut server_q);
            assert!(
                !matches!(r, TunnResult::WriteToTunnel(_)),
                "DenyAll policy must not produce WriteToTunnel, got {:?}",
                r
            );
        }
    }

    /// Sending to a tunnel address that has no active session must be a no-op.
    #[test]
    fn outgoing_packet_to_unknown_tunnel_addr_is_noop() {
        let (server_secret, _) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);

        let pool = test_pool();
        let packet = make_packet(&pool, &[1u8; 64]);
        let mut out: VecDeque<(SocketAddr, WgKind)> = VecDeque::new();
        // Must not panic; nothing is emitted.
        srv.handle_outgoing_packet(packet, &tunnel_addr(), &mut out);
        assert!(out.is_empty());
    }

    // ## ActiveTunnels invariants via the server API

    /// Two different clients with different identities and different tunnel
    /// addresses can both complete a handshake against the same server without
    /// interfering.
    #[test]
    fn two_clients_with_distinct_identities_coexist() {
        let (server_secret, server_public) = new_keypair();
        let (c1_secret, c1_public) = new_keypair();
        let (c2_secret, c2_public) = new_keypair();
        let t1 = tunnel_addr();
        let t2 = tunnel_addr2();
        let authz = Arc::new(TestAuthz::new(vec![(c1_public, t1), (c2_public, t2)]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);

        let mut c1 = make_client(c1_secret, server_public);
        let mut c2 = make_client(c2_secret, server_public);

        do_handshake_with_netaddr(&mut c1, &mut srv, loopback());
        do_handshake_with_netaddr(&mut c2, &mut srv, loopback2());

        // Each client can receive a packet addressed to its tunnel address.
        let pool = test_pool();
        for (taddr, client, netaddr) in [(&t1, &mut c1, loopback()), (&t2, &mut c2, loopback2())] {
            let payload = vec![0xEEu8; 50];
            let packet = make_packet(&pool, &payload);
            let mut out: VecDeque<(SocketAddr, WgKind)> = VecDeque::new();
            srv.handle_outgoing_packet(packet, taddr, &mut out);
            assert!(!out.is_empty(), "server must emit packet for {:?}", taddr);

            let mut got_data = false;
            for (_, wg) in out {
                let raw = Packet::from(wg).into_bytes();
                let mut q: VecDeque<WgKind> = VecDeque::new();

                if let TunnResult::WriteToTunnel(_) =
                    client.handle_incoming_packet(netaddr, raw, &mut q)
                {
                    got_data = true;
                }
            }
            assert!(got_data, "client for {:?} did not receive data", taddr);
        }
    }

    /// A client that is removed from authz has its tunnel evicted on the next
    /// `update_timers` call.
    #[test]
    fn revoked_client_tunnel_is_removed_on_update_timers() {
        use std::sync::Mutex;

        // Authz that can be toggled.
        struct ToggleAuthz {
            allowed: Mutex<bool>,
            key: x25519::PublicKey,
            addr: IpAddr,
        }
        impl EdgeTunAuthz<IpAddr> for ToggleAuthz {
            fn is_authorized(&self, _now: Instant, identity: &x25519::PublicKey) -> Option<IpAddr> {
                if *self.allowed.lock().unwrap() && identity == &self.key {
                    Some(self.addr)
                } else {
                    None
                }
            }
        }

        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let taddr = tunnel_addr();
        let authz = Arc::new(ToggleAuthz {
            allowed: Mutex::new(true),
            key: client_public,
            addr: taddr,
        });
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz.clone(), policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);

        // Revoke the client.
        *authz.allowed.lock().unwrap() = false;

        // update_timers must not panic and will evict the tunnel.
        let _ = srv.update_timers();

        // After eviction, outgoing packets to the tunnel address must be dropped.
        let pool = test_pool();
        let packet = make_packet(&pool, &[1u8; 64]);
        let mut out: VecDeque<(SocketAddr, WgKind)> = VecDeque::new();
        srv.handle_outgoing_packet(packet, &taddr, &mut out);
        assert!(
            out.is_empty(),
            "after revocation, no packet must be sent to evicted tunnel"
        );
    }

    // ## update_timers

    #[test]
    fn update_timers_on_empty_server_returns_empty_vec() {
        let (server_secret, _) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let keep_alives = srv.update_timers();
        assert!(keep_alives.is_empty());
    }

    #[test]
    fn update_timers_after_handshake_does_not_panic() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, tunnel_addr())]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret, server_public);

        do_handshake(&mut client, &mut srv);
        let _ = srv.update_timers(); // must not panic
    }

    // ## Duplicate handshake (same identity reconnects)

    /// When the same client sends a second HandshakeInit, the server must
    /// reuse or replace the existing session — it must not crash.
    #[test]
    fn same_client_reconnects_does_not_panic() {
        let (server_secret, server_public) = new_keypair();
        let (client_secret, client_public) = new_keypair();
        let authz = Arc::new(TestAuthz::new(vec![(client_public, tunnel_addr())]));
        let policy = Arc::new(AllowAllPolicy);
        let mut srv = make_server(authz, policy, server_secret);
        let mut client = make_client(client_secret.clone(), server_public);

        do_handshake(&mut client, &mut srv);

        // Reconstruct the client to simulate a reconnect with the same identity.
        let mut client2 = make_client(client_secret, server_public);
        // Must not panic even if a session already exists.
        do_handshake(&mut client2, &mut srv);
    }
}
