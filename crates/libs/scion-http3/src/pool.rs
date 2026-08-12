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

//! An origin-keyed connection pool.
//!
//! [`Http3Client`] is already a per-origin connection pool: it owns one
//! connection, establishes it lazily, reconnects transparently, and
//! multiplexes concurrent requests over it. What this module adds is the map
//! from [`Origin`] to client ([`OriginMap`]) and the multi-candidate
//! establishment that a single `Http3Client` (which takes one
//! already-resolved address) cannot do itself ([`OriginClient`]).

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use scion_quic::{h3::client::Http3Client, quic::config::QuicConfig};
use sciparse::address::{ip_addr::ScionIpAddr, ip_socket_addr::ScionSocketIpAddr};

use crate::{
    config::Config,
    epoch::Network,
    error::{AttemptError, Error, TimeoutPhase},
    establish::staggered_first_ok,
    origin::{Candidates, Origin},
};

/// Counts the re-establishments of one origin's connection.
///
/// A caller that saw its request fail carries the generation it observed; if
/// the stored one has moved past it, someone else already re-established and
/// the caller adopts that connection instead of repeating the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Generation(u64);

impl Generation {
    /// The generation after this one. Wrapping: only equality is ever asked of
    /// it, so the wrap is harmless.
    fn next(self) -> Generation {
        Generation(self.0.wrapping_add(1))
    }
}

/// One origin's connectivity: its candidate addresses, staggered
/// establishment, and the active client.
///
/// The async mutex around the active client is deliberate: holding it across
/// establishment is the per-origin single-flight. It queues
/// only same-origin requests, and only while no live connection exists. The
/// generation counter lets a caller that saw its request fail adopt a client
/// someone else established in the meantime instead of re-establishing
/// (see [`reconnect`](Self::reconnect)).
pub(crate) struct OriginClient {
    /// Copy of this entry's key in the [`OriginMap`]. Deliberately redundant:
    /// the `Arc` escapes the map lock, and a self-contained value makes it
    /// impossible to drive an `OriginClient` with the wrong origin.
    origin: Origin,
    /// The network to establish over: sockets and name resolution. Held
    /// directly rather than passed in per call, so establishing needs nothing
    /// from the epoch that owns this entry.
    network: Arc<Network>,
    /// Establishment configuration snapshot.
    quic: QuicConfig,
    /// Delay between staggered connection attempts to different candidates.
    attempt_delay: Duration,
    /// Timeout for the entire connection establishment, including all attempts.
    connect_timeout: Duration,
    /// The active connection and its generation. The mutex hold during
    /// establishment is the single-flight.
    current: tokio::sync::Mutex<(Option<Arc<Http3Client>>, Generation)>,
    /// Set by [`close`](Self::close), so a caller racing it gets
    /// [`Error::Closed`] rather than a freshly established connection nobody
    /// will close again.
    closed: AtomicBool,
    /// When this entry was last handed out; drives the idle sweep and LRU
    /// eviction.
    last_used: StdMutex<Instant>,
}

impl OriginClient {
    fn new(origin: Origin, config: &Config, now: Instant, network: Arc<Network>) -> Self {
        OriginClient {
            origin,
            network,
            quic: config.quic.clone(),
            attempt_delay: config.connection_attempt_delay,
            connect_timeout: config.connect_timeout,
            current: tokio::sync::Mutex::new((None, Generation::default())),
            closed: AtomicBool::new(false),
            last_used: StdMutex::new(now),
        }
    }

    pub(crate) fn touch(&self, now: Instant) {
        *self.last_used.lock().expect("last-used lock poisoned") = now;
    }

    pub(crate) fn last_used(&self) -> Instant {
        *self.last_used.lock().expect("last-used lock poisoned")
    }

    /// Returns the active connection and its generation, establishing one on
    /// first use.
    ///
    /// Connection breaks are not handled here: [`Http3Client`] reconnects
    /// to its pinned address internally. This level re-establishes, possibly
    /// to a different candidate, only through [`reconnect`](Self::reconnect).
    pub(crate) async fn connection(&self) -> Result<(Arc<Http3Client>, Generation), Error> {
        let mut current = self.current.lock().await;
        self.check_open()?;
        if let Some(connection) = &current.0 {
            return Ok((connection.clone(), current.1));
        }
        self.establish_and_store(&mut current).await
    }

    /// Re-resolves and re-establishes after establishment through the active
    /// connection failed (its pinned address may be gone).
    ///
    /// `seen` is the generation the caller observed the failure at: if the
    /// stored generation has moved on, someone else already re-established
    /// and the fresh connection is adopted instead of repeating the work.
    pub(crate) async fn reconnect(
        &self,
        seen: Generation,
    ) -> Result<(Arc<Http3Client>, Generation), Error> {
        let mut current = self.current.lock().await;
        self.check_open()?;
        if current.1 != seen
            && let Some(connection) = &current.0
        {
            return Ok((connection.clone(), current.1));
        }
        self.establish_and_store(&mut current).await
    }

    /// Closes the active connection, faulting its in-flight requests promptly.
    /// Callers that still hold its `Arc` observe the close. The entry itself is
    /// expected to be removed from the map by the caller.
    pub(crate) async fn close(&self) {
        // Set the flag before taking the mutex, mirroring `Http3Client::close`:
        // an establishment holding it must not hand out a connection afterwards.
        self.closed.store(true, Ordering::Release);
        let connection = self.current.lock().await.0.take();
        if let Some(connection) = connection {
            connection.close().await;
        }
    }

    /// Fails once [`close`](Self::close) has been called. Checked under the
    /// `current` lock, so an establishment that was already in flight when the
    /// close landed cannot publish its result.
    fn check_open(&self) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        Ok(())
    }

    async fn establish_and_store(
        &self,
        current: &mut (Option<Arc<Http3Client>>, Generation),
    ) -> Result<(Arc<Http3Client>, Generation), Error> {
        let established =
            tokio::time::timeout(self.connect_timeout, self.establish(current.0.as_deref()))
                .await
                .map_err(|_| {
                    Error::Timeout {
                        phase: TimeoutPhase::Connect,
                        timeout: self.connect_timeout,
                    }
                })??;
        // A close that landed while we were establishing wins: hand the caller
        // the error rather than a connection the shutdown will never see.
        if self.closed.load(Ordering::Acquire) {
            established.close().await;
            return Err(Error::Closed);
        }
        current.0 = Some(established.clone());
        current.1 = current.1.next();
        Ok((established, current.1))
    }

    /// Resolves the candidates and runs staggered connection attempts, one
    /// fresh socket per attempt (each QUIC connection needs its own socket).
    async fn establish(&self, previous: Option<&Http3Client>) -> Result<Arc<Http3Client>, Error> {
        let hosts: Vec<ScionIpAddr> = match &self.origin.candidates {
            Candidates::Static(list) => list.clone(),
            Candidates::Dns => self.network.resolve(&self.origin.host).await?,
        };
        // The port is single-sourced from the URL; candidates carry none.
        let mut addrs: Vec<ScionSocketIpAddr> = hosts
            .iter()
            .map(|host| ScionSocketIpAddr::new(host.isd_asn(), host.ip(), self.origin.port))
            .collect();

        // Last known good first. Derived from the outgoing client rather than
        // tracked separately: only winners are ever stored, so the two are
        // always equal.
        if let Some(previous) = previous {
            let last_good = previous.remote();
            if let Some(position) = addrs.iter().position(|addr| *addr == last_good) {
                addrs.remove(position);
                addrs.insert(0, last_good);
            }
        }

        let attempts = addrs.into_iter().map(|addr| self.attempt(addr));
        staggered_first_ok(attempts, self.attempt_delay)
            .await
            .map_err(|errors| {
                Error::from_attempt_errors(&self.origin.host, self.origin.port, errors)
            })
    }

    async fn attempt(&self, addr: ScionSocketIpAddr) -> Result<Arc<Http3Client>, AttemptError> {
        let socket = self.network.bind().await.map_err(AttemptError::Bind)?;
        let client = Http3Client::with_config(
            addr,
            socket,
            Some(self.origin.host.clone()),
            self.quic.clone(),
        );
        client.connect().await.map_err(AttemptError::Establish)?;
        Ok(Arc::new(client))
    }
}

/// The bounded map from [`Origin`] to [`OriginClient`].
///
/// The policy is deliberately crude: LRU eviction on the insert path, an
/// opportunistic idle sweep, no background task. For a REST client the cap
/// should essentially never fire, and QUIC's own idle timeout already closes
/// dormant connections, so the sweep only reclaims sockets.
pub(crate) struct OriginMap {
    entries: HashMap<Origin, Arc<OriginClient>>,
    max_origins: usize,
    idle_timeout: Duration,
}

impl OriginMap {
    pub(crate) fn new(max_origins: usize, idle_timeout: Duration) -> Self {
        OriginMap {
            entries: HashMap::new(),
            max_origins: max_origins.max(1),
            idle_timeout,
        }
    }

    /// Returns the entry for `origin`, inserting it if absent. On the insert
    /// path, idle entries are swept and if the map is still full the
    /// least recently used entry is evicted.
    pub(crate) fn get_or_insert(
        &mut self,
        origin: Origin,
        now: Instant,
        config: &Config,
        network: &Arc<Network>,
    ) -> Arc<OriginClient> {
        if let Some(client) = self.entries.get(&origin) {
            client.touch(now);
            return client.clone();
        }

        self.entries.retain(|origin, client| {
            let keep = now.saturating_duration_since(client.last_used()) <= self.idle_timeout;
            if !keep {
                tracing::trace!(%origin, "Sweeping idle origin");
            }
            keep
        });

        if self.entries.len() >= self.max_origins {
            let lru = self
                .entries
                .iter()
                .min_by_key(|(_, client)| client.last_used())
                .map(|(origin, _)| origin.clone());
            if let Some(lru) = lru {
                self.entries.remove(&lru);
                tracing::debug!(origin = %lru, "Origin cap reached, evicting least recently used");
            }
        }

        let client = Arc::new(OriginClient::new(
            origin.clone(),
            config,
            now,
            network.clone(),
        ));
        self.entries.insert(origin, client.clone());
        client
    }

    /// Removes and returns all entries (for epoch shutdown).
    pub(crate) fn drain(&mut self) -> Vec<Arc<OriginClient>> {
        self.entries.drain().map(|(_, client)| client).collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, origin: &Origin) -> bool {
        self.entries.contains_key(origin)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::SeqCst;

    use test_log::test;

    use super::*;
    use crate::test_support::{
        SERVER_PORT, StaticResolver, TestServerHarness, dead_scion_ip, server_scion_ip,
        test_config, test_epoch, test_network, test_router,
    };

    /// A network with no live candidates; enough for the map-level tests, which
    /// never establish.
    fn inert_network() -> Arc<Network> {
        test_network(
            TestServerHarness::new(test_router().0),
            StaticResolver::new(vec![]),
        )
    }

    fn static_origin(host: &str, candidates: Vec<ScionIpAddr>) -> Origin {
        Origin {
            host: host.to_string(),
            port: SERVER_PORT,
            candidates: Candidates::Static(candidates),
        }
    }

    /// A test instant `millis` after a fixed base, so the map's time-based
    /// policies can be driven without sleeping.
    fn at(millis: u64) -> Instant {
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *BASE.get_or_init(Instant::now) + Duration::from_millis(millis)
    }

    fn dns_origin(host: &str) -> Origin {
        Origin {
            host: host.to_string(),
            port: SERVER_PORT,
            candidates: Candidates::Dns,
        }
    }

    // --- OriginMap: bounded and swept, no I/O ---

    #[test]
    fn origin_map_evicts_lru_at_cap() {
        let config = test_config();
        let network = inert_network();
        let mut map = OriginMap::new(2, Duration::from_secs(3600));
        let (a, b, c) = (dns_origin("a"), dns_origin("b"), dns_origin("c"));

        map.get_or_insert(a.clone(), at(0), &config, &network);
        map.get_or_insert(b.clone(), at(10), &config, &network);
        // Touch `a`, making `b` the least recently used.
        map.get_or_insert(a.clone(), at(20), &config, &network);
        map.get_or_insert(c.clone(), at(30), &config, &network);

        assert_eq!(map.len(), 2);
        assert!(map.contains(&a));
        assert!(map.contains(&c));
        assert!(!map.contains(&b));
    }

    #[test]
    fn origin_map_sweeps_idle_on_insert() {
        let config = test_config();
        let network = inert_network();
        let mut map = OriginMap::new(10, Duration::from_millis(100));
        let (a, b, c) = (dns_origin("a"), dns_origin("b"), dns_origin("c"));

        map.get_or_insert(a.clone(), at(0), &config, &network);
        map.get_or_insert(b.clone(), at(150), &config, &network);
        // At t=300, `a` (idle 300ms) and `b` (idle 150ms) are both stale.
        map.get_or_insert(c.clone(), at(300), &config, &network);

        assert_eq!(map.len(), 1);
        assert!(map.contains(&c));
    }

    #[test]
    fn origin_map_hit_does_not_sweep() {
        let config = test_config();
        let network = inert_network();
        let mut map = OriginMap::new(10, Duration::from_millis(100));
        let (a, b) = (dns_origin("a"), dns_origin("b"));

        map.get_or_insert(a.clone(), at(0), &config, &network);
        map.get_or_insert(b.clone(), at(0), &config, &network);
        // A hit on `a` long past the idle timeout must not sweep anything —
        // the sweep runs only on the insert path.
        map.get_or_insert(a.clone(), at(1_000), &config, &network);

        assert_eq!(map.len(), 2);
    }

    // --- OriginClient over the in-memory server ---

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn steady_state_reuses_single_connection() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        let client = OriginClient::new(
            static_origin("localhost", vec![server_scion_ip()]),
            &config,
            Instant::now(),
            network,
        );

        let (first, generation) = client.connection().await.unwrap();
        for _ in 0..4 {
            let (next, next_generation) = client.connection().await.unwrap();
            assert!(Arc::ptr_eq(&first, &next));
            assert_eq!(generation, next_generation);
        }
        assert_eq!(harness.binds.load(SeqCst), 1);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn concurrent_requests_share_one_establishment() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        harness.stall_first_bind();
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        let client = Arc::new(OriginClient::new(
            static_origin("localhost", vec![server_scion_ip()]),
            &config,
            Instant::now(),
            network,
        ));

        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move { client.connection().await })
            })
            .collect();
        // Let all three queue up behind the establishment single-flight.
        tokio::time::sleep(Duration::from_millis(100)).await;
        harness.release_stalled();

        let mut clients = Vec::new();
        for task in tasks {
            let (client, generation) = task.await.unwrap().unwrap();
            assert_eq!(generation, Generation(1));
            clients.push(client);
        }
        assert!(Arc::ptr_eq(&clients[0], &clients[1]));
        assert!(Arc::ptr_eq(&clients[0], &clients[2]));
        assert_eq!(harness.binds.load(SeqCst), 1);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn reconnect_adopts_peer_established_client() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        let client = OriginClient::new(
            static_origin("localhost", vec![server_scion_ip()]),
            &config,
            Instant::now(),
            network,
        );

        let (_, generation) = client.connection().await.unwrap();
        assert_eq!(harness.binds.load(SeqCst), 1);

        // A caller that observed a failure at `generation` re-establishes.
        let (fresh, fresh_generation) = client.reconnect(generation).await.unwrap();
        assert_eq!(harness.binds.load(SeqCst), 2);
        assert_ne!(fresh_generation, generation);

        // A second caller with the same stale view adopts the fresh client
        // instead of re-establishing again.
        let (adopted, adopted_generation) = client.reconnect(generation).await.unwrap();
        assert!(Arc::ptr_eq(&fresh, &adopted));
        assert_eq!(adopted_generation, fresh_generation);
        assert_eq!(harness.binds.load(SeqCst), 2);
    }

    #[test(tokio::test)]
    #[ntest::timeout(20_000)]
    async fn reconnect_tries_last_known_good_first() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        // Sorted candidate order puts the dead address first, so the initial
        // establishment attempts it, staggers, and wins on the live one.
        let client = OriginClient::new(
            static_origin("localhost", vec![dead_scion_ip(), server_scion_ip()]),
            &config,
            Instant::now(),
            network,
        );

        let (first, generation) = client.connection().await.unwrap();
        assert_eq!(first.remote().ip(), server_scion_ip().ip());
        assert_eq!(harness.binds.load(SeqCst), 2);

        // On re-establishment the last known good address is tried first, so
        // the dead candidate is never attempted: exactly one more bind.
        let (fresh, _) = client.reconnect(generation).await.unwrap();
        assert_eq!(fresh.remote().ip(), server_scion_ip().ip());
        assert_eq!(harness.binds.load(SeqCst), 3);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn dns_candidates_resolve_via_epoch_resolver() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let config = test_config();
        let network = test_network(harness.clone(), resolver.clone());
        let client = OriginClient::new(dns_origin("localhost"), &config, Instant::now(), network);

        let (_, generation) = client.connection().await.unwrap();
        assert_eq!(resolver.calls.load(SeqCst), 1);

        // Re-establishment re-resolves: the pinned address may be gone.
        client.reconnect(generation).await.unwrap();
        assert_eq!(resolver.calls.load(SeqCst), 2);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn all_candidates_dead_fails_with_connect() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        let client = OriginClient::new(
            static_origin("localhost", vec![dead_scion_ip()]),
            &config,
            Instant::now(),
            network,
        );

        let Err(err) = client.connection().await else {
            panic!("establishment to a dead candidate succeeded");
        };
        assert!(matches!(err, Error::Connect { .. }), "{err}");
        assert!(err.is_retryable());
    }

    /// A closed entry stays closed: it hands out no further connections rather
    /// than silently establishing a replacement nobody will ever close.
    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn closed_origin_client_refuses_to_reconnect() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let network = test_network(harness.clone(), StaticResolver::new(vec![]));
        let client = OriginClient::new(
            static_origin("localhost", vec![server_scion_ip()]),
            &config,
            Instant::now(),
            network,
        );

        let (_, generation) = client.connection().await.unwrap();
        client.close().await;

        assert!(matches!(client.connection().await, Err(Error::Closed)));
        assert!(matches!(
            client.reconnect(generation).await,
            Err(Error::Closed)
        ));
        // No re-establishment was attempted after the close.
        assert_eq!(harness.binds.load(SeqCst), 1);
    }

    /// A request racing epoch shutdown fails rather than repopulating the map
    /// that was just drained.
    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn epoch_refuses_origins_after_shutdown() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let config = test_config();
        let epoch = test_epoch(harness.clone(), StaticResolver::new(vec![]), &config);

        let origin = static_origin("localhost", vec![server_scion_ip()]);
        epoch
            .origin_client(origin.clone(), Instant::now(), &config)
            .expect("origin client before shutdown");

        epoch.clone().shutdown().await;

        assert!(matches!(
            epoch.origin_client(origin, Instant::now(), &config),
            Err(Error::Closed)
        ));
    }
}
