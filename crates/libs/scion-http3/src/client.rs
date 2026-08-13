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

//! The client: epoch lifecycle and request orchestration.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use scion_quic::h3::client::{H3ResponseBody, Http3Client, RequestError as H3RequestError};

use crate::{
    config::Config,
    epoch::Epoch,
    error::{Error, TimeoutPhase},
    origin::Origin,
    request::{IntoUrl, Request},
    response::Response,
};

/// The current connectivity, or the reason there is none.
enum EpochSlot {
    /// No connectivity has been built yet (construction does no I/O; the
    /// first request builds it).
    Init,
    /// Active connectivity, tagged with the reset generation it was built
    /// at: the epoch is current only while the tag matches
    /// [`Client::reset_generation`].
    Active(Arc<Epoch>, u64),
    /// [`Client::close`] was called; the client is permanently closed.
    Closed,
}

/// A high-level HTTP/3-over-SCION client: URL in, response out.
///
/// The client owns everything between a URL and a connection: SCION
/// connectivity, DNS resolution, a connection pool, and timeouts. It is cheap
/// to construct and intended to be a long-lived value shared across an
/// application: it is `Send + Sync`, and requests borrow it immutably.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use scion_http3::{Client, Config};
///
/// const MAX_BODY_SIZE: usize = 1 << 20;
///
/// let client = Client::new(Config::new("https://endhost-api.example.org".parse()?));
/// let response = client.get("https://chat.example.org/rooms").await?;
/// let (body, _trailers) = response.text(Some(MAX_BODY_SIZE)).await?;
/// # Ok(())
/// # }
/// ```
pub struct Client {
    /// The current epoch, or the reason there is none.
    epoch: tokio::sync::RwLock<EpochSlot>,
    /// Bumped by [`reset`](Self::reset); the active epoch carries the value
    /// it was built at and a mismatch marks it stale. It's a counter rather than
    /// a flag so a reset that arrives while a rebuild runs is not lost:
    /// the rebuild tags its epoch with a pre-build snapshot, which the reset
    /// has already moved past.
    reset_generation: AtomicU64,
    /// The client configuration.
    config: Config,
    /// Test only: replaces [`Epoch::build`] so epoch lifecycle is testable
    /// without a real stack.
    #[cfg(test)]
    epoch_factory: Option<EpochFactory>,
}

#[cfg(test)]
type EpochFactory =
    Box<dyn Fn() -> futures::future::BoxFuture<'static, Result<Epoch, Error>> + Send + Sync>;

impl Client {
    /// Creates a client. Performs no I/O: connectivity is built lazily by the
    /// first request (or by [`warm_up`](Self::warm_up)).
    #[must_use]
    pub fn new(config: Config) -> Self {
        Client {
            epoch: tokio::sync::RwLock::new(EpochSlot::Init),
            reset_generation: AtomicU64::new(0),
            config,
            #[cfg(test)]
            epoch_factory: None,
        }
    }

    /// Creates a client whose epochs come from `factory` instead of
    /// [`Epoch::build`].
    #[cfg(test)]
    pub(crate) fn with_epoch_factory(config: Config, factory: EpochFactory) -> Self {
        let mut client = Client::new(config);
        client.epoch_factory = Some(factory);
        client
    }

    /// Issues a request and returns the response once its head has arrived.
    ///
    /// The whole call, building connectivity if needed, resolving the
    /// origin, establishing or reusing its connection, and waiting for the
    /// response head, runs under the request timeout (the per-request
    /// override, or the configured default). Collecting the body on the
    /// returned [`Response`] runs under the remainder of the same deadline.
    ///
    /// If establishing a connection through a pooled client fails, the origin
    /// is re-resolved and re-established once and the request re-issued. This
    /// is safe for non-idempotent requests: establishment failure means
    /// nothing reached the wire, and bodies are buffered and thus replayable.
    /// Errors after the request reached the wire are never retried here; see
    /// [`Error::is_retryable`] for what the caller may retry.
    pub async fn request(&self, request: Request) -> Result<Response, Error> {
        let timeout = request
            .request_timeout()
            .unwrap_or(self.config.request_timeout);
        let now = tokio::time::Instant::now();
        // A timeout too large to represent is effectively "no deadline"; 30
        // years stands in for it (mirroring tokio's internal far_future).
        let deadline = now
            .checked_add(timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86400 * 365 * 30));
        let (response, connection) = tokio::time::timeout_at(deadline, self.request_head(&request))
            .await
            .map_err(|_| {
                Error::Timeout {
                    phase: TimeoutPhase::Request,
                    timeout,
                }
            })??;
        Ok(Response::new(response, deadline, timeout, connection))
    }

    /// Issues a GET request to `url`. Shorthand for building a [`Request`]
    /// with defaults and calling [`request`](Self::request).
    pub async fn get(&self, url: impl IntoUrl) -> Result<Response, Error> {
        let request = Request::get(url).build()?;
        self.request(request).await
    }

    /// Issues a POST request with the given body to `url`. Shorthand for
    /// building a [`Request`] with defaults and calling
    /// [`request`](Self::request).
    pub async fn post(&self, url: impl IntoUrl, body: impl Into<Bytes>) -> Result<Response, Error> {
        let request = Request::post(url).body(body).build()?;
        self.request(request).await
    }

    /// Pre-establishes connectivity to `url`'s origin: builds the stack if
    /// needed, resolves the origin, and performs the QUIC handshake, so the
    /// first request pays none of it. Runs under the connect timeout (plus
    /// stack build time).
    pub async fn warm_up(&self, url: impl IntoUrl) -> Result<(), Error> {
        let request = Request::get(url).build()?;
        let origin = Origin::from_request(&request)?;
        let epoch = self.current_epoch().await?;
        let origin_client = epoch.origin_client(origin, Instant::now(), &self.config)?;
        origin_client.connection().await?;
        Ok(())
    }

    /// Marks connectivity stale: the next request tears down the current
    /// connections and rebuilds the stack, discovery, and resolver state.
    ///
    /// Call this when the network below the client changed (for example on a
    /// platform network-change signal). Never blocks; if the rebuild fails,
    /// the failing request reports the build error and the next request
    /// retries the rebuild.
    pub fn reset(&self) {
        self.reset_generation.fetch_add(1, Ordering::Release);
    }

    /// Closes the client: tears down all pooled connections, faulting
    /// in-flight requests promptly. Subsequent requests fail with
    /// [`Error::Closed`]. Idempotent.
    pub async fn close(&self) {
        let previous = {
            let mut slot = self.epoch.write().await;
            std::mem::replace(&mut *slot, EpochSlot::Closed)
        };
        if let EpochSlot::Active(epoch, _) = previous {
            epoch.shutdown().await;
        }
    }

    /// The request path up to the response head. The request timeout is
    /// applied around this by [`request`](Self::request). Returns the
    /// transport client alongside the response so the [`Response`] can keep
    /// the connection alive while the body streams.
    async fn request_head(
        &self,
        request: &Request,
    ) -> Result<(http::Response<H3ResponseBody>, Arc<Http3Client>), Error> {
        let origin = Origin::from_request(request)?;
        let (host, port) = (origin.host.clone(), origin.port);
        let epoch = self.current_epoch().await?;
        let origin_client = epoch.origin_client(origin, Instant::now(), &self.config)?;

        let (connection, generation) = origin_client.connection().await?;
        match connection.request(request.to_http()?).await {
            Ok(response) => Ok((response, connection)),
            // Establishment failure means nothing reached the wire, so one
            // re-establish (possibly to a different candidate) and retry is
            // safe even for non-idempotent requests.
            Err(H3RequestError::Establish(_)) => {
                let (connection, _) = origin_client.reconnect(generation).await?;
                let response = connection
                    .request(request.to_http()?)
                    .await
                    .map_err(|e| Error::from_h3_request_error(&host, port, e))?;
                Ok((response, connection))
            }
            Err(e) => Err(Error::from_h3_request_error(&host, port, e)),
        }
    }

    /// Returns the current epoch, building or rebuilding it if needed.
    ///
    /// Fast path: a read lock and a generation check. Slow path: the write
    /// lock serializes rebuilds (concurrent requests block here, then take
    /// the re-check and adopt the fresh epoch). On rebuild failure the old
    /// epoch stays in place with its stale tag: requests fail fast with the
    /// build error and the next one retries the rebuild.
    async fn current_epoch(&self) -> Result<Arc<Epoch>, Error> {
        {
            let slot = self.epoch.read().await;
            match &*slot {
                EpochSlot::Closed => return Err(Error::Closed),
                EpochSlot::Active(epoch, built)
                    if *built == self.reset_generation.load(Ordering::Acquire) =>
                {
                    return Ok(epoch.clone());
                }
                _ => {}
            }
        }

        let mut slot = self.epoch.write().await;
        match &*slot {
            EpochSlot::Closed => Err(Error::Closed),
            EpochSlot::Active(epoch, built)
                if *built == self.reset_generation.load(Ordering::Acquire) =>
            {
                Ok(epoch.clone())
            }
            _ => {
                // Snapshot before building: a reset that arrives while the
                // build runs leaves the counter ahead of this snapshot, so
                // the next request rebuilds again instead of trusting an
                // epoch built against the network that was just replaced.
                let generation = self.reset_generation.load(Ordering::Acquire);
                let fresh = Arc::new(self.build_epoch().await?);
                let previous =
                    std::mem::replace(&mut *slot, EpochSlot::Active(fresh.clone(), generation));
                if let EpochSlot::Active(previous, _) = previous {
                    // Best effort, off the lock: in-flight requests on the old
                    // epoch are faulted promptly by the shutdown's close().
                    tracing::debug!("Replacing SCION connectivity epoch");
                    tokio::spawn(previous.shutdown());
                }
                Ok(fresh)
            }
        }
    }

    async fn build_epoch(&self) -> Result<Epoch, Error> {
        #[cfg(test)]
        if let Some(factory) = &self.epoch_factory {
            return factory().await;
        }
        Epoch::build(&self.config).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
        time::Duration,
    };

    use scion_quic::quic::config::QuicConfig;
    use test_log::test;

    use super::*;
    use crate::test_support::{
        FailingResolver, SERVER_PORT, StaticResolver, TestServerHarness, server_scion_ip,
        test_config, test_router,
    };

    /// A client whose epochs are assembled from the given harness/resolver
    /// instead of a real stack; `builds` counts epoch (re)builds.
    fn harness_client(
        harness: Arc<TestServerHarness>,
        resolver: Arc<dyn scion_stack::resolver::ScionDnsResolver>,
        config: Config,
    ) -> (Client, Arc<AtomicUsize>) {
        let builds = Arc::new(AtomicUsize::new(0));
        let factory_builds = builds.clone();
        let factory_config = config.clone();
        let client = Client::with_epoch_factory(
            config,
            Box::new(move || {
                factory_builds.fetch_add(1, SeqCst);
                let harness = harness.clone();
                let resolver = resolver.clone();
                let config = factory_config.clone();
                Box::pin(async move { Ok(Epoch::new(harness, resolver, &config)) })
            }),
        );
        (client, builds)
    }

    fn url(host: &str, path: &str) -> String {
        format!("https://{host}:{SERVER_PORT}{path}")
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn get_resolves_via_dns_path() {
        let (router, hits) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config());

        let response = client.get(url("localhost", "/hello")).await.unwrap();
        assert!(response.is_success());
        let (body, _) = response.text(Some(1024)).await.unwrap();
        assert_eq!(body, "world");
        assert_eq!(hits.load(SeqCst), 1);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn duration_max_timeout_does_not_panic() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config());

        let request = Request::get(url("localhost", "/hello"))
            .request_timeout(Duration::MAX)
            .build()
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert!(response.is_success());
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn target_bypasses_the_resolver() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let (client, _) = harness_client(harness, Arc::new(FailingResolver), test_config());

        let request = Request::post(url("localhost", "/echo"))
            .body("ping")
            .target(server_scion_ip())
            .build()
            .unwrap();
        let response = client.request(request).await.unwrap();
        let (body, _) = response.text(Some(1024)).await.unwrap();
        assert_eq!(body, "ping");
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn resolution_failure_surfaces_as_retryable_resolution_error() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let (client, _) = harness_client(harness, Arc::new(FailingResolver), test_config());

        let err = client.get(url("localhost", "/hello")).await.err().unwrap();
        assert!(matches!(err, Error::Resolution { .. }), "{err}");
        assert!(err.is_retryable());
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn establish_failure_reconnects_once_and_retries() {
        let (router, hits) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness.clone(), resolver, test_config());

        let response = client.get(url("localhost", "/hello")).await.unwrap();
        assert!(response.is_success());
        assert_eq!(harness.binds.load(SeqCst), 1);

        // Break the established connection by taking its socket away. The
        // pooled client's own re-establishment (same, still broken socket)
        // then fails, so the request path re-establishes through the pool
        // (fresh socket, fresh server) and retries — invisible to the caller.
        harness.break_sockets();
        // Long enough for the client to notice the broken socket, which takes
        // a couple of task wake-ups rather than any timeout.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let response = client.get(url("localhost", "/hello")).await.unwrap();
        assert!(response.is_success());
        assert_eq!(harness.binds.load(SeqCst), 2);
        assert_eq!(hits.load(SeqCst), 2);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn stream_level_errors_are_not_retried() {
        let (router, _) = test_router();
        // A server that allows zero concurrent request streams: the request
        // fails at the stream level, after establishment.
        let mut server_quic = QuicConfig::builder().verify_peer(false).build();
        server_quic.initial_max_streams_bidi = 0;
        let harness = TestServerHarness::with_server_quic(router, server_quic);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness.clone(), resolver, test_config());

        let err = client.get(url("localhost", "/hello")).await.err().unwrap();
        assert!(matches!(err, Error::ConnectionLimit), "{err}");
        // No re-establishment was attempted: stream-level failures are not
        // establishment failures, so the establish-retry must not fire.
        assert_eq!(harness.binds.load(SeqCst), 1);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn reset_is_lazy_and_rebuild_is_single_flight() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, builds) = harness_client(harness, resolver, test_config());
        let client = Arc::new(client);

        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(builds.load(SeqCst), 1);

        // Reset alone does nothing: the rebuild happens on the next request.
        client.reset();
        assert_eq!(builds.load(SeqCst), 1);

        // Concurrent requests after a reset trigger exactly one rebuild: the
        // write lock is the single-flight.
        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move { client.get(url("localhost", "/hello")).await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(builds.load(SeqCst), 2);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn reset_during_rebuild_triggers_another_rebuild() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let builds = Arc::new(AtomicUsize::new(0));
        // Every build consumes one permit, so the test controls when a
        // rebuild may complete.
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let factory_builds = builds.clone();
        let factory_gate = gate.clone();
        let config = test_config();
        let factory_config = config.clone();
        let client = Arc::new(Client::with_epoch_factory(
            config,
            Box::new(move || {
                let builds = factory_builds.clone();
                let gate = factory_gate.clone();
                let harness = harness.clone();
                let resolver = resolver.clone();
                let config = factory_config.clone();
                Box::pin(async move {
                    gate.acquire().await.expect("gate closed").forget();
                    builds.fetch_add(1, SeqCst);
                    Ok(Epoch::new(harness, resolver, &config))
                })
            }),
        ));

        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(builds.load(SeqCst), 1);

        // Start a rebuild and hold it open at the gate...
        client.reset();
        let pending = {
            let client = client.clone();
            tokio::spawn(async move { client.get(url("localhost", "/hello")).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(builds.load(SeqCst), 1);

        // ...then reset again while the rebuild is running (the network
        // changed again mid-build), and let the rebuild finish.
        client.reset();
        gate.add_permits(2);
        pending.await.unwrap().unwrap();
        assert_eq!(builds.load(SeqCst), 2);

        // The mid-build reset must not be swallowed: the next request
        // rebuilds again instead of trusting the epoch built against the
        // network that was replaced under it.
        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(builds.load(SeqCst), 3);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn failed_rebuild_keeps_stale_and_retries_next_request() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let builds = Arc::new(AtomicUsize::new(0));
        let factory_builds = builds.clone();
        let config = test_config();
        let factory_config = config.clone();
        let client = Client::with_epoch_factory(
            config,
            Box::new(move || {
                let build = factory_builds.fetch_add(1, SeqCst) + 1;
                let harness = harness.clone();
                let resolver = resolver.clone();
                let config = factory_config.clone();
                Box::pin(async move {
                    if build == 2 {
                        return Err(Error::StackBuild {
                            retryable: true,
                            source: "flaky discovery".into(),
                        });
                    }
                    Ok(Epoch::new(harness, resolver, &config))
                })
            }),
        );

        client.get(url("localhost", "/hello")).await.unwrap();
        client.reset();

        // The rebuild fails: the request reports the build error...
        let err = client.get(url("localhost", "/hello")).await.err().unwrap();
        assert!(matches!(err, Error::StackBuild { .. }), "{err}");
        assert!(err.is_retryable());

        // ...and the next request retries the rebuild and succeeds.
        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(builds.load(SeqCst), 3);
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn epochs_do_not_share_stacks_across_reset() {
        // After a reset, sockets come from the new epoch's binder only.
        let (router_one, _) = test_router();
        let (router_two, _) = test_router();
        let first = TestServerHarness::new(router_one);
        let second = TestServerHarness::new(router_two);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let builds = Arc::new(AtomicUsize::new(0));
        let factory_builds = builds.clone();
        let config = test_config();
        let factory_config = config.clone();
        let factory_first = first.clone();
        let factory_second = second.clone();
        let client = Client::with_epoch_factory(
            config,
            Box::new(move || {
                let build = factory_builds.fetch_add(1, SeqCst) + 1;
                let harness = if build == 1 {
                    factory_first.clone()
                } else {
                    factory_second.clone()
                };
                let resolver = resolver.clone();
                let config = factory_config.clone();
                Box::pin(async move { Ok(Epoch::new(harness, resolver, &config)) })
            }),
        );

        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(
            (first.binds.load(SeqCst), second.binds.load(SeqCst)),
            (1, 0)
        );

        client.reset();
        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(
            (first.binds.load(SeqCst), second.binds.load(SeqCst)),
            (1, 1)
        );
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn stalled_establishment_does_not_block_other_origins() {
        // One origin stuck in establishment holds only its own
        // single-flight; other origins proceed.
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        harness.stall_first_bind();
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness.clone(), resolver, test_config());
        let client = Arc::new(client);

        let stalled = {
            let client = client.clone();
            tokio::spawn(async move { client.get(url("a.local", "/hello")).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!stalled.is_finished());

        // A different origin (different host, same live server) completes
        // while the first is still stalled.
        let response = client.get(url("b.local", "/hello")).await.unwrap();
        assert!(response.is_success());
        assert!(!stalled.is_finished());

        harness.release_stalled();
        stalled.await.unwrap().unwrap();
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn evicted_origin_completes_in_flight_request() {
        // Removal is not destruction — an in-flight request keeps its
        // client alive through the `Arc` and completes after eviction.
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config().with_max_origins(1));
        let client = Arc::new(client);

        let slow = {
            let client = client.clone();
            tokio::spawn(async move {
                let response = client.get(url("a.local", "/slow")).await?;
                response.text(Some(1024)).await
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;

        // This inserts a second origin into a map capped at one, evicting the
        // origin with the in-flight request.
        client.get(url("b.local", "/hello")).await.unwrap();

        let (body, _) = slow.await.unwrap().unwrap();
        assert_eq!(body, "slow");
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn close_rejects_new_requests_and_faults_in_flight() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config());
        let client = Arc::new(client);

        client.get(url("localhost", "/hello")).await.unwrap();

        // An in-flight request faults promptly on close instead of running to
        // completion or timing out.
        let in_flight = {
            let client = client.clone();
            tokio::spawn(async move {
                let response = client.get(url("localhost", "/slow")).await?;
                response.text(Some(1024)).await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.close().await;

        let start = tokio::time::Instant::now();
        let result = in_flight.await.unwrap();
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_millis(300));

        // The client is permanently closed; closing again is a no-op.
        let err = client.get(url("localhost", "/hello")).await.err().unwrap();
        assert!(matches!(err, Error::Closed), "{err}");
        client.close().await;
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn per_request_timeout_overrides_the_default() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config());

        let request = Request::get(url("localhost", "/slow"))
            .request_timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let err = client.request(request).await.err().unwrap();
        assert!(
            matches!(
                err,
                Error::Timeout {
                    phase: TimeoutPhase::Request,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn body_collection_respects_max_size() {
        let (router, _) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, _) = harness_client(harness, resolver, test_config());

        let response = client.get(url("localhost", "/hello")).await.unwrap();
        let err = response.bytes(Some(2)).await.err().unwrap();
        assert!(matches!(err, Error::BodyTooLarge { limit: 2 }), "{err}");
    }

    #[test(tokio::test)]
    #[ntest::timeout(10_000)]
    async fn warm_up_establishes_without_a_request() {
        let (router, hits) = test_router();
        let harness = TestServerHarness::new(router);
        let resolver = StaticResolver::new(vec![server_scion_ip()]);
        let (client, builds) = harness_client(harness.clone(), resolver, test_config());

        client.warm_up(url("localhost", "/")).await.unwrap();
        assert_eq!(builds.load(SeqCst), 1);
        assert_eq!(harness.binds.load(SeqCst), 1);
        assert_eq!(hits.load(SeqCst), 0);

        // The warmed-up connection is the one the request uses.
        client.get(url("localhost", "/hello")).await.unwrap();
        assert_eq!(harness.binds.load(SeqCst), 1);
        assert_eq!(hits.load(SeqCst), 1);
    }
}
