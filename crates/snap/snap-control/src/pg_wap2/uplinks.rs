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

//! Uplink management.
//!
//! One uplink is established per (path, WAG) pair and shared by every stream that wants to
//! reach that WAG over that path.
//!
//! [`UplinkManager::maintain`] re-paths uplinks whose path is about to expire and cleans the ones
//! that no stream is using anymore or that are closed.
//!
//! The dataplane is reached through two traits: [`UplinkEstablisher`] opens the connections, and
//! [`GenericUplink`] is one established connection.
//!
//! An uplink is closed from either side: the uplink itself reports that it is no longer usable,
//! e.g. after a network error, and the manager closes one it is dropping.
//!
//! Either way a closed uplink is not handed out again and its streams are torn down.
//!
//! The invariants we maintain are:
//! - There is only one uplink per (path, WAG) pair.
//! - Only a client which is authorized for the (path, SNI) can establish a stream on an uplink.
//! - An uplink is closed when it signals it is no longer usable, or when the manager drops it.
//! - An uplink will be closed when there are no streams using it anymore.
//! - An uplink tries to refresh its path with the same segments before it expires, otherwise
//!   closes.
//!
//! ## Authorization
//!
//! Uplinks are established for a certain path, which is built from public and granted segments.
//! They are not directly tied to the authentication of the client that established them.
//!
//! As long as the authorized segments of at least one client are still valid, the uplink can use
//! this segment.
//!
//! The uplink is closed when:
//! a. no client is using it
//! b. the segments used for the uplink can no longer be refreshed, e.g. because they are no longer
//! granted to any client.
//!
//! The client's authentication is tracked through [`UplinkStreamGuard::grant_expired`] returned by
//! [`UplinkManager::establish_stream`]. When this triggers, the client must tear down its stream.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use sciparse::{
    address::socket_addr::ScionSocketAddr,
    path::{ScionPath, fingerprint::data_plane::DpPathFingerprint},
};
use tokio_util::sync::CancellationToken;

use crate::pg_wap2::{
    auth::DestinationSNI,
    paths::{GrantWatch, PathManager, PathSegmentsGuard, UsedPath},
};

/// Identifies an uplink by the (path, WAG) pair it was established for.
///
/// [`DpPathFingerprint`] covers the hops of the path but not their expiration times, so an
/// uplink keeps its key when its path is refreshed from newer copies of the same segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkKey {
    /// Fingerprint of the path the uplink sends over.
    pub path_fp: DpPathFingerprint,
    /// The WAG the uplink is connected to.
    pub wag: ScionSocketAddr,
}

/// Owns the uplinks towards the WAGs, one per (path, WAG) pair.
///
/// Cheap to clone; all clones share the same state.
pub struct UplinkManager<Establisher: UplinkEstablisher>(Arc<UplinkManagerInner<Establisher>>);

// Not derived: the derive would require `Establisher: Clone`, which it need not be.
impl<Establisher: UplinkEstablisher> Clone for UplinkManager<Establisher> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// The state shared by all clones of an [`UplinkManager`].
struct UplinkManagerInner<Establisher: UplinkEstablisher> {
    uplinks: RwLock<HashMap<UplinkKey, Arc<UplinkEntry<Establisher::Uplink>>>>,
    /// Opens the connections to the WAGs.
    establisher: Establisher,
    paths: PathManager,
    /// An uplink whose path has less than this left is re-pathed by [`UplinkManager::maintain`].
    min_path_lifetime: Duration,
    /// Interval between two [`UplinkManager::maintain`] runs.
    maintenance_interval: Duration,
}

impl<Establisher: UplinkEstablisher> UplinkManager<Establisher> {
    /// Creates a new, empty uplink manager, connecting to the WAGs through `establisher`.
    pub fn new(
        establisher: Establisher,
        paths: PathManager,
        min_path_lifetime: Duration,
        maintenance_interval: Duration,
    ) -> Self {
        Self(Arc::new(UplinkManagerInner {
            uplinks: RwLock::new(HashMap::new()),
            establisher,
            paths,
            min_path_lifetime,
            maintenance_interval,
        }))
    }

    /// Opens a stream for `client_ip` to `dst_sni` over the uplink for the given (path, WAG) pair,
    /// establishing that uplink if it does not exist yet.
    ///
    /// The uplink stays alive as long as at least one of the returned guards is alive.
    ///
    /// The returned guard carries the client's authorization for the path, see
    /// [`UplinkStreamGuard::grant_expired`]. `used_path` has to be the path
    /// [`PathManager::best_path`] returned for this client and SNI.
    pub async fn establish_stream(
        &self,
        client_ip: IpAddr,
        dst_sni: &DestinationSNI,
        used_path: UsedPath,
        wag: ScionSocketAddr,
        now: SystemTime,
    ) -> anyhow::Result<UplinkStreamGuard<Establisher::Uplink>> {
        // Watch the client's grants before anything is established, so an unauthorized client
        // cannot cause an uplink to be built.
        let grants = self
            .0
            .paths
            .watch_grants(client_ip, dst_sni, &used_path, now)
            .context("Client is not authorized to use the path")?;

        // Prepare the uplink and increase its stream count, so it is not cleaned while the stream
        // is being established.
        let reservation = self.reserve_uplink(used_path, wag, now).await?;

        let stream = reservation
            .entry()
            .uplink
            .establish_stream(dst_sni)
            .await
            .context("Failed to establish stream on the uplink")?;

        Ok(reservation.attach(stream, grants))
    }

    /// Returns a reservation on the uplink for the given (path, WAG) pair, establishing it if
    /// it does not exist yet.
    ///
    /// The reservation keeps the uplink from being reaped until it is dropped or turned into a
    /// stream guard.
    async fn reserve_uplink(
        &self,
        used_path: UsedPath,
        wag: ScionSocketAddr,
        now: SystemTime,
    ) -> anyhow::Result<UplinkReservation<Establisher::Uplink>> {
        let key = UplinkKey {
            path_fp: used_path.path.fingerprint(),
            wag,
        };

        // Check if the uplink already exists. The reservation is taken while the map is
        // locked, so the entry cannot be reaped between finding and reserving it.
        //
        // A closed uplink is not reused but replaced below
        {
            let uplinks = self.0.uplinks.read().unwrap();
            if let Some(entry) = uplinks.get(&key).filter(|entry| !entry.is_closed()) {
                return Ok(UplinkReservation::new(entry.clone()));
            }
        }

        // Keep the segments the path was built from available for as long as the uplink lives, so
        // it can still be re-pathed over them.
        let segments_guard = self
            .0
            .paths
            .hold_segments(&used_path, now)
            .await
            .context("Failed to guard the segments of the uplink path")?;

        // Establish the connection without holding the lock. Two clients racing for the same
        // key both establish one, and the loser's connection is dropped again below.
        let closed = CancellationToken::new();
        let uplink = self
            .0
            .establisher
            .establish_connection(used_path.path.clone(), wag, closed.clone())
            .await
            .context("Failed to establish uplink")?;

        let entry = Arc::new(UplinkEntry {
            uplink,
            established: now,
            used_path: RwLock::new(used_path),
            _segments_guard: segments_guard,
            active_stream_count: AtomicUsize::new(0),
            closed,
        });

        // Anything the map drops here still has our reservation counted on the new entry, so the
        // replaced uplink is dropped once its own streams are gone.
        let mut replaced = None;

        let mut uplinks = self.0.uplinks.write().unwrap();
        let entry = match uplinks.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut occupied)
                if occupied.get().is_closed() =>
            {
                tracing::debug!(?key, "Replacing a closed uplink");
                replaced = Some(occupied.insert(entry.clone()));

                entry
            }
            std::collections::hash_map::Entry::Occupied(occupied) => {
                tracing::debug!(?key, "Lost the race to establish an uplink, dropping ours");
                occupied.get().clone()
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                tracing::debug!(?key, "Established a new uplink");
                vacant.insert(entry).clone()
            }
        };

        let reservation = UplinkReservation::new(entry);

        drop(uplinks);
        // Drop replaced outside the lock
        drop(replaced);

        Ok(reservation)
    }

    /// Runs the maintenance loop for the uplink manager.
    ///
    /// Reads the wall clock itself, unlike every other entry point. Never returns.
    pub async fn run(&self) {
        loop {
            self.maintain(SystemTime::now()).await;
            tokio::time::sleep(self.0.maintenance_interval).await;
        }
    }

    /// Re-paths uplinks whose path is about to expire, then reaps the closed and unused ones.
    pub async fn maintain(&self, now: SystemTime) {
        // Snapshot the uplinks so the map is not locked while we compute paths.
        let uplinks: Vec<(UplinkKey, Arc<UplinkEntry<Establisher::Uplink>>)> = self
            .0
            .uplinks
            .read()
            .unwrap()
            .iter()
            .map(|(key, entry)| (*key, entry.clone()))
            .collect();

        for (key, entry) in uplinks {
            // A closed uplink is about to be dropped, re-pathing it would be wasted work.
            if entry.is_closed() {
                continue;
            }

            let used_path = entry.used_path();

            // A path without an expiration, e.g. an AS local one, never needs refreshing.
            let Some(expiry) = used_path.expiration() else {
                continue;
            };

            if expiry > now + self.0.min_path_lifetime {
                continue;
            }

            self.refresh_uplink_path(key, &entry, &used_path, now).await;
        }

        self.reap();
    }

    /// Drops the uplinks that are closed or that no stream is using anymore.
    ///
    /// A closed uplink goes regardless of its streams, since they cannot carry anything over it
    /// either way. Everything the manager drops is closed first, so a stream still holding an entry
    /// finds out that it is gone.
    fn reap(&self) {
        let mut reaped = Vec::new();

        {
            let mut uplinks = self.0.uplinks.write().unwrap();

            uplinks.retain(|key, entry| {
                let keep =
                    !entry.is_closed() && entry.active_stream_count.load(Ordering::Relaxed) > 0;

                if !keep {
                    tracing::debug!(
                        ?key,
                        closed = entry.is_closed(),
                        "Removing uplink from the manager"
                    );

                    entry.closed.cancel();
                    reaped.push(entry.clone());
                }

                keep
            });
        }

        // Dropped outside the lock: tearing a connection down may block.
        drop(reaped);
    }

    /// Tries to give the uplink a path over the same segments with a later expiration.
    async fn refresh_uplink_path(
        &self,
        key: UplinkKey,
        entry: &UplinkEntry<Establisher::Uplink>,
        used_path: &UsedPath,
        now: SystemTime,
    ) {
        let refreshed = match self.0.paths.refresh_path(used_path, now).await {
            Ok(refreshed) => refreshed,
            Err(e) => {
                tracing::warn!(
                    ?key,
                    ?e,
                    "Failed to refresh path of uplink, keeping old version"
                );
                return;
            }
        };

        if refreshed.expiration() <= used_path.expiration() {
            tracing::debug!(
                ?key,
                "Refreshed path does not live longer, keeping the old one"
            );
            return;
        }

        // The refreshed path must stay reachable under the same key, otherwise a client
        // asking for the old path would establish a second uplink over the new one.
        if refreshed.path.fingerprint() != key.path_fp {
            debug_assert!(
                false,
                "Refreshed path has a different fingerprint, this should not happen"
            );
            tracing::warn!(
                ?key,
                "Refreshed path has a different fingerprint, keeping the old one"
            );
            return;
        }

        if let Err(e) = entry.uplink.replace_path(refreshed.path.clone()) {
            tracing::warn!(?key, "Uplink rejected the refreshed path: {e:#}");
            return;
        }

        tracing::debug!(?key, expiry = ?refreshed.expiration(), "Refreshed the path of an uplink");

        *entry.used_path.write().unwrap() = refreshed;
    }
}

/// An established uplink and the state the manager keeps about it.
pub struct UplinkEntry<UplinkType: GenericUplink> {
    uplink: UplinkType,
    established: SystemTime,
    /// The path the uplink currently sends over, replaced when it is refreshed.
    used_path: RwLock<UsedPath>,
    /// Keeps the public segments of `used_path` available while the uplink lives.
    ///
    /// A refreshed path is built from the very same segments, so this stays valid across
    /// [`UplinkManager::refresh_uplink_path`].
    _segments_guard: PathSegmentsGuard,
    active_stream_count: AtomicUsize,
    /// Cancelled once the uplink is closed, either by the uplink itself after a network error or
    /// by the manager when it drops the uplink.
    closed: CancellationToken,
}

impl<UplinkType: GenericUplink> UplinkEntry<UplinkType> {
    /// The path the uplink currently sends over.
    pub fn used_path(&self) -> UsedPath {
        self.used_path.read().unwrap().clone()
    }

    /// When the uplink was established.
    pub fn established(&self) -> SystemTime {
        self.established
    }

    /// Whether the uplink is closed, see [`GenericUplink::establish_connection`].
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Resolves once the uplink is closed.
    pub async fn closed(&self) {
        self.closed.cancelled().await;
    }

    /// The uplink itself.
    pub fn uplink(&self) -> &UplinkType {
        &self.uplink
    }

    fn release_stream(&self) {
        let previous = self.active_stream_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "released a stream that was never reserved");
    }
}

impl<UplinkType: GenericUplink> Drop for UplinkEntry<UplinkType> {
    fn drop(&mut self) {
        // Always cancel the uplink's closed token on drop
        self.closed.cancel();
    }
}

/// Keeps an uplink from being reaped while a stream is being established on it.
struct UplinkReservation<UplinkType: GenericUplink>(Option<Arc<UplinkEntry<UplinkType>>>);

impl<UplinkType: GenericUplink> UplinkReservation<UplinkType> {
    /// Reserves the uplink. Must be called while the uplink map is locked, so the reservation
    /// cannot race with [`UplinkManager::maintain`] reaping the entry.
    fn new(entry: Arc<UplinkEntry<UplinkType>>) -> Self {
        entry.active_stream_count.fetch_add(1, Ordering::Relaxed);
        Self(Some(entry))
    }

    fn entry(&self) -> &Arc<UplinkEntry<UplinkType>> {
        self.0
            .as_ref()
            .expect("the reservation is only taken by `attach`, which consumes self")
    }

    /// Turns the reservation into the guard of an established stream.
    fn attach(
        mut self,
        stream: UplinkType::StreamType,
        grants: GrantWatch,
    ) -> UplinkStreamGuard<UplinkType> {
        UplinkStreamGuard {
            uplink_entry: self.0.take().expect("attach consumes self"),
            stream: Some(stream),
            grants,
        }
    }
}

impl<UplinkType: GenericUplink> Drop for UplinkReservation<UplinkType> {
    fn drop(&mut self) {
        // Still holding the reservation, i.e. no stream was established on it.
        if let Some(entry) = self.0.take() {
            entry.release_stream();
        }
    }
}

/// A stream on an uplink.
///
/// The uplink is kept alive for as long as this guard is.
pub struct UplinkStreamGuard<UplinkType: GenericUplink> {
    uplink_entry: Arc<UplinkEntry<UplinkType>>,
    stream: Option<UplinkType::StreamType>,
    /// The authorization of the client this stream was opened for.
    grants: GrantWatch,
}

impl<UplinkType: GenericUplink> UplinkStreamGuard<UplinkType> {
    /// Resolves once the client this stream belongs to loses its authorization for the path.
    ///
    /// The stream has to be torn down when this resolves.
    ///
    /// Cancel safe, so it can be awaited in a `select!`
    pub async fn grant_expired(&self) {
        self.grants.expired().await;
    }

    /// Resolves once the uplink underneath this stream is closed, so the stream has to be torn
    /// down. The uplink may have failed, or the manager may simply be dropping it.
    ///
    /// This fires for every stream on the uplink, unlike [`Self::grant_expired`], which is per
    /// client. Cancel safe.
    pub async fn uplink_closed(&self) {
        self.uplink_entry.closed().await;
    }

    /// Takes the stream out of the guard, so it can be used for forwarding.
    pub fn take_stream(&mut self) -> Option<UplinkType::StreamType> {
        self.stream.take()
    }

    /// The uplink the stream runs on.
    pub fn uplink_entry(&self) -> &Arc<UplinkEntry<UplinkType>> {
        &self.uplink_entry
    }
}

impl<UplinkType: GenericUplink> Drop for UplinkStreamGuard<UplinkType> {
    fn drop(&mut self) {
        self.uplink_entry.release_stream();
    }
}

/// Opens the connections towards the WAGs that the [`UplinkManager`] hands out streams on.
///
/// Separate from [`GenericUplink`] so that establishing can carry state of its own, e.g. the
/// dataplane handle or socket the connections are made on.
#[async_trait::async_trait]
pub trait UplinkEstablisher: Send + Sync + 'static {
    /// The uplinks this establishes.
    type Uplink: GenericUplink;

    /// Establishes a connection to `dst_addr` over `path`.
    ///
    /// `closed` ends the uplink's life and is cancelled from both sides.
    ///
    /// The uplink has to cancel it once it is no longer usable, e.g. after a network error. An
    /// uplink that never cancels the token keeps being used.
    ///
    /// The manager cancels it when it drops the uplink, which is not a failure: an uplink is also
    /// dropped once nothing streams over it anymore. An implementation can await it to shut its own
    /// tasks down.
    async fn establish_connection(
        &self,
        path: ScionPath,
        dst_addr: ScionSocketAddr,
        closed: CancellationToken,
    ) -> anyhow::Result<Self::Uplink>;
}

/// An established uplink to a WAG, as seen by the control plane.
///
/// The implementation lives in the dataplane; the control plane only decides which uplinks
/// exist, which path they use, and when they are torn down.
#[async_trait::async_trait]
pub trait GenericUplink: Send + Sync + 'static {
    /// A stream multiplexed onto the uplink.
    type StreamType: Send;

    /// Opens a new stream to `dst_sni` on this uplink.
    async fn establish_stream(&self, dst_sni: &str) -> anyhow::Result<Self::StreamType>;

    /// Switches the uplink over to `new_path` without interrupting its streams.
    fn replace_path(&self, new_path: ScionPath) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures::FutureExt;

    use super::*;
    use crate::pg_wap2::{
        paths::UsedPath,
        test_util::{
            Fixture, IDLE_EVICTION_TIME, MockFetcher, SNI, at, client_ip, core_ia, granted_id,
            leaf_ia, other_client_ip, sni, stranger_ip, up_segment, wag,
        },
    };

    /// A `min_path_lifetime` longer than any test path lives, so every maintenance run tries to
    /// re-path the uplinks.
    const ALWAYS_REPATH: Duration = Duration::from_secs(30 * 24 * 3600);
    /// A `min_path_lifetime` shorter than any test path lives, so maintenance never re-paths.
    const NEVER_REPATH: Duration = Duration::from_secs(60);

    /// Establishes [`TestUplink`]s and records what they were asked to do.
    ///
    /// A test hands one clone to its [`UplinkManager`] and keeps another to inspect the log and to
    /// drive the failure paths; all clones share one state.
    #[derive(Clone, Default)]
    struct TestUplinks(Arc<Mutex<TestUplinkState>>);

    /// What the [`TestUplink`]s of one test were asked to do, and how they should respond.
    #[derive(Default)]
    struct TestUplinkState {
        /// Every operation the manager performed, in order.
        log: Vec<UplinkEvent>,
        /// The close tokens handed to the uplinks, in the order they were established, so a test
        /// can close one from the dataplane side.
        close_tokens: Vec<CancellationToken>,
        /// Operations the test wants to fail, so the manager's error paths can be driven.
        failing: Failures,
    }

    #[derive(Default)]
    struct Failures {
        connect: bool,
        stream: bool,
        replace_path: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum UplinkEvent {
        Connected(ScionSocketAddr),
        ConnectionRefused,
        Stream(String),
        StreamRefused,
        PathReplaced,
        PathReplacementRejected,
    }

    impl TestUplinks {
        fn with_state<T>(&self, f: impl FnOnce(&mut TestUplinkState) -> T) -> T {
            f(&mut self.0.lock().unwrap())
        }

        /// Makes the uplinks established from now on fail, or stops doing so.
        fn fail_connections(&self, fail: bool) {
            self.with_state(|state| state.failing.connect = fail);
        }

        /// Makes the streams opened from now on fail, or stops doing so.
        fn fail_streams(&self, fail: bool) {
            self.with_state(|state| state.failing.stream = fail);
        }

        /// Makes the uplinks reject the paths the manager hands them, or stops doing so.
        fn fail_path_replacements(&self, fail: bool) {
            self.with_state(|state| state.failing.replace_path = fail);
        }

        /// Makes the uplink established `index`th report itself as unusable.
        fn close(&self, index: usize) {
            self.with_state(|state| state.close_tokens[index].cancel());
        }

        /// Whether the uplink established `index`th has been closed, by either side.
        fn is_closed(&self, index: usize) -> bool {
            self.with_state(|state| state.close_tokens[index].is_cancelled())
        }

        fn count_events(&self, matching: impl Fn(&UplinkEvent) -> bool) -> usize {
            self.with_state(|state| state.log.iter().filter(|event| matching(event)).count())
        }

        fn path_replacements(&self) -> usize {
            self.count_events(|event| matches!(event, UplinkEvent::PathReplaced))
        }

        fn path_replacement_attempts(&self) -> usize {
            self.count_events(|event| {
                matches!(
                    event,
                    UplinkEvent::PathReplaced | UplinkEvent::PathReplacementRejected
                )
            })
        }

        fn connections(&self) -> usize {
            self.count_events(|event| matches!(event, UplinkEvent::Connected(_)))
        }

        /// Connections the manager tried to establish, successful or not.
        fn connection_attempts(&self) -> usize {
            self.count_events(|event| {
                matches!(
                    event,
                    UplinkEvent::Connected(_) | UplinkEvent::ConnectionRefused
                )
            })
        }

        /// Streams the manager tried to open, successful or not.
        fn stream_attempts(&self) -> usize {
            self.count_events(|event| {
                matches!(event, UplinkEvent::Stream(_) | UplinkEvent::StreamRefused)
            })
        }

        fn streamed_snis(&self) -> Vec<String> {
            self.with_state(|state| {
                state
                    .log
                    .iter()
                    .filter_map(|event| {
                        match event {
                            UplinkEvent::Stream(sni) => Some(sni.clone()),
                            _ => None,
                        }
                    })
                    .collect()
            })
        }
    }

    #[async_trait::async_trait]
    impl UplinkEstablisher for TestUplinks {
        type Uplink = TestUplink;

        async fn establish_connection(
            &self,
            _path: ScionPath,
            dst_addr: ScionSocketAddr,
            closed: CancellationToken,
        ) -> anyhow::Result<Self::Uplink> {
            self.with_state(|state| {
                if state.failing.connect {
                    state.log.push(UplinkEvent::ConnectionRefused);
                    anyhow::bail!("the test asked connecting to fail");
                }

                state.log.push(UplinkEvent::Connected(dst_addr));
                state.close_tokens.push(closed);
                Ok(TestUplink(self.clone()))
            })
        }
    }

    /// One uplink established by [`TestUplinks`], reporting into the same state.
    struct TestUplink(TestUplinks);

    #[async_trait::async_trait]
    impl GenericUplink for TestUplink {
        type StreamType = ();

        async fn establish_stream(&self, dst_sni: &str) -> anyhow::Result<Self::StreamType> {
            self.0.with_state(|state| {
                if state.failing.stream {
                    state.log.push(UplinkEvent::StreamRefused);
                    anyhow::bail!("the test asked streaming to fail");
                }

                state.log.push(UplinkEvent::Stream(dst_sni.to_string()));
                Ok(())
            })
        }

        fn replace_path(&self, _new_path: ScionPath) -> anyhow::Result<()> {
            self.0.with_state(|state| {
                if state.failing.replace_path {
                    state.log.push(UplinkEvent::PathReplacementRejected);
                    anyhow::bail!("the test asked path replacement to fail");
                }

                state.log.push(UplinkEvent::PathReplaced);
                Ok(())
            })
        }
    }

    /// Everything a test needs: the primitives, the uplinks the manager establishes, the manager,
    /// and a path to establish them over.
    type Harness = (Fixture, TestUplinks, UplinkManager<TestUplinks>, UsedPath);

    /// An uplink manager on top of `fixture`, which re-paths uplinks with less than
    /// `min_path_lifetime` left.
    fn manager_for(
        fixture: &Fixture,
        uplinks: TestUplinks,
        min_path_lifetime: Duration,
    ) -> UplinkManager<TestUplinks> {
        UplinkManager::new(
            uplinks,
            fixture.paths.clone(),
            min_path_lifetime,
            Duration::from_secs(10),
        )
    }

    /// An uplink manager and an AS local path to establish uplinks over, which is built from no
    /// segments at all.
    async fn uplink_fixture() -> Harness {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));
        fixture.grant_non_core(Vec::new(), at(0));

        let uplinks = TestUplinks::default();
        let manager = manager_for(&fixture, uplinks.clone(), NEVER_REPATH);
        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), leaf_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("an AS local path always exists");

        (fixture, uplinks, manager, used)
    }

    /// An uplink manager and a path over a public up segment, so the path depends on the segment
    /// store rather than on a grant.
    async fn public_path_fixture(min_path_lifetime: Duration) -> Harness {
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(10 * 24 * 3600),
        );
        // Granting the target without any segment leaves the public segment as the only input.
        fixture.grant_non_core(Vec::new(), at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the public segment yields a path");

        let uplinks = TestUplinks::default();
        let manager = manager_for(&fixture, uplinks.clone(), min_path_lifetime);

        (fixture, uplinks, manager, used)
    }

    /// An uplink manager and a path over a privately granted up segment, so the path depends on a
    /// grant rather than on the segment store.
    async fn granted_path_fixture(min_path_lifetime: Duration, auth_duration: Duration) -> Harness {
        let fixture = Fixture::new(MockFetcher::empty(), auth_duration);
        fixture.grant_non_core(vec![up_segment(0)], at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted segment yields a path");

        let uplinks = TestUplinks::default();
        let manager = manager_for(&fixture, uplinks.clone(), min_path_lifetime);

        (fixture, uplinks, manager, used)
    }

    #[tokio::test]
    async fn uplinks_are_shared_per_path_and_wag() {
        let (fixture, uplinks, manager, used) = uplink_fixture().await;
        fixture.grant_target(client_ip(), "other.example.com", at(0));

        let first = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the first stream is established");
        let second = manager
            .establish_stream(
                client_ip(),
                &"other.example.com".to_string(),
                used.clone(),
                wag(leaf_ia()),
                at(0),
            )
            .await
            .expect("the second stream is established");

        assert_eq!(
            uplinks.connections(),
            1,
            "the same (path, WAG) pair must share one uplink"
        );
        assert_eq!(
            uplinks.streamed_snis(),
            vec![SNI.to_string(), "other.example.com".to_string()],
            "both SNIs get their own stream on that uplink"
        );
        assert!(std::ptr::eq(
            Arc::as_ptr(first.uplink_entry()),
            Arc::as_ptr(second.uplink_entry())
        ));

        // A different WAG over the same path is a different uplink.
        let other_wag = manager
            .establish_stream(client_ip(), &sni(), used, wag(core_ia()), at(0))
            .await
            .expect("the stream to the other WAG is established");
        assert_eq!(uplinks.connections(), 2);
        assert!(!std::ptr::eq(
            Arc::as_ptr(first.uplink_entry()),
            Arc::as_ptr(other_wag.uplink_entry())
        ));
    }

    #[tokio::test]
    async fn uplinks_without_streams_are_reaped() {
        let (_fixture, uplinks, manager, used) = uplink_fixture().await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");

        // As long as a stream is alive, the uplink survives maintenance and is reused.
        manager.maintain(at(0)).await;
        let second = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the second stream is established");
        assert_eq!(uplinks.connections(), 1);

        drop(stream);
        drop(second);

        manager.maintain(at(0)).await;
        manager
            .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(0))
            .await
            .expect("a new stream is established");
        assert_eq!(
            uplinks.connections(),
            2,
            "the reaped uplink has to be established again"
        );
    }

    /// Two clients granted the same private segment, both streaming over the uplink it yields.
    async fn shared_uplink_fixture() -> Harness {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));
        fixture.grant_non_core(vec![up_segment(0)], at(0));
        fixture.grant_non_core_to(other_client_ip(), vec![up_segment(0)], at(0));

        let uplinks = TestUplinks::default();
        let manager = manager_for(&fixture, uplinks.clone(), ALWAYS_REPATH);

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted segment yields a path");

        (fixture, uplinks, manager, used)
    }

    #[tokio::test]
    async fn a_shared_uplink_outlives_the_grant_of_the_client_that_established_it() {
        let (fixture, uplinks, manager, used) = shared_uplink_fixture().await;

        let first = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(core_ia()), at(0))
            .await
            .expect("the first client's stream is established");
        let second = manager
            .establish_stream(
                other_client_ip(),
                &sni(),
                used.clone(),
                wag(core_ia()),
                at(0),
            )
            .await
            .expect("the second client's stream is established");
        assert_eq!(uplinks.connections(), 1, "both clients share one uplink");

        // The first client's grant lapses; the second refreshes and keeps the segment granted.
        fixture.grant_non_core_to(other_client_ip(), vec![up_segment(600)], at(90));
        fixture.auth.clean(at(101));

        // The segment is no longer granted to the first client, but is still granted to the second,
        // which is what keeps the path usable.
        assert!(
            fixture
                .auth
                .segment_grant_expiry(client_ip(), &sni(), &granted_id(&up_segment(0)), at(101))
                .is_none()
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&up_segment(0)), at(101))
                .is_some(),
            "a segment stays available while any client is granted it"
        );

        // Only the client that lost its grant is told to tear down. Expiry is latched, so a
        // single poll of each is enough to tell them apart.
        assert!(
            first.grant_expired().now_or_never().is_some(),
            "the client whose grant lapsed must observe it"
        );
        assert!(
            second.grant_expired().now_or_never().is_none(),
            "the client that refreshed must keep its stream"
        );

        // The uplink was established by the first client, but its path is still granted to the
        // second, so re-pathing it must still work.
        manager.maintain(at(101)).await;
        assert_eq!(
            uplinks.path_replacements(),
            1,
            "the uplink is re-pathed off a grant it was not established with"
        );
        assert_eq!(
            second.uplink_entry().used_path().expiration(),
            used.expiration().map(|old| old + Duration::from_secs(600))
        );
        assert_eq!(
            uplinks.connections(),
            1,
            "re-pathing must not reconnect the uplink"
        );
    }

    #[tokio::test]
    async fn a_stream_is_refused_without_a_grant_for_the_paths_segments() {
        let (fixture, uplinks, manager, used) = shared_uplink_fixture().await;

        // A third client is granted the target, but not the private segment the path uses.
        fixture.grant_target(stranger_ip(), SNI, at(0));

        assert!(
            manager
                .establish_stream(stranger_ip(), &sni(), used, wag(core_ia()), at(0))
                .await
                .is_err(),
            "a client without a grant on the path's segments must not get a stream on it"
        );
        assert_eq!(
            uplinks.connection_attempts(),
            0,
            "and no uplink is established for it"
        );
    }

    #[tokio::test]
    async fn a_stream_is_refused_for_an_ip_without_any_authorization() {
        let (fixture, uplinks, manager, used) = uplink_fixture().await;

        assert!(!fixture.auth.ip_is_authorized(stranger_ip(), at(0)));
        assert!(
            manager
                .establish_stream(stranger_ip(), &sni(), used, wag(leaf_ia()), at(0))
                .await
                .is_err(),
            "an unauthenticated client must not get a stream"
        );
        assert_eq!(
            uplinks.connection_attempts(),
            0,
            "and must not cause any dataplane work"
        );
    }

    #[tokio::test]
    async fn a_stream_is_refused_once_the_clients_grant_has_expired() {
        let (fixture, uplinks, manager, used) = uplink_fixture().await;

        // The path is AS local and built from no segments at all, so the destination grant is the
        // only thing that can authorize it.
        assert!(used.segments.is_empty());

        // The grant lapsed but nothing has swept it yet: the check must not depend on
        // `AuthService::clean` having run.
        assert!(
            manager
                .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(101))
                .await
                .is_err(),
            "a lapsed grant does not authorize a stream, swept or not"
        );

        fixture.auth.clean(at(101));
        assert!(
            manager
                .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(101))
                .await
                .is_err(),
            "and still does not once it has been swept"
        );
        assert_eq!(
            uplinks.connection_attempts(),
            0,
            "an unauthorized client must not cause any dataplane work"
        );
    }

    #[tokio::test]
    async fn an_uplink_is_reused_by_a_stream_that_arrives_before_the_reaper() {
        let (_fixture, uplinks, manager, used) = uplink_fixture().await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");
        let entry = stream.uplink_entry().clone();

        // The uplink has no streams left and is reapable, but until maintenance runs it is still
        // there to be picked up again.
        drop(stream);
        let second = manager
            .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(0))
            .await
            .expect("the second stream is established");

        assert_eq!(
            uplinks.connections(),
            1,
            "an idle uplink is reused rather than replaced"
        );
        assert!(std::ptr::eq(
            Arc::as_ptr(&entry),
            Arc::as_ptr(second.uplink_entry())
        ));

        // And the reservation the second stream took keeps it from being reaped after all.
        manager.maintain(at(0)).await;
        assert!(
            !second.uplink_entry().is_closed(),
            "an uplink that was picked up again must survive the reaper"
        );
    }

    #[tokio::test]
    async fn a_closed_uplink_tears_down_its_streams_and_is_not_reused() {
        let (_fixture, uplinks, manager, used) = uplink_fixture().await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");
        assert_eq!(uplinks.connections(), 1);

        // Nothing has gone wrong yet, so no stream is asked to tear down.
        assert!(stream.uplink_closed().now_or_never().is_none());

        // The dataplane reports the uplink as unusable.
        uplinks.close(0);

        assert!(
            stream.uplink_closed().now_or_never().is_some(),
            "every stream on a closed uplink has to be told to tear down"
        );

        // A new stream must not be put on the closed uplink, even before maintenance runs and even
        // though the old stream still holds it.
        let replacement = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established on a new uplink");
        assert_eq!(uplinks.connections(), 2, "the closed uplink is replaced");
        assert!(!std::ptr::eq(
            Arc::as_ptr(stream.uplink_entry()),
            Arc::as_ptr(replacement.uplink_entry())
        ));
        assert!(
            !replacement.uplink_entry().is_closed(),
            "the replacement is usable"
        );
    }

    #[tokio::test]
    async fn a_closed_uplink_is_reaped_even_though_it_still_has_streams() {
        let (_fixture, uplinks, manager, used) = uplink_fixture().await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");

        uplinks.close(0);
        manager.maintain(at(0)).await;

        // The stream is still alive and holding the entry, but the manager has let it go.
        let replacement = manager
            .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");
        assert_eq!(
            uplinks.connections(),
            2,
            "the reaped uplink has to be established again"
        );
        assert!(!std::ptr::eq(
            Arc::as_ptr(stream.uplink_entry()),
            Arc::as_ptr(replacement.uplink_entry())
        ));
    }

    #[tokio::test]
    async fn reaping_an_unused_uplink_tells_its_holders_it_is_gone() {
        let (_fixture, _uplinks, manager, used) = uplink_fixture().await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(0))
            .await
            .expect("the stream is established");
        let entry = stream.uplink_entry().clone();

        // Dropping the last stream makes the uplink reapable; whoever still holds the entry has to
        // learn that it is no longer managed.
        drop(stream);
        manager.maintain(at(0)).await;

        assert!(
            entry.is_closed(),
            "a reaped uplink counts as unusable for anything still holding it"
        );
    }

    #[tokio::test]
    async fn a_live_uplink_holds_the_segments_of_its_path() {
        let (fixture, _uplinks, manager, used) = public_path_fixture(NEVER_REPATH).await;

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(core_ia()), at(0))
            .await
            .expect("the stream is established");

        // Well past the fixture's 60s idle eviction time, with nothing looking the pair up in the
        // meantime: the uplink's guard alone has to keep it managed.
        let held_at = at(121);
        fixture.segments.maintain(held_at).await;

        assert_eq!(
            fixture.fetcher.calls(),
            1,
            "the guarded pair was never evicted, so it never had to be fetched again"
        );
        assert!(
            fixture.paths.refresh_path(&used, held_at).await.is_ok(),
            "the segments of a live uplink must stay resolvable"
        );

        // Reaping the uplink releases its guard, and the pair goes back to being evicted when idle.
        drop(stream);
        manager.maintain(held_at).await;

        let idle_at = at(242);
        fixture.segments.maintain(idle_at).await;
        fixture
            .segments
            .segments(leaf_ia(), core_ia(), idle_at)
            .await
            .expect("segments are fetched again");
        assert_eq!(
            fixture.fetcher.calls(),
            2,
            "an unheld pair is evicted again once it goes idle"
        );
    }

    #[tokio::test]
    async fn uplinks_are_re_pathed_before_their_path_expires() {
        // Every path is inside the refresh window, so maintenance always tries to re-path.
        let (fixture, uplinks, manager, used) =
            granted_path_fixture(ALWAYS_REPATH, Duration::from_secs(10 * 24 * 3600)).await;
        let expiry = used
            .expiration()
            .expect("a combined path has an expiration");

        let stream = manager
            .establish_stream(client_ip(), &sni(), used, wag(core_ia()), at(0))
            .await
            .expect("the stream is established");

        // Nothing fresher is available yet, so the uplink keeps the path it has.
        manager.maintain(at(0)).await;
        assert_eq!(uplinks.path_replacements(), 0);

        // The client refreshes its grant, which carries a newer copy of the same segment.
        fixture.grant_non_core(vec![up_segment(600)], at(0));
        manager.maintain(at(0)).await;

        assert_eq!(
            uplinks.path_replacements(),
            1,
            "the uplink is given the newer path"
        );
        assert_eq!(
            stream.uplink_entry().used_path().expiration(),
            Some(expiry + Duration::from_secs(600))
        );
        assert_eq!(
            uplinks.connections(),
            1,
            "re-pathing must not reconnect the uplink"
        );
    }

    #[tokio::test]
    async fn an_uplink_that_rejects_a_refreshed_path_keeps_the_one_it_has() {
        let (fixture, uplinks, manager, used) =
            granted_path_fixture(ALWAYS_REPATH, Duration::from_secs(10 * 24 * 3600)).await;
        let expiry = used
            .expiration()
            .expect("a combined path has an expiration");

        let stream = manager
            .establish_stream(client_ip(), &sni(), used, wag(core_ia()), at(0))
            .await
            .expect("the stream is established");

        // A newer copy of the segment is available, but the uplink refuses to switch over.
        fixture.grant_non_core(vec![up_segment(600)], at(0));
        uplinks.fail_path_replacements(true);
        manager.maintain(at(0)).await;

        assert_eq!(
            uplinks.path_replacement_attempts(),
            1,
            "the refresh was offered"
        );
        assert_eq!(uplinks.path_replacements(), 0, "and was rejected");
        assert_eq!(
            stream.uplink_entry().used_path().expiration(),
            Some(expiry),
            "the uplink must keep sending over the path it still has"
        );
        assert!(
            !stream.uplink_entry().is_closed(),
            "a rejected refresh is not fatal to the uplink"
        );

        // The uplink stays due for a refresh, so the next run offers it again.
        uplinks.fail_path_replacements(false);
        manager.maintain(at(0)).await;
        assert_eq!(uplinks.path_replacements(), 1);
        assert_eq!(
            stream.uplink_entry().used_path().expiration(),
            Some(expiry + Duration::from_secs(600))
        );
    }

    #[tokio::test]
    async fn an_uplink_whose_segments_are_gone_keeps_the_path_it_has() {
        let (fixture, uplinks, manager, used) =
            granted_path_fixture(ALWAYS_REPATH, Duration::from_secs(100)).await;
        let expiry = used
            .expiration()
            .expect("a combined path has an expiration");

        let stream = manager
            .establish_stream(client_ip(), &sni(), used.clone(), wag(core_ia()), at(0))
            .await
            .expect("the stream is established");

        // The only grant on the path's segment lapses, so the path cannot be rebuilt at all.
        fixture.auth.clean(at(101));
        assert!(fixture.paths.refresh_path(&used, at(101)).await.is_err());

        manager.maintain(at(101)).await;

        assert_eq!(
            uplinks.path_replacement_attempts(),
            0,
            "there is no path to offer the uplink"
        );
        assert_eq!(
            stream.uplink_entry().used_path().expiration(),
            Some(expiry),
            "a failed refresh leaves the uplink on its current path"
        );
        assert!(
            !stream.uplink_entry().is_closed(),
            "the uplink is only torn down once nothing streams over it"
        );
    }

    #[tokio::test]
    async fn a_failed_stream_releases_its_reservation_on_the_uplink() {
        let (_fixture, uplinks, manager, used) = uplink_fixture().await;

        uplinks.fail_streams(true);
        assert!(
            manager
                .establish_stream(client_ip(), &sni(), used.clone(), wag(leaf_ia()), at(0))
                .await
                .is_err(),
            "the client gets no stream if the uplink cannot open one"
        );
        assert_eq!(
            uplinks.connections(),
            1,
            "the uplink itself was established before the stream failed"
        );
        assert_eq!(uplinks.stream_attempts(), 1);

        // The reservation the failed stream held has to be gone, otherwise the uplink counts as
        // in use forever and is never reaped.
        manager.maintain(at(0)).await;
        assert!(
            uplinks.is_closed(0),
            "an uplink whose only stream failed has to be reaped"
        );

        uplinks.fail_streams(false);
        manager
            .establish_stream(client_ip(), &sni(), used, wag(leaf_ia()), at(0))
            .await
            .expect("the next stream is established");
        assert_eq!(
            uplinks.connections(),
            2,
            "the reaped uplink had to be established again"
        );
    }

    #[tokio::test]
    async fn a_failed_uplink_releases_the_segments_of_its_path() {
        let (fixture, uplinks, manager, used) = public_path_fixture(NEVER_REPATH).await;

        uplinks.fail_connections(true);
        assert!(
            manager
                .establish_stream(client_ip(), &sni(), used.clone(), wag(core_ia()), at(0))
                .await
                .is_err(),
            "the client gets no stream if the uplink cannot be established"
        );
        assert_eq!(
            uplinks.connection_attempts(),
            1,
            "the connection was attempted"
        );

        // The guard on the path's public segments went with the failed attempt, so the pair is
        // subject to idle eviction again.
        let idle_at = at(IDLE_EVICTION_TIME.as_secs() * 2 + 1);
        fixture.segments.maintain(idle_at).await;
        fixture
            .segments
            .segments(leaf_ia(), core_ia(), idle_at)
            .await
            .expect("segments are fetched again");
        assert_eq!(
            fixture.fetcher.calls(),
            2,
            "the pair of a failed uplink must not stay held"
        );

        // Nothing was left in the manager either, so a later client establishes its own uplink.
        uplinks.fail_connections(false);
        manager
            .establish_stream(client_ip(), &sni(), used, wag(core_ia()), idle_at)
            .await
            .expect("the next stream is established");
        assert_eq!(uplinks.connections(), 1);
    }

    #[tokio::test]
    async fn a_stream_is_refused_when_the_paths_segments_cannot_be_held() {
        let (fixture, uplinks, manager, used) = public_path_fixture(NEVER_REPATH).await;

        // The pair backing the path goes idle and is evicted, and refetching it fails.
        let evicted_at = at(IDLE_EVICTION_TIME.as_secs() + 1);
        fixture.segments.maintain(evicted_at).await;
        fixture.fetcher.set_failing(true);

        assert!(
            manager
                .establish_stream(client_ip(), &sni(), used, wag(core_ia()), evicted_at)
                .await
                .is_err(),
            "an uplink whose segments cannot be kept available must not be established"
        );
        assert_eq!(
            uplinks.connection_attempts(),
            0,
            "the segments are secured before anything is connected"
        );
    }
}
