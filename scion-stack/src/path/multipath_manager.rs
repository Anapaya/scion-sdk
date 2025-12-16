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

//! Multipath manager for SCION path selection.
//!
//! Runs one task per (src,dst) pair. Each task fetches paths, filters them, applies issue
//! penalties, ranks candidates, and picks an active path.
//!
//! Tasks track expiry, refetch intervals, backoff after failures, and drop entries that go
//! idle. The Active path for a (src,dst) pair is exposed lock-free via `ArcSwap`.
//!
//! All path data comes from the provided `PathFetcher`. Issue reports feed
//! into reliability scoring and can trigger immediate re-ranking.
//!
//! ## Issue Handling & Penalties
//!
//! Incoming issues are applied to cached paths immediately and can trigger an active-path
//! switch. Issues are cached with a timestamp and applied to newly fetched paths.
//!
//! Penalties on individual paths and individual cached issues decay over time. Allowing paths
//! to recover.
//!
//! ## Active Path Switching
//!
//! If no active path exists, the highest-ranked valid path is selected.
//! Active path is replaced when it expires, nears expiry, or falls behind the best candidate
//! by a configured score margin.

// Internal:
//
// ## Core components
//
// MultiPathManager: Central entry point. Holds configuration, the global issue manager, and a
// concurrent map from (src, dst) to worker. Spawns a worker on first access and provides lock-free
// reads to workers.
//
// PathSet: Per-tuple worker. Fetches paths, filters them, applies issue penalties, ranks
// candidates, and maintains an active path. Runs a periodic maintenance loop handling refetch,
// backoff, and idle shutdown.
//
// PathIssueManager:  Global issue cache and broadcast system. Deduplicates issues and notifies all
// workers of incoming issues.
//
// IssueKind / IssueMarker: Describe concrete path problems (SCMP, socket errors). Compute the
// affected hop or full path, assign a penalty, and support deduplication and decay.

use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque, hash_map},
    fmt::Display,
    hash::RandomState,
    sync::{Arc, Mutex, Weak, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwapOption;
use scc::HashIndex;
use scion_proto::{
    address::IsdAsn,
    path::{Path, PathFingerprint},
};
use scion_sdk_utils::backoff::{BackoffConfig, ExponentialBackoff};
use tokio::{
    select,
    sync::{
        Notify,
        broadcast::{self},
    },
    task::JoinHandle,
};
use tracing::{Instrument, instrument};

use crate::path::{
    PathStrategy,
    fetcher::{
        PathFetcherImpl,
        traits::{PathFetchError, PathFetcher},
    },
    multipath_manager::{
        issues::{IssueKind, IssueMarker, IssueMarkerTarget},
        reliability::ReliabilityScore,
        traits::{PathManager, PathPrefetcher, PathWaitError, SyncPathManager},
    },
    types::PathManagerPath,
};

/// Path fetcher traits and types.
pub mod traits {

    use std::{io, time::Duration};

    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use scion_proto::{address::IsdAsn, path::Path};
    use thiserror::Error;
    use tracing::error;

    use crate::types::ResFut;

    /// Trait for active path management with async interface.
    pub trait PathManager: SyncPathManager {
        /// Returns a path to the destination from the path cache or requests a new path from the
        /// SCION Control Plane.
        fn path_wait(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
            now: DateTime<Utc>,
        ) -> impl ResFut<'_, Path<Bytes>, PathWaitError>;

        /// Returns a path to the destination from the path cache or requests a new path from the
        /// SCION Control Plane, with a maximum wait time.
        fn path_timeout(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
            now: DateTime<Utc>,
            timeout: Duration,
        ) -> impl ResFut<'_, Path<Bytes>, PathWaitTimeoutError> {
            let fut = self.path_wait(src, dst, now);
            async move {
                match tokio::time::timeout(timeout, fut).await {
                    Ok(result) => {
                        result.map_err(|e| {
                            match e {
                                PathWaitError::FetchFailed(msg) => {
                                    PathWaitTimeoutError::FetchFailed(msg)
                                }
                                PathWaitError::NoPathFound => PathWaitTimeoutError::NoPathFound,
                            }
                        })
                    }
                    Err(_) => Err(PathWaitTimeoutError::Timeout),
                }
            }
        }
    }

    /// Path wait errors.
    #[derive(Debug, Clone, Error)]
    pub enum PathWaitError {
        /// Path fetch failed.
        #[error("path fetch failed: {0}")]
        FetchFailed(String),
        /// No path found.
        #[error("no path found")]
        NoPathFound,
    }

    /// Path wait errors.
    #[derive(Debug, Clone, Error)]
    pub enum PathWaitTimeoutError {
        /// Path fetch failed.
        #[error("path fetch failed: {0}")]
        FetchFailed(String),
        /// No path found.
        #[error("no path found")]
        NoPathFound,
        /// Waiting for path timed out
        #[error("waiting for path timed out")]
        Timeout,
    }

    /// Trait for active path management with sync interface. Implementors of this trait should be
    /// able to be used in sync and async context. The functions must not block.
    pub trait SyncPathManager {
        /// Add a path to the path cache. This can be used to register reverse paths.
        fn register_path(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>, path: Path<Bytes>);

        /// Returns a path to the destination from the path cache.
        /// If the path is not in the cache, it returns Ok(None), possibly causing the path to be
        /// fetched in the background. If the cache is locked an io error WouldBlock is
        /// returned.
        fn try_cached_path(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
            now: DateTime<Utc>,
        ) -> io::Result<Option<Path<Bytes>>>;
    }

    /// Trait for prefetching paths in the path manager.
    pub trait PathPrefetcher {
        /// Prefetch a paths for the given source and destination.
        fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn);
    }
}

/// Configuration for the MultiPathManager.
#[derive(Debug, Clone, Copy)]
pub struct MultiPathManagerConfig {
    /// Maximum number of cached paths per src-dst pair.
    max_cached_paths_per_pair: usize,
    /// Interval between path refetches
    refetch_interval: Duration,
    /// Minimum duration between path refetches.
    min_refetch_delay: Duration,
    /// Minimum remaining expiry before refetching paths.
    min_expiry_threshold: Duration,
    /// Maximum idle period before the managed paths are removed.
    max_idle_period: Duration,
    /// Backoff configuration for path fetch failures.
    fetch_failure_backoff: BackoffConfig,
    /// Count of issues to be cached
    issue_cache_size: usize,
    /// Size of the issue cache broadcast channel
    issue_broadcast_size: usize,
    /// Time window to ignore duplicate issues
    issue_deduplication_window: Duration,
    /// Score difference after which active path should be replaced
    path_swap_score_threshold: f32,
}

impl Default for MultiPathManagerConfig {
    fn default() -> Self {
        MultiPathManagerConfig {
            max_cached_paths_per_pair: 50,
            refetch_interval: Duration::from_secs(60 * 30), // 30 minutes
            min_refetch_delay: Duration::from_secs(60),
            min_expiry_threshold: Duration::from_secs(60 * 5), // 5 minutes
            max_idle_period: Duration::from_secs(60 * 2),      // 2 minutes
            fetch_failure_backoff: BackoffConfig {
                minimum_delay_secs: 60.0,
                maximum_delay_secs: 300.0,
                factor: 1.5,
                jitter_secs: 5.0,
            },
            issue_cache_size: 100,
            issue_broadcast_size: 10,
            // Same issue within 10s is duplicate
            issue_deduplication_window: Duration::from_secs(10),
            path_swap_score_threshold: 0.5,
        }
    }
}

impl MultiPathManagerConfig {
    /// Validates the configuration.
    fn validate(&self) -> Result<(), &'static str> {
        if self.min_refetch_delay > self.refetch_interval {
            return Err("min_refetch_delay must be smaller than refetch_interval");
            // Otherwise, refetch interval makes no sense
        }

        if self.min_refetch_delay > self.min_expiry_threshold {
            return Err("min_refetch_delay must be smaller than min_expiry_threshold");
            // Otherwise, very unlikely, we have paths expiring before we can refetch
        }

        Ok(())
    }
}

/// Errors that can occur when getting a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GetPathError {
    /// No paths are available for the given src-dst pair.
    #[error("no paths are available for the given src-dst pair")]
    NoPaths,
}

// TODO : Implement path fingerprinting by hop fields instead of requiring metadata
/// Path manager managing multiple paths per src-dst pair.
pub struct MultiPathManager<F: PathFetcher = PathFetcherImpl>(Arc<MultiPathManagerInner<F>>);

impl<F> Clone for MultiPathManager<F>
where
    F: PathFetcher,
{
    fn clone(&self) -> Self {
        MultiPathManager(self.0.clone())
    }
}

struct MultiPathManagerInner<F: PathFetcher> {
    config: MultiPathManagerConfig,
    fetcher: F,
    path_strategy: PathStrategy,
    issue_manager: Mutex<PathIssueManager>,
    managed_paths: HashIndex<(IsdAsn, IsdAsn), (PathSetHandle, PathSetTask)>,
}

impl<F: PathFetcher> MultiPathManager<F> {
    /// Creates a new [`MultiPathManager`].
    pub fn new(
        config: MultiPathManagerConfig,
        fetcher: F,
        path_strategy: PathStrategy,
    ) -> Result<Self, &'static str> {
        config.validate()?;

        let issue_manager = Mutex::new(PathIssueManager::new(
            config.issue_cache_size,
            config.issue_broadcast_size,
            config.issue_deduplication_window,
        ));

        Ok(MultiPathManager(Arc::new(MultiPathManagerInner {
            config,
            fetcher,
            issue_manager,
            path_strategy,
            managed_paths: HashIndex::new(),
        })))
    }

    /// Tries to get the active path for the given src-dst pair.
    ///
    /// If no active path is set, returns None.
    ///
    /// If the src-dst pair is not yet managed, starts managing it.
    pub fn try_path(&self, src: IsdAsn, dst: IsdAsn, now: SystemTime) -> Option<Path> {
        let try_path = self
            .0
            .managed_paths
            .peek_with(&(src, dst), |_, (handle, _)| {
                handle.try_active_path().as_deref().map(|p| p.0.clone())
            })
            .flatten();

        match try_path {
            Some(active) => {
                // XXX(ake): Since the Paths are actively managed, they should never be expired
                // here.
                let expired = active.is_expired(now.into()).unwrap_or(true);
                debug_assert!(!expired, "Returned expired path from try_get_path");

                Some(active)
            }
            None => {
                // Start managing paths for the src-dst pair
                self.fast_ensure_managed_paths(src, dst);
                None
            }
        }
    }

    /// Gets the active path for the given src-dst pair.
    ///
    /// If the src-dst pair is not yet managed, starts managing it, possibly waiting for the first
    /// path fetch.
    ///
    /// Returns an error if no path is available after waiting.
    pub async fn path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: SystemTime,
    ) -> Result<Path, Arc<PathFetchError>> {
        let try_path = self
            .0
            .managed_paths
            .peek_with(&(src, dst), |_, (handle, _)| {
                handle.try_active_path().as_deref().map(|p| p.0.clone())
            })
            .flatten();

        let res = match try_path {
            Some(active) => Ok(active),
            None => {
                // Ensure paths are being managed
                let path_set = self.ensure_managed_paths(src, dst);

                // Try to get active path, possibly waiting for initialization/update
                let active = path_set.active_path().await.as_ref().map(|p| p.0.clone());

                // Check active path after waiting
                match active {
                    Some(active) => Ok(active),
                    None => {
                        // No active path even after waiting, return last error if any
                        let last_error = path_set.current_error();
                        match last_error {
                            Some(e) => Err(e),
                            None => {
                                // There is a chance for a race here, where the error was cleared
                                // between the wait and now. In that case, we assume no paths were
                                // found.
                                Err(Arc::new(PathFetchError::NoPathsFound))
                            }
                        }
                    }
                }
            }
        };

        if let Ok(active) = &res {
            // XXX(ake): Since the Paths are actively managed, they should never be expired
            // here.
            let expired = active.is_expired(now.into()).unwrap_or(true);
            debug_assert!(!expired, "Returned expired path from get_path");
        }

        res
    }

    /// Creates a weak reference to this MultiPathManager.
    pub fn weak_ref(&self) -> MultiPathManagerRef<F> {
        MultiPathManagerRef(Arc::downgrade(&self.0))
    }

    /// Quickly ensures that paths are being managed for the given src-dst pair.
    ///
    /// Does nothing if paths are already being managed.
    fn fast_ensure_managed_paths(&self, src: IsdAsn, dst: IsdAsn) {
        if self.0.managed_paths.contains(&(src, dst)) {
            return;
        }

        self.ensure_managed_paths(src, dst);
    }

    /// Starts managing paths for the given src-dst pair.
    ///
    /// Returns a reference to the managed paths.
    fn ensure_managed_paths(&self, src: IsdAsn, dst: IsdAsn) -> PathSetHandle {
        let entry = match self.0.managed_paths.entry_sync((src, dst)) {
            scc::hash_index::Entry::Occupied(occupied) => {
                tracing::trace!(%src, %dst, "Already managing paths for src-dst pair");
                occupied
            }
            scc::hash_index::Entry::Vacant(vacant) => {
                tracing::info!(%src, %dst, "Starting to manage paths for src-dst pair");
                let managed = PathSet::new(
                    src,
                    dst,
                    self.weak_ref(),
                    self.0.config,
                    self.0.issue_manager.lock().unwrap().issues_subscriber(),
                );

                vacant.insert_entry(managed.manage())
            }
        };

        entry.get().0.clone()
    }

    /// Stops managing paths for the given src-dst pair.
    pub fn stop_managing_paths(&self, src: IsdAsn, dst: IsdAsn) {
        if self.0.managed_paths.remove_sync(&(src, dst)) {
            tracing::info!(%src, %dst, "Stopped managing paths for src-dst pair");
        }
    }

    /// report error
    pub fn report_path_issue(&self, timestamp: SystemTime, issue: IssueKind, path: Option<&Path>) {
        let Some(applies_to) = issue.target_type(path) else {
            // Not a path issue we care about
            return;
        };

        if matches!(applies_to, IssueMarkerTarget::DestinationNetwork { .. }) {
            // We can't handle dst network issues in a global path manager
            return;
        }

        tracing::debug!(%issue, "New path issue");

        let issue_marker = IssueMarker {
            target: applies_to,
            timestamp,
            penalty: issue.penalty(),
        };

        // Push to issues cache
        {
            let mut issues_guard = self.0.issue_manager.lock().unwrap();
            issues_guard.add_issue(issue, issue_marker.clone());
        }
    }
}

impl<F: PathFetcher> SyncPathManager for MultiPathManager<F> {
    fn register_path(
        &self,
        _src: IsdAsn,
        _dst: IsdAsn,
        _now: chrono::DateTime<chrono::Utc>,
        _path: Path<bytes::Bytes>,
    ) {
        // No-op
        // Based on discussions we do not support externally registered paths in the PathManager
        // Likely we will handle path mirroring in Connection Based Protocols instead
    }

    fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: chrono::DateTime<chrono::Utc>,
    ) -> std::io::Result<Option<Path<bytes::Bytes>>> {
        Ok(self.try_path(src, dst, now.into()))
    }
}

impl<F: PathFetcher> PathManager for MultiPathManager<F> {
    fn path_wait(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl crate::types::ResFut<'_, Path<bytes::Bytes>, PathWaitError> {
        async move {
            match self.path(src, dst, now.into()).await {
                Ok(path) => Ok(path),
                Err(e) => {
                    match &*e {
                        PathFetchError::FetchSegments(error) => {
                            Err(PathWaitError::FetchFailed(format!("{error}")))
                        }
                        PathFetchError::InternalError(msg) => {
                            Err(PathWaitError::FetchFailed(msg.to_string()))
                        }
                        PathFetchError::NoPathsFound => Err(PathWaitError::NoPathFound),
                    }
                }
            }
        }
    }
}

impl<F: PathFetcher> PathPrefetcher for MultiPathManager<F> {
    fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn) {
        self.ensure_managed_paths(src, dst);
    }
}

/// Weak reference to a MultiPathManager.
pub struct MultiPathManagerRef<F: PathFetcher>(Weak<MultiPathManagerInner<F>>);

impl<F: PathFetcher> Clone for MultiPathManagerRef<F> {
    fn clone(&self) -> Self {
        MultiPathManagerRef(self.0.clone())
    }
}

impl<F: PathFetcher> MultiPathManagerRef<F> {
    /// Attempts to upgrade the weak reference to a strong reference.
    pub fn get(&self) -> Option<MultiPathManager<F>> {
        self.0.upgrade().map(|arc| MultiPathManager(arc))
    }
}

/// Path Issue manager
struct PathIssueManager {
    // Config
    max_entries: usize,
    deduplication_window: Duration,

    // Mutable
    /// Map of issue ID to issue marker
    cache: HashMap<u64, IssueMarker>,
    // FiFo queue of issue IDs and their timestamps
    fifo_issues: VecDeque<(u64, SystemTime)>,

    /// Channel for broadcasting issues
    issue_broadcast_tx: broadcast::Sender<(u64, IssueMarker)>,
}

impl PathIssueManager {
    fn new(max_entries: usize, broadcast_buffer: usize, deduplication_window: Duration) -> Self {
        let (issue_broadcast_tx, _) = broadcast::channel(broadcast_buffer);
        PathIssueManager {
            max_entries,
            deduplication_window,
            cache: HashMap::new(),
            fifo_issues: VecDeque::new(),
            issue_broadcast_tx,
        }
    }

    /// Returns a subscriber to the issue broadcast channel.
    pub fn issues_subscriber(&self) -> broadcast::Receiver<(u64, IssueMarker)> {
        self.issue_broadcast_tx.subscribe()
    }

    /// Adds a new issue to the manager.
    ///
    /// Issues might cause the Active path to change immediately.
    ///
    /// All issues get cached to be applied to newly fetched paths.
    ///
    /// If a similar issue, applying to the same Path is seen in the deduplication window, it will
    /// be ignored.
    pub fn add_issue(&mut self, issue: IssueKind, marker: IssueMarker) {
        let id = issue.dedup_id(&marker.target);

        // Check if we already have this issue
        if let Some(existing_marker) = self.cache.get(&id) {
            let time_since_last_seen = marker
                .timestamp
                .duration_since(existing_marker.timestamp)
                .unwrap_or_else(|_| Duration::from_secs(0));

            if time_since_last_seen < self.deduplication_window {
                tracing::trace!(%id, ?time_since_last_seen, ?marker, %issue, "Ignoring duplicate path issue");
                // Too soon since last seen, ignore
                return;
            }
        }

        // Broadcast issue
        self.issue_broadcast_tx.send((id, marker.clone())).ok();

        if self.cache.len() >= self.max_entries {
            self.pop_front();
        }

        // Insert issue
        self.fifo_issues.push_back((id, marker.timestamp)); // Store timestamp for matching on removal
        self.cache.insert(id, marker);
    }

    /// Applies all cached issues to the given path.
    ///
    /// This is called when a path is fetched, to ensure that issues affecting it are applied.
    /// Should only be called on fresh paths.
    ///
    /// Returns true if any issues were applied.
    /// Returns the max
    pub fn apply_cached_issues(&self, entry: &mut PathManagerPath, now: SystemTime) -> bool {
        let mut applied = false;
        for issue in self.cache.values() {
            if issue.target.matches_path(&entry.path, &entry.fingerprint) {
                entry.reliability.update(issue.decayed_penalty(now), now);
                applied = true;
            }
        }
        applied
    }

    /// Pops the oldest issue from the cache.
    fn pop_front(&mut self) -> Option<IssueMarker> {
        let (issue_id, timestamp) = self.fifo_issues.pop_front()?;

        match self.cache.entry(issue_id) {
            hash_map::Entry::Occupied(occupied_entry) => {
                // Only remove if timestamps match
                match occupied_entry.get().timestamp == timestamp {
                    true => Some(occupied_entry.remove()),
                    false => None, // Entry was updated, do not remove
                }
            }
            hash_map::Entry::Vacant(_) => {
                debug_assert!(false, "Bad cache: issue ID not found in cache");
                None
            }
        }
    }
}

/// Handle to a managed set of paths for a specific src-dst pair.
#[derive(Clone)]
struct PathSetHandle {
    shared: Arc<PathSetSharedState>,
}

impl PathSetHandle {
    /// Tries to get the currently active path without awaiting ongoing updates.
    pub fn try_active_path(
        &self,
    ) -> arc_swap::Guard<Option<Arc<(scion_proto::path::Path, PathFingerprint)>>> {
        self.shared
            .was_used_in_idle_period
            .store(true, std::sync::atomic::Ordering::Relaxed);

        self.shared.active_path.load()
    }

    /// Gets the currently active path, awaiting ongoing updates if necessary.
    pub async fn active_path(
        &self,
    ) -> arc_swap::Guard<Option<Arc<(scion_proto::path::Path, PathFingerprint)>>> {
        self.shared
            .was_used_in_idle_period
            .store(true, std::sync::atomic::Ordering::Relaxed);

        {
            let active_guard = self.shared.active_path.load();
            if active_guard.is_some() {
                return active_guard;
            }
        }

        self.await_ongoing_update().await;

        self.shared.active_path.load()
    }

    /// Awaits ongoing path update if there is one.
    pub async fn await_ongoing_update(&self) {
        let finish_notification = {
            let notify_guard = self.shared.sync.lock().unwrap();

            // No ongoing update
            if notify_guard.ongoing_start.is_none() && notify_guard.initialized {
                return;
            }

            notify_guard.completed_notify.clone().notified_owned()
        };

        finish_notification.await;
    }

    /// Returns the current fetch error, if any
    pub fn current_error(&self) -> Option<Arc<PathFetchError>> {
        self.shared.sync.lock().unwrap().current_error.clone()
    }

    /// Awaits initial path fetch completion.
    #[allow(unused)]
    pub async fn wait_initialized(&self) {
        let finish_notification = {
            let notify_guard = self.shared.sync.lock().unwrap();

            // Already initialized
            if notify_guard.initialized {
                return;
            }

            notify_guard.completed_notify.clone().notified_owned()
        };

        finish_notification.await;
    }
}

struct PathSetTask {
    _task: JoinHandle<()>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl Drop for PathSetTask {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Manages paths for a specific src-dst pair.
struct PathSet<F: PathFetcher> {
    /// Source ISD-AS
    src: IsdAsn,
    /// Destination ISD-AS
    dst: IsdAsn,
    /// Config
    config: MultiPathManagerConfig,
    /// Backoff for path fetch failures
    backoff: ExponentialBackoff,
    /// Parent multipath manager
    manager: MultiPathManagerRef<F>,
    /// Internal state
    internal: PathSetInternal,
    /// Shared State
    shared: Arc<PathSetSharedState>,
}

struct PathSetSharedState {
    /// Currently active path
    active_path: ArcSwapOption<(Path, PathFingerprint)>,
    /// Fast path usage tracker
    was_used_in_idle_period: AtomicBool,
    /// Separate state for synchronization
    sync: Mutex<PathSetSyncState>,
}

#[derive(Debug, Default)]
struct PathSetSyncState {
    /// Initial fetch was completed
    initialized: bool,
    /// Ongoing fetch start time
    ongoing_start: Option<SystemTime>,
    /// Fetch completion notifier
    completed_notify: Arc<Notify>,
    /// Error encountered during path fetch
    current_error: Option<Arc<PathFetchError>>,
}

/// Internal state of the managed path set.
struct PathSetInternal {
    /// Cached paths
    cached_paths: Vec<PathManagerPath>,
    /// Number of consecutive failed fetch attempts
    failed_attempts: u32,
    /// Next time to refetch paths
    next_refetch: SystemTime,
    /// Next time to check for idleness
    next_idle_check: SystemTime,
    /// Issue notifications
    issue_rx: broadcast::Receiver<(u64, IssueMarker)>,
}

// Public api
impl<F: PathFetcher> PathSet<F> {
    pub fn new(
        src: IsdAsn,
        dst: IsdAsn,
        manager: MultiPathManagerRef<F>,
        config: MultiPathManagerConfig,
        issue_rx: broadcast::Receiver<(u64, IssueMarker)>,
    ) -> Self {
        Self::new_with_time(src, dst, manager, config, issue_rx, SystemTime::now())
    }

    fn new_with_time(
        src: IsdAsn,
        dst: IsdAsn,
        manager: MultiPathManagerRef<F>,
        config: MultiPathManagerConfig,
        issue_rx: broadcast::Receiver<(u64, IssueMarker)>,
        now: SystemTime,
    ) -> Self {
        let backoff = ExponentialBackoff::new_from_config(config.fetch_failure_backoff);

        let internal = PathSetInternal {
            cached_paths: Vec::new(),
            failed_attempts: 0,
            next_refetch: now,
            next_idle_check: now + config.max_idle_period,
            issue_rx,
        };

        PathSet {
            src,
            dst,
            config,
            backoff,
            manager,
            internal,
            shared: Arc::new(PathSetSharedState {
                active_path: ArcSwapOption::new(None),
                was_used_in_idle_period: AtomicBool::new(false),
                sync: Mutex::new(PathSetSyncState {
                    initialized: false,
                    ongoing_start: None,
                    completed_notify: Arc::new(Notify::new()),
                    current_error: None,
                }),
            }),
        }
    }
}

// Management task
impl<F: PathFetcher> PathSet<F> {
    #[instrument(name = "path-set", skip(self), fields(src= ?self.src, dst= ?self.dst))]
    fn manage(mut self) -> (PathSetHandle, PathSetTask) {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let shared = self.shared.clone();

        let task = {
            let cancel_token = cancel_token.clone();

            async move {
                let maintain = async {
                    // Update the managed path tuple on start
                    {
                        let Some(manager) = self.manager.get() else {
                            return "manager dropped";
                        };
                        self.fetch_and_update(SystemTime::now(), &manager).await;
                    }

                    loop {
                        let now = SystemTime::now();
                        tracing::trace!("Managed paths task tick");
                        let next_tick = self.next_maintain(now);

                        select! {
                            biased;
                            // Cancellation
                            _ = cancel_token.cancelled() => {
                                return "cancelled";
                            }
                            // Maintenance Tick
                            _ = tokio::time::sleep(next_tick) => {
                                let Some(manager) = self.manager.get() else {
                                    return "manager dropped";
                                };

                                if let Some(reason) = self.maintain(SystemTime::now(), &manager).await {
                                    return reason;
                                }
                            }
                            // Issue Notifications
                            issue = self.internal.issue_rx.recv() => {
                                let Some(manager) = self.manager.get() else {
                                    return "manager dropped";
                                };

                                if let Some(reason) = self.handle_issue_rx(SystemTime::now(), issue, &manager) {
                                    return reason;
                                }
                            }
                        }
                    }
                };

                let exit_reason = maintain.await;

                // If manager still exists, drop the PathSet entry
                if let Some(mgr) = self.manager.get() {
                    mgr.stop_managing_paths(self.src, self.dst);
                }

                // Ensure no waiting tasks remain
                let mut sync_guard = self.shared.sync.lock().unwrap();
                sync_guard.ongoing_start = None;
                sync_guard.initialized = true;
                sync_guard.completed_notify.notify_waiters();

                // On exit, set error state - handles could still be around
                sync_guard.current_error = Some(Arc::new(PathFetchError::InternalError(
                    format!("PathSet task exited: {exit_reason}").into(),
                )));

                // Clear active path
                self.shared.active_path.store(None);

                tracing::info!(exit_reason, "Managed paths task exiting");
            }
        };

        (
            PathSetHandle { shared },
            PathSetTask {
                _task: tokio::spawn(task.in_current_span()),
                cancel_token,
            },
        )
    }

    /// Handles received path issues.
    ///
    /// Returns a string containing a reason if task should be stopped
    fn handle_issue_rx(
        &mut self,
        now: SystemTime,
        recv: Result<(u64, IssueMarker), broadcast::error::RecvError>,
        manager: &MultiPathManager<F>,
    ) -> Option<&'static str> {
        // Sadly we don't have a way to peek broadcast so we have to handle first recv separately
        let (_, issue) = match recv {
            Ok(issue) => issue,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                tracing::warn!("Missed path issue notifications");
                return None; // Will immediately receive next notification
            }
            Err(broadcast::error::RecvError::Closed) => {
                return Some("issue channel closed, manager was likely dropped");
            }
        };

        // Check if issue applies to this path set
        if !issue.target.applies_to_path(self.src, self.dst) {
            return None;
        }

        let mut res = self.ingest_path_issue(now, &issue);
        let (mut issue_count, res2) = self.drain_and_apply_issue_channel(now);

        issue_count += 1;
        res.combine(&res2);

        tracing::debug!(count = issue_count, ?res, "Ingested path issues");

        if res.active_path_affected {
            tracing::info!("Active path affected by path issues, re-evaluating");
            self.rerank(now, manager);
            self.maybe_update_active_path(now, manager);
        }

        None
    }

    /// Drains the issue channel and applies all pending issues.
    ///
    /// Returns the number of applied issues and the aggregated result.
    fn drain_and_apply_issue_channel(&mut self, now: SystemTime) -> (u32, PathIssueIngestResult) {
        let mut applied_issue_count = 0;
        // see if any more issues are pending
        let mut agg = PathIssueIngestResult {
            active_path_affected: false,
            total_paths_affected: 0,
        };

        loop {
            let rx = self.internal.issue_rx.try_recv();
            let (_, issue) = match rx {
                Ok(issue) => issue,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    tracing::warn!("Missed path issue notifications during issue drain");
                    continue;
                }
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => break,
            };

            // We can ignore errors here, Closed will be handled on next recv, lagged should be
            // impossible here.
            if !issue.target.applies_to_path(self.src, self.dst) {
                continue;
            }

            let res = self.ingest_path_issue(now, &issue);

            applied_issue_count += 1;

            agg.combine(&res);
        }

        (applied_issue_count, agg)
    }

    fn next_maintain(&self, now: SystemTime) -> Duration {
        // If time is in the past, tick immediately
        std::cmp::min(self.internal.next_refetch, self.internal.next_idle_check)
            .duration_since(now)
            .unwrap_or_else(|_| Duration::from_secs(0))
    }

    /// Maintains the path set by checking for idle paths and refetching if necessary.
    ///
    /// Returns Some with a reason if the path set should be dropped
    async fn maintain(
        &mut self,
        now: SystemTime,
        manager: &MultiPathManager<F>,
    ) -> Option<&'static str> {
        if now >= self.internal.next_idle_check && self.idle_check(now).await {
            return Some("idle");
        }

        if now >= self.internal.next_refetch {
            self.fetch_and_update(now, manager).await;
        }

        None
    }
}

// Internal
impl<F: PathFetcher> PathSet<F> {
    /// Checks if the path tuple is idle and should be removed.
    async fn idle_check(&mut self, now: SystemTime) -> bool {
        // Was called before idle timeout, do nothing
        if now < self.internal.next_idle_check {
            return false;
        }

        let was_used = self
            .shared
            .was_used_in_idle_period
            .load(std::sync::atomic::Ordering::Relaxed);

        if was_used {
            // Reset usage flag and last idle check time
            self.shared
                .was_used_in_idle_period
                .store(false, std::sync::atomic::Ordering::Relaxed);
            self.internal.next_idle_check = now + self.config.max_idle_period;
            false
        } else {
            // Path tuple is idle, remove it
            let unused_since = self.internal.next_idle_check - self.config.max_idle_period;
            tracing::info!(?unused_since, "Path tuple is idle, removing");
            true
        }
    }

    /// Refetches paths and updates the cache
    async fn fetch_and_update(&mut self, now: SystemTime, manager: &MultiPathManager<F>) {
        tracing::debug!("Refetching paths for src-dst pair");

        // Set update state
        {
            let mut notify_guard = self.shared.sync.lock().unwrap();
            if notify_guard.ongoing_start.is_some() {
                debug_assert!(
                    false,
                    "Path refetch already ongoing, this should not happen"
                );
                tracing::warn!("Path refetch already ongoing, this should not happen");
                return;
            }

            notify_guard.ongoing_start = Some(now);
        }

        let path_fetch = async {
            let fetched_paths = self.fetch_and_filter_paths(manager).await?;

            if fetched_paths.is_empty() {
                // If no paths were found or all were filtered out
                // start going by backoff rules, client can just hope a new path appears out of
                // nowhere
                return Err(PathFetchError::NoPathsFound);
            }

            Ok(fetched_paths)
        };

        let result = path_fetch.await;
        match result {
            // Successful fetch and ingestion, at least one path available
            Ok(fetched_paths) => {
                debug_assert!(
                    !fetched_paths.is_empty(),
                    "Must have at least one path after successful fetch and filter"
                );

                self.update_path_cache(fetched_paths, now, manager);
                let earliest_expiry = self
                    .earliest_expiry()
                    .expect("should have a path available, as new paths were ingested");

                // Reset error state
                self.shared.sync.lock().unwrap().current_error = None;
                self.internal.failed_attempts = 0;
                // Update next refetch time
                self.internal.next_refetch =
                    // Either after refetch interval, or before earliest expiry
                    (now + self.config.refetch_interval).min(earliest_expiry - self.config.min_expiry_threshold)
                    // But at least after min refetch delay
                    .max(now + self.config.min_refetch_delay);
            }
            // Failed to fetch, might have no paths available
            Err(e) => {
                // Maintain path cache with no new paths
                self.update_path_cache(vec![], now, manager);

                self.internal.failed_attempts += 1;
                // Schedule next refetch after a delay
                self.internal.next_refetch = now
                    + self
                        .backoff
                        .duration(self.internal.failed_attempts)
                        .max(self.config.min_refetch_delay);

                tracing::error!(
                    attempt = self.internal.failed_attempts,
                    next_try = ?self.internal.next_refetch,
                    error = %e,
                    "Failed to fetch new paths"
                );

                self.shared.sync.lock().unwrap().current_error = Some(Arc::new(e));
            }
        }

        // Always update ranking, and possibly active path
        self.rerank(now, manager);
        self.maybe_update_active_path(now, manager);

        // Set update state
        {
            let mut notify_guard = self.shared.sync.lock().unwrap();
            notify_guard.ongoing_start = None;
            notify_guard.initialized = true;
            notify_guard.completed_notify.notify_waiters();
        }

        tracing::debug!("Completed path refetch and update");
    }

    /// Returns the earliest expiry time among the cached paths.
    fn earliest_expiry(&self) -> Option<SystemTime> {
        self.internal
            .cached_paths
            .iter()
            .filter_map(|entry| entry.path.expiry_time())
            .min()
            .map(SystemTime::from)
    }

    /// Fetches paths from the fetcher and applies path selection filtering.
    async fn fetch_and_filter_paths(
        &self,
        manager: &MultiPathManager<F>,
    ) -> Result<Vec<Path>, PathFetchError> {
        let mut paths = manager.0.fetcher.fetch_paths(self.src, self.dst).await?;

        let before_filter_count = paths.len();

        paths.retain(|p| manager.0.path_strategy.predicate(p));

        tracing::info!(
            total_paths = before_filter_count,
            filtered_paths = paths.len(),
            "Fetched and filtered paths"
        );

        if paths.is_empty() {
            tracing::warn!("No paths available after filtering");
        }

        Ok(paths)
    }

    /// Updates the path cache with new paths
    ///
    /// Possibly updates or removes the active path
    fn update_path_cache(
        &mut self,
        fetched_paths: Vec<Path>,
        now: SystemTime,
        manager: &MultiPathManager<F>,
    ) {
        let mut fetched_paths: HashMap<PathFingerprint, Path, RandomState> =
            HashMap::from_iter(fetched_paths.into_iter().map(|path| {
                let fingerprint = path.fingerprint().unwrap();
                (fingerprint, path)
            }));

        let active_path_fp = self.shared.active_path.load().as_ref().map(|p| p.1);

        // Update cached paths
        self.internal.cached_paths.retain_mut(|cached_path| {
            let mut keep = true;
            let fp = cached_path.fingerprint;

            // Update existing path if it exists
            if let Some(matching_path) = fetched_paths.remove(&fp) {
                cached_path.path = matching_path
            };

            // Don't keep expired paths
            if check_path_expiry(&cached_path.path, now, self.config.min_expiry_threshold)
                == ExpiryState::Expired
            {
                tracing::debug!(fp = format!("{fp:#}"), "Removing expired path from cache");
                keep = false;
            }

            // Maintain active path reference
            if Some(fp) == active_path_fp {
                match keep {
                    true => {
                        tracing::trace!(fp = format!("{fp:#}"), "Keeping updated active path");
                        self.shared
                            .active_path
                            .store(Some(Arc::new((cached_path.path.clone(), fp))));
                    }
                    false => {
                        tracing::info!(
                            fp = format!("{fp:#}"),
                            "Active path is expired, clearing active path"
                        );
                        self.shared.active_path.store(None);
                    }
                }
            };

            keep
        });

        // Work on new paths
        if !fetched_paths.is_empty() {
            // Drain issue channel before lock to reduce lock time
            let (issue_count, res) = self.drain_and_apply_issue_channel(now);
            if issue_count > 0 {
                tracing::debug!(
                    count = issue_count,
                    ?res,
                    "Ingested path issues before applying to new paths"
                );
            }

            // Apply cached issues to fetched paths
            let mut new_path_candidates = {
                // Take issues cache lock
                let issues_guard = manager.0.issue_manager.lock().unwrap();

                // Drain issue channel again to catch any issues that arrived during lock
                // acquisition
                let (issue_count, res) = self.drain_and_apply_issue_channel(now);
                if issue_count > 0 {
                    tracing::debug!(
                        count = issue_count,
                        ?res,
                        "Ingested path issues before applying to new paths after lock acquisition"
                    );
                }

                // Apply the issues to new paths
                // XXX(ake): This could be pretty expensive if we have a lot of new path candidates.
                // Possibly we need to reduce the candidates before this in the future
                fetched_paths
                    .into_iter()
                    .map(|(fp, path)| {
                        let mut entry = PathManagerPath {
                            path,
                            fingerprint: fp,
                            reliability: ReliabilityScore::new_with_time(now),
                        };
                        issues_guard.apply_cached_issues(&mut entry, now);
                        entry
                    })
                    .collect::<Vec<_>>()
            };

            // Rank new paths
            manager
                .0
                .path_strategy
                .rank_inplace(&mut new_path_candidates, now);

            let active_fp = self.shared.active_path.load().as_ref().map(|p| p.1);

            // Merge new paths into cache
            merge_new_paths_algo(
                &mut self.internal.cached_paths,
                &mut new_path_candidates,
                active_fp,
                self.config.max_cached_paths_per_pair,
                &manager.0.path_strategy,
                now,
            );
        }
    }

    // Applies path ranking and selects active path if necessary.
    fn rerank(&mut self, now: SystemTime, manager: &MultiPathManager<F>) {
        manager
            .0
            .path_strategy
            .rank_inplace(&mut self.internal.cached_paths, now);
    }

    /// Creates the decision for whether to update the active path and returns the best candidate.
    fn decide_active_path_update(
        &self,
        now: SystemTime,
        manager: &MultiPathManager<F>,
    ) -> (ActivePathDecision, Option<&PathManagerPath>) {
        let active_path_guard = self.shared.active_path.load();
        let active_path = active_path_guard.as_ref();
        let best_path = self.best_path(now);

        // Determine if active path needs replacement - just by active path
        let mut decision = match active_path {
            // No active path, set best available path
            None => ActivePathDecision::Replace("no active path"),
            Some(active) => {
                match check_path_expiry(&active.0, now, self.config.min_expiry_threshold) {
                    ExpiryState::Valid => ActivePathDecision::NoChange,
                    // Near expiry, should be replaced
                    // XXX(ake): Ranking does not consider expiry currently, so falling over when
                    // near expiry might fail, as it keeps wanting to use the
                    // same path. Not a big deal, as near expiry is an edgecase
                    // which should be rare.
                    ExpiryState::NearExpiry => {
                        ActivePathDecision::Replace("active path near expiry")
                    }
                    // Expired, must be replaced
                    ExpiryState::Expired => ActivePathDecision::ForceReplace("active path expired"),
                }
            }
        };

        // If no reason to change, and we have a best path, check if there is a reason to switch
        if ActivePathDecision::NoChange == decision
            && let Some(best_path) = best_path
        {
            match self.active_path_entry() {
                Some(active_entry) => {
                    let active_score = manager.0.path_strategy.scoring.score(active_entry, now);
                    let best_score = manager.0.path_strategy.scoring.score(best_path, now);
                    let diff = best_score - active_score;

                    tracing::trace!(
                        active_score = %active_score,
                        best_score = %best_score,
                        score_diff = %diff,
                        "Active path score comparison"
                    );

                    if diff > self.config.path_swap_score_threshold {
                        decision = ActivePathDecision::Replace("swap threshold reached")
                    }
                }
                None => {
                    debug_assert!(
                        false,
                        "failed to find active path entry, but active path is set"
                    );
                    tracing::warn!("no active path entry, but active path is set, unexpected")
                }
            }
        }

        (decision, best_path)
    }

    /// Executes the decision to update the active path.
    fn apply_active_path_decision(
        &self,
        decision: ActivePathDecision,
        mut best_path: Option<&PathManagerPath>,
        now: SystemTime,
        manager: &MultiPathManager<F>,
    ) {
        let scorer = &manager.0.path_strategy.scoring;
        let active_path_guard = self.shared.active_path.load();
        let active_path = active_path_guard.as_ref();

        let active_fp = format_option(&active_path.map(|p| p.1));
        let best_fp = format_option(&best_path.map(|p| p.fingerprint));
        tracing::trace!(?decision, %active_fp, %best_fp, "Active path update decision");

        // If best path is the active path, ignore it
        if active_path.map(|p| p.1) == best_path.map(|p| p.fingerprint) {
            // Best path is active path
            best_path = None;
        }

        // Apply update if needed
        match (decision, best_path) {
            // No reason to replace active path
            (ActivePathDecision::NoChange, _) => {}
            // No better path available
            (ActivePathDecision::Replace(reason), None) => {
                tracing::warn!(%active_fp, %reason, "Active path should be replaced, but no better path is available");
            }
            (ActivePathDecision::ForceReplace(reason), None) => {
                tracing::warn!(%active_fp, %reason, "Active path must be replaced, but no better path is available");
                self.shared.active_path.store(None);
            }
            // We have a reason and a better path
            (
                ActivePathDecision::ForceReplace(reason) | ActivePathDecision::Replace(reason),
                Some(best_path),
            ) => {
                tracing::info!(%active_fp, %best_fp, %reason, "Replacing active path");

                // Try printing score details
                if let Some(active_entry) = self.active_path_entry() {
                    let active_score = scorer.score_report(active_entry, now);
                    tracing::debug!("Active path score: {active_score}");
                    tracing::debug!("{}", active_entry.path);
                }

                let best_score = scorer.score_report(best_path, now);
                tracing::debug!("New path score: {best_score} ({})", best_path.path);
                tracing::debug!("{}", best_path.path);

                self.shared.active_path.store(Some(Arc::new((
                    best_path.path.clone(),
                    best_path.fingerprint,
                ))));
            }
        }
    }

    /// Updates the active path if required
    fn maybe_update_active_path(&self, now: SystemTime, mgr: &MultiPathManager<F>) {
        let (decision, best_path) = self.decide_active_path_update(now, mgr);
        self.apply_active_path_decision(decision, best_path, now, mgr);
    }

    /// Selects the best path from the cached paths
    ///
    /// Expects paths to be ranked already
    fn best_path(&self, now: SystemTime) -> Option<&PathManagerPath> {
        let path_iter = self.internal.cached_paths.iter();

        for path in path_iter {
            // Only consider paths that are not near expiry
            if check_path_expiry(&path.path, now, self.config.min_expiry_threshold)
                != ExpiryState::Valid
            {
                continue;
            }

            return Some(path);
        }

        None
    }

    /// Returns the entry of the current active path
    fn active_path_entry(&self) -> Option<&PathManagerPath> {
        let active_path_fp = self.shared.active_path.load().as_ref().map(|p| p.1)?;

        self.internal
            .cached_paths
            .iter()
            .find(|e| e.fingerprint == active_path_fp)
    }

    #[allow(dead_code)]
    fn mut_active_path_entry(&mut self) -> Option<&mut PathManagerPath> {
        let active_path_fp = self.shared.active_path.load().as_ref().map(|p| p.1)?;

        self.internal
            .cached_paths
            .iter_mut()
            .find(|e| e.fingerprint == active_path_fp)
    }
}

/// Decision on active path update, including reason
#[derive(Debug, PartialEq, Eq)]
enum ActivePathDecision {
    /// No change needed
    NoChange,
    /// Active path should be replaced if a better path is available
    Replace(&'static str),
    /// Active path must be removed, even if no better path is available
    ForceReplace(&'static str),
}

/// Merges paths from `new_paths` and `existing_paths` by path ranking.
/// Resulting in an updated `existing_paths` containing the best paths from both vectors.
/// The active path, if provided, is always retained in `existing_paths`.
///
/// Both path vectors should be in ranked order (best first).
/// No paths from new_paths should be present in existing_paths.
///
/// Total number of paths after merge will be at most `target_path_count`.
///
/// Returns (kept_existing_count, kept_new_count)
fn merge_new_paths_algo(
    existing_paths: &mut Vec<PathManagerPath>,
    new_paths: &mut Vec<PathManagerPath>,
    active_fp: Option<PathFingerprint>,
    target_path_count: usize,
    path_strategy: &PathStrategy,
    now: SystemTime,
) -> (usize, usize) {
    // Handle the active path.
    // If it exists, swap it to the front (index 0) and start kept count at 1.
    let mut kept_existing = 0;

    if let Some(fp) = active_fp {
        if let Some(idx) = existing_paths.iter().position(|p| p.fingerprint == fp) {
            existing_paths.swap(0, idx);
            kept_existing = 1;
        } else {
            debug_assert!(
                false,
                "Active path fingerprint must be present in existing paths"
            );
        }
    }

    let mut kept_new = 0;

    // Select the best remaining paths until we reach target count.
    let is_existing_better = |e: &PathManagerPath, n: &PathManagerPath| -> bool {
        let ord = path_strategy.rank_order(e, n, now);
        // Prefer existing on tie to reduce churn
        ord != Ordering::Greater
    };

    while kept_existing + kept_new < target_path_count {
        match (existing_paths.get(kept_existing), new_paths.get(kept_new)) {
            (Some(e), Some(n)) => {
                if is_existing_better(e, n) {
                    kept_existing += 1;
                } else {
                    kept_new += 1;
                }
            }
            (Some(_), None) => kept_existing += 1,
            (None, Some(_)) => kept_new += 1,
            (None, None) => break,
        }
    }

    // Truncate to the calculated cutoff points.
    existing_paths.truncate(kept_existing);
    new_paths.truncate(kept_new);

    // Merge
    let truncated_new = new_paths.drain(..);
    existing_paths.extend(truncated_new);

    (kept_existing, kept_new)
}

// Error handling support
#[derive(Debug)]
struct PathIssueIngestResult {
    /// Whether the active path was affected and needs re-evaluation
    pub active_path_affected: bool,
    /// Total number of paths affected by the issue
    pub total_paths_affected: usize,
}

impl PathIssueIngestResult {
    /// Combines two PathIssueIngestResults into one.
    pub fn combine(&mut self, other: &PathIssueIngestResult) {
        self.active_path_affected |= other.active_path_affected;
        self.total_paths_affected += other.total_paths_affected;
    }
}

impl<F: PathFetcher> PathSet<F> {
    /// Handles a reported path issue by updating the reliability scores of affected paths.
    ///
    /// Returns information indicating whether the active path was affected and the total number of
    /// paths affected.
    fn ingest_path_issue(&mut self, now: SystemTime, issue: &IssueMarker) -> PathIssueIngestResult {
        let scan_all = issue.target.applies_to_multiple_paths();
        let active_path_fp = self.shared.active_path.load().as_ref().map(|p| p.1);

        let mut res = PathIssueIngestResult {
            active_path_affected: false,
            total_paths_affected: 0,
        };

        match scan_all {
            // Scan all cached paths and update those that match
            true => {
                for entry in self.internal.cached_paths.iter_mut() {
                    // TODO: matches_path_checked can be used to optimize matching with e.g. a bloom
                    // filter
                    if issue.target.matches_path(&entry.path, &entry.fingerprint) {
                        res.total_paths_affected += 1;
                        entry.reliability.update(issue.penalty, now);

                        if Some(entry.fingerprint) == active_path_fp {
                            res.active_path_affected = true;
                        }
                    }
                }
            }
            // Only update the first matching path
            false => {
                if let Some(entry) = self
                    .internal
                    .cached_paths
                    .iter_mut()
                    .find(|entry| issue.target.matches_path(&entry.path, &entry.fingerprint))
                {
                    res.total_paths_affected += 1;
                    entry.reliability.update(issue.penalty, now);

                    if Some(entry.fingerprint) == active_path_fp {
                        res.active_path_affected = true;
                    }
                }
            }
        }

        res
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
enum ExpiryState {
    Valid,
    NearExpiry,
    Expired,
}

fn check_path_expiry(path: &Path, now: SystemTime, threshold: Duration) -> ExpiryState {
    let expiry: SystemTime = path
        .expiry_time()
        .expect("Path should have expiry time")
        .into();

    match expiry.duration_since(now) {
        Err(_) => ExpiryState::Expired,
        Ok(time_left) if time_left == Duration::from_secs(0) => ExpiryState::Expired,
        Ok(time_left) if time_left <= threshold => ExpiryState::NearExpiry,
        Ok(_) => ExpiryState::Valid,
    }
}

fn format_option<T: Display>(opt: &Option<T>) -> String {
    match opt {
        Some(v) => format!("{v:#}"),
        None => "None".into(),
    }
}

mod issues {
    use std::{
        fmt::Display,
        hash::{DefaultHasher, Hash, Hasher},
        ops::Deref,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use scion_proto::{
        address::{HostAddr, IsdAsn},
        packet::ScionPacketRaw,
        path::{Path, PathFingerprint},
        scmp::{DestinationUnreachableCode, ScmpErrorMessage},
        wire_encoding::WireDecode,
    };

    use crate::{
        path::{multipath_manager::algo::exponential_decay, types::Score},
        scionstack::{NetworkError, ScionSocketSendError},
    };

    /// Marker for a path issue
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssueMarker {
        pub target: IssueMarkerTarget,
        pub timestamp: SystemTime,
        pub penalty: Score,
    }

    impl IssueMarker {
        const SYSTEM_HALF_LIFE: Duration = Duration::from_secs(30);

        /// Returns the decayed penalty score of the issue.
        pub fn decayed_penalty(&self, now: SystemTime) -> Score {
            let elapsed = now
                .duration_since(self.timestamp)
                .unwrap_or(Duration::from_secs(0));

            let decayed = exponential_decay(self.penalty.value(), elapsed, Self::SYSTEM_HALF_LIFE);

            Score::new_clamped(decayed)
        }
    }

    /// The Path type that the issue marker targets.
    ///
    /// This is global and only applies to SCION paths, and is not specific to any specific endhost.
    #[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
    pub enum IssueMarkerTarget {
        FullPath {
            fingerprint: PathFingerprint,
        },
        Interface {
            isd_asn: IsdAsn,
            /// Optionally only applies when arriving on this ingress interface
            ingress_filter: Option<u16>,
            /// Applies when leaving on this egress interface
            egress_filter: u16,
        },
        FirstHop {
            isd_asn: IsdAsn,
            egress_interface: u16,
        },
        LastHop {
            isd_asn: IsdAsn,
            ingress_interface: u16,
        },
        // XXX(ake) : These DestinationNetwork errors are not handled in the PathManager
        DestinationNetwork {
            isd_asn: IsdAsn,
            ingress_interface: u16,
            dst_host: HostAddr,
        },
    }

    impl IssueMarkerTarget {
        /// Checks if the issue marker target matches the given path.
        ///
        /// If the path does not contain metadata, hop based targets cannot be matched.
        ///
        /// If it's possible to optimize path matching, use `matches_path_checked` instead.
        pub fn matches_path(&self, path: &Path, fingerprint: &PathFingerprint) -> bool {
            self.matches_path_checked(path, fingerprint, |_, _| true)
        }

        /// Checks if the issue marker target matches the given path.
        ///
        /// `might_include_check` is a closure allowing optimizations to skip paths that definitely
        /// won't match, called before any detailed matching is done.
        ///
        /// If the path does not contain metadata, hop based targets cannot be matched.
        pub fn matches_path_checked<F>(
            &self,
            path: &Path,
            fingerprint: &PathFingerprint,
            might_include_check: F,
        ) -> bool
        where
            F: Fn(&IssueMarkerTarget, &Path) -> bool,
        {
            match self {
                // Check per fingerprint
                Self::FullPath {
                    fingerprint: target_fingerprint,
                } => fingerprint == target_fingerprint,
                // Just need to check first interface
                Self::FirstHop {
                    isd_asn,
                    egress_interface,
                } => {
                    path.first_hop_egress_interface().is_some_and(|intf| {
                        intf.isd_asn == *isd_asn && intf.id == *egress_interface
                    })
                }
                // Just need to check last interface
                Self::DestinationNetwork {
                    isd_asn,
                    ingress_interface,
                    ..
                }
                | Self::LastHop {
                    isd_asn,
                    ingress_interface,
                } => {
                    path.last_hop_ingress_interface().is_some_and(|intf| {
                        intf.isd_asn == *isd_asn && intf.id == *ingress_interface
                    })
                }
                // Check all interfaces for matching ingress/egress pair
                Self::Interface {
                    isd_asn,
                    egress_filter,
                    ingress_filter,
                } => {
                    // Quick check if path might include the targeted AS
                    if !might_include_check(self, path) {
                        return false;
                    }

                    let interfaces = match path
                        .metadata
                        .as_ref()
                        .and_then(|meta| meta.interfaces.as_ref())
                    {
                        Some(interfaces) => interfaces,
                        None => return false, // No metadata, cannot match
                    };

                    // We start in the source AS, so first interface is always source egress
                    if path.source() == *isd_asn {
                        return match ingress_filter {
                            Some(_) => false, /* we are in src, but an ingress filter is set, */
                            // cannot match
                            None => {
                                interfaces
                                    .first()
                                    .is_some_and(|iface| &iface.id == egress_filter)
                            }
                        };
                    }

                    let mut iter = interfaces.iter();

                    // Check every ingress interface if it's in the target AS
                    while let Some(interface) = iter.nth(1) {
                        if interface.isd_asn != *isd_asn {
                            continue;
                        }

                        // Check ingress filter
                        if let Some(ingress) = ingress_filter
                            && interface.id != *ingress
                        {
                            return false;
                        }

                        // Next interface is egress
                        return iter
                            .next()
                            .is_some_and(|egress| &egress.id == egress_filter);
                    }

                    false
                }
            }
        }

        /// Returns how many entries this issue marker can apply to.
        pub fn applies_to_multiple_paths(&self) -> bool {
            match self {
                IssueMarkerTarget::Interface { .. }
                | IssueMarkerTarget::FirstHop { .. }
                | IssueMarkerTarget::LastHop { .. }
                | IssueMarkerTarget::DestinationNetwork { .. } => true,
                IssueMarkerTarget::FullPath { .. } => false,
            }
        }

        /// Checks if the issue marker can apply to a path between the given src and dst ISD-ASNs.
        pub fn applies_to_path(&self, src: IsdAsn, dst: IsdAsn) -> bool {
            match self {
                // Applies to all src-dst pairs
                IssueMarkerTarget::FullPath { .. } | IssueMarkerTarget::Interface { .. } => true,
                // Applies to specific src
                IssueMarkerTarget::FirstHop { isd_asn, .. } => src == *isd_asn,
                // Applies to specific dst
                IssueMarkerTarget::LastHop { isd_asn, .. }
                | IssueMarkerTarget::DestinationNetwork { isd_asn, .. } => dst == *isd_asn,
            }
        }
    }

    /// Marks a specific issue experienced on a path
    ///
    /// Issue markers serve as a hard indicator of health and mostly immediately downgrade path
    /// usability
    #[derive(Debug, Clone)]
    pub enum IssueKind {
        /// Path received SCMP error
        Scmp { error: ScmpErrorMessage },
        /// ICMP error
        Icmp {/* icmp error details */}, //TODO: details
        /// Socket error
        Socket { err: Arc<ScionSocketSendError> },
    }
    impl Display for IssueKind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                IssueKind::Scmp { error } => write!(f, "SCMP Error: {}", error),
                IssueKind::Icmp { .. } => write!(f, "ICMP Error"),
                IssueKind::Socket { err } => write!(f, "Socket Error: {}", err),
            }
        }
    }
    impl IssueKind {
        /// Returns a hash for deduplication of issues.
        pub fn dedup_id(&self, marker: &IssueMarkerTarget) -> u64 {
            let mut hasher = DefaultHasher::new();

            // Deduplicate based on target
            marker.hash(&mut hasher);
            // And issue kind
            // TODO: Took shortcut here, need to properly implement
            let error_str = format!("{}", self);
            error_str.hash(&mut hasher);

            hasher.finish()
        }

        /// Returns the target type the issue applies to, if any.
        pub fn target_type(&self, path: Option<&Path>) -> Option<IssueMarkerTarget> {
            match self {
                IssueKind::Scmp { error } => {
                    let Some(path) = path else {
                        debug_assert!(false, "Path must be provided on SCMP errors");
                        return None;
                    };

                    match error {
                        ScmpErrorMessage::DestinationUnreachable(scmp_destination_unreachable) => {
                            // XXX(ake): Destination Unreachable depend on the destination host,
                            // thus they can't be applied globally
                            use scion_proto::scmp::DestinationUnreachableCode::*;
                            match scmp_destination_unreachable.code {
                                NoRouteToDestination
                                | AddressUnreachable
                                | BeyondScopeOfSourceAddress
                                | CommunicationAdministrativelyDenied
                                | SourceAddressFailedIngressEgressPolicy
                                | RejectRouteToDestination => {
                                    let dst = path.last_hop_ingress_interface()?;
                                    let mut offending =
                                        scmp_destination_unreachable.get_offending_packet();
                                    let pkt = ScionPacketRaw::decode(&mut offending).ok()?;
                                    let dst_host = pkt.headers.address.destination()?.host();

                                    Some(IssueMarkerTarget::DestinationNetwork {
                                        isd_asn: dst.isd_asn,
                                        ingress_interface: dst.id,
                                        dst_host,
                                    })
                                }
                                // Filter out unspecific
                                Unassigned(_) | PortUnreachable | _ => None,
                            }
                        }
                        ScmpErrorMessage::ExternalInterfaceDown(msg) => {
                            Some(IssueMarkerTarget::Interface {
                                isd_asn: msg.isd_asn,
                                ingress_filter: None,
                                // TODO: docs on field say something about the value being encoded
                                // in the LSB of this field. Figure out what was done there and how
                                // to decode it.
                                egress_filter: msg.interface_id as u16,
                            })
                        }
                        ScmpErrorMessage::InternalConnectivityDown(msg) => {
                            Some(IssueMarkerTarget::Interface {
                                isd_asn: msg.isd_asn,
                                ingress_filter: Some(msg.ingress_interface_id as u16),
                                egress_filter: msg.egress_interface_id as u16,
                            })
                        }

                        ScmpErrorMessage::Unknown(_) => None,
                        ScmpErrorMessage::PacketTooBig(_) => None,
                        ScmpErrorMessage::ParameterProblem(_) => None,
                    }
                }
                IssueKind::Icmp { .. } => None,
                IssueKind::Socket { err } => {
                    let Some(path) = path else {
                        debug_assert!(false, "Path must be provided on SCMP errors");
                        return None;
                    };

                    match err.deref() {
                        ScionSocketSendError::NetworkUnreachable(network_error) => {
                            match network_error {
                                // XXX(ake): Destination Unreachable is used for multiple errors,
                                // which are not relevant for paths
                                NetworkError::DestinationUnreachable(_) => None,
                                NetworkError::UnderlayNextHopUnreachable {
                                    isd_as,
                                    interface_id,
                                    msg: _,
                                } => {
                                    Some(IssueMarkerTarget::FirstHop {
                                        isd_asn: *isd_as,
                                        egress_interface: *interface_id,
                                    })
                                }
                            }
                        }
                        ScionSocketSendError::IoError(error) => {
                            match error.kind() {
                                std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::HostUnreachable
                                | std::io::ErrorKind::NetworkUnreachable
                                | std::io::ErrorKind::ConnectionAborted => {
                                    let first_hop = path.first_hop_egress_interface()?;
                                    Some(IssueMarkerTarget::FirstHop {
                                        isd_asn: first_hop.isd_asn,
                                        egress_interface: first_hop.id,
                                    })
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    }
                }
            }
        }

        /// Calculates the penalty based on the severity of the issue.
        /// Returns a negative score (penalty).
        pub fn penalty(&self) -> Score {
            let magnitude = match self {
                IssueKind::Scmp { error } => {
                    match error {
                        // LINK FAILURES (Max penalty)
                        // Interface down means the link is physically/logically broken.
                        // With 30s half-life, it takes ~3 mins to recover to > -0.01
                        ScmpErrorMessage::ExternalInterfaceDown(_)
                        | ScmpErrorMessage::InternalConnectivityDown(_) => -1.0,

                        // ROUTING ISSUES (High)
                        // Dst AS can't route the packet internally
                        ScmpErrorMessage::DestinationUnreachable(err) => {
                            // XXX(ake): Destination Errors are not handled in the Path Manager
                            match err.code {
                                // Can't forward packet to dst ip
                                DestinationUnreachableCode::NoRouteToDestination
                                | DestinationUnreachableCode::AddressUnreachable => -0.8,
                                // Admin denied might be policy, treated as severe
                                DestinationUnreachableCode::CommunicationAdministrativelyDenied => {
                                    -0.9
                                }

                                // Unreachable Port is beyond routing
                                DestinationUnreachableCode::PortUnreachable => 0.0,
                                _ => -0.5,
                            }
                        }
                        // Unspecific
                        ScmpErrorMessage::Unknown(_) => -0.2,
                        // Irrelevant
                        ScmpErrorMessage::PacketTooBig(_)
                        | ScmpErrorMessage::ParameterProblem(_) => 0.0,
                    }
                }

                // SOCKET / TRANSIENT (Medium)
                // Often temporary congestion or local buffer issues.
                // Penalty: -0.4.
                // Recovers quickly (within ~45 seconds).
                IssueKind::Socket { err } => {
                    match err.as_ref() {
                        ScionSocketSendError::NetworkUnreachable(_) => -0.4,
                        // Errors irrelevant for paths:
                        ScionSocketSendError::PathLookupError(_)
                        | ScionSocketSendError::InvalidPacket(_)
                        | ScionSocketSendError::IoError(_)
                        | ScionSocketSendError::Closed
                        | ScionSocketSendError::NotConnected => 0.0,
                    }
                }

                // Unhandled as of now
                IssueKind::Icmp { .. } => 0.0,
            };

            Score::new_clamped(magnitude)
        }
    }
}

mod algo {
    use std::time::Duration;

    /// Exponential decay: value halves every `half_life`.
    /// Formula: N(t) = N0 * 2^(-t / half_life)
    pub fn exponential_decay(base: f32, time_delta: Duration, half_life: Duration) -> f32 {
        if base == 0.0 {
            return 0.0;
        }

        let half_life_secs = half_life.as_secs_f32();
        let elapsed_secs = time_delta.as_secs_f32();

        // Safety check
        if half_life_secs <= 0.0 {
            return 0.0;
        }

        let decay_factor = 2f32.powf(-elapsed_secs / half_life_secs);
        base * decay_factor
    }
}

/// Path reliability tracking
pub mod reliability {
    use std::time::{Duration, SystemTime};

    use crate::path::{multipath_manager::algo::exponential_decay, types::Score};

    /// Duration after which the reliability score decays to half its value.
    /// After 20 half-lives, the score approaches zero.
    const EXPONENTIAL_DECAY_HALFLIFE: Duration = Duration::from_secs(90); // Full decay in ~30 min

    /// Reliability score for a path
    ///
    /// A reliability score indicates how reliable a path is, based on reported issues.
    /// The score decays over time, allowing paths to recover over time if no further issues are
    /// reported.
    #[derive(Debug, Clone)]
    pub struct ReliabilityScore {
        score: f32,
        last_updated: SystemTime,
    }

    impl ReliabilityScore {
        /// Returns the current reliability score, decayed to `now`.
        pub fn score(&self, now: SystemTime) -> Score {
            Score::new_clamped(exponential_decay(
                self.score,
                now.duration_since(self.last_updated)
                    .unwrap_or_else(|_| Duration::from_secs(0)),
                EXPONENTIAL_DECAY_HALFLIFE,
            ))
        }

        /// Creates a new ReliabilityScore with initial score of 0.0
        ///
        /// `now` is the current time for initialization, used for decay calculations.
        pub fn new_with_time(now: SystemTime) -> Self {
            ReliabilityScore {
                score: 0.0,
                last_updated: now,
            }
        }

        /// Updates the reliability score based on the reported issue.
        ///
        /// `penalty` is the penalty score to apply usually a negative value.
        /// `now` is the current time for decay calculations.
        pub fn update(&mut self, penalty: Score, now: SystemTime) {
            let current_score = self.score(now); // Get decayed score
            let new_score = current_score.value() + penalty.value(); // Apply penalty

            self.score = new_score.clamp(-1000.0, 1000.0); // For sanity, clamp score
            self.last_updated = now;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    mod helpers {
        use std::{
            hash::{DefaultHasher, Hash, Hasher},
            net::{IpAddr, Ipv4Addr},
            sync::{Arc, Mutex},
            time::{Duration, SystemTime},
        };

        use scion_proto::{
            address::{Asn, EndhostAddr, Isd, IsdAsn},
            path::{Path, test_builder::TestPathBuilder},
        };

        use super::*;

        pub const SRC_ADDR: EndhostAddr = EndhostAddr::new(
            IsdAsn::new(Isd(1), Asn(1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        pub const DST_ADDR: EndhostAddr = EndhostAddr::new(
            IsdAsn::new(Isd(2), Asn(1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        );

        pub const DEFAULT_EXP_UNITS: u8 = 100;
        pub const BASE_TIME: SystemTime = SystemTime::UNIX_EPOCH;

        pub fn dummy_path(hop_count: u16, timestamp: u32, exp_units: u8, asn_seed: u32) -> Path {
            let mut builder = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
                .using_info_timestamp(timestamp)
                .with_hop_expiry(exp_units)
                .up();

            builder = builder.add_hop(0, 1);

            for cnt in 0..hop_count {
                let mut hash = DefaultHasher::new();
                asn_seed.hash(&mut hash);
                cnt.hash(&mut hash);
                let hash = hash.finish() as u32;

                builder = builder.with_asn(hash).add_hop(cnt + 1, cnt + 2);
            }

            builder = builder.add_hop(1, 0);

            builder.build(timestamp).path()
        }

        pub fn base_config() -> MultiPathManagerConfig {
            MultiPathManagerConfig {
                max_cached_paths_per_pair: 5,
                refetch_interval: Duration::from_secs(100),
                min_refetch_delay: Duration::from_secs(1),
                min_expiry_threshold: Duration::from_secs(5),
                max_idle_period: Duration::from_secs(30),
                fetch_failure_backoff: BackoffConfig {
                    minimum_delay_secs: 1.0,
                    maximum_delay_secs: 10.0,
                    factor: 2.0,
                    jitter_secs: 0.0,
                },
                issue_cache_size: 64,
                issue_broadcast_size: 64,
                issue_deduplication_window: Duration::from_secs(10),
                path_swap_score_threshold: 0.1,
            }
        }

        pub fn generate_responses(
            path_count: u16,
            path_seed: u32,
            timestamp: SystemTime,
            exp_units: u8,
        ) -> Result<Vec<Path>, String> {
            let mut paths = Vec::new();
            for resp_id in 0..path_count {
                paths.push(dummy_path(
                    2,
                    timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32,
                    exp_units,
                    path_seed + resp_id as u32,
                ));
            }

            Ok(paths)
        }

        pub struct MockFetcher {
            next_response: Result<Vec<Path>, String>,
            pub received_requests: usize,
            pub wait_till_notify: bool,
            pub notify_to_resolve: Arc<Notify>,
        }
        impl MockFetcher {
            pub fn new(response: Result<Vec<Path>, String>) -> Arc<Mutex<Self>> {
                Arc::new(Mutex::new(Self {
                    next_response: response,
                    received_requests: 0,
                    wait_till_notify: false,
                    notify_to_resolve: Arc::new(Notify::new()),
                }))
            }

            pub fn set_response(&mut self, response: Result<Vec<Path>, String>) {
                self.next_response = response;
            }

            pub fn wait_till_notify(&mut self, wait: bool) {
                self.wait_till_notify = wait;
            }

            pub fn notify(&self) {
                self.notify_to_resolve.notify_waiters();
            }
        }

        impl PathFetcher for Arc<Mutex<MockFetcher>> {
            async fn fetch_paths(
                &self,
                _src: IsdAsn,
                _dst: IsdAsn,
            ) -> Result<Vec<Path>, PathFetchError> {
                let response;
                // Wait for notification if needed
                let notify = {
                    let mut guard = self.lock().unwrap();

                    guard.received_requests += 1;
                    response = guard.next_response.clone();

                    // maybe wait till notified
                    if guard.wait_till_notify {
                        let notif = guard.notify_to_resolve.clone().notified_owned();
                        Some(notif)
                    } else {
                        None
                    }
                };

                if let Some(notif) = notify {
                    notif.await;
                }

                match response {
                    Ok(paths) if paths.is_empty() => Err(PathFetchError::NoPathsFound),
                    Ok(paths) => Ok(paths),
                    Err(e) => Err(PathFetchError::InternalError(e.into())),
                }
            }
        }

        pub fn manual_pathset<F: PathFetcher>(
            now: SystemTime,
            fetcher: F,
            cfg: MultiPathManagerConfig,
            strategy: Option<PathStrategy>,
        ) -> (MultiPathManager<F>, PathSet<F>) {
            let mgr_inner = MultiPathManagerInner {
                config: cfg,
                fetcher,
                path_strategy: strategy.unwrap_or_else(|| {
                    let mut ps = PathStrategy::default();
                    ps.scoring.use_default_scorers();
                    ps
                }),
                issue_manager: Mutex::new(PathIssueManager::new(64, 64, Duration::from_secs(10))),
                managed_paths: HashIndex::new(),
            };
            let mgr = MultiPathManager(Arc::new(mgr_inner));
            let issue_rx = mgr.0.issue_manager.lock().unwrap().issues_subscriber();
            let mgr_ref = mgr.weak_ref();
            (
                mgr,
                PathSet::new_with_time(
                    SRC_ADDR.isd_asn(),
                    DST_ADDR.isd_asn(),
                    mgr_ref,
                    cfg,
                    issue_rx,
                    now,
                ),
            )
        }
    }

    mod path_set {
        use super::{helpers::*, *};

        // --------------------------------------------------------------------
        // Tests (direct PathSet, driving maintain() with synthetic time)
        // --------------------------------------------------------------------

        // Test Cases

        /// Basic path fetching, caching and active path setting
        mod basic {
            use super::*;

            // Should successfully fetch, set active path and reduce cache to max paths
            // A maintain call before next refetch should do nothing
            #[tokio::test]
            #[test_log::test]

            async fn should_fetch_and_cache_paths() {
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(10, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;
                assert_eq!(fetcher.lock().unwrap().received_requests, 1);

                // Check cached paths
                assert_eq!(
                    path_set.internal.cached_paths.len(),
                    cfg.max_cached_paths_per_pair
                );

                // Check active path
                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());

                let active_fp = active_path.as_ref().unwrap().1;
                assert!(
                    path_set
                        .internal
                        .cached_paths
                        .iter()
                        .any(|p| p.fingerprint == active_fp),
                    "Active path should be in cached paths"
                );

                let expected_next_refetch = BASE_TIME + cfg.refetch_interval;
                assert_eq!(path_set.internal.next_refetch, expected_next_refetch);

                let expected_next_idle_check = BASE_TIME + cfg.max_idle_period;
                assert_eq!(path_set.internal.next_idle_check, expected_next_idle_check);

                // second maintain should not trigger fetch
                path_set.maintain(BASE_TIME, &mgr).await;
                assert_eq!(fetcher.lock().unwrap().received_requests, 1);
            }

            // Refetch should keep active path if it's not expired
            // If the same path is available, it should remain active and be updated
            #[tokio::test]
            #[test_log::test]
            async fn should_update_active_path_on_refetch() {
                // INIT
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(10, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;
                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };
                // Get active path to ensure no idle removal
                let active = handle.try_active_path().clone();
                assert!(active.is_some());
                let first_active_fp = active.as_ref().unwrap().1;
                let first_active_expiry = active.as_ref().unwrap().0.expiry_time().unwrap();

                let next_refetch = path_set.internal.next_refetch;

                // Next fetch with same paths but updated expiry
                fetcher.lock().unwrap().set_response(generate_responses(
                    10,
                    0,
                    next_refetch,
                    DEFAULT_EXP_UNITS,
                ));

                path_set.maintain(next_refetch, &mgr).await;

                // Should have fetched again
                assert_eq!(fetcher.lock().unwrap().received_requests, 2);
                // Should still have max cached paths
                assert_eq!(
                    path_set.internal.cached_paths.len(),
                    cfg.max_cached_paths_per_pair
                );

                // Active path should be same
                let new_active_path = path_set.shared.active_path.load();
                assert!(new_active_path.is_some());

                let new_active_fp = new_active_path.as_ref().unwrap().1;
                assert_eq!(
                    first_active_fp, new_active_fp,
                    "Active path fingerprint should be the same after refetch"
                );
                let new_active_expiry = new_active_path.as_ref().unwrap().0.expiry_time().unwrap();
                assert_ne!(
                    first_active_expiry, new_active_expiry,
                    "Active path expiry should not be the same after refetch"
                );
            }

            // If initial fetch has less than max paths, refetch with more paths should restock
            // cache without touching active path
            #[tokio::test]
            #[test_log::test]
            async fn should_restock_cache_on_refetch() {
                // INIT - start with only 2 paths
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(2, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;
                assert_eq!(fetcher.lock().unwrap().received_requests, 1);

                // Should have only 2 cached paths
                assert_eq!(path_set.internal.cached_paths.len(), 2);

                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());
                let first_active_fp = active_path.as_ref().unwrap().1;

                let next_refetch = path_set.internal.next_refetch;

                // Fetch with more paths but same seed to fill up cache
                fetcher.lock().unwrap().set_response(generate_responses(
                    10,
                    0,
                    BASE_TIME,
                    DEFAULT_EXP_UNITS,
                ));

                // Mark as used in idle period
                path_set
                    .shared
                    .was_used_in_idle_period
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                path_set.maintain(next_refetch, &mgr).await;

                // Should have fetched again
                assert_eq!(fetcher.lock().unwrap().received_requests, 2);
                // Should now have max cached paths
                assert_eq!(
                    path_set.internal.cached_paths.len(),
                    cfg.max_cached_paths_per_pair
                );

                // Active path should remain unchanged
                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());
                let new_active_fp = active_path.as_ref().unwrap().1;
                assert_eq!(
                    first_active_fp, new_active_fp,
                    "Active path should not change"
                );
            }

            // Refetch should keep active path if it's not expired
            // If the same path is not available, but active path is still valid, it should remain
            // active
            #[tokio::test]
            #[test_log::test]
            async fn should_keep_active_path_if_not_expired_even_if_not_in_new_fetch() {
                // INIT
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(2, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;
                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());
                let first_active_fp = active_path.as_ref().unwrap().1;

                let next_refetch = path_set.internal.next_refetch;

                // Next fetch with completely different paths (different seed)
                fetcher.lock().unwrap().set_response(generate_responses(
                    5,
                    100, // Different seed = different paths
                    BASE_TIME,
                    DEFAULT_EXP_UNITS,
                ));

                // Mark as used in idle period
                path_set
                    .shared
                    .was_used_in_idle_period
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                path_set.maintain(next_refetch, &mgr).await;

                // Should have fetched again
                assert_eq!(fetcher.lock().unwrap().received_requests, 2);

                // Active path should still be the same (kept from cache even though not in new
                // fetch)
                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());
                let new_active_fp = active_path.as_ref().unwrap().1;
                assert_eq!(
                    first_active_fp, new_active_fp,
                    "Active path should remain if still valid"
                );
            }
        }

        /// Decisions around active path replacement
        mod active_path_replacement {

            use super::*;
            use crate::path::types::Score;
            // ACTIVE PATH REPLACEMENT

            // If active path is near expiry, and another valid path is available, it should be
            // replaced
            #[tokio::test]
            #[test_log::test]
            async fn should_create_correct_decisions_based_on_active_path_expiry() {
                // INIT with paths that will expire soon
                let cfg = base_config();
                let short_exp = 2;
                let path = dummy_path(1, 0, short_exp, 0);
                let fetcher = MockFetcher::new(Ok(vec![path.clone()]));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;
                let active_path = path_set.shared.active_path.load();
                assert!(active_path.is_some());

                // Check decisions
                let expiry: SystemTime = path.expiry_time().unwrap().into();
                let near_expiry_time = expiry - cfg.min_expiry_threshold;
                let not_near_expiry_time =
                    expiry - cfg.min_expiry_threshold - Duration::from_secs(1);

                let (decision_not_near, _) =
                    path_set.decide_active_path_update(not_near_expiry_time, &mgr);
                assert_eq!(
                    decision_not_near,
                    ActivePathDecision::NoChange,
                    "Active path should be kept when not near expiry"
                );

                let (decision, _) = path_set.decide_active_path_update(near_expiry_time, &mgr);
                assert_eq!(
                    decision,
                    ActivePathDecision::Replace("active path near expiry"),
                    "Active path should be replaced when near expiry"
                );

                let (decision, _) = path_set.decide_active_path_update(expiry, &mgr);
                assert_eq!(
                    decision,
                    ActivePathDecision::ForceReplace("active path expired"),
                    "Active path should be force replaced when expired"
                );
            }

            // If active path's score is much worse than the best path, it should be replaced
            // Should be tied to path_swap_score_threshold
            #[tokio::test]
            #[test_log::test]
            async fn should_replace_active_path_if_much_worse_than_best() {
                // INIT
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);
                path_set.maintain(BASE_TIME, &mgr).await;

                let active_path = path_set.shared.active_path.load();
                let active_fp = active_path.as_ref().unwrap().1;

                // Apply a significant penalty to the active path
                let active_entry = path_set
                    .internal
                    .cached_paths
                    .iter_mut()
                    .find(|e| e.fingerprint == active_fp)
                    .expect("Active path should be in cache");

                active_entry
                    .reliability
                    .update(Score::new_clamped(-1.0), BASE_TIME);

                // Re-rank
                path_set.rerank(BASE_TIME, &mgr);

                // Check decision
                let (decision, best) = path_set.decide_active_path_update(BASE_TIME, &mgr);
                assert_eq!(
                    decision,
                    ActivePathDecision::Replace("swap threshold reached"),
                    "Active path should be replaced due to low score"
                );

                assert!(
                    best.is_some(),
                    "There should be a best path available to replace active path"
                );
                assert_ne!(
                    best.unwrap().fingerprint,
                    active_fp,
                    "Best path should not be the active path"
                );
            }

            #[tokio::test]
            #[test_log::test]
            async fn path_replacement_decision_should_be_applied() {
                // INIT
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);
                path_set.maintain(BASE_TIME, &mgr).await;

                let active_path = path_set.shared.active_path.load();

                let fake_better_path = path_set.internal.cached_paths.get(1).unwrap();

                // No change case
                path_set.apply_active_path_decision(
                    ActivePathDecision::NoChange,
                    None,
                    BASE_TIME,
                    &mgr,
                );
                let active_path_after = path_set.shared.active_path.load();
                assert_eq!(
                    active_path.as_ref().unwrap().1,
                    active_path_after.as_ref().unwrap().1,
                    "Active path should remain unchanged in no change case"
                );
                // Replace no better path case
                path_set.apply_active_path_decision(
                    ActivePathDecision::Replace("no better path"),
                    None,
                    BASE_TIME,
                    &mgr,
                );
                let active_path_after = path_set.shared.active_path.load();
                assert_eq!(
                    active_path.as_ref().unwrap().1,
                    active_path_after.as_ref().unwrap().1,
                    "Active path should remain unchanged in replace no better path case"
                );

                // Force replace no better path case
                path_set.apply_active_path_decision(
                    ActivePathDecision::ForceReplace("must replace"),
                    None,
                    BASE_TIME,
                    &mgr,
                );
                let active_path_after = path_set.shared.active_path.load();
                assert!(
                    active_path_after.is_none(),
                    "Active path should be None after force replace with no better path"
                );

                // Replace with better path case
                path_set.shared.active_path.store(active_path.clone()); // Restore active path
                path_set.apply_active_path_decision(
                    ActivePathDecision::Replace("better path available"),
                    Some(fake_better_path),
                    BASE_TIME,
                    &mgr,
                );
                let active_path_after = path_set.shared.active_path.load();
                assert_eq!(
                    active_path_after.as_ref().unwrap().1,
                    fake_better_path.fingerprint,
                    "Active path should be replaced with better path"
                );

                // Force replace with better path case
                path_set.shared.active_path.store(active_path.clone()); // Restore active path
                path_set.apply_active_path_decision(
                    ActivePathDecision::ForceReplace("must replace with better path"),
                    Some(fake_better_path),
                    BASE_TIME,
                    &mgr,
                );
                let active_path_after = path_set.shared.active_path.load();
                assert_eq!(
                    active_path_after.as_ref().unwrap().1,
                    fake_better_path.fingerprint,
                    "Active path should be replaced with better path"
                );
            }
        }

        // TIMING
        mod timing {
            use super::*;

            // If a cached path is near expiry, next refetch should be scheduled before expiry
            // If the near expiry fetch fails the next refetch should still be before expiry,
            #[tokio::test]
            #[test_log::test]
            async fn next_refetch_should_detect_near_expiry() {
                // INIT with short expiry paths
                let cfg = base_config();
                let short_exp = 3; // 10 EXP_TIME_UNITs
                let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, short_exp));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let earliest_expiry = path_set.earliest_expiry().expect("Should have paths");
                let next_refetch = path_set.internal.next_refetch;

                // Next refetch should be scheduled before earliest expiry minus threshold
                let expected_refetch_deadline = earliest_expiry - cfg.min_expiry_threshold;
                assert!(
                    next_refetch <= expected_refetch_deadline,
                    "Next refetch should be before expiry threshold. next_refetch: {:?}, deadline: {:?}",
                    next_refetch,
                    expected_refetch_deadline
                );
            }

            // If fetching paths fails, backoff should be applied to next refetch time
            #[tokio::test]
            #[test_log::test]
            async fn should_do_backoff_on_fetch_failure() {
                // INIT
                let cfg = base_config();
                let fetcher = MockFetcher::new(Err("Fetch failed".to_string()));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                // Should have failed
                assert_eq!(fetcher.lock().unwrap().received_requests, 1);
                assert_eq!(path_set.internal.failed_attempts, 1);
                assert!(
                    path_set
                        .shared
                        .sync
                        .lock()
                        .unwrap()
                        .current_error
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap()
                        .contains("Fetch failed")
                );

                let first_next_refetch = path_set.internal.next_refetch;

                // Next refetch should be scheduled with backoff
                let backoff = ExponentialBackoff::new_from_config(cfg.fetch_failure_backoff);

                let expected_next_refetch = BASE_TIME + backoff.duration(1);

                assert_eq!(
                    first_next_refetch, expected_next_refetch,
                    "Next refetch should apply backoff delay"
                );

                // Fail again - with no paths
                fetcher.lock().unwrap().set_response(Ok(vec![]));

                // Mark as used in idle period
                path_set
                    .shared
                    .was_used_in_idle_period
                    .store(true, std::sync::atomic::Ordering::Relaxed);

                path_set.maintain(first_next_refetch, &mgr).await;
                assert_eq!(path_set.internal.failed_attempts, 2);

                let second_next_refetch = first_next_refetch + backoff.duration(2);

                // Second failure should have longer backoff
                assert!(
                    path_set.internal.next_refetch == second_next_refetch,
                    "Backoff should increase with consecutive failures"
                );
            }

            // If the next refetch time is later than next idle check, next tick should be set to
            // idle check
            #[tokio::test]
            #[test_log::test]
            async fn should_set_next_tick_to_idle_check() {
                // INIT
                let mut cfg = base_config();
                cfg.max_idle_period = Duration::from_secs(10); // Short idle period
                cfg.refetch_interval = Duration::from_secs(100); // Long refetch interval

                let fetcher =
                    MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let next_refetch = path_set.internal.next_refetch;
                let next_idle_check = path_set.internal.next_idle_check;

                // Idle check should be before refetch
                assert!(next_idle_check < next_refetch);

                // Next maintain time should be idle check
                let next_maintain = path_set.next_maintain(BASE_TIME);
                assert_eq!(
                    next_maintain,
                    next_idle_check.duration_since(BASE_TIME).unwrap(),
                    "Next maintain should be at idle check time"
                );
            }
        }

        // If the pathset was not used during idle period, it should be removed
        #[tokio::test]
        #[test_log::test]
        async fn should_remove_pathset_on_idle() {
            // INIT
            let mut cfg = base_config();
            cfg.max_idle_period = Duration::from_secs(10);
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);
            path_set.maintain(BASE_TIME, &mgr).await;

            // Don't use the path (don't call try_active_path or active_path)
            let idle_check_time = path_set.internal.next_idle_check;

            // Maintain at idle check time
            let result = path_set.maintain(idle_check_time, &mgr).await;

            // Should return Some("idle")
            assert_eq!(
                result,
                Some("idle"),
                "PathSet should be marked for removal when idle"
            );
        }

        // If the pathset was used during idle period, it should not be removed
        #[tokio::test]
        #[test_log::test]
        async fn should_not_remove_pathset_if_used_in_idle_period() {
            // INIT
            let mut cfg = base_config();
            cfg.max_idle_period = Duration::from_secs(10);
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);
            path_set.maintain(BASE_TIME, &mgr).await;

            let handle = PathSetHandle {
                shared: path_set.shared.clone(),
            };

            // Use the path during idle period
            let _active = handle.try_active_path();
            let idle_check_time = path_set.internal.next_idle_check;

            // Maintain at idle check time
            let result = path_set.maintain(idle_check_time, &mgr).await;

            // Should return None (not removed)
            assert_eq!(
                result, None,
                "PathSet should not be removed if used during idle period"
            );
        }

        mod initialization {
            use std::task::Poll;

            use futures::poll;
            use tokio::{task::yield_now, time::timeout};

            use super::*;
            // INITIALIZATION

            // The Path Handle active_path() call should wait for initialization
            #[tokio::test]
            #[test_log::test]
            async fn handle_active_path_should_wait_for_initialization() {
                // INIT - don't call maintain yet
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };

                let future = handle.active_path();
                // first poll must not complete
                tokio::pin!(future);
                let poll_result = poll!(&mut future);
                assert!(
                    poll_result.is_pending(),
                    "Should be pending before initialization"
                );

                path_set.maintain(BASE_TIME, &mgr).await; // Initialize

                // Single poll after initialization must complete
                let poll_result = poll!(&mut future);
                assert!(
                    poll_result.is_ready(),
                    "Should be ready after initialization"
                );
            }

            // The Path Handle active_path() call should wait for ongoing update if no active path
            // is set
            #[tokio::test]
            #[test_log::test]
            async fn handle_active_path_should_wait_for_ongoing_update_if_no_active_path() {
                // INIT
                let cfg = base_config();
                let fetcher = MockFetcher::new(Ok(vec![])); // No paths initially
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };

                // Verify no active path
                assert!(handle.try_active_path().is_none());

                // Set up a fetch that will return paths
                fetcher.lock().unwrap().set_response(generate_responses(
                    5,
                    0,
                    BASE_TIME,
                    DEFAULT_EXP_UNITS,
                ));

                // Make fetcher wait till notified
                fetcher.lock().unwrap().wait_till_notify(true);

                // Trigger update
                let next_refetch = path_set.internal.next_refetch;
                let maintain_notif = path_set
                    .shared
                    .sync
                    .lock()
                    .unwrap()
                    .completed_notify
                    .clone()
                    .notified_owned();
                let path_set_shared = path_set.shared.clone();

                tokio::spawn(async move {
                    path_set.maintain(next_refetch, &mgr).await;
                });

                // Yield till update started
                while path_set_shared.sync.lock().unwrap().ongoing_start.is_none() {
                    yield_now().await;
                }

                // first poll must not complete
                let wait_future = handle.active_path();

                println!("Polling active_path future, should be pending");
                tokio::pin!(wait_future);
                let poll_result = poll!(&mut wait_future);
                println!("Poll result: {:?}", poll_result);
                assert!(
                    poll_result.is_pending(),
                    "Should be pending while waiting for update"
                );

                // Notify fetcher to proceed
                fetcher.lock().unwrap().notify_to_resolve.notify_waiters();

                // Wait for maintain to complete
                timeout(Duration::from_millis(100), maintain_notif)
                    .await
                    .expect("Timeout waiting for maintain to complete");

                // Single poll after update must complete
                let poll_result = poll!(&mut wait_future);
                match poll_result {
                    Poll::Ready(res) => {
                        assert!(
                            res.is_some(),
                            "Should have active path after waiting for update"
                        );
                    }
                    Poll::Pending => {
                        panic!("Should be ready after update");
                    }
                }
            }
        }

        mod error_handling {
            use std::task::Poll;

            use futures::poll;

            use super::*;
            // The Path Handle active_path() call should return the last fetch error if no active
            // path is set
            #[tokio::test]
            #[test_log::test]
            async fn handle_active_path_should_return_error_if_no_active_path() {
                // INIT with fetch error
                let cfg = base_config();
                let fetcher = MockFetcher::new(Err("Fetch failed".to_string()));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };

                // Should have no active path
                assert!(handle.try_active_path().is_none());

                // Should have an error
                let error = handle.current_error();
                assert!(error.is_some(), "Should have fetch error");

                // active should immediately return the error in a single poll
                let future = handle.active_path();
                tokio::pin!(future);
                let poll_result = poll!(&mut future);
                match poll_result {
                    Poll::Ready(res) => {
                        assert!(
                            res.is_none(),
                            "Should have no active path due to fetch error"
                        );
                    }
                    Poll::Pending => {
                        panic!("Should be ready with error");
                    }
                }
            }

            // The Path Handle active_path() call should return active path if set, even if there
            // is a fetch error
            #[tokio::test]
            #[test_log::test]
            async fn handle_active_path_should_return_active_path_even_if_error() {
                // INIT with good paths
                let cfg = base_config();
                let fetcher =
                    MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };

                // Should have active path
                let active = handle.try_active_path();
                assert!(active.is_some());
                let active_fp = active.as_ref().unwrap().1;

                // Now make fetcher fail
                fetcher
                    .lock()
                    .unwrap()
                    .set_response(Err("Fetch failed".to_string()));

                let next_refetch = path_set.internal.next_refetch;
                path_set.maintain(next_refetch, &mgr).await;

                // Should have error
                assert!(handle.current_error().is_some());

                // But should still have active path (old one kept in cache)
                let active = handle.try_active_path();
                assert!(
                    active.is_some(),
                    "Should keep active path even with fetch error"
                );
                assert_eq!(
                    active.as_ref().unwrap().1,
                    active_fp,
                    "Active path should be unchanged"
                );
            }

            // The Path Handle should have access to an error if no paths are available
            // paths were filtered out
            #[tokio::test]
            #[test_log::test]
            async fn handle_active_path_should_return_error_if_no_paths_found() {
                // INIT - fetcher returns empty (simulates all paths filtered out)
                let cfg = base_config();
                let fetcher = MockFetcher::new(Ok(vec![])); // No paths = simulates filtering

                let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

                path_set.maintain(BASE_TIME, &mgr).await;

                let handle = PathSetHandle {
                    shared: path_set.shared.clone(),
                };

                // Should have no active path (all filtered out)
                assert!(handle.try_active_path().is_none());

                // Should have error indicating no paths found
                let error = handle.current_error();
                assert!(error.is_some(), "Should have error when all paths filtered");

                // Check it's the right error type
                match error.as_ref().unwrap().as_ref() {
                    PathFetchError::NoPathsFound => {} // Expected
                    other => panic!("Expected NoPathsFound error, got: {:?}", other),
                }
            }
        }

        mod merge_algo {
            use super::*;
            use crate::path::{scoring::PathScoring, types::Score};

            fn make_path_vec(fpr_base: u16, count: u16) -> Vec<PathManagerPath> {
                (0..count)
                    .map(|i| {
                        PathManagerPath {
                            fingerprint: PathFingerprint::local(IsdAsn((fpr_base + i) as u64)),
                            path: dummy_path(i, 0, 100, (fpr_base + i) as u32),
                            reliability: ReliabilityScore::new_with_time(BASE_TIME),
                        }
                    })
                    .collect()
            }

            #[test]
            fn should_keep_correct_number_of_paths() {
                let mut existing_paths = make_path_vec(0, 10);
                let mut new_paths = make_path_vec(100, 10);

                let mut keep = Vec::new();
                // add half of both existing and new paths to keep
                keep.extend(
                    existing_paths
                        .iter()
                        .take(5)
                        .map(|p| p.fingerprint)
                        .collect::<Vec<_>>(),
                );
                keep.extend(
                    new_paths
                        .iter()
                        .take(5)
                        .map(|p| p.fingerprint)
                        .collect::<Vec<_>>(),
                );

                let mut strat = PathStrategy::default();

                struct TestScorer {
                    keep: Vec<PathFingerprint>,
                }
                impl PathScoring for TestScorer {
                    fn metric_name(&self) -> &'static str {
                        "test"
                    }

                    fn score(
                        &self,
                        path: &PathManagerPath,
                        _now: SystemTime,
                    ) -> crate::path::types::Score {
                        if self.keep.contains(&path.fingerprint) {
                            Score::new_clamped(1.0)
                        } else {
                            Score::new_clamped(0.0)
                        }
                    }
                }

                // Add a scoring alternates between 0 and 1 to force equal ranking between existing
                // paths
                strat.add_scoring(TestScorer { keep }, 1.0);

                let (kept_new, kept_existing) = merge_new_paths_algo(
                    &mut existing_paths,
                    &mut new_paths,
                    None,
                    10,
                    &strat,
                    SystemTime::now(),
                );

                assert_eq!(
                    existing_paths.len(),
                    10,
                    "Total paths should be reduced to exactly 10"
                );
                assert_eq!(kept_existing, 5, "should keep 5 existing paths");
                assert_eq!(kept_new, 5, "should take 5 new paths");
            }

            #[test]
            fn should_ensure_active_path_is_kept() {
                let mut existing_paths = make_path_vec(0, 10);
                let mut new_paths = make_path_vec(100, 10);

                // Use path which would be removed without active path consideration
                let active_fp = existing_paths[9].fingerprint;

                let mut strat = PathStrategy::default();

                struct TestScorer {
                    existing_fps: Vec<PathFingerprint>,
                }
                impl PathScoring for TestScorer {
                    fn metric_name(&self) -> &'static str {
                        "test"
                    }

                    fn score(
                        &self,
                        path: &PathManagerPath,
                        _now: SystemTime,
                    ) -> crate::path::types::Score {
                        if self.existing_fps.contains(&path.fingerprint) {
                            Score::new_clamped(0.0)
                        } else {
                            Score::new_clamped(1.0)
                        }
                    }
                }
                // Add a ranking that ranks all new paths better than existing paths
                strat.add_scoring(
                    TestScorer {
                        existing_fps: existing_paths.iter().map(|e| e.fingerprint).collect(),
                    },
                    1.0,
                );

                let (kept_existing, kept_new) = merge_new_paths_algo(
                    &mut existing_paths,
                    &mut new_paths,
                    Some(active_fp),
                    10,
                    &strat,
                    SystemTime::now(),
                );

                let total_paths = existing_paths.len() + new_paths.len();
                assert_eq!(
                    total_paths, 10,
                    "Total paths should be reduced to exactly 10"
                );
                assert_eq!(
                    kept_existing, 1,
                    "Should have taken 1 existing path (the active path)"
                );
                assert!(
                    existing_paths.iter().any(|e| e.fingerprint == active_fp),
                    "Active path should be kept in existing paths"
                );
                assert_eq!(kept_new, 9, "Should have taken 9 new paths");
            }
        }
    }

    mod issue_handling {
        use scion_proto::address::{Asn, Isd};

        use super::{helpers::*, *};
        use crate::path::types::Score;

        // When an issue is ingested, affected paths should have their reliability scores updated
        // appropriately The issue should be in the issue cache
        #[tokio::test]
        #[test_log::test]
        async fn should_ingest_issues_and_apply_to_existing_paths() {
            let cfg = base_config();
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

            path_set.maintain(BASE_TIME, &mgr).await;

            // Get the first path to create an issue for
            let first_path = &path_set.internal.cached_paths[0];
            let first_fp = first_path.fingerprint;

            // Create an issue targeting the first hop of the first path
            let issue = IssueKind::Socket {
                err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                    crate::scionstack::NetworkError::UnderlayNextHopUnreachable {
                        isd_as: first_path.path.source(),
                        interface_id: first_path.path.first_hop_egress_interface().unwrap().id,
                        msg: "test".into(),
                    },
                )),
            };

            let penalty = Score::new_clamped(-0.3);
            let marker = IssueMarker {
                target: issue.target_type(Some(&first_path.path)).unwrap(),
                timestamp: BASE_TIME,
                penalty,
            };

            {
                let mut issues_guard = mgr.0.issue_manager.lock().unwrap();
                // Add issue to manager
                issues_guard.add_issue(issue, marker);
                // Check issue is in cache
                assert!(!issues_guard.cache.is_empty(), "Issue should be in cache");
            }
            // Handle the issue in path_set
            let recv_result = path_set.internal.issue_rx.recv().await;
            path_set.handle_issue_rx(BASE_TIME, recv_result, &mgr);

            // Check that the path's score was updated
            let updated_path = path_set
                .internal
                .cached_paths
                .iter()
                .find(|e| e.fingerprint == first_fp)
                .expect("Path should still exist");

            let updated_score = updated_path.reliability.score(BASE_TIME).value();

            assert!(
                updated_score == penalty.value(),
                "Path score should be updated by penalty. Expected: {}, Got: {}",
                penalty.value(),
                updated_score
            );

            // Should decay over time
            let later_time = BASE_TIME + Duration::from_secs(30);
            let decayed_score = updated_path.reliability.score(later_time).value();
            assert!(
                decayed_score > updated_score,
                "Path score should recover over time. Updated: {}, Decayed: {}",
                updated_score,
                decayed_score
            );
        }

        #[tokio::test]
        #[test_log::test]
        async fn should_deduplicate_issues_within_window() {
            let cfg = base_config();
            let mgr_inner = MultiPathManagerInner {
                config: cfg,
                fetcher: MockFetcher::new(Ok(vec![])),
                path_strategy: PathStrategy::default(),
                issue_manager: Mutex::new(PathIssueManager::new(64, 64, Duration::from_secs(10))),
                managed_paths: HashIndex::new(),
            };
            let mgr = MultiPathManager(Arc::new(mgr_inner));

            let issue_marker = IssueMarker {
                target: IssueMarkerTarget::FirstHop {
                    isd_asn: SRC_ADDR.isd_asn(),
                    egress_interface: 1,
                },
                timestamp: BASE_TIME,
                penalty: Score::new_clamped(-0.3),
            };

            let issue = IssueKind::Socket {
                err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                    crate::scionstack::NetworkError::DestinationUnreachable("test".into()),
                )),
            };

            // Add issue first time
            mgr.0
                .issue_manager
                .lock()
                .unwrap()
                .add_issue(issue.clone(), issue_marker.clone());
            let cache_size_1 = mgr.0.issue_manager.lock().unwrap().cache.len();
            assert_eq!(cache_size_1, 1);

            // Add same issue within dedup window (should be ignored)
            let issue_marker_2 = IssueMarker {
                timestamp: BASE_TIME + Duration::from_secs(1), // Within 10s window
                ..issue_marker.clone()
            };
            mgr.0
                .issue_manager
                .lock()
                .unwrap()
                .add_issue(issue.clone(), issue_marker_2);

            let fifo_size = mgr.0.issue_manager.lock().unwrap().fifo_issues.len();
            let cache_size_2 = mgr.0.issue_manager.lock().unwrap().cache.len();
            assert_eq!(cache_size_2, 1, "Duplicate issue should be ignored");
            assert_eq!(
                fifo_size, 1,
                "FIFO queue size should remain unchanged on duplicate issue"
            );

            // Add same issue outside dedup window (should be added)
            let issue_marker_3 = IssueMarker {
                timestamp: BASE_TIME + Duration::from_secs(11), // Outside 10s window
                ..issue_marker
            };
            mgr.0
                .issue_manager
                .lock()
                .unwrap()
                .add_issue(issue, issue_marker_3);

            let fifo_size_3 = mgr.0.issue_manager.lock().unwrap().fifo_issues.len();
            let cache_size_3 = mgr.0.issue_manager.lock().unwrap().cache.len();
            assert_eq!(
                cache_size_3, 1,
                "Issue outside dedup window should update existing"
            );
            assert_eq!(
                fifo_size_3, 2,
                "FIFO queue size should increase for new issue outside dedup window"
            );
        }

        // When new paths are fetched, existing issues in the issue cache should be applied to them
        #[tokio::test]
        #[test_log::test]
        async fn should_apply_issues_to_new_paths_on_fetch() {
            let cfg = base_config();
            let fetcher = MockFetcher::new(Ok(vec![]));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

            path_set.maintain(BASE_TIME, &mgr).await;

            // Create an issue
            let issue_marker = IssueMarker {
                target: IssueMarkerTarget::FirstHop {
                    isd_asn: SRC_ADDR.isd_asn(),
                    egress_interface: 1,
                },
                timestamp: BASE_TIME,
                penalty: Score::new_clamped(-0.5),
            };

            let issue = IssueKind::Socket {
                err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                    crate::scionstack::NetworkError::DestinationUnreachable("test".into()),
                )),
            };

            // Add to manager's issue cache
            mgr.0
                .issue_manager
                .lock()
                .unwrap()
                .add_issue(issue, issue_marker);

            // Drain issue channel so no issues are pending
            path_set.drain_and_apply_issue_channel(BASE_TIME);

            // Now fetch paths again - the issue should be applied to the newly fetched path
            fetcher.lock().unwrap().set_response(generate_responses(
                3,
                0,
                BASE_TIME + Duration::from_secs(1),
                DEFAULT_EXP_UNITS,
            ));

            let next_refetch = path_set.internal.next_refetch;
            path_set.maintain(next_refetch, &mgr).await;

            // The newly fetched path should have the penalty applied
            let affected_path = path_set
                .internal
                .cached_paths
                .first()
                .expect("Path should exist");

            let score = affected_path
                .reliability
                .score(BASE_TIME + Duration::from_secs(1))
                .value();
            assert!(
                score < 0.0,
                "Newly fetched path should have cached issue applied. Score: {}",
                score
            );
        }

        // If the active path is affected by an issue, it should be re-evaluated
        #[tokio::test]
        #[test_log::test]
        async fn should_trigger_active_path_reevaluation_on_issue() {
            let cfg = base_config();
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

            path_set.maintain(BASE_TIME, &mgr).await;

            let active_fp = path_set.shared.active_path.load().as_ref().unwrap().1;

            // Create a severe issue targeting the active path
            let issue_marker = IssueMarker {
                target: IssueMarkerTarget::FullPath {
                    fingerprint: active_fp,
                },
                timestamp: BASE_TIME,
                penalty: Score::new_clamped(-1.0), // Severe penalty
            };

            let issue = IssueKind::Socket {
                err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                    crate::scionstack::NetworkError::DestinationUnreachable("test".into()),
                )),
            };

            // Add issue
            mgr.0
                .issue_manager
                .lock()
                .unwrap()
                .add_issue(issue, issue_marker);

            // Handle issue
            let recv_result = path_set.internal.issue_rx.recv().await;
            path_set.handle_issue_rx(BASE_TIME, recv_result, &mgr);

            // Active path should have changed
            let new_active_fp = path_set.shared.active_path.load().as_ref().unwrap().1;
            assert_ne!(
                active_fp, new_active_fp,
                "Active path should change when severely penalized"
            );
        }

        #[tokio::test]
        #[test_log::test]
        async fn should_swap_to_better_path_if_one_appears() {
            let cfg = base_config();
            let fetcher = MockFetcher::new(generate_responses(1, 0, BASE_TIME, DEFAULT_EXP_UNITS));
            let (mgr, mut path_set) = manual_pathset(BASE_TIME, fetcher.clone(), cfg, None);

            path_set.maintain(BASE_TIME, &mgr).await;

            // mark as used to prevent idle removal
            path_set
                .shared
                .was_used_in_idle_period
                .store(true, std::sync::atomic::Ordering::Relaxed);

            let active_fp = path_set.shared.active_path.load().as_ref().unwrap().1;

            // add issue to active path to lower its score
            let issue_marker = IssueMarker {
                target: IssueMarkerTarget::FullPath {
                    fingerprint: active_fp,
                },
                timestamp: BASE_TIME,
                penalty: Score::new_clamped(-0.8),
            };

            mgr.0.issue_manager.lock().unwrap().add_issue(
                IssueKind::Socket {
                    err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                        crate::scionstack::NetworkError::DestinationUnreachable("test".into()),
                    )),
                },
                issue_marker,
            );

            // active path should be the same
            let active_fp_after_issue = path_set.shared.active_path.load().as_ref().unwrap().1;
            assert_eq!(
                active_fp, active_fp_after_issue,
                "Active path should remain the same if no better path exists"
            );

            // Now fetch a better path
            fetcher.lock().unwrap().set_response(generate_responses(
                1,
                100,
                BASE_TIME + Duration::from_secs(1),
                DEFAULT_EXP_UNITS,
            ));

            path_set
                .maintain(path_set.internal.next_refetch, &mgr)
                .await;
            // mark as used to prevent idle removal
            path_set
                .shared
                .was_used_in_idle_period
                .store(true, std::sync::atomic::Ordering::Relaxed);

            // Active path should have changed
            let new_active_fp = path_set.shared.active_path.load().as_ref().unwrap().1;
            assert_ne!(
                active_fp, new_active_fp,
                "Active path should change when a better path appears"
            );

            // Should also work for positive score changes
            let positive_score = Score::new_clamped(0.8);
            let mut reliability = ReliabilityScore::new_with_time(path_set.internal.next_refetch);
            reliability.update(positive_score, path_set.internal.next_refetch);

            // Change old paths reliability to be better
            path_set
                .internal
                .cached_paths
                .iter_mut()
                .find(|e| e.fingerprint == active_fp)
                .unwrap()
                .reliability = reliability;

            path_set
                .maintain(path_set.internal.next_refetch, &mgr)
                .await;

            assert_eq!(
                active_fp,
                path_set.shared.active_path.load().as_ref().unwrap().1,
                "Active path should change on positive score diff"
            );
        }

        #[tokio::test]
        #[test_log::test]
        async fn should_keep_max_issue_cache_size() {
            let max_size = 10;
            let mut issue_mgr = PathIssueManager::new(max_size, 64, Duration::from_secs(10));

            // Add more issues than max_size
            for i in 0..20u16 {
                let issue_marker = IssueMarker {
                    target: IssueMarkerTarget::FirstHop {
                        isd_asn: IsdAsn::new(Isd(1), Asn(1)),
                        egress_interface: i,
                    },
                    timestamp: BASE_TIME + Duration::from_secs(i as u64),
                    penalty: Score::new_clamped(-0.1),
                };

                let issue = IssueKind::Socket {
                    err: Arc::new(crate::scionstack::ScionSocketSendError::NetworkUnreachable(
                        crate::scionstack::NetworkError::DestinationUnreachable("test".into()),
                    )),
                };

                issue_mgr.add_issue(issue, issue_marker);
            }

            // Cache should not exceed max_size
            assert!(
                issue_mgr.cache.len() <= max_size,
                "Cache size {} should not exceed max {}",
                issue_mgr.cache.len(),
                max_size
            );

            // FIFO queue should match cache size
            assert_eq!(issue_mgr.cache.len(), issue_mgr.fifo_issues.len());
        }
    }

    mod manager {
        use tokio::time::timeout;

        use super::{helpers::*, *};

        // The manager should create path sets on request
        #[tokio::test]
        #[test_log::test]
        async fn should_create_pathset_on_request() {
            let cfg = base_config();
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));

            let mgr = MultiPathManager::new(cfg, fetcher, PathStrategy::default())
                .expect("Should create manager");

            // Initially no managed paths
            assert!(mgr.0.managed_paths.is_empty());

            // Request a path - should create path set
            let path = mgr.try_path(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn(), BASE_TIME);
            // First call returns None (not yet initialized)
            assert!(path.is_none());

            // But path set should be created
            assert!(
                mgr.0
                    .managed_paths
                    .contains(&(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn()))
            );
        }

        // The manager should remove idle path sets
        #[tokio::test]
        #[test_log::test]
        async fn should_remove_idle_pathsets() {
            let mut cfg = base_config();
            cfg.max_idle_period = Duration::from_millis(10); // Short idle period for testing

            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));

            let mgr = MultiPathManager::new(cfg, fetcher, PathStrategy::default())
                .expect("Should create manager");

            // Create path set
            let handle = mgr.ensure_managed_paths(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn());

            // Should exist
            assert!(
                mgr.0
                    .managed_paths
                    .contains(&(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn()))
            );

            // Wait for idle timeout plus some margin
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Path set should be removed by idle check
            let contains = mgr
                .0
                .managed_paths
                .contains(&(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn()));

            assert!(!contains, "Idle path set should be removed");

            let err = handle.current_error();
            assert!(
                err.is_some(),
                "Handle should report error after path set removal"
            );
            println!("Error after idle removal: {:?}", err);
            assert!(
                err.unwrap().to_string().contains("idle"),
                "Error message should indicate idle removal"
            );
        }

        // Dropping the manager should cancel all path set maintenance tasks
        #[tokio::test]
        #[test_log::test]
        async fn should_cancel_pathset_tasks_on_drop() {
            let cfg: MultiPathManagerConfig = base_config();
            let fetcher = MockFetcher::new(generate_responses(5, 0, BASE_TIME, DEFAULT_EXP_UNITS));

            let mgr = MultiPathManager::new(cfg, fetcher, PathStrategy::default())
                .expect("Should create manager");

            // ensure path set exists and initialized
            let handle = mgr.ensure_managed_paths(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn());
            handle.wait_initialized().await;

            let mut set_entry = mgr
                .0
                .managed_paths
                .get_sync(&(SRC_ADDR.isd_asn(), DST_ADDR.isd_asn()))
                .unwrap();

            let task_handle = unsafe {
                // swap join handle with a fake one, only possible since the manager doesn't use the
                // handle
                let swap_handle = tokio::spawn(async {});
                std::mem::replace(&mut set_entry.get_mut().1._task, swap_handle)
            };

            let cancel_token = set_entry.get().1.cancel_token.clone();

            let count = mgr.0.managed_paths.len();
            assert_eq!(count, 1, "Should have 1 managed path set");

            // Drop the manager
            drop(mgr);
            // Cancel token should be triggered
            assert!(
                cancel_token.is_cancelled(),
                "Cancel token should be triggered"
            );

            // Give tasks time to detect manager drop and exit
            timeout(Duration::from_millis(50), task_handle)
                .await
                .unwrap()
                .unwrap();

            let err = handle
                .shared
                .sync
                .lock()
                .unwrap()
                .current_error
                .clone()
                .expect("Should have error after manager drop");

            // XXX(ake): exit reason may vary between "cancelled" and "manager dropped" because of
            // select!
            assert!(
                err.to_string().contains("cancelled") || err.to_string().contains("dropped"),
                "Error message should indicate cancellation or manager drop"
            );
        }
    }
}
// LeftoverTodos:
// [] File Split up
// [] Integration
//  [] Change types for path_strategy to support ranking and filtering

// Future Todos:
// [] Performance Scoring
// [] ICMP
