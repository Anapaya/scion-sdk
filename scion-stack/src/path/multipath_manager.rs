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

//! Multi-path manager
//!
//! Manages multiple paths per src-dst pair, including path fetching, caching, and selection.
//!
//! Uses a background task per src-dst pair to manage path fetching and refreshing.

use std::{
    collections::{HashMap, VecDeque, hash_map},
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
    manager::{PathFetchError, PathFetcher, PathManager, SyncPathManager},
    multipath_manager::{
        issues::{IssueKind, IssueMarker, IssueMarkerTarget},
        reliability::ReliabilityScore,
    },
    types::PathManagerPath,
};

/// Configuration for the MultiPathManager.
pub struct MultiPathManagerConfig {
    /// Maximum number of cached paths per src-dst pair.
    _max_cached_paths_per_pair: usize,
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
pub struct MultiPathManager<F: PathFetcher>(Arc<MultiPathManagerInner<F>>);
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
                    self.0.config.refetch_interval,
                    self.0.config.min_refetch_delay,
                    self.0.config.min_expiry_threshold,
                    self.0.config.max_idle_period,
                    self.0.config.fetch_failure_backoff,
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
    ) -> impl crate::types::ResFut<'_, Path<bytes::Bytes>, super::manager::PathWaitError> {
        async move {
            match self.path(src, dst, now.into()).await {
                Ok(path) => Ok(path),
                Err(e) => {
                    match &*e {
                        PathFetchError::FetchSegments(error) => {
                            Err(super::manager::PathWaitError::FetchFailed(format!(
                                "{error}"
                            )))
                        }
                        PathFetchError::InternalError(msg) => {
                            Err(super::manager::PathWaitError::FetchFailed(msg.to_string()))
                        }
                        PathFetchError::NoPathsFound => {
                            Err(super::manager::PathWaitError::NoPathFound)
                        }
                    }
                }
            }
        }
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
    pub fn apply_cached_issues(&self, entry: &mut PathSetEntry, now: SystemTime) -> bool {
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
    #[expect(unused)]
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

/// Entry in the path set cache.
struct PathSetEntry {
    path: Path,
    fingerprint: PathFingerprint,
    reliability: ReliabilityScore,
}

/// Manages paths for a specific src-dst pair.
struct PathSet<F: PathFetcher> {
    // Immutable
    /// Source ISD-AS
    src: IsdAsn,
    /// Destination ISD-AS
    dst: IsdAsn,
    /// Interval between path refetches
    refetch_interval: Duration,
    /// Minimum duration between refetches
    min_refetch_delay: Duration,
    /// Minimum expiry threshold before refetching paths
    min_expiry_threshold: Duration,
    /// Maximum idle period before the ManagedPathTuple is removed
    max_idle_period: Duration,
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
    cached_paths: Vec<PathSetEntry>,
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
        refetch_interval: Duration,
        min_refetch_delay: Duration,
        min_expiry_threshold: Duration,
        max_idle_period: Duration,
        backoff: BackoffConfig,
        issue_rx: broadcast::Receiver<(u64, IssueMarker)>,
    ) -> Self {
        PathSet {
            src,
            dst,
            refetch_interval,
            min_refetch_delay,
            min_expiry_threshold,
            max_idle_period,
            backoff: ExponentialBackoff::new_from_config(backoff),
            manager,
            internal: PathSetInternal {
                cached_paths: Vec::new(),
                failed_attempts: 0,
                next_refetch: SystemTime::now(),
                next_idle_check: SystemTime::now() + max_idle_period,
                issue_rx,
            },
            shared: Arc::new(PathSetSharedState {
                active_path: ArcSwapOption::new(None),
                was_used_in_idle_period: AtomicBool::new(true),
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
                // Update the managed path tuple on start
                self.fetch_and_update(SystemTime::now()).await;

                loop {
                    let now = SystemTime::now();
                    tracing::trace!("Managed paths task tick");
                    let next_tick = self.next_maintain(now).await;

                    select! {
                        // Issue Notifications
                        issue = self.internal.issue_rx.recv() => {
                            if !self.handle_issue_rx(SystemTime::now(), issue) {
                                break;
                            }
                        }
                        // Maintenance Tick
                        _ = tokio::time::sleep(next_tick) => {
                            self.maintain(SystemTime::now()).await;
                        }
                        // Cancellation
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                    }
                }

                tracing::info!("Managed paths task exiting");
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
    /// Returns false if the task should exit.
    fn handle_issue_rx(
        &mut self,
        now: SystemTime,
        recv: Result<(u64, IssueMarker), broadcast::error::RecvError>,
    ) -> bool {
        // Sadly we don't have a way to peek broadcast so we have to handle first recv separately
        let (_, issue) = match recv {
            Ok(issue) => issue,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                tracing::warn!("Missed path issue notifications");
                return true;
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("Issue notification channel closed, exiting managed paths task");
                return false;
            }
        };

        // Check if issue applies to this path set
        if !issue.target.applies_to_path(self.src, self.dst) {
            return true;
        }

        let mut res = self.ingest_path_issue(now, &issue);
        let (mut issue_count, res2) = self.drain_and_apply_issue_channel(now);

        issue_count += 1;
        res.combine(&res2);

        tracing::debug!(count = issue_count, ?res, "Ingested path issues");

        if res.active_path_affected {
            tracing::info!("Active path affected by path issues, re-evaluating");
            self.rerank();
            self.maybe_update_active_path(now);
        }

        true
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

    async fn next_maintain(&self, now: SystemTime) -> Duration {
        // If time is in the past, tick immediately
        std::cmp::min(self.internal.next_refetch, self.internal.next_idle_check)
            .duration_since(now)
            .unwrap_or_else(|_| Duration::from_secs(0))
    }

    /// Maintains the path set by checking for idle paths and refetching if necessary.
    ///
    /// Returns true if the path set is idle and should be removed.
    async fn maintain(&mut self, now: SystemTime) -> bool {
        if now >= self.internal.next_idle_check && self.idle_check(now).await {
            if let Some(mgr) = self.manager.get() {
                mgr.stop_managing_paths(self.src, self.dst);
            }

            return true;
        }

        if now >= self.internal.next_refetch {
            self.fetch_and_update(now).await;
        }

        false
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
            self.internal.next_idle_check = now + self.max_idle_period;
            false
        } else {
            // Path tuple is idle, remove it
            let unused_since = self.internal.next_idle_check - self.max_idle_period;
            tracing::info!(?unused_since, "Path tuple is idle, removing");
            true
        }
    }

    /// Refetches paths and updates the cache
    async fn fetch_and_update(&mut self, now: SystemTime) {
        tracing::debug!("Refetching paths for src-dst pair");

        // Update update state
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
            let fetched_paths = self.fetch_and_filter_paths().await?;

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

                self.update_path_cache(fetched_paths, now);
                let earliest_expiry = self
                    .earliest_expiry()
                    .expect("should have a path available, as new paths were ingested");

                // Reset error state
                self.shared.sync.lock().unwrap().current_error = None;
                self.internal.failed_attempts = 0;
                // Update next refetch time
                self.internal.next_refetch =
                    // Either after refetch interval, or before earliest expiry
                    (now + self.refetch_interval).min(earliest_expiry - self.min_expiry_threshold)
                    // But at least after min refetch delay
                    .max(now + self.min_refetch_delay);
            }
            // Failed to fetch, might have no paths available
            Err(e) => {
                // Maintain path cache with no new paths
                self.update_path_cache(vec![], now);

                self.internal.failed_attempts += 1;
                // Schedule next refetch after a delay
                self.internal.next_refetch = now
                    + self
                        .backoff
                        .duration(self.internal.failed_attempts)
                        .max(self.min_refetch_delay);

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
        self.rerank();
        self.maybe_update_active_path(now);

        // Update update state
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
    async fn fetch_and_filter_paths(&self) -> Result<Vec<Path>, PathFetchError> {
        let manager = match self.manager.get() {
            Some(mgr) => mgr,
            None => {
                return Err(PathFetchError::InternalError(
                    "Parent path manager has been dropped".into(),
                ));
            }
        };

        let mut paths = manager.0.fetcher.fetch_paths(self.src, self.dst).await?;

        let before_filter_count = paths.len();

        paths.retain(|p| {
            // TODO: predicate type needs to be changed, this is temporary
            manager.0.path_strategy.predicate(&PathManagerPath {
                path: p.clone(),
                from_registration: false,
            })
        });

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
    fn update_path_cache(&mut self, new_paths: Vec<Path>, now: SystemTime) {
        // TODO: Currently caches every path, should Reduce paths to max cached paths per pair
        // But this requires another path ranking, possibly focussed on diversity

        let mut new_paths: HashMap<PathFingerprint, Path, RandomState> =
            HashMap::from_iter(new_paths.into_iter().map(|path| {
                let fingerprint = path.fingerprint().unwrap();
                (fingerprint, path)
            }));

        let active_path_fp = self.shared.active_path.load().as_ref().map(|p| p.1);

        // Update cached paths
        self.internal.cached_paths.retain_mut(|cached_path| {
            let fp = cached_path.fingerprint;

            // Take path from new paths if it exists
            let mut keep = match new_paths.remove(&fp) {
                // Update existing
                Some(new_path) => {
                    cached_path.path = new_path;
                    true
                }
                // TODO: When path Reduction is implemented, this might have to be changed
                None => true,
            };

            // Don't keep expired paths
            if check_path_expiry(&cached_path.path, now, self.min_expiry_threshold)
                == ExpiryState::Expired
            {
                tracing::info!(?fp, "Removing expired path from cache");
                keep = false;
            }

            // Maintain active path reference
            if Some(fp) == active_path_fp {
                match keep {
                    true => {
                        tracing::debug!(?fp, "Keeping updated active path");
                        self.shared
                            .active_path
                            .store(Some(Arc::new((cached_path.path.clone(), fp))));
                    }
                    false => {
                        tracing::info!(
                            ?active_path_fp,
                            "Active path is expired, clearing active path"
                        );
                        self.shared.active_path.store(None);
                    }
                }
            };

            keep
        });

        // Work on new paths
        if !new_paths.is_empty() {
            let manager = match self.manager.get() {
                Some(mgr) => mgr,
                None => {
                    tracing::info!(
                        "Parent path manager has been dropped, skipping path cache update"
                    );
                    return;
                }
            };

            // Drain issue channel before lock to reduce lock time
            let (issue_count, res) = self.drain_and_apply_issue_channel(now);
            if issue_count > 0 {
                tracing::debug!(
                    count = issue_count,
                    ?res,
                    "Ingested path issues before applying to new paths"
                );
            }

            // Take issues cache lock
            let issues_guard = manager.0.issue_manager.lock().unwrap();

            // Drain issue channel again to catch any issues that arrived during lock acquisition
            let (issue_count, res) = self.drain_and_apply_issue_channel(now);
            if issue_count > 0 {
                tracing::debug!(
                    count = issue_count,
                    ?res,
                    "Ingested path issues before applying to new paths after lock acquisition"
                );
            }

            // Insert and update new paths
            for (new_fp, new_path) in new_paths {
                let mut entry = PathSetEntry {
                    fingerprint: new_fp,
                    path: new_path,
                    reliability: ReliabilityScore::new_with_time(now),
                };

                // Apply cached issues to new paths
                issues_guard.apply_cached_issues(&mut entry, now);
                self.internal.cached_paths.push(entry);
            }
        }
    }

    // Applies path ranking and selects active path if necessary.
    fn rerank(&mut self) {
        // TODO: just a placeholder ranking for now - by reliability score
        self.internal.cached_paths.sort_by(|a, b| {
            b.reliability
                .score()
                .total_cmp(&a.reliability.score())
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });

        // Rank paths
        // TODO: For ranking, path_strategy type needs to be changed
    }

    /// Updates the active path if required
    fn maybe_update_active_path(&self, now: SystemTime) {
        /// Decision on active path update, including reason
        enum Decision {
            /// No change needed
            NoChange,
            /// Active path should be replaced if a better path is available
            Replace(&'static str),
            /// Active path must be removed, even if no better path is available
            ForceReplace(&'static str),
        }

        let active_path_guard = self.shared.active_path.load();
        let active_path = active_path_guard.as_ref();
        let best_path = self.best_path(now);

        // Determine if active path needs replacement
        let decision = match active_path {
            // No active path, set best available path
            None => Decision::Replace("no active path"),
            // We have active path, only update if there is a much better path
            Some(active) => {
                match check_path_expiry(&active.0, now, self.min_expiry_threshold) {
                    ExpiryState::Valid => {
                        // TODO: Check if best path is better than active path
                        Decision::NoChange
                    }
                    // Near expiry, should be replaced
                    ExpiryState::NearExpiry => Decision::Replace("active path near expiry"),
                    // Expired, must be replaced
                    ExpiryState::Expired => Decision::ForceReplace("active path expired"),
                }
            }
        };

        let active_fp = active_path
            .map(|p| p.1.to_string())
            .unwrap_or_else(|| "None".into());

        // Apply update if needed
        match (decision, best_path) {
            // No reason to replace active path
            (Decision::NoChange, _) => {}
            // No better path available
            (Decision::Replace(reason), None) => {
                tracing::warn!(%active_fp, %reason, "Active path should be replaced, but no better path is available");
            }
            (Decision::ForceReplace(reason), None) => {
                tracing::warn!(%active_fp, %reason, "Active path must be replaced, but no better path is available");
                self.shared.active_path.store(None);
            }
            // We have a reason and a better path
            (Decision::ForceReplace(reason) | Decision::Replace(reason), Some(best_path)) => {
                let active_detail = active_path
                    .map(|p| p.0.to_string())
                    .unwrap_or_else(|| "None".into());

                tracing::info!(%active_fp, best_fp=?best_path.fingerprint, %reason, "Replacing active path");
                tracing::debug!("Old active path: {}", active_detail);
                tracing::debug!("New active path: {}", best_path.path);

                self.shared.active_path.store(Some(Arc::new((
                    best_path.path.clone(),
                    best_path.fingerprint,
                ))));
            }
        }
    }

    /// Selects the best path from the cached paths
    fn best_path(&self, now: SystemTime) -> Option<&PathSetEntry> {
        let path_iter = self.internal.cached_paths.iter();

        for path in path_iter {
            // Only consider paths that are not near expiry
            if check_path_expiry(&path.path, now, self.min_expiry_threshold) != ExpiryState::Valid {
                continue;
            }

            return Some(path);
        }

        None
    }
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
        Ok(time_left) if time_left <= threshold => ExpiryState::NearExpiry,
        Ok(_) => ExpiryState::Valid,
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
        path::multipath_manager::{algo::exponential_decay, types::Score},
        scionstack::ScionSocketSendError,
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
                IssueKind::Icmp { .. } => todo!(), //TODO
                IssueKind::Socket { err } => {
                    let Some(path) = path else {
                        debug_assert!(false, "Path must be provided on SCMP errors");
                        return None;
                    };

                    match err.deref() {
                        ScionSocketSendError::NetworkUnreachable(network_error) => {
                            match network_error {
                                crate::scionstack::NetworkError::DestinationUnreachable(_) => {
                                    // TODO: Seems to be used in mixed contexts, need more info to
                                    // interpret
                                    None
                                }
                                crate::scionstack::NetworkError::UnderlayNextHopUnreachable {
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

mod types {
    /// Float with range -1.0 to 1.0
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Score(f32);

    impl Eq for Score {}

    impl Ord for Score {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0
                .partial_cmp(&other.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        }
    }
    impl PartialOrd for Score {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Score {
        pub fn new_clamped(value: f32) -> Self {
            let value = match value.is_nan() {
                true => 0.0,
                false => value,
            };
            Score(value.clamp(-1.0, 1.0))
        }

        pub fn value(&self) -> f32 {
            self.0
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
mod reliability {
    use std::time::{Duration, SystemTime};

    use super::types::Score;
    use crate::path::multipath_manager::algo::exponential_decay;

    /// Duration after which the reliability score decays to half its value.
    /// After 20 half-lives, the score approaches zero.
    const EXPONENTIAL_DECAY_HALFLIFE: Duration = Duration::from_secs(90); // Full decay in ~30 min

    #[derive(Debug, Clone)]
    pub struct ReliabilityScore {
        score: Score,
        last_updated: SystemTime,
    }

    impl ReliabilityScore {
        pub fn score(&self) -> f32 {
            self.score.value()
        }

        pub fn new_with_time(now: SystemTime) -> Self {
            ReliabilityScore {
                score: Score::new_clamped(0.0),
                last_updated: now,
            }
        }

        pub fn get_score(&self, now: SystemTime) -> f32 {
            exponential_decay(
                self.score.value(),
                now.duration_since(self.last_updated)
                    .unwrap_or_else(|_| Duration::from_secs(0)),
                EXPONENTIAL_DECAY_HALFLIFE,
            )
        }

        /// Updates the reliability score based on the reported issue.
        pub fn update(&mut self, penalty: Score, now: SystemTime) {
            let current_score = self.get_score(now); // Get decayed score
            let new_score = current_score + penalty.value(); // Apply penalty
            self.score = Score::new_clamped(new_score);
            self.last_updated = now;
        }
    }
}

// LeftoverTodos:
// [] Path Reduction on Fetch
// [] Implement proper issue target extraction from IssueKind
// [] Implement proper penalty calculation in IssueKind
// [] Implement proper performance scoring
// [] Integration
// [] Change types for path_strategy to support ranking and filtering
