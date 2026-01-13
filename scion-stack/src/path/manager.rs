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
    collections::{HashMap, VecDeque, hash_map},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime},
};

use scc::HashIndex;
use scion_proto::{address::IsdAsn, path::Path, scmp::ScmpErrorMessage};
use scion_sdk_utils::backoff::BackoffConfig;
use tokio::sync::broadcast::{self};

use crate::{
    path::{
        PathStrategy,
        fetcher::{
            PathFetcherImpl,
            traits::{PathFetchError, PathFetcher},
        },
        manager::{
            issues::{IssueKind, IssueMarker, IssueMarkerTarget, SendError},
            pathset::{PathSet, PathSetHandle, PathSetTask},
            traits::{PathManager, PathPrefetcher, PathWaitError, SyncPathManager},
        },
        types::PathManagerPath,
    },
    scionstack::{
        ScionSocketSendError, scmp_handler::ScmpErrorReceiver, socket::SendErrorReceiver,
    },
};

mod algo;
/// Path issue definitions, including mapping issues to affected targets and their respective
/// penalties
mod issues;
/// Pathsets manage paths for a specific src-dst pair.
mod pathset;
/// Path reliability tracking
pub mod reliability;
/// Path fetcher traits and types.
pub mod traits;

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

impl<F: PathFetcher> ScmpErrorReceiver for MultiPathManager<F> {
    fn report_scmp_error(&self, scmp_error: ScmpErrorMessage, path: &Path) {
        self.report_path_issue(
            SystemTime::now(),
            IssueKind::Scmp { error: scmp_error },
            Some(path),
        );
    }
}

impl<F: PathFetcher> SendErrorReceiver for MultiPathManager<F> {
    fn report_send_error(&self, error: &ScionSocketSendError) {
        if let Some(send_error) = SendError::from_socket_send_error(error) {
            self.report_path_issue(
                SystemTime::now(),
                IssueKind::Socket { err: send_error },
                None,
            );
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
///
/// Can be upgraded to a strong reference using [`get`](Self::get).
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
///
/// Receives reported issues, deduplicates them, and broadcasts them to all path sets.
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

#[cfg(test)]
mod tests {
    use helpers::*;
    use tokio::time::timeout;

    use super::*;

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
            // swap join handle with a fake one, only possible since the manager doesn't use
            // the handle
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

        // XXX(ake): exit reason may vary between "cancelled" and "manager dropped" because
        // of select!
        assert!(
            err.to_string().contains("cancelled") || err.to_string().contains("dropped"),
            "Error message should indicate cancellation or manager drop"
        );
    }

    mod issue_handling {
        use scc::HashIndex;
        use scion_proto::address::{Asn, Isd};

        use super::*;
        use crate::path::{
            manager::{MultiPathManagerInner, PathIssueManager, reliability::ReliabilityScore},
            types::Score,
        };

        // When an issue is ingested, affected paths should have their reliability scores
        // updated appropriately The issue should be in the issue cache
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
                err: SendError::FirstHopUnreachable {
                    isd_asn: first_path.path.source(),
                    interface_id: first_path.path.first_hop_egress_interface().unwrap().id,
                    msg: "test".into(),
                },
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
                err: SendError::FirstHopUnreachable {
                    isd_asn: SRC_ADDR.isd_asn(),
                    interface_id: 1,
                    msg: "test".into(),
                },
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

        // When new paths are fetched, existing issues in the issue cache should be applied to
        // them
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
                err: SendError::FirstHopUnreachable {
                    isd_asn: SRC_ADDR.isd_asn(),
                    interface_id: 1,
                    msg: "test".into(),
                },
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
                err: SendError::FirstHopUnreachable {
                    isd_asn: SRC_ADDR.isd_asn(),
                    interface_id: 1,
                    msg: "test".into(),
                },
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
                    err: SendError::FirstHopUnreachable {
                        isd_asn: SRC_ADDR.isd_asn(),
                        interface_id: 1,
                        msg: "test".into(),
                    },
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
                    err: SendError::FirstHopUnreachable {
                        isd_asn: IsdAsn::new(Isd(1), Asn(1)),
                        interface_id: i,
                        msg: "test".into(),
                    },
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

    pub mod helpers {
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
        use tokio::sync::Notify;

        use super::*;
        use crate::path::manager::{MultiPathManagerInner, PathIssueManager, pathset::PathSet};

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

        pub fn dummy_path(hop_count: u16, timestamp: u32, exp_units: u8, seed: u32) -> Path {
            let mut builder: TestPathBuilder = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
                .using_info_timestamp(timestamp)
                .with_hop_expiry(exp_units)
                .up();

            builder = builder.add_hop(0, 1);

            for cnt in 0..hop_count {
                let mut hash = DefaultHasher::new();
                seed.hash(&mut hash);
                cnt.hash(&mut hash);
                let hash = hash.finish() as u32;

                let hop = hash.saturating_sub(2) as u16; // ensure no underflow or overflow
                builder = builder.with_asn(hash).add_hop(hop + 1, hop + 2);
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
}
