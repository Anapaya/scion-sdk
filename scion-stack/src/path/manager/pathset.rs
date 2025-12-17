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

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Display,
    hash::RandomState,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwapOption;
use scion_proto::{
    address::IsdAsn,
    path::{Path, PathFingerprint},
};
use scion_sdk_utils::backoff::ExponentialBackoff;
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
    fetcher::traits::{PathFetchError, PathFetcher},
    manager::{
        MultiPathManager, MultiPathManagerConfig, MultiPathManagerRef, issues::IssueMarker,
        reliability::ReliabilityScore,
    },
    types::PathManagerPath,
};

/// Manages paths for a specific src-dst pair.
pub struct PathSet<F: PathFetcher> {
    /// Source ISD-AS
    pub src: IsdAsn,
    /// Destination ISD-AS
    pub dst: IsdAsn,
    /// Config
    pub config: MultiPathManagerConfig,
    /// Backoff for path fetch failures
    pub backoff: ExponentialBackoff,
    /// Parent multipath manager
    pub manager: MultiPathManagerRef<F>,
    /// Internal state
    pub internal: PathSetInternal,
    /// Shared State
    pub shared: Arc<PathSetSharedState>,
}

/// Shared state of the managed path set.
pub struct PathSetSharedState {
    /// Currently active path
    pub active_path: ArcSwapOption<(Path, PathFingerprint)>,
    /// Fast path usage tracker
    pub was_used_in_idle_period: AtomicBool,
    /// Separate state for synchronization
    pub sync: Mutex<PathSetSyncState>,
}

/// Synchronization state for path set operations.
#[derive(Debug, Default)]
pub struct PathSetSyncState {
    /// Initial fetch was completed
    pub initialized: bool,
    /// Ongoing fetch start time
    pub ongoing_start: Option<SystemTime>,
    /// Fetch completion notifier
    pub completed_notify: Arc<Notify>,
    /// Error encountered during path fetch
    pub current_error: Option<Arc<PathFetchError>>,
}

/// Internal state of the managed path set.
pub struct PathSetInternal {
    /// Cached paths
    pub cached_paths: Vec<PathManagerPath>,
    /// Number of consecutive failed fetch attempts
    pub failed_attempts: u32,
    /// Next time to refetch paths
    pub next_refetch: SystemTime,
    /// Next time to check for idleness
    pub next_idle_check: SystemTime,
    /// Issue notifications
    pub issue_rx: broadcast::Receiver<(u64, IssueMarker)>,
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

    pub fn new_with_time(
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
    pub fn manage(mut self) -> (PathSetHandle, PathSetTask) {
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
    pub fn handle_issue_rx(
        &mut self,
        now: SystemTime,
        recv: Result<(u64, IssueMarker), broadcast::error::RecvError>,
        manager: &MultiPathManager<F>,
    ) -> Option<&'static str> {
        // Sadly we don't have a way to peek broadcast so we have to handle first recv
        // separately
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
    pub fn drain_and_apply_issue_channel(
        &mut self,
        now: SystemTime,
    ) -> (u32, PathIssueIngestResult) {
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

    pub fn next_maintain(&self, now: SystemTime) -> Duration {
        // If time is in the past, tick immediately
        std::cmp::min(self.internal.next_refetch, self.internal.next_idle_check)
            .duration_since(now)
            .unwrap_or_else(|_| Duration::from_secs(0))
    }

    /// Maintains the path set by checking for idle paths and refetching if necessary.
    ///
    /// Returns Some with a reason if the path set should be dropped
    pub async fn maintain(
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
                // XXX(ake): This could be pretty expensive if we have a lot of new path
                // candidates. Possibly we need to reduce the candidates
                // before this in the future
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

    /// Creates the decision for whether to update the active path and returns the best
    /// candidate.
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
                    // XXX(ake): Ranking does not consider expiry currently, so falling over
                    // when near expiry might fail, as it keeps wanting
                    // to use the same path. Not a big deal, as near
                    // expiry is an edgecase which should be rare.
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

// Error handling support
#[derive(Debug)]
pub struct PathIssueIngestResult {
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
    /// Returns information indicating whether the active path was affected and the total number
    /// of paths affected.
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
                    // TODO: matches_path_checked can be used to optimize matching with e.g. a
                    // bloom filter
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

/// Handle to a managed set of paths for a specific src-dst pair.
#[derive(Clone)]
pub struct PathSetHandle {
    pub shared: Arc<PathSetSharedState>,
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

pub struct PathSetTask {
    pub _task: JoinHandle<()>,
    pub cancel_token: tokio_util::sync::CancellationToken,
}

impl Drop for PathSetTask {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::path::manager::tests::helpers::*;

    mod path_set {
        use super::*;
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
            // If the same path is not available, but active path is still valid, it should
            // remain active
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

            // If the next refetch time is later than next idle check, next tick should be set
            // to idle check
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

            // The Path Handle active_path() call should wait for ongoing update if no active
            // path is set
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
            // The Path Handle active_path() call should return the last fetch error if no
            // active path is set
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

            // The Path Handle active_path() call should return active path if set, even if
            // there is a fetch error
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

                // Add a scoring alternates between 0 and 1 to force equal ranking between
                // existing paths
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
}
