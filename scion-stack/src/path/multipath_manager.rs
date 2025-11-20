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
    collections::HashMap,
    hash::RandomState,
    ops::Deref,
    sync::{Arc, Weak, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwapOption;
use scc::HashIndex;
use scion_proto::{
    address::IsdAsn,
    path::{Path, PathFingerprint},
};
use scion_sdk_utils::backoff::{BackoffConfig, ExponentialBackoff};
use tokio::{select, task::JoinHandle};
use tracing::{Instrument, instrument, span};

use crate::path::{
    PathStrategy,
    manager::{PathFetchError, PathFetcher, PathManager, SyncPathManager},
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
    managed_paths: HashIndex<(IsdAsn, IsdAsn), PathSetHandle<F>>,
}

impl<F: PathFetcher> MultiPathManager<F> {
    /// Creates a new [`MultiPathManager`].
    pub fn new(
        config: MultiPathManagerConfig,
        fetcher: F,
        path_strategy: PathStrategy,
    ) -> Result<Self, &'static str> {
        config.validate()?;

        Ok(MultiPathManager(Arc::new(MultiPathManagerInner {
            config,
            fetcher,
            path_strategy,
            managed_paths: HashIndex::new(),
        })))
    }

    /// Tries to get the active path for the given src-dst pair.
    ///
    /// If no active path is set, returns None.
    ///
    /// If the src-dst pair is not yet managed, starts managing it.
    pub fn try_get_path(&self, src: IsdAsn, dst: IsdAsn, now: SystemTime) -> Option<Path> {
        let guard = scc::Guard::new();

        // Active path should never be expired
        match self
            .0
            .managed_paths
            .peek(&(src, dst), &guard)?
            .try_active_path()
            .as_ref()
        {
            Some(active) => {
                // XXX(ake): Since the Paths are actively managed, they should never be expired
                // here.
                let expired = active.0.is_expired(now.into()).unwrap_or(true);
                debug_assert!(!expired, "Returned expired path from try_get_path");

                Some(active.0.clone())
            }
            None => {
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
    /// If no paths are available, either because of failure or non-existence, returns None.
    pub async fn get_path(&self, src: IsdAsn, dst: IsdAsn, now: SystemTime) -> Option<Path> {
        // Get currently active path
        if let Some(path) = self.try_get_path(src, dst, now) {
            return Some(path);
        }

        // Ensure the src-dst pair is managed and await active path
        let managed = self.ensure_managed_paths(src, dst);

        // Await path update if necessary

        let span = span!(tracing::Level::DEBUG, "get_path", %src, %dst);
        managed.maybe_await_path_update(now).instrument(span).await;

        // Get active path again
        let active = managed.try_active_path().as_ref().map(|p| p.0.clone())?;

        let expired = active.is_expired(now.into()).unwrap_or(true);
        debug_assert!(!expired, "Returned expired path from get_path");

        Some(active)
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
    fn ensure_managed_paths(&self, src: IsdAsn, dst: IsdAsn) -> Arc<PathSet<F>> {
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
                );

                vacant.insert_entry(managed.manage())
            }
        };

        entry.get().handle.clone()
    }

    /// Stops managing paths for the given src-dst pair.
    pub fn stop_managing_paths(&self, src: IsdAsn, dst: IsdAsn) {
        if self.0.managed_paths.remove_sync(&(src, dst)) {
            tracing::info!(%src, %dst, "Stopped managing paths for src-dst pair");
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
        Ok(self.try_get_path(src, dst, now.into()))
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
            self.get_path(src, dst, now.into())
                .await
                .ok_or(super::manager::PathWaitError::NoPathFound)
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

/// Handle to a managed set of paths for a specific src-dst pair.
struct PathSetHandle<F: PathFetcher> {
    handle: Arc<PathSet<F>>,
    _task: JoinHandle<()>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl<F: PathFetcher> Drop for PathSetHandle<F> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<F: PathFetcher> Deref for PathSetHandle<F> {
    type Target = PathSet<F>;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

/// Entry in the path set cache.
struct PathSetEntry {
    path: Path,
    fingerprint: PathFingerprint,
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

    // Fast Access
    /// Currently active path
    active_path: ArcSwapOption<(Path, PathFingerprint)>,
    /// Fast path usage tracker
    was_used_in_idle_period: AtomicBool,

    /// Internal state
    state: tokio::sync::Mutex<PathSetState>,
}

/// Internal state of the managed path set.
struct PathSetState {
    /// Cached paths
    cached_paths: Vec<PathSetEntry>,
    /// Last time paths were refetched
    last_refetch: SystemTime,
    /// Last error encountered during path fetch
    last_error: Option<PathFetchError>,
    /// Number of consecutive failed fetch attempts
    failed_attempts: u32,
    /// Next time to refetch paths
    next_refetch: SystemTime,
    /// Next time to check for idleness
    next_idle_check: SystemTime,
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
    ) -> Self {
        PathSet {
            src,
            dst,
            manager,
            refetch_interval,
            min_refetch_delay,
            backoff: ExponentialBackoff::new_from_config(backoff),
            min_expiry_threshold,
            max_idle_period,
            state: tokio::sync::Mutex::new(PathSetState {
                cached_paths: Vec::new(),
                last_refetch: SystemTime::UNIX_EPOCH,
                last_error: None,
                failed_attempts: 0,
                next_refetch: SystemTime::now(),
                next_idle_check: SystemTime::now() + max_idle_period,
            }),
            active_path: ArcSwapOption::from(None),
            was_used_in_idle_period: AtomicBool::new(true),
        }
    }

    /// Tries to get the currently active path without refetching.
    pub fn try_active_path(
        &self,
    ) -> arc_swap::Guard<Option<Arc<(scion_proto::path::Path, PathFingerprint)>>> {
        self.was_used_in_idle_period
            .store(true, std::sync::atomic::Ordering::Relaxed);

        self.active_path.load()
    }
}
// Management task
impl<F: PathFetcher> PathSet<F> {
    #[instrument(name = "path-set", skip(self), fields(src= ?self.src, dst= ?self.dst))]
    fn manage(self) -> PathSetHandle<F> {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let this = Arc::new(self);

        let task = {
            let this = this.clone();
            let cancel_token = cancel_token.clone();

            async move {
                // Update the managed path tuple on start
                this.maybe_refetch_and_update(SystemTime::now()).await;

                loop {
                    let now = SystemTime::now();
                    tracing::trace!("Managed paths task tick");

                    let (next_refetch, next_idle_check) = {
                        let guard = this.state.lock().await;
                        (guard.next_refetch, guard.next_idle_check)
                    };
                    // Determine the next fetch timeout
                    let next_fetch_timeout = next_refetch
                        .duration_since(now)
                        .unwrap_or_else(|_| Duration::from_secs(0)); // If time is in the past, fetch immediately

                    let next_idle_timeout = next_idle_check
                        .duration_since(now)
                        .unwrap_or_else(|_| Duration::from_secs(0)); // If time is in the past, check immediately

                    select! {
                        // Next fetch timeout
                        _ = tokio::time::sleep(next_fetch_timeout) => {
                            this.maybe_refetch_and_update(now).await;
                        }
                        // Idle timeout
                        _ = tokio::time::sleep(next_idle_timeout) => {
                            if this.idle_check(now).await {
                                if let Some(mgr) = this.manager.get() {
                                    mgr.stop_managing_paths(this.src, this.dst);
                                }
                                break;
                            }
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

        PathSetHandle {
            handle: this,
            _task: tokio::spawn(task.in_current_span()),
            cancel_token,
        }
    }
}
// Internal management
impl<F: PathFetcher> PathSet<F> {
    /// If no active path is set, ensures that paths are up to date and waits for the update to
    /// complete.
    async fn maybe_await_path_update(&self, now: SystemTime) {
        if self.active_path.load().is_some() {
            // Active path is already set, no need to await update
            return;
        }

        self.maybe_refetch_and_update(now).await;
    }

    /// Conditionally refetches paths and updates the cache
    ///
    /// If currently fetching, waits for the fetch to complete
    async fn maybe_refetch_and_update(&self, now: SystemTime) {
        // Acquire lock and check if refetch is needed
        // Since a running refetch holds the lock, this also ensures we wait for ongoing refetches
        let mut guard = self.state.lock().await;

        // No refetch if minimum delay has not passed
        if guard.last_refetch + self.min_refetch_delay > now {
            tracing::trace!(last_fetch = ?guard.last_refetch, now = ?now, "Skipping path refetch, refetch delay not passed");
            return;
        }

        // Proceed with refetch
        self.locked_refetch_and_update(&mut guard, now).await
    }

    /// Checks if the path tuple is idle and should be removed.
    async fn idle_check(&self, now: SystemTime) -> bool {
        let mut guard = self.state.lock().await;

        // Was called before idle timeout, do nothing
        if now < guard.next_idle_check {
            return false;
        }

        let was_used = self
            .was_used_in_idle_period
            .load(std::sync::atomic::Ordering::Relaxed);

        if was_used {
            // Reset usage flag and last idle check time
            self.was_used_in_idle_period
                .store(false, std::sync::atomic::Ordering::Relaxed);
            guard.next_idle_check = now + self.max_idle_period;
            false
        } else {
            // Path tuple is idle, remove it
            let unused_since = guard.next_idle_check - self.max_idle_period;
            tracing::info!(?unused_since, "Path tuple is idle, removing");
            true
        }
    }
}
// Internal support functions
impl<F: PathFetcher> PathSet<F> {
    /// Refetches paths and updates the cache
    async fn locked_refetch_and_update(&self, state: &mut PathSetState, now: SystemTime) {
        tracing::debug!("Refetching paths for src-dst pair");

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

        match path_fetch.await {
            // Successful fetch and ingestion, at least one path available
            Ok(fetched_paths) => {
                debug_assert!(
                    !fetched_paths.is_empty(),
                    "Must have at least one path after successful fetch and filter"
                );

                self.locked_update_path_cache(state, fetched_paths, now);
                let earliest_expiry = self
                    .locked_earliest_expiry(state)
                    .expect("should have a path available, as new paths were ingested");

                // Reset error state
                state.last_error = None;
                state.failed_attempts = 0;
                // Update next refetch time
                state.next_refetch =
                    // Either after refetch interval, or before earliest expiry
                    (now + self.refetch_interval).min(earliest_expiry - self.min_expiry_threshold)
                    // But at least after min refetch delay
                    .max(now + self.min_refetch_delay);
            }
            // Failed to fetch, might have no paths available
            Err(e) => {
                // Maintain path cache with no new paths
                self.locked_update_path_cache(state, vec![], now);

                state.failed_attempts += 1;
                // Schedule next refetch after a delay
                state.next_refetch = now
                    + self
                        .backoff
                        .duration(state.failed_attempts)
                        .max(self.min_refetch_delay);

                tracing::error!(
                    attempt = state.failed_attempts,
                    next_try = ?state.next_refetch,
                    error = %e,
                    "Failed to fetch new paths"
                );

                state.last_error = Some(e);
            }
        }

        // Always update ranking, and possibly active path
        self.locked_rerank(state);
        self.locked_maybe_update_active_path(state, now);
        tracing::debug!("Completed path refetch and update");
    }

    /// Returns the earliest expiry time among the cached paths.
    fn locked_earliest_expiry(&self, state: &PathSetState) -> Option<SystemTime> {
        state
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
    fn locked_update_path_cache(
        &self,
        state: &mut PathSetState,
        new_paths: Vec<Path>,
        now: SystemTime,
    ) {
        // TODO: Currently caches every path, should Reduce paths to max cached paths per pair
        // But this requires another path ranking, possibly focussed on diversity

        let mut new_paths: HashMap<PathFingerprint, Path, RandomState> =
            HashMap::from_iter(new_paths.into_iter().map(|path| {
                let fingerprint = path.fingerprint().unwrap();
                (fingerprint, path)
            }));

        let active_path_fp = self.active_path.load().as_ref().map(|p| p.1);

        // Update cached paths
        state.cached_paths.retain_mut(|cached_path| {
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
                        self.active_path
                            .store(Some(Arc::new((cached_path.path.clone(), fp))));
                    }
                    false => {
                        tracing::info!(
                            ?active_path_fp,
                            "Active path is expired, clearing active path"
                        );
                        self.active_path.store(None);
                    }
                }
            };

            keep
        });

        // Insert and update new paths
        for (new_fp, new_path) in new_paths {
            state.cached_paths.push(PathSetEntry {
                fingerprint: new_fp,
                path: new_path,
            });
        }
    }

    // Applies path ranking and selects active path if necessary.
    fn locked_rerank(&self, _state: &mut PathSetState) {
        // Rank paths
        // TODO: For ranking, path_strategy type needs to be changed
    }

    /// Updates the active path if required
    fn locked_maybe_update_active_path(&self, state: &mut PathSetState, now: SystemTime) {
        /// Decision on active path update, including reason
        enum Decision {
            /// No change needed
            NoChange,
            /// Active path should be replaced if a better path is available
            Replace(&'static str),
            /// Active path must be removed, even if no better path is available
            ForceReplace(&'static str),
        }

        let active_path_guard = self.active_path.load();
        let active_path = active_path_guard.as_ref();
        let best_path = self.locked_best_path(state, now);

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
                self.active_path.store(None);
            }
            // We have a reason and a better path
            (Decision::ForceReplace(reason) | Decision::Replace(reason), Some(best_path)) => {
                let active_detail = active_path
                    .map(|p| p.0.to_string())
                    .unwrap_or_else(|| "None".into());

                tracing::info!(%active_fp, best_fp=?best_path.fingerprint, %reason, "Replacing active path");
                tracing::debug!("Old active path: {}", active_detail);
                tracing::debug!("New active path: {}", best_path.path);

                self.active_path.store(Some(Arc::new((
                    best_path.path.clone(),
                    best_path.fingerprint,
                ))));
            }
        }
    }

    /// Selects the best path from the cached paths
    fn locked_best_path<'a>(
        &self,
        state: &'a mut PathSetState,
        now: SystemTime,
    ) -> Option<&'a PathSetEntry> {
        let path_iter = state.cached_paths.iter();

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
