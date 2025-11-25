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
//! # Path manager
//!
//! A [PathManager] provides applications with SCION paths. The method
//! [PathManager::path_wait] is an async implementation that possibly awaits
//! asynchronous, external path requests before returning. The sync-equivalent
//! is [SyncPathManager::try_cached_path] which returns immediately in all
//! cases.
//!
//! The main implementation provided in this module is the [CachingPathManager]
//! which is an _active_ component: [CachingPathManager::start] will start an
//! asynchronous background task (via `tokio::spawn`) that fetches requested
//! paths using the provided [PathFetcher].
//!
//! Constraints on the used path, like e.g. not using certain ASes, or preferring paths with low
//! latency, can be expressed using [PathPolicies](crate::path::policy::PathPolicy) and
//! [PathRankings](crate::path::ranking::PathRanking).
//!
//! PathPolicies are used to filter out unwanted paths.
//! PathRankings are used to rank paths based on their characteristics.

use std::{borrow::Cow, cmp::Ordering, future::Future, io, sync::Arc, time::Duration};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use derive_more::Deref;
use endhost_api_client::client::EndhostApiClient;
use futures::{
    FutureExt,
    future::{self, BoxFuture},
};
use scc::{Guard, HashIndex, hash_index::Entry};
use scion_proto::{
    address::IsdAsn,
    path::{self, Path},
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument};

use crate::{
    path::{PathStrategy, types::PathManagerPath},
    types::ResFut,
};

/// Minimum time remaining before path expiry to trigger refetch
const PATH_EXPIRY_REFRESH_THRESHOLD: Duration = Duration::from_secs(60);
/// Interval after which to refetch paths unless they expire earlier
const PATH_REFETCH_INTERVAL: Duration = Duration::from_secs(60 * 30); // 30 minutes

/// Path fetch errors.
#[derive(Debug, Error)]
pub enum PathToError {
    /// Path fetch failed.
    #[error("path fetch failed: {0}")]
    FetchFailed(String),
    /// No path found.
    #[error("no path found")]
    NoPathFound,
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

impl From<PathToError> for PathWaitError {
    fn from(error: PathToError) -> Self {
        match error {
            PathToError::FetchFailed(msg) => PathWaitError::FetchFailed(msg),
            PathToError::NoPathFound => PathWaitError::NoPathFound,
        }
    }
}

/// Trait for active path management with async interface.
pub trait PathManager: SyncPathManager {
    /// Returns a path to the destination from the path cache or requests a new path from the SCION
    /// Control Plane.
    fn path_wait(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> impl ResFut<'_, Path<Bytes>, PathWaitError>;

    /// Returns a path to the destination from the path cache or requests a new path from the SCION
    /// Control Plane, with a maximum wait time.
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

/// Trait for active path management with sync interface. Implementors of this trait should be
/// able to be used in sync and async context. The functions must not block.
pub trait SyncPathManager {
    /// Add a path to the path cache. This can be used to register reverse paths.
    fn register_path(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>, path: Path<Bytes>);

    /// Returns a path to the destination from the path cache.
    /// If the path is not in the cache, it returns Ok(None)
    /// If the cache is locked an io error WouldBlock is returned.
    fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> io::Result<Option<Path<Bytes>>>;
}

/// Request for prefetching a path
#[derive(Debug, Clone)]
struct PrefetchRequest {
    pub src: IsdAsn,
    pub dst: IsdAsn,
    pub now: DateTime<Utc>,
}

/// Registration of a new path
#[derive(Debug, Clone)]
struct PathRegistration {
    pub src: IsdAsn,
    pub dst: IsdAsn,
    pub now: DateTime<Utc>,
    pub path: Path<Bytes>,
}

/// Cached path entry with metadata
#[derive(Debug, Clone)]
struct PathCacheEntry {
    path: PathManagerPath,
    #[expect(unused)]
    cached_at: DateTime<Utc>,
    refresh_at: DateTime<Utc>,
}

impl PathCacheEntry {
    fn new(
        path: PathManagerPath,
        now: DateTime<Utc>,
        refetch_interval: Duration,
        expiry_threshold: Duration,
    ) -> Self {
        let refresh_at = (now + refetch_interval).min(
            path.scion_path().expiry_time().unwrap_or_else(|| {
                tracing::warn!(
                    src = %path.scion_path().source(),
                    dst = %path.scion_path().destination(),
                    "Preferred path has no expiry time"
                );
                now + refetch_interval
            }) - expiry_threshold,
        );

        Self {
            path,
            cached_at: now,
            refresh_at,
        }
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.path
            .scion_path()
            .expiry_time()
            .map(|expiry| expiry < now)
            .unwrap_or(true)
    }

    fn expiry_state(&self, now: DateTime<Utc>) -> ExpiryState {
        if self.is_expired(now) {
            ExpiryState::Expired
        } else if now >= self.refresh_at {
            ExpiryState::NeedsRefresh
        } else {
            ExpiryState::Valid
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiryState {
    Expired,
    NeedsRefresh,
    Valid,
}

/// Active path manager that runs as a background task
pub struct CachingPathManager<F: PathFetcher = PathFetcherImpl> {
    /// Shared state between the manager and the background task
    state: CachingPathManagerState<F>,
    /// Channels for communicating with the background task
    prefetch_tx: mpsc::Sender<PrefetchRequest>,
    registration_tx: mpsc::Sender<PathRegistration>,
    /// Cancellation token for the background task
    cancellation_token: CancellationToken,
}

/// Path fetch errors.
#[derive(Debug, thiserror::Error)]
pub enum PathFetchError {
    /// Segment fetch failed.
    #[error("failed to fetch segments: {0}")]
    FetchSegments(#[from] SegmentFetchError),

    /// No paths found.
    #[error("no paths found")]
    NoPathsFound,

    /// Non network related internal error.
    #[error("internal error: {0}")]
    InternalError(Cow<'static, str>),
}

/// Path fetcher trait.
pub trait PathFetcher: Send + Sync + 'static {
    /// Fetch paths between source and destination ISD-AS.
    fn fetch_paths(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> impl ResFut<'_, Vec<path::Path>, PathFetchError>;
}

type BoxedPathLookupResult = BoxFuture<'static, Result<Path<Bytes>, PathWaitError>>;

struct CachingPathManagerStateInner<F: PathFetcher> {
    /// Policy for path selection
    selection: PathStrategy,
    /// Path fetcher for requesting new paths
    fetcher: F,
    /// Cache of paths indexed by (src, dst)
    path_cache: HashIndex<(IsdAsn, IsdAsn), PathCacheEntry>,
    /// In-flight path requests indexed by (src, dst)
    inflight: HashIndex<(IsdAsn, IsdAsn), future::Shared<BoxedPathLookupResult>>,
    /// Minimum time remaining before triggering path refresh
    refresh_threshold: Duration,
    /// Interval after which to refetch paths unless they expire earlier
    refetch_interval: Duration,
}

/// Shared state for the active path manager
#[derive(Deref)]
#[deref(forward)]
struct CachingPathManagerState<F: PathFetcher>(Arc<CachingPathManagerStateInner<F>>);

impl<F: PathFetcher> Clone for CachingPathManagerState<F> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<F: PathFetcher + Send + Sync + 'static> CachingPathManager<F> {
    /// Create and start an active path manager with automatic task management.
    /// The background task is spawned internally and will be cancelled when the manager is dropped.
    /// This is the recommended method for most users.
    pub fn start(path_strategy: PathStrategy, fetcher: F) -> Self {
        let cancellation_token = CancellationToken::new();
        let (manager, task_future) =
            Self::start_future(path_strategy, fetcher, cancellation_token.clone());

        // Spawn task internally, it is stopped when the manager is dropped.
        tokio::spawn(async move {
            task_future.await;
        });

        manager
    }

    /// Create the manager and task future.
    pub fn start_future(
        selection: PathStrategy,
        fetcher: F,
        cancellation_token: CancellationToken,
    ) -> (Self, impl std::future::Future<Output = ()>) {
        let (prefetch_tx, prefetch_rx) = mpsc::channel(1000);
        let (registration_tx, registration_rx) = mpsc::channel(1000);

        let state = CachingPathManagerState(Arc::new(CachingPathManagerStateInner {
            selection,
            fetcher,
            path_cache: HashIndex::new(),
            inflight: HashIndex::new(),
            refresh_threshold: PATH_EXPIRY_REFRESH_THRESHOLD,
            refetch_interval: PATH_REFETCH_INTERVAL,
        }));

        let manager = Self {
            state: state.clone(),
            prefetch_tx,
            registration_tx,
            cancellation_token: cancellation_token.clone(),
        };

        let task_future = async move {
            let task =
                PathManagerTask::new(state, prefetch_rx, registration_rx, cancellation_token);
            task.run().await
        };

        (manager, task_future)
    }

    /// Returns a cached path if it is not expired.
    pub fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> io::Result<Option<Path<Bytes>>> {
        Ok(self.state.try_cached_path(src, dst, now))
    }

    fn prefetch_path_internal(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>) {
        if let Err(e) = self.prefetch_tx.try_send(PrefetchRequest { src, dst, now }) {
            tracing::warn!(err=?e, "Prefetch path channel send failed");
        }
    }

    fn register_path_internal(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
        path: Path<Bytes>,
    ) {
        if let Err(e) = self.registration_tx.try_send(PathRegistration {
            src,
            dst,
            now,
            path,
        }) {
            tracing::warn!(err=?e, "Register path channel send failed");
        }
    }
}

impl<F: PathFetcher> Drop for CachingPathManager<F> {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}

impl<F: PathFetcher + Send + Sync + 'static> SyncPathManager for CachingPathManager<F> {
    fn register_path(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>, path: Path<Bytes>) {
        self.register_path_internal(src, dst, now, path);
    }

    /// Returns a cached path if it is not expired or prefetches it if it is not in the cache.
    /// If the path is not in the cache, it returns Ok(None).
    /// If the cache is locked an io error WouldBlock is returned.
    fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> io::Result<Option<Path<Bytes>>> {
        match self.state.try_cached_path(src, dst, now) {
            Some(path) => Ok(Some(path)),
            None => {
                // If the path is not found in the cache, we issue a prefetch request.
                self.prefetch_path_internal(src, dst, now);
                Ok(None)
            }
        }
    }
}

impl<F: PathFetcher + Send + Sync + 'static> PathManager for CachingPathManager<F> {
    fn path_wait(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> impl ResFut<'_, Path<Bytes>, PathWaitError> {
        async move {
            // First check if we have a cached path
            if let Some(cached) = self.state.try_cached_path(src, dst, now) {
                return Ok(cached);
            }

            // Fetch new path
            self.state
                .fetch_and_cache_path(src, dst, now, "path_wait")
                .await
        }
    }
}

/// Trait for prefetching paths in the path manager.
pub trait PathPrefetcher {
    /// Prefetch a paths for the given source and destination.
    fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn);
}

impl<F: PathFetcher + Send + Sync + 'static> PathPrefetcher for CachingPathManager<F> {
    fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn) {
        self.prefetch_path_internal(src, dst, Utc::now());
    }
}

impl<F: PathFetcher + Send + Sync + 'static> CachingPathManagerState<F> {
    /// Returns a cached path if it is not expired.
    ///
    /// If the path is expired or not found, returns None.
    ///
    /// Possibly initiates a refresh if the path requires it.
    fn try_cached_path(&self, src: IsdAsn, dst: IsdAsn, now: DateTime<Utc>) -> Option<Path<Bytes>> {
        let guard = Guard::new();
        match self.path_cache.peek(&(src, dst), &guard) {
            Some(cached) => {
                match cached.expiry_state(now) {
                    ExpiryState::Expired => {
                        tracing::debug!(
                            src = %src,
                            dst = %dst,
                            expiry = ?cached.path.scion_path().expiry_time(),
                            "Cached path expired"
                        );

                        drop(self.get_or_create_inflight_request(src, dst, now, "expired"));

                        None
                    }
                    ExpiryState::NeedsRefresh => {
                        drop(self.get_or_create_inflight_request(src, dst, now, "refresh"));

                        Some(cached.path.scion_path().clone())
                    }
                    ExpiryState::Valid => Some(cached.path.scion_path().clone()),
                }
            }
            None => None,
        }
    }

    /// Fetches a path, coalescing concurrent requests for the same source and destination.
    async fn fetch_and_cache_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<Path<Bytes>, PathWaitError> {
        self.get_or_create_inflight_request(src, dst, now, reason)
            .await
    }

    /// Ensure there is an in-flight request for the given source and destination.
    /// If there is already an in-flight request, it is returned.
    fn get_or_create_inflight_request(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
        reason: &str,
    ) -> future::Shared<BoxedPathLookupResult> {
        match self.inflight.entry_sync((src, dst)) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => {
                tracing::debug!(%src, %dst, %reason, "New path fetch initiated");
                let self_c = self.clone();
                entry.insert_entry(
                    async move {
                        let result = self_c.do_fetch_and_cache(src, dst, now).await;
                        self_c.inflight.remove_sync(&(src, dst));
                        result
                    }
                    .boxed()
                    .shared(),
                )
            }
        }
        .get()
        .clone()
    }

    /// Helper to do the actual fetching and caching of paths between source and destination.
    async fn do_fetch_and_cache(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: DateTime<Utc>,
    ) -> Result<Path<Bytes>, PathWaitError> {
        tracing::debug!(
            src = %src,
            dst = %dst,
            "Fetching paths"
        );

        let mut paths = self
            .fetcher
            .fetch_paths(src, dst)
            .await
            .map_err(|e| PathWaitError::FetchFailed(e.to_string()))?
            .into_iter()
            .map(|p| PathManagerPath::new(p, false))
            .collect::<Vec<_>>();

        let initial = paths.len();

        self.selection.filter_inplace(&mut paths);
        self.selection.rank_inplace(&mut paths);

        tracing::info!(
            src = %src,
            dst = %dst,
            n_initial = initial,
            n_ok = paths.len(),
            "Fetched and filtered paths",
        );

        let preferred_path = paths.into_iter().next().ok_or(PathWaitError::NoPathFound)?;

        let preferred_path_entry = PathCacheEntry::new(
            preferred_path.clone(),
            now,
            self.refetch_interval,
            self.refresh_threshold,
        );

        match self.path_cache.entry_sync((src, dst)) {
            Entry::Occupied(mut entry) => {
                entry.update(preferred_path_entry);
            }
            Entry::Vacant(entry) => {
                entry.insert_entry(preferred_path_entry);
            }
        }

        Ok(preferred_path.path)
    }

    /// Check if there is an in-flight request for the given source and destination.
    fn request_inflight(&self, src: IsdAsn, dst: IsdAsn) -> bool {
        let guard = Guard::new();
        self.inflight.peek(&(src, dst), &guard).is_some()
    }
}

/// Background task that handles prefetch requests and path registrations
struct PathManagerTask<F: PathFetcher> {
    state: CachingPathManagerState<F>,
    prefetch_rx: mpsc::Receiver<PrefetchRequest>,
    registration_rx: mpsc::Receiver<PathRegistration>,
    cancellation_token: CancellationToken,
}

impl<F: PathFetcher + Send + Sync + 'static> PathManagerTask<F> {
    fn new(
        state: CachingPathManagerState<F>,
        prefetch_rx: mpsc::Receiver<PrefetchRequest>,
        registration_rx: mpsc::Receiver<PathRegistration>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            state,
            prefetch_rx,
            registration_rx,
            cancellation_token,
        }
    }

    async fn run(mut self) {
        tracing::trace!("Starting active path manager task");

        loop {
            tokio::select! {
                // Handle cancellation with highest priority
                _ = self.cancellation_token.cancelled() => {
                    tracing::info!("Path manager task cancelled");
                    break;
                }

                // Handle path registrations (higher priority than prefetch)
                registration = self.registration_rx.recv() => {
                    match registration {
                        Some(reg) => {
                            self.handle_registration(reg).await;
                        }
                        None => {
                            tracing::info!("Registration channel closed");
                            break;
                        }
                    }
                }

                // Handle prefetch requests
                prefetch = self.prefetch_rx.recv() => {
                    match prefetch {
                        Some(req) => {
                            self.handle_prefetch(req).await;
                        }
                        None => {
                            tracing::info!("Prefetch channel closed");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!("Path manager task finished");
    }

    async fn handle_registration(&self, registration: PathRegistration) {
        tracing::trace!(
            src = %registration.src,
            dst = %registration.dst,
            "Handling path registration"
        );

        let new_path = PathManagerPath::new(registration.path, true);

        // Check if the path is accepted by the policy
        if !self.state.selection.predicate(&new_path) {
            tracing::trace!(
                src = %registration.src,
                dst = %registration.dst,
                "Registered path rejected by policy"
            );
            return;
        }

        // See if we already have a cached path
        let entry = self
            .state
            .path_cache
            .entry_sync((registration.src, registration.dst));

        match entry {
            Entry::Occupied(mut entry) => {
                // Update the cached path if the cached path is expired or the new path is preferred
                if entry.is_expired(registration.now)
                    // or if the new path is preferred (Ordering::Less means new_path is preferred)
                    || self.state.selection.rank_order(&new_path, &entry.path) == Ordering::Less
                {
                    tracing::info!(
                        src = %registration.src,
                        dst = %registration.dst,
                        "Updating active path"
                    );
                    entry.update(PathCacheEntry::new(
                        new_path,
                        registration.now,
                        self.state.refetch_interval,
                        self.state.refresh_threshold,
                    ));
                }
            }
            Entry::Vacant(entry) => {
                entry.insert_entry(PathCacheEntry::new(
                    new_path,
                    registration.now,
                    self.state.refetch_interval,
                    self.state.refresh_threshold,
                ));
            }
        }
    }

    /// Handle a prefetch request by checking the cache and fetching the path if necessary.
    /// If the path is already cached or there is an in-flight request, it skips fetching.
    /// Otherwise, it fetches the path and caches it.
    #[instrument(name = "prefetch", fields(src = %request.src, dst = %request.dst), skip_all)]
    async fn handle_prefetch(&self, request: PrefetchRequest) {
        tracing::debug!("Handling prefetch request");

        let mut reason = "prefetch";
        // Check if we already have a valid cached path
        {
            let guard = Guard::new();
            let cached = self
                .state
                .path_cache
                .peek(&(request.src, request.dst), &guard);

            if let Some(cached) = cached {
                match cached.expiry_state(request.now) {
                    ExpiryState::Valid => {
                        tracing::debug!("Path already cached and valid, skipping prefetch");
                        return;
                    }
                    ExpiryState::NeedsRefresh => {
                        reason = "refresh";
                        tracing::debug!("Path needs refresh, ensuring refresh");
                    }
                    ExpiryState::Expired => {
                        reason = "expired";
                        tracing::debug!("Path expired, proceeding to prefetch");
                    }
                }
            }
        }
        // Check if there is an in-flight request for the same source and destination
        if self.state.request_inflight(request.src, request.dst) {
            tracing::debug!("Path request already in flight, skipping prefetch");
            return;
        }

        // Perform the actual fetching and caching of the path. It might be that in the mean time
        // another request for the same path has been made, but in that case the path will be cached
        // by the other request or the prefetch will be coalesced with it.
        match self
            .state
            .fetch_and_cache_path(request.src, request.dst, request.now, reason)
            .await
        {
            Ok(_) => {
                tracing::debug!("Successfully prefetched path");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to prefetch path"
                );
            }
        }
    }
}

/// Segment fetch error.
pub type SegmentFetchError = Box<dyn std::error::Error + Send + Sync>;

/// Path segments.
pub struct Segments {
    /// Core segments.
    pub core_segments: Vec<path::PathSegment>,
    /// Non-core segments.
    pub non_core_segments: Vec<path::PathSegment>,
}

/// Segment fetcher trait.
pub trait SegmentFetcher: Send + Sync + 'static {
    /// Fetch path segments between src and dst.
    fn fetch_segments<'a>(
        &'a self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> impl Future<Output = Result<Segments, SegmentFetchError>> + Send + 'a;
}

/// Connect RPC segment fetcher.
pub struct ConnectRpcSegmentFetcher {
    client: Arc<dyn EndhostApiClient>,
}

impl ConnectRpcSegmentFetcher {
    /// Creates a new connect RPC segment fetcher.
    pub fn new(client: Arc<dyn EndhostApiClient>) -> Self {
        Self { client }
    }
}

impl SegmentFetcher for ConnectRpcSegmentFetcher {
    async fn fetch_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<Segments, SegmentFetchError> {
        let resp = self
            .client
            .list_segments(src, dst, 128, "".to_string())
            .await?;

        tracing::debug!(
            n_core=resp.core_segments.len(),
            n_up=resp.up_segments.len(),
            n_down=resp.down_segments.len(),
            src = %src,
            dst = %dst,
            "Received segments from control plane"
        );

        let (core_segments, non_core_segments) = resp.split_parts();
        Ok(Segments {
            core_segments,
            non_core_segments,
        })
    }
}

/// Path fetcher.
pub struct PathFetcherImpl<F: SegmentFetcher = ConnectRpcSegmentFetcher> {
    segment_fetcher: F,
}

impl<F: SegmentFetcher> PathFetcherImpl<F> {
    /// Creates a new path fetcher.
    pub fn new(segment_fetcher: F) -> Self {
        Self { segment_fetcher }
    }
}

impl<L: SegmentFetcher> PathFetcher for PathFetcherImpl<L> {
    async fn fetch_paths(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<Vec<path::Path>, PathFetchError> {
        let Segments {
            core_segments,
            non_core_segments,
        } = self.segment_fetcher.fetch_segments(src, dst).await?;

        tracing::trace!(
            n_core_segments = core_segments.len(),
            n_non_core_segments = non_core_segments.len(),
            src = %src,
            dst = %dst,
            "Fetched segments"
        );

        let paths = path::combinator::combine(src, dst, core_segments, non_core_segments);
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use bytes::{BufMut, BytesMut};
    use scion_proto::{
        address::IsdAsn,
        packet::ByEndpoint,
        path::{self, DataPlanePath, EncodedStandardPath, Path},
        wire_encoding::WireDecode,
    };
    use tokio::{sync::Barrier, task::yield_now};

    use super::*;
    use crate::path::ranking::Shortest;

    type PathMap = HashMap<(IsdAsn, IsdAsn), Result<Vec<Path>, PathFetchError>>;
    #[derive(Default)]
    struct MockPathFetcher {
        paths: Mutex<PathMap>,
        call_count: AtomicUsize,
        call_delay: Option<usize>,
        barrier: Option<Arc<Barrier>>,
    }

    impl MockPathFetcher {
        fn with_path(src: IsdAsn, dst: IsdAsn, path: Path) -> Self {
            let mut paths = HashMap::new();
            paths.insert((src, dst), Ok(vec![path]));
            Self {
                paths: Mutex::new(paths),
                call_count: AtomicUsize::new(0),
                call_delay: None,
                barrier: None,
            }
        }

        fn with_error(src: IsdAsn, dst: IsdAsn, error: &'static str) -> Self {
            let mut paths = HashMap::new();
            paths.insert((src, dst), Err(PathFetchError::FetchSegments(error.into())));
            Self {
                paths: Mutex::new(paths),
                call_count: AtomicUsize::new(0),
                call_delay: None,
                barrier: None,
            }
        }

        fn with_barrier(mut self, barrier: Arc<Barrier>) -> Self {
            self.barrier = Some(barrier);
            self
        }
    }

    impl PathFetcher for MockPathFetcher {
        fn fetch_paths(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
        ) -> impl ResFut<'_, Vec<path::Path>, PathFetchError> {
            async move {
                self.call_count.fetch_add(1, Ordering::Relaxed);
                if let Some(delay) = self.call_delay {
                    while self.call_count.load(Ordering::SeqCst) < delay {
                        yield_now().await;
                    }
                }
                if let Some(barrier) = &self.barrier {
                    barrier.wait().await;
                }
                match self.paths.lock().unwrap().get(&(src, dst)) {
                    Some(Ok(paths)) => Ok(paths.clone()),
                    None => Ok(vec![]),
                    Some(Err(_)) => Err(PathFetchError::FetchSegments("other error".into())),
                }
            }
        }
    }

    fn test_path(src: IsdAsn, dst: IsdAsn) -> Path {
        let mut path_raw = BytesMut::with_capacity(36);
        path_raw.put_u32(0x0000_2000);
        path_raw.put_slice(&[0_u8; 32]);
        let dp_path =
            DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap());

        Path::new(
            dp_path,
            ByEndpoint {
                source: src,
                destination: dst,
            },
            None,
        )
    }

    fn setup_pm(fetcher: MockPathFetcher) -> CachingPathManagerState<MockPathFetcher> {
        CachingPathManagerState(Arc::new(CachingPathManagerStateInner {
            fetcher,
            path_cache: HashIndex::new(),
            inflight: HashIndex::new(),
            selection: PathStrategy {
                policies: vec![],
                ranking: vec![Arc::new(Shortest)],
            },
            refresh_threshold: PATH_EXPIRY_REFRESH_THRESHOLD,
            refetch_interval: PATH_REFETCH_INTERVAL,
        }))
    }

    #[tokio::test]
    async fn fetch_and_cache_path_single_request_success() {
        let src = IsdAsn(0x1_ff00_0000_0110);
        let dst = IsdAsn(0x1_ff00_0000_0111);
        let path = test_path(src, dst);
        let fetcher = MockPathFetcher::with_path(src, dst, path.clone());
        let state = setup_pm(fetcher);

        let result = state
            .fetch_and_cache_path(src, dst, Utc::now(), "test")
            .await;

        assert!(
            result.is_ok(),
            "fetch_and_cache_path() returned Err. path fetch should succeed"
        );
        assert_eq!(
            state.fetcher.call_count.load(Ordering::SeqCst),
            1,
            "path fetcher should be called exactly once"
        );
        let guard = Guard::new();
        assert!(
            state.path_cache.peek(&(src, dst), &guard).is_some(),
            "peek() on path_cache returned None. fetched path should be cached"
        );
        assert!(
            state.inflight.peek(&(src, dst), &guard).is_none(),
            "peek() on inflight returned Some. no in-flight request should remain after completion"
        );
    }

    #[tokio::test]
    async fn fetch_and_cache_path_concurrent_requests_coalesced() {
        let src = IsdAsn(0x1_ff00_0000_0110);
        let dst = IsdAsn(0x1_ff00_0000_0111);
        let path = test_path(src, dst);
        let barrier = Arc::new(Barrier::new(2));
        let fetcher =
            MockPathFetcher::with_path(src, dst, path.clone()).with_barrier(barrier.clone());
        let state = setup_pm(fetcher);

        let state_clone = state.clone();
        let task1 = tokio::spawn(async move {
            state_clone
                .fetch_and_cache_path(src, dst, Utc::now(), "test")
                .await
        });
        // Wait for the first task to start the fetch operation.
        while state.fetcher.call_count.load(Ordering::SeqCst) < 1 {
            yield_now().await;
        }

        let state_clone2 = state.clone();
        let task2 = tokio::spawn(async move {
            state_clone2
                .fetch_and_cache_path(src, dst, Utc::now(), "test")
                .await
        });

        // Unblock the fetcher
        barrier.wait().await;

        let (res1, res2) = future::join(task1, task2).await;

        assert_eq!(
            state.fetcher.call_count.load(Ordering::SeqCst),
            1,
            "Path fetcher should be called only once despite concurrent requests"
        );
        res1.unwrap().unwrap();
        res2.unwrap().unwrap();
        let guard = Guard::new();
        assert!(
            state.inflight.peek(&(src, dst), &guard).is_none(),
            "peek() on inflight returned Some. no in-flight request should remain after concurrent requests complete"
        );
    }

    #[tokio::test]
    async fn fetch_and_cache_path_fetch_error() {
        let src = IsdAsn(0x1_ff00_0000_0110);
        let dst = IsdAsn(0x1_ff00_0000_0111);
        let fetcher = MockPathFetcher::with_error(src, dst, "error");
        let state = setup_pm(fetcher);

        let result = state
            .fetch_and_cache_path(src, dst, Utc::now(), "test")
            .await;

        assert!(matches!(result, Err(PathWaitError::FetchFailed(_))));
        assert_eq!(state.fetcher.call_count.load(Ordering::SeqCst), 1);
        let guard = Guard::new();
        assert!(state.path_cache.peek(&(src, dst), &guard).is_none());
        assert!(state.inflight.peek(&(src, dst), &guard).is_none());
    }

    #[tokio::test]
    async fn fetch_and_cache_path_no_path_found() {
        let src = IsdAsn(0x1_ff00_0000_0110);
        let dst = IsdAsn(0x1_ff00_0000_0111);
        let fetcher = MockPathFetcher::default();
        let state = setup_pm(fetcher);

        let result = state
            .fetch_and_cache_path(src, dst, Utc::now(), "test")
            .await;

        assert!(matches!(result, Err(PathWaitError::NoPathFound)));
        assert_eq!(state.fetcher.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_and_cache_path_concurrent_requests_different_keys() {
        let src1 = IsdAsn(0x1_ff00_0000_0110);
        let dst1 = IsdAsn(0x1_ff00_0000_0111);
        let src2 = IsdAsn(0x1_ff00_0000_0120);
        let dst2 = IsdAsn(0x1_ff00_0000_0121);
        let path1 = test_path(src1, dst1);
        let path2 = test_path(src2, dst2);

        let mut paths = HashMap::new();
        paths.insert((src1, dst1), Ok(vec![path1.clone()]));
        paths.insert((src2, dst2), Ok(vec![path2.clone()]));

        let barrier = Arc::new(Barrier::new(3));

        let fetcher = MockPathFetcher {
            paths: Mutex::new(paths),
            ..Default::default()
        }
        .with_barrier(barrier.clone());
        let state = setup_pm(fetcher);

        let state_clone1 = state.clone();
        let task1 = tokio::spawn(async move {
            state_clone1
                .fetch_and_cache_path(src1, dst1, Utc::now(), "test")
                .await
        });

        let state_clone2 = state.clone();
        let task2 = tokio::spawn(async move {
            state_clone2
                .fetch_and_cache_path(src2, dst2, Utc::now(), "test")
                .await
        });

        // Unblock the fetcher
        barrier.wait().await;

        let (res1, res2) = future::join(task1, task2).await;

        assert_eq!(state.fetcher.call_count.load(Ordering::SeqCst), 2);
        let got1 = res1.unwrap().unwrap();
        let got2 = res2.unwrap().unwrap();
        assert_eq!(got1.source(), path1.source());
        assert_eq!(got1.destination(), path1.destination());
        assert_eq!(got2.source(), path2.source());
        assert_eq!(got2.destination(), path2.destination());
    }
}
