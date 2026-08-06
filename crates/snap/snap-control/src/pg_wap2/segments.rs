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

//! Segment management.
//!
//! [`SegmentManager`] keeps the public segments of every (src, dst) pair that is in use available
//! and fresh, and evicts the pairs that stop being used.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use endhost_api_models::SegmentsDiscovery;
use scc::hash_map::OccupiedEntry;
use sciparse::{
    identifier::isd_asn::IsdAsn,
    segment::{SegmentFp, Segments, SignedPathSegment},
};

/// Number of segments to request per segment fetch.
const SEGMENT_FETCH_PAGE_SIZE: i32 = 250;

// Note: This can be improved a lot, instead of storing all segments per src, dst, we can split
// up CORE and NON_CORE segments, and manage them separately. This would deduplicate
// segments, and allow us to do smaller more precise fetches.

/// Keeps the public segments of every (src, dst) pair that is in use available and fresh.
///
/// A pair starts being managed the first time it is asked for, is refetched before its
/// segments expire, and is evicted once it has not been used for `idle_eviction_time`.
///
/// A consumer that keeps using a pair longer than `idle_eviction_time` must hold a
/// [`PairGuard`] from [`Self::hold_pair`] on it, which exempts it from eviction.
///
/// Cheap to clone; all clones share the same state.
#[derive(Clone)]
pub struct SegmentManager(Arc<SegmentManagerInner>);

/// The state shared by all clones of a [`SegmentManager`].
struct SegmentManagerInner {
    segments: scc::HashMap<(IsdAsn, IsdAsn), SegmentStore>,

    segment_fetcher: Box<dyn SegmentsDiscovery>,

    /// The minimum duration between two fetches of segments for the same (src, dst) pair.
    minimum_segment_fetch_interval: Duration,
    /// The maximum duration between two fetches of segments for the same (src, dst) pair.
    maximum_segment_fetch_interval: Duration,
    /// The duration after which an unused (src, dst) pair is removed from the store.
    idle_eviction_time: Duration,
    /// Minimum duration a segment must have left to be kept in the store.
    min_segment_lifetime: Duration,
    /// The duration before the segments expiry is reached to start fetching new segments.
    segment_lifetime_buffer: Duration,
}

impl SegmentManager {
    /// Creates a new, empty segment manager.
    pub fn new(
        maximum_segment_fetch_interval: Duration,
        minimum_segment_fetch_interval: Duration,
        idle_eviction_time: Duration,
        min_segment_lifetime: Duration,
        segment_lifetime_buffer: Duration,
        segment_fetcher: Box<dyn SegmentsDiscovery>,
    ) -> Self {
        Self(Arc::new(SegmentManagerInner {
            segments: scc::HashMap::new(),
            segment_fetcher,
            minimum_segment_fetch_interval,
            maximum_segment_fetch_interval,
            idle_eviction_time,
            min_segment_lifetime,
            segment_lifetime_buffer,
        }))
    }

    /// Returns the segment with the given fingerprint, if it is in the store.
    ///
    /// Counts as a use of the segment's (src, dst) pair.
    pub async fn segment(&self, id: SegmentStoreId, now: SystemTime) -> Option<SignedPathSegment> {
        let store = self.0.segments.get_async(&(id.src(), id.dst())).await?;
        store.get().touch(now);

        let segments = match id {
            SegmentStoreId::Core { .. } => &store.get().core_segments,
            SegmentStoreId::NonCore { .. } => &store.get().non_core_segments,
        };

        segments
            .get(&id.fp())
            .map(|segment_entry| segment_entry.segment.clone())
    }

    /// Keeps the given (src, dst) pair managed for as long as the returned guard is held,
    /// fetching its segments if it is not managed yet.
    ///
    /// A guarded pair is exempt from idle eviction, so a long lived consumer cannot have the
    /// segments it depends on evicted out from under it. Refreshing is unaffected: a guarded
    /// pair keeps being refetched as its segments approach expiry.
    pub async fn hold_pair(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: SystemTime,
    ) -> anyhow::Result<PairGuard> {
        let store = self.ensure_managed(src, dst, now).await?;
        let ref_count = store.get().acquire();

        tracing::trace!(%src, %dst, "Holding a pair against eviction");

        Ok(PairGuard {
            ref_count,
            src,
            dst,
        })
    }

    /// Returns a [`SegmentsIter`] for the given (src, dst) pair, fetching segments if
    /// necessary.
    ///
    /// Allows iterating over all core and non-core segments for the given (src, dst) pair.
    pub async fn segments<'this>(
        &'this self,
        src: IsdAsn,
        dst: IsdAsn,
        now: SystemTime,
    ) -> anyhow::Result<SegmentsIter<'this>> {
        let store = self.ensure_managed(src, dst, now).await?;
        store.get().touch(now);

        Ok(SegmentsIter { store })
    }

    /// Runs the maintenance loop for the segment manager, which periodically evicts unused
    /// (src, dst) pairs and refetches the ones that are due for a refresh.
    ///
    /// Reads the wall clock itself, unlike every other entry point. Never returns.
    pub async fn run(&self) {
        loop {
            let now = SystemTime::now();
            let next = self.maintain(now).await;
            let duration = next.duration_since(now).unwrap_or(Duration::ZERO);
            tracing::trace!("Next segment manager maintenance in {:?}", duration);
            tokio::time::sleep(duration).await;
        }
    }

    /// Ensures that the segment store for the given (src, dst) pair is managed, fetching
    /// segments if necessary.
    async fn ensure_managed(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: SystemTime,
    ) -> anyhow::Result<OccupiedEntry<'_, (IsdAsn, IsdAsn), SegmentStore>> {
        // Try to get the store for the (src, dst) pair. If it exists, touch it and return it.
        if let Some(entry) = self.0.segments.get_async(&(src, dst)).await {
            entry.get().touch(now);
            return Ok(entry);
        }

        // Otherwise, fetch the segments for the (src, dst) pair and create a new store.
        tracing::info!(%src, %dst, "Fetching segments for a new (src, dst) pair");

        // XXX: This is racy, multiple callers can fetch the same (src, dst) pair concurrently. We
        // could add a fetch-in-progress lock to avoid this. ATM we just throw out extra fetches.
        // TODO: Paging is not supported yet.
        let fetched = self
            .0
            .segment_fetcher
            .list_segments(src, dst, SEGMENT_FETCH_PAGE_SIZE, String::new())
            .await
            .with_context(|| format!("Failed to fetch segments for ({src}, {dst})"))?;

        // Prepare the store for the (src, dst) pair with the fetched segments.
        let mut store = SegmentStore::new((src, dst), now);
        store.update_segments(
            fetched.segments,
            now,
            self.0.minimum_segment_fetch_interval,
            self.0.maximum_segment_fetch_interval,
            self.0.min_segment_lifetime,
            self.0.segment_lifetime_buffer,
        );

        match self.0.segments.entry_async((src, dst)).await {
            // Someone else already created a store for the (src, dst) pair, return it and discard
            // the one we just created.
            scc::hash_map::Entry::Occupied(occupied_entry) => Ok(occupied_entry),
            // No entry exists for the (src, dst) pair, fetch segments and create a new store.
            scc::hash_map::Entry::Vacant(vacant_entry) => Ok(vacant_entry.insert_entry(store)),
        }
    }

    /// Maintains the segment store by removing unused entries and fetching new segments for
    /// (src, dst) pairs that are due for refresh.
    ///
    /// Returns the next scheduled maintenance time, which is the earliest next refresh time of
    /// all (src, dst) pairs in the store.
    ///
    /// If no (src, dst) pairs are due for refresh, the next maintenance time is the maximum
    /// segment fetch interval from now.
    pub async fn maintain(&self, now: SystemTime) -> SystemTime {
        let mut update_keys = Vec::new();
        let mut next_maintain = now + self.0.maximum_segment_fetch_interval;

        // Evict all unused entries from the store and plan to update segments for (src, dst)
        // pairs that are due for refresh.
        self.0
            .segments
            .retain_async(|key, entry| {
                // A referenced pair is still in use, however long ago it was last looked at.
                if !entry.has_references() && entry.last_use() + self.0.idle_eviction_time < now {
                    tracing::debug!(
                        src = %key.0, dst = %key.1,
                        "Evicting unused segments from the store"
                    );
                    return false;
                }

                // Plan to update segments for the (src, dst) pair if the next refresh is due.
                if entry.next_refresh < now {
                    update_keys.push(*key);
                } else {
                    // If we don't update now, track the next refresh time for scheduling the
                    // next maintenance run.
                    next_maintain = next_maintain.min(entry.next_refresh);
                }

                true
            })
            .await;

        for (src, dst) in update_keys {
            // Fetch new segments for the (src, dst) pair and update the store.
            // TODO: Paging is not supported yet.
            let fetched = self
                .0
                .segment_fetcher
                .list_segments(src, dst, SEGMENT_FETCH_PAGE_SIZE, String::new())
                .await;

            let fetched = match fetched {
                Ok(fetched) => fetched,
                Err(e) => {
                    // The entry stays due for a refresh; retry no earlier than the minimum
                    // fetch interval from now.
                    next_maintain = next_maintain.min(now + self.0.minimum_segment_fetch_interval);
                    tracing::error!(%src, %dst, "Failed to fetch segments: {e}");
                    continue;
                }
            };

            let Some(mut entry) = self.0.segments.get_async(&(src, dst)).await else {
                tracing::debug!(
                    %src, %dst,
                    "Segments were evicted from the store before they could be updated"
                );
                continue;
            };

            entry.get_mut().update_segments(
                fetched.segments,
                now,
                self.0.minimum_segment_fetch_interval,
                self.0.maximum_segment_fetch_interval,
                self.0.min_segment_lifetime,
                self.0.segment_lifetime_buffer,
            );

            next_maintain = next_maintain.min(entry.get().next_refresh);
        }

        next_maintain
    }
}

/// A store of segments for a given (src, dst) pair, with expiration and last-use timestamps.
struct SegmentStore {
    /// The query used to fetch the segments.
    query: (IsdAsn, IsdAsn),
    /// When the next refresh of the segments is due, based on the earliest expiration of the
    /// segments.
    next_refresh: SystemTime,
    /// When the segments were last used, as seconds since the UNIX epoch.
    last_use: AtomicU64,
    /// Number of live [`PairGuard`]s on this pair. If this is greater than zero, the pair is
    /// exempt from idle eviction.
    refs: Arc<AtomicUsize>,
    /// All core segments for the (src ISD, dst ISD) pair, indexed by their fingerprint.
    core_segments: HashMap<SegmentFp, SegmentEntry>,
    /// All non-core segments for the (src, dst) pair, indexed by their fingerprint.
    non_core_segments: HashMap<SegmentFp, SegmentEntry>,
}

struct SegmentEntry {
    segment: SignedPathSegment,
    expiration: SystemTime,
}

impl SegmentStore {
    /// Creates a new empty segment store for the given (src, dst) pair which needs to be
    /// updated with new segments.
    fn new(query: (IsdAsn, IsdAsn), now: SystemTime) -> Self {
        let this = Self {
            query,
            next_refresh: now,
            last_use: AtomicU64::new(0),
            refs: Arc::new(AtomicUsize::new(0)),
            core_segments: HashMap::new(),
            non_core_segments: HashMap::new(),
        };
        this.touch(now);
        this
    }

    /// Takes one more reference on this pair, returning the count to be held by its guard.
    fn acquire(&self) -> Arc<AtomicUsize> {
        self.refs.fetch_add(1, Ordering::Relaxed);
        self.refs.clone()
    }

    /// Whether anything holds a [`PairGuard`] on this pair.
    fn has_references(&self) -> bool {
        self.refs.load(Ordering::Relaxed) > 0
    }

    /// Records that the store was used at `now`.
    fn touch(&self, now: SystemTime) {
        let secs = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.last_use.fetch_max(secs, Ordering::Relaxed);
    }

    /// When the store was last used. A store counts as used when it is created.
    fn last_use(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.last_use.load(Ordering::Relaxed))
    }

    /// Updates the segments store.
    ///
    /// Does the following steps:
    /// - Merges the new segments into the store
    /// - Removes segments that have less than `min_segment_lifetime` left
    /// - Updates the next refresh time based on the earliest expiration of the remaining segments,
    ///   or the maximum refetch delay, whichever is earlier
    ///
    /// The next refresh time is between now + min_refetch_delay and now + max_refetch_delay,
    /// trying to capture the earliest expiration of the segments.
    ///
    /// ### Parameters
    /// - `new_segments`: The new segments to merge into the store.
    /// - `now`: The current time
    /// - `min_refetch_delay`: The minimum duration between two fetches of segments for the same
    ///   (src, dst) pair.
    /// - `max_refetch_delay`: The maximum duration between two fetches of segments for the same
    ///   (src, dst) pair.
    /// - `min_segment_lifetime`: The minimum duration a segment must have left to be kept in the
    ///   store.
    /// - `segment_lifetime_buffer`: The duration before a segment expires at which we want to have
    ///   fetched its replacement.
    fn update_segments(
        &mut self,
        new_segments: Segments,
        now: SystemTime,
        min_refetch_delay: Duration,
        max_refetch_delay: Duration,
        min_segment_lifetime: Duration,
        segment_lifetime_buffer: Duration,
    ) {
        let start_core_count = self.core_segments.len();
        let start_non_core_count = self.non_core_segments.len();

        let (new_core, new_non_core) = new_segments.split_parts();

        for (segments, store) in [
            (new_core, &mut self.core_segments),
            (new_non_core, &mut self.non_core_segments),
        ] {
            for segment in segments {
                // We don't compare the new segment with the existing one, we just replace it.
                // New segments should always have the same or later expiration than the existing
                // ones.
                let expiration = segment.expires_earliest();
                store.insert(
                    segment.fingerprint(),
                    SegmentEntry {
                        segment,
                        expiration,
                    },
                );
            }
        }

        // Never refetch later than max_refetch_delay from now, even if all segments live
        // longer than that.
        let mut next_refetch = now + max_refetch_delay;
        for store in [&mut self.core_segments, &mut self.non_core_segments] {
            store.retain(|_, segment| {
                // Drop segments that are expired, or so close to expiry that a path built
                // from them would be useless.
                if segment.expiration < now + min_segment_lifetime {
                    return false;
                }

                // Try to have fetched a replacement before the earliest segment expires.
                let refetch_at = segment
                    .expiration
                    .checked_sub(segment_lifetime_buffer)
                    .unwrap_or(now);

                next_refetch = next_refetch.min(refetch_at);

                true
            });
        }

        // If we have neither core nor non-core segments, force a early refetch
        if self.core_segments.is_empty() && self.non_core_segments.is_empty() {
            tracing::debug!(
                src = %self.query.0, dst = %self.query.1,
                "Segment store is empty after update, forcing a refetch in {}s",
                min_refetch_delay.as_secs()
            );

            next_refetch = now + min_refetch_delay;
        }

        // Ensure that the next refresh time is at least now + min_refetch_delay, to avoid
        // fetching too frequently.
        next_refetch = next_refetch.max(now + min_refetch_delay);

        tracing::info!(
            "Updated segments for ({}, {}): core: {} -> {}, non-core: {} -> {}, next refresh: {:?}",
            self.query.0,
            self.query.1,
            start_core_count,
            self.core_segments.len(),
            start_non_core_count,
            self.non_core_segments.len(),
            next_refetch
        );

        self.next_refresh = next_refetch;
    }
}

/// Keeps the segments of one (src, dst) pair managed for as long as it is held.
///
/// Handed out by [`SegmentManager::hold_pair`]. Dropping it makes the pair subject to idle
/// eviction again.
pub struct PairGuard {
    /// The reference count of the guarded pair, shared with its entry in the store.
    ref_count: Arc<AtomicUsize>,
    src: IsdAsn,
    dst: IsdAsn,
}

impl Drop for PairGuard {
    fn drop(&mut self) {
        let previous = self.ref_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(
            previous > 0,
            "released a pair guard that was never acquired"
        );

        tracing::trace!(src = %self.src, dst = %self.dst, "Released a pair guard");
    }
}

/// A unique identifier for a segment in the store, based on the (src, dst) pair it was fetched
/// for and its fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentStoreId {
    /// A core segment.
    Core {
        /// The source of the query the segment was fetched for.
        src: IsdAsn,
        /// The destination of the query the segment was fetched for.
        dst: IsdAsn,
        /// The fingerprint of the segment.
        fp: SegmentFp,
    },
    /// An up or down segment.
    NonCore {
        /// The source of the query the segment was fetched for.
        src: IsdAsn,
        /// The destination of the query the segment was fetched for.
        dst: IsdAsn,
        /// The fingerprint of the segment.
        fp: SegmentFp,
    },
}

impl SegmentStoreId {
    /// The source of the query the segment was fetched for.
    pub fn src(&self) -> IsdAsn {
        match self {
            Self::Core { src, .. } | Self::NonCore { src, .. } => *src,
        }
    }

    /// The destination of the query the segment was fetched for.
    pub fn dst(&self) -> IsdAsn {
        match self {
            Self::Core { dst, .. } | Self::NonCore { dst, .. } => *dst,
        }
    }

    /// The fingerprint of the segment.
    pub fn fp(&self) -> SegmentFp {
        match self {
            Self::Core { fp, .. } | Self::NonCore { fp, .. } => *fp,
        }
    }

    /// Returns true if this identifies a core segment.
    pub fn is_core(&self) -> bool {
        matches!(self, Self::Core { .. })
    }
}

/// Borrowed view of the segments of one (src, dst) pair.
///
/// This holds a lock on the store entry, so it must not be held across an `.await` that can
/// touch the [`SegmentManager`] again.
pub struct SegmentsIter<'store> {
    store: OccupiedEntry<'store, (IsdAsn, IsdAsn), SegmentStore>,
}

impl SegmentsIter<'_> {
    /// Iterates over the core segments of the pair.
    pub fn iter_core_segments(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.store
            .get()
            .core_segments
            .values()
            .map(|entry| &entry.segment)
    }

    /// Iterates over the up and down segments of the pair.
    pub fn iter_non_core_segments(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.store
            .get()
            .non_core_segments
            .values()
            .map(|entry| &entry.segment)
    }

    /// Returns whether the pair holds a core segment with the given fingerprint.
    pub fn has_core_segment(&self, fp: SegmentFp) -> bool {
        self.store.get().core_segments.contains_key(&fp)
    }

    /// Returns whether the pair holds an up or down segment with the given fingerprint.
    pub fn has_non_core_segment(&self, fp: SegmentFp) -> bool {
        self.store.get().non_core_segments.contains_key(&fp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pg_wap2::test_util::{
        Fixture, MAX_FETCH_INTERVAL, MIN_FETCH_INTERVAL, MockFetcher, SEGMENT_LIFETIME_BUFFER, at,
        core_ia, leaf_ia, other_leaf_ia, secs_since_epoch, short_lived_up_segment, store_id,
        up_segment,
    };

    #[tokio::test]
    async fn segments_are_fetched_once_per_pair_and_queryable_by_fingerprint() {
        let up = up_segment(0);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up.clone()]),
            Duration::from_secs(100),
        );

        let fingerprints = {
            let segments = fixture
                .segments
                .segments(leaf_ia(), core_ia(), at(0))
                .await
                .expect("segments are fetched");
            segments
                .iter_non_core_segments()
                .map(SignedPathSegment::fingerprint)
                .collect::<Vec<_>>()
        };
        assert_eq!(fingerprints, vec![up.fingerprint()]);
        assert_eq!(fixture.fetcher.calls(), 1);

        // A second request for the same pair is served from the store.
        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("segments are served from the store");
        assert_eq!(fixture.fetcher.calls(), 1);

        let id = store_id(&up);
        assert!(fixture.segments.segment(id, at(0)).await.is_some());
        assert!(
            fixture
                .segments
                .segment(
                    SegmentStoreId::NonCore {
                        src: leaf_ia(),
                        dst: core_ia(),
                        fp: SegmentFp::default(),
                    },
                    at(0)
                )
                .await
                .is_none(),
            "an unknown fingerprint is not found"
        );
    }

    #[tokio::test]
    async fn segments_close_to_expiry_are_not_stored() {
        let up = up_segment(0);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up.clone()]),
            Duration::from_secs(100),
        );

        // The fixture keeps segments with at least 60s left; leave 30s.
        let nearly_expired = at(secs_since_epoch(up.expires_earliest()) - 30);

        let segments = fixture
            .segments
            .segments(leaf_ia(), core_ia(), nearly_expired)
            .await
            .expect("segments are fetched");
        assert_eq!(segments.iter_non_core_segments().count(), 0);
    }

    #[tokio::test]
    async fn maintenance_is_scheduled_no_later_than_the_fetch_interval_cap() {
        let fixture = Fixture::new(
            // Lives for 24h, i.e. far longer than the cap.
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(100),
        );

        assert_eq!(
            fixture.segments.maintain(at(0)).await,
            at(0) + MAX_FETCH_INTERVAL,
            "with nothing managed there is nothing to schedule around"
        );

        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("segments are fetched");

        assert_eq!(
            fixture.segments.maintain(at(0)).await,
            at(0) + MAX_FETCH_INTERVAL,
            "a long lived pair is still refetched at the cap"
        );
        assert_eq!(
            fixture.fetcher.calls(),
            1,
            "nothing was due, so nothing was refetched"
        );
    }

    #[tokio::test]
    async fn maintenance_is_scheduled_a_buffer_before_the_earliest_expiry() {
        // Lives ~28min, so its replacement is due well inside the fetch interval cap.
        let up = short_lived_up_segment(0, 4);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up.clone()]),
            Duration::from_secs(100),
        );

        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("segments are fetched");

        assert_eq!(
            fixture.segments.maintain(at(0)).await,
            up.expires_earliest() - SEGMENT_LIFETIME_BUFFER,
            "the replacement has to be fetched before the segment expires"
        );
    }

    #[tokio::test]
    async fn maintenance_is_scheduled_for_the_earliest_of_all_pairs() {
        let short = short_lived_up_segment(0, 4);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(100),
        );

        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("the long lived pair is fetched");
        fixture.fetcher.set_segments(Segments {
            up_segments: vec![short.clone()],
            ..Segments::default()
        });
        fixture
            .segments
            .segments(leaf_ia(), other_leaf_ia(), at(0))
            .await
            .expect("the short lived pair is fetched");

        assert_eq!(
            fixture.segments.maintain(at(0)).await,
            short.expires_earliest() - SEGMENT_LIFETIME_BUFFER,
            "the pair that expires first decides when maintenance runs again"
        );
    }

    #[tokio::test]
    async fn a_pair_without_segments_is_retried_at_the_minimum_interval() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("the empty pair is managed");
        assert_eq!(fixture.fetcher.calls(), 1);

        assert_eq!(
            fixture.segments.maintain(at(0)).await,
            at(0) + MIN_FETCH_INTERVAL,
            "a pair we know nothing about is retried as soon as we are allowed to"
        );

        // And that retry actually happens, rather than the pair sitting there empty.
        fixture
            .segments
            .maintain(at(MIN_FETCH_INTERVAL.as_secs() + 1))
            .await;
        assert_eq!(fixture.fetcher.calls(), 2);
    }

    #[tokio::test]
    async fn maintenance_reports_the_schedule_of_the_pairs_it_just_refetched() {
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(100),
        );

        // Held, so the pair survives long enough to become due for a refetch.
        let _guard = fixture
            .segments
            .hold_pair(leaf_ia(), core_ia(), at(0))
            .await
            .expect("the pair is fetched and held");
        assert_eq!(fixture.fetcher.calls(), 1);

        let due_at = MAX_FETCH_INTERVAL.as_secs() + 1;

        assert_eq!(
            fixture.segments.maintain(at(due_at)).await,
            at(due_at) + MAX_FETCH_INTERVAL,
            "the returned time must be the refetched pair's new schedule, not the one it was due at"
        );
        assert_eq!(fixture.fetcher.calls(), 2, "the pair was due and refetched");
    }

    #[tokio::test]
    async fn a_failed_refetch_is_retried_at_the_minimum_interval() {
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(100),
        );

        let _guard = fixture
            .segments
            .hold_pair(leaf_ia(), core_ia(), at(0))
            .await
            .expect("the pair is fetched and held");

        let due_at = MAX_FETCH_INTERVAL.as_secs() + 1;
        fixture.fetcher.set_failing(true);

        assert_eq!(
            fixture.segments.maintain(at(due_at)).await,
            at(due_at) + MIN_FETCH_INTERVAL,
            "a failed fetch is retried as soon as we are allowed to"
        );
        assert_eq!(
            fixture.fetcher.calls(),
            2,
            "the failing fetch was attempted"
        );

        // The pair stayed due, so the next run tries again instead of waiting for the cap.
        fixture.fetcher.set_failing(false);
        let retried_at = at(due_at + MIN_FETCH_INTERVAL.as_secs() + 1);
        assert_eq!(
            fixture.segments.maintain(retried_at).await,
            retried_at + MAX_FETCH_INTERVAL
        );
        assert_eq!(fixture.fetcher.calls(), 3);
        assert!(
            fixture
                .segments
                .segment(store_id(&up_segment(0)), retried_at)
                .await
                .is_some(),
            "the retry restored the segments of the pair"
        );
    }

    #[tokio::test]
    async fn unused_pairs_are_evicted_and_used_ones_kept() {
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up_segment(0)]),
            Duration::from_secs(100),
        );

        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(0))
            .await
            .expect("segments are fetched");
        assert_eq!(fixture.fetcher.calls(), 1);

        // The fixture evicts after 60s of no use.
        fixture.segments.maintain(at(30)).await;
        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(30))
            .await
            .expect("segments are still in the store");
        assert_eq!(fixture.fetcher.calls(), 1, "the pair was still fresh");

        // The last use is the request above, at t=30.
        fixture.segments.maintain(at(91)).await;
        fixture
            .segments
            .segments(leaf_ia(), core_ia(), at(91))
            .await
            .expect("segments are fetched again");
        assert_eq!(
            fixture.fetcher.calls(),
            2,
            "the evicted pair has to be fetched again"
        );
    }
}
