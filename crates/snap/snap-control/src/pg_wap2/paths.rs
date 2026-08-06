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

//! Path combination.
//!
//! [`PathManager`] combines the public segments of the [`SegmentManager`] with the segments granted
//! by the [`AuthService`] into the single best path, and reports which segments went into it so
//! callers can re-path and observe grant expiry.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use sciparse::{
    identifier::isd_asn::IsdAsn,
    path::{
        ScionPath,
        combinator::graph::{InputSegment, MultiGraph, number_of_hops},
    },
    reexport::tinyvec::ArrayVec,
    segment::{SegmentFp, SignedPathSegment},
};
use tokio_util::sync::CancellationToken;

use crate::pg_wap2::{
    auth::{AuthService, DestinationSNI, DstGrant, GrantedSegmentId},
    segments::{PairGuard, SegmentManager, SegmentStoreId, SegmentsIter},
};

/// Combines public and granted segments into paths.
///
/// Cheap to clone; all clones share the same state.
#[derive(Clone)]
pub struct PathManager(Arc<PathManagerInner>);

/// The state shared by all clones of a [`PathManager`].
struct PathManagerInner {
    segments: SegmentManager,
    auth: AuthService,
}

impl PathManager {
    /// Creates a path manager on top of the given segment sources.
    pub fn new(segments: SegmentManager, auth: AuthService) -> Self {
        Self(Arc::new(PathManagerInner { segments, auth }))
    }

    /// Returns the best path from the given source ISD-ASN to the destination ISD-ASN.
    ///
    /// This combines public segments in the segment manager and the granted segments for the
    /// given client IP and destination SNI.
    ///
    /// Returns the best path and the segments that make up the path.
    /// Returns None if no path could be found.
    /// Returns an error if something went wrong while fetching segments or computing the path.
    ///
    /// ### Parameters
    /// - `client_ip`: The IP address of the client requesting the path.
    /// - `dst_sni`: The destination SNI for which the path is requested.
    /// - `src`: The source ISD-ASN.
    /// - `dst`: The destination ISD-ASN.
    pub async fn best_path(
        &self,
        client_ip: IpAddr,
        dst_sni: &DestinationSNI,
        src: IsdAsn,
        dst: IsdAsn,
        now: SystemTime,
    ) -> anyhow::Result<Option<UsedPath>> {
        if src.is_wildcard() || dst.is_wildcard() {
            bail!("Source and destination ISD-ASNs must be specified, wildcards are not allowed");
        }

        // Check if the client is authorized for the destination SNI and get the granted segments.
        let auth_segments = self.0.auth.dst_grant(client_ip, dst_sni, now).context(
            "IP address is not authorized for the given destination SNI or the grant has expired",
        )?;

        // Check if the destination is in the same AS
        if src == dst {
            return Ok(Some(UsedPath {
                path: ScionPath::local(src).expect("checked above that src is not a wildcard"),
                src,
                dst,
                segments: ArrayVec::new(),
            }));
        }

        // Get all public segments for the (src, dst) pair. This holds a lock on the store's entry
        // bucket, so nothing below may await on the segment manager again.
        let store_segments = self
            .0
            .segments
            .segments(src, dst, now)
            .await
            .context("Failed to get segments for the given (src, dst) pair")?;

        let inputs = store_segments
            .iter_core_segments()
            .map(InputSegment::new_core)
            .chain(
                store_segments
                    .iter_non_core_segments()
                    .map(InputSegment::new_non_core),
            )
            .chain(
                auth_segments
                    .iter_core_segments()
                    .map(InputSegment::new_core),
            )
            .chain(
                auth_segments
                    .iter_non_core_segments()
                    .map(InputSegment::new_non_core),
            );

        // TODO: This will have to start taking path issues into account, either in the
        // scoring function, or when selecting the best solution from the graph.
        let Some((path, fps)) = best_solution(src, dst, inputs, |_| true) else {
            return Ok(None);
        };

        // For each fingerprint in the path, find out which source it came
        let mut segments = ArrayVec::new();
        for fp in fps {
            segments.push(
                segment_source(fp, src, dst, &store_segments, &auth_segments)
                .context("The path used a segment that is no longer available in either the store or the grant")?,
            );
        }

        Ok(Some(UsedPath {
            path,
            src,
            dst,
            segments,
        }))
    }

    /// Rebuilds `used` from the current copies of the exact segments it was built from.
    ///
    /// Allows the caller to pick up a later expiration of the underlying segments.
    ///
    /// Returns `Ok(UsedPath)` if the path could be rebuilt, or `Err` if it could not be rebuilt.
    pub async fn refresh_path(&self, used: &UsedPath, now: SystemTime) -> anyhow::Result<UsedPath> {
        if used.segments.is_empty() {
            // An AS local path is not built from segments and never expires.
            return Ok(used.clone());
        }

        let mut segments = Vec::with_capacity(used.segments.len());
        for id in used.segments.iter() {
            let Some(segment) = self.resolve(id, now).await else {
                bail!("Segment {:?} is no longer available", id);
            };
            segments.push((id.is_core(), segment));
        }

        let inputs = segments.iter().map(|(is_core, segment)| {
            if *is_core {
                InputSegment::new_core(segment)
            } else {
                InputSegment::new_non_core(segment)
            }
        });

        // Only the segments of `used` went into the graph, so every solution uses a subset of
        // them. Require the exact same segments in the same order, so the refreshed path is
        // interchangeable with the one it replaces.
        let expected: Vec<SegmentFp> = used.segments.iter().map(SegmentSourceId::fp).collect();
        let (path, _segment_fps) =
            best_solution(used.src, used.dst, inputs, |fps| fps == &expected[..])
                .context("Refreshed segments did not combine into a path")?;

        Ok(UsedPath {
            path,
            src: used.src,
            dst: used.dst,
            segments: used.segments.clone(),
        })
    }

    /// Keeps the public segments `used` was built from available for as long as the returned
    /// guard is alive, so [`Self::refresh_path`] can still resolve them.
    ///
    /// Anything that keeps a [`UsedPath`] around for longer than the segment manager's
    /// `idle_eviction_time` has to hold on to the guard, otherwise the pair backing the path is
    /// evicted while the path is still in use.
    ///
    /// Granted segments need no guard: they are held in place by their grant, not by use.
    pub async fn hold_segments(
        &self,
        used: &UsedPath,
        now: SystemTime,
    ) -> anyhow::Result<PathSegmentsGuard> {
        let mut guards = Vec::new();

        for id in used.segments.iter() {
            let SegmentSourceId::Store(id) = id else {
                continue;
            };

            guards.push(
                self.0
                    .segments
                    .hold_pair(id.src(), id.dst(), now)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to hold the segments of ({}, {})",
                            id.src(),
                            id.dst()
                        )
                    })?,
            );
        }

        Ok(PathSegmentsGuard { _guards: guards })
    }

    /// Watches the grants that let `client_ip` use `used` towards `dst_sni`.
    ///
    /// The returned watch resolves once any of the grants that authorize the path expires, so the
    /// caller can close the connection.
    ///
    /// Returns an error if the client is not authorized for the path in the first place.
    pub fn watch_grants(
        &self,
        client_ip: IpAddr,
        dst_sni: &DestinationSNI,
        used: &UsedPath,
        now: SystemTime,
    ) -> anyhow::Result<GrantWatch> {
        let dst_grant = self
            .0
            .auth
            .watch_grant(client_ip, dst_sni, now)
            .with_context(|| format!("No live grant of {client_ip} for {dst_sni}"))?;

        let mut grants = vec![dst_grant];

        for id in used.segments.iter() {
            let SegmentSourceId::Auth(id) = id else {
                continue;
            };

            grants.push(
                self.0
                    .auth
                    .watch_segment_grant(client_ip, dst_sni, id, now)
                    .with_context(|| {
                        format!(
                            "No live grant of {client_ip} for segment {} of the path",
                            id.fp()
                        )
                    })?,
            );
        }

        Ok(GrantWatch { grants })
    }

    /// Looks a segment up in the source it came from.
    async fn resolve(&self, id: &SegmentSourceId, now: SystemTime) -> Option<SignedPathSegment> {
        match id {
            SegmentSourceId::Store(id) => self.0.segments.segment(*id, now).await,
            SegmentSourceId::Auth(id) => self.0.auth.segment(id, now),
        }
    }
}

/// Combines `inputs` into the cheapest loop free path from `src` to `dst` that `accept`ed.
///
/// Solutions are returned by the graph in ascending cost, so the first match is the best one.
fn best_solution<'segments>(
    src: IsdAsn,
    dst: IsdAsn,
    inputs: impl Iterator<Item = InputSegment<'segments, sciparse::segment::SignedAsEntry>>,
    accept: impl Fn(&[SegmentFp]) -> bool,
) -> Option<(ScionPath, ArrayVec<[SegmentFp; 3]>)> {
    // Build a graph of all segments and find all paths from src to dst, using the number of
    // hops as the cost function.
    let mut graph = MultiGraph::new(number_of_hops);
    graph.add_segments(inputs);

    graph
        .get_paths(src, dst)
        .iter()
        .filter_map(|solution| solution.path().ok().flatten())
        .find(|(_, fps)| accept(fps))
}

/// Finds which of the two sources the segment `fp` refers to was taken from.
///
/// Returns `None` if neither source holds it.
fn segment_source(
    fp: SegmentFp,
    src: IsdAsn,
    dst: IsdAsn,
    store: &SegmentsIter<'_>,
    granted: &DstGrant,
) -> Option<SegmentSourceId> {
    // XXX: This is awful, we should ideally be able to tag segments with their source in the graph
    // directly.
    if store.has_core_segment(fp) {
        return Some(SegmentSourceId::Store(SegmentStoreId::Core {
            src,
            dst,
            fp,
        }));
    }
    if store.has_non_core_segment(fp) {
        return Some(SegmentSourceId::Store(SegmentStoreId::NonCore {
            src,
            dst,
            fp,
        }));
    }
    if granted.has_core_segment(fp) {
        return Some(SegmentSourceId::Auth(GrantedSegmentId::Core(fp)));
    }
    if granted.has_non_core_segment(fp) {
        return Some(SegmentSourceId::Auth(GrantedSegmentId::NonCore(fp)));
    }

    None
}

/// Where a segment used in a path came from.
///
/// Lets a consumer of a path go back to the segment it was built from, either to pick up a
/// fresher copy of it, or to observe the expiry of the grant that made it available.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SegmentSourceId {
    /// A public segment from the [`SegmentManager`].
    Store(SegmentStoreId),
    /// A private segment granted by the [`AuthService`].
    Auth(GrantedSegmentId),
}

impl SegmentSourceId {
    /// The fingerprint of the segment.
    pub fn fp(&self) -> SegmentFp {
        match self {
            Self::Store(id) => id.fp(),
            Self::Auth(id) => id.fp(),
        }
    }

    /// Returns true if this identifies a core segment.
    pub fn is_core(&self) -> bool {
        match self {
            Self::Store(id) => id.is_core(),
            Self::Auth(id) => id.is_core(),
        }
    }
}

// Required by `tinyvec::ArrayVec`, which needs a `Default` item to back its inline storage.
impl Default for SegmentSourceId {
    fn default() -> Self {
        Self::Store(SegmentStoreId::Core {
            src: IsdAsn(0),
            dst: IsdAsn(0),
            fp: SegmentFp::default(),
        })
    }
}

/// Watches one client's authorization to use a path.
pub struct GrantWatch {
    /// The grants the client needs to keep using the path, first the target grant.
    grants: Vec<CancellationToken>,
}

impl GrantWatch {
    /// Resolves once the client loses any of the grants that authorize the path.
    ///
    /// Cancel safe: dropping this future and awaiting it again `still observes an expiry that
    /// happened in between.
    pub async fn expired(&self) {
        // Only ever empty if a caller built this by hand; `watch_grants` always has the target
        // grant. `select_all` would panic on an empty iterator.
        if self.grants.is_empty() {
            debug_assert!(false, "a grant watch without grants never resolves");
            std::future::pending::<()>().await;
        }

        let expiries = self.grants.iter().map(|grant| Box::pin(grant.cancelled()));

        futures::future::select_all(expiries).await;
    }
}

/// Keeps the public segments a [`UsedPath`] was built from available.
///
/// Handed out by [`PathManager::hold_segments`]; a path can be built from at most three segments,
/// so this holds at most three guards.
pub struct PathSegmentsGuard {
    _guards: Vec<PairGuard>,
}

/// A path together with the segments it was combined from.
///
/// A path can be built from at most three segments (up, core, down).
#[derive(Debug, Clone)]
pub struct UsedPath {
    /// The combined path.
    pub path: ScionPath,
    /// The source the path was combined for.
    pub src: IsdAsn,
    /// The destination the path was combined for.
    pub dst: IsdAsn,
    /// The segments the path was combined from, in path order.
    pub segments: ArrayVec<[SegmentSourceId; 3]>,
}

impl UsedPath {
    /// The expiration of the underlying dataplane path.
    ///
    /// `None` for paths that do not carry an expiration, e.g. AS local paths.
    pub fn expiration(&self) -> Option<SystemTime> {
        self.path
            .expiration()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(u64::from(secs)))
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use sciparse::segment::Segments;

    use super::*;
    use crate::pg_wap2::test_util::{
        Fixture, IDLE_EVICTION_TIME, MAX_FETCH_INTERVAL, MockFetcher, SNI, at, client_ip, core_ia,
        core_segment, core_store_id, down_segment, granted_core_id, granted_id, leaf_ia,
        non_core_store_id, other_leaf_ia, sni, store_id, up_segment,
    };

    #[tokio::test]
    async fn best_path_combines_granted_segments_and_reports_them() {
        let up = up_segment(0);
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
                .await
                .is_err(),
            "a client without a grant for the target gets no path at all"
        );

        // Granting the target without granting any segment leaves nothing to combine.
        fixture.grant_non_core(Vec::new(), at(0));
        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
                .await
                .expect("path combination succeeds")
                .is_none(),
            "without any segments there is no path"
        );

        fixture.grant_non_core(vec![up.clone()], at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted segment yields a path");

        assert_eq!(
            used.segments.as_slice(),
            [SegmentSourceId::Auth(granted_id(&up))],
            "the path must report the grant it depends on"
        );
    }

    #[tokio::test]
    async fn best_path_reports_public_segments_as_public() {
        let up = up_segment(0);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up.clone()]),
            Duration::from_secs(100),
        );
        // The same segment is also granted; the public copy must win, so the path does not
        // needlessly depend on a grant.
        fixture.grant_non_core(vec![up.clone()], at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the public segment yields a path");

        assert_eq!(
            used.segments.as_slice(),
            [SegmentSourceId::Store(store_id(&up))]
        );
    }

    /// A path over all three segment types, with the core segment public and the up and down
    /// segments granted, so both sources contribute to one path.
    ///
    /// Returns the fixture and the path from [`leaf_ia`] to [`other_leaf_ia`].
    async fn three_segment_fixture() -> (Fixture, UsedPath) {
        let fixture = Fixture::new(
            MockFetcher::new(Segments {
                core_segments: vec![core_segment(0)],
                ..Segments::default()
            }),
            Duration::from_secs(10 * 24 * 3600),
        );
        fixture.grant_for(
            client_ip(),
            SNI,
            Vec::new(),
            vec![up_segment(0), down_segment(0)],
            at(0),
        );

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), other_leaf_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("up, core and down combine into a path");

        (fixture, used)
    }

    #[tokio::test]
    async fn best_path_combines_up_core_and_down_and_tags_every_source() {
        let (_fixture, used) = three_segment_fixture().await;

        assert_eq!(
            used.segments.as_slice(),
            [
                SegmentSourceId::Auth(granted_id(&up_segment(0))),
                SegmentSourceId::Store(core_store_id(&core_segment(0), leaf_ia(), other_leaf_ia())),
                SegmentSourceId::Auth(granted_id(&down_segment(0))),
            ],
            "the path reports its three segments in path order, each tagged with its source"
        );
    }

    #[tokio::test]
    async fn best_path_combines_a_granted_core_segment_with_public_up_and_down() {
        let fixture = Fixture::new(
            MockFetcher::new(Segments {
                up_segments: vec![up_segment(0)],
                down_segments: vec![down_segment(0)],
                ..Segments::default()
            }),
            Duration::from_secs(100),
        );
        // The core hop between the two core ASes is the private part of this path.
        fixture.grant_for(client_ip(), SNI, vec![core_segment(0)], Vec::new(), at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), other_leaf_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted core segment closes the gap between the public ones");

        assert_eq!(
            used.segments.as_slice(),
            [
                SegmentSourceId::Store(non_core_store_id(
                    &up_segment(0),
                    leaf_ia(),
                    other_leaf_ia()
                )),
                SegmentSourceId::Auth(granted_core_id(&core_segment(0))),
                SegmentSourceId::Store(non_core_store_id(
                    &down_segment(0),
                    leaf_ia(),
                    other_leaf_ia()
                )),
            ],
            "a granted core segment is reported as granted, not as public"
        );

        // The client keeps the path only while its grant on that core segment holds.
        let watch = fixture
            .paths
            .watch_grants(client_ip(), &sni(), &used, at(0))
            .expect("the client is authorized for the path");
        fixture.auth.clean(at(101));
        assert!(watch.expired().now_or_never().is_some());
    }

    #[tokio::test]
    async fn refresh_path_keeps_a_three_segment_path_intact() {
        let (fixture, used) = three_segment_fixture().await;

        // The uplink's guard is what keeps the public pair from being evicted while we wait for
        // its refresh to come due.
        let _guard = fixture
            .paths
            .hold_segments(&used, at(0))
            .await
            .expect("the public pair of the path can be held");

        // Every one of the three segments is re-beaconed 600s later: the granted ones by a
        // re-auth, the public one by the segment manager refetching the pair.
        let refreshed_at = at(MAX_FETCH_INTERVAL.as_secs() + 1);
        fixture.grant_for(
            client_ip(),
            SNI,
            Vec::new(),
            vec![up_segment(600), down_segment(600)],
            refreshed_at,
        );
        fixture.fetcher.set_segments(Segments {
            core_segments: vec![core_segment(600)],
            ..Segments::default()
        });
        fixture.segments.maintain(refreshed_at).await;

        let refreshed = fixture
            .paths
            .refresh_path(&used, refreshed_at)
            .await
            .expect("refreshing succeeds");

        assert_eq!(
            refreshed.segments, used.segments,
            "the refreshed path must use the very same segments, in the same order"
        );
        assert_eq!(
            refreshed.path.fingerprint(),
            used.path.fingerprint(),
            "the refreshed path is the same path, so uplinks keep their key"
        );
        assert_eq!(
            refreshed.expiration(),
            used.expiration().map(|old| old + Duration::from_secs(600)),
            "all three segments moved, so the whole path lives 600s longer"
        );
    }

    #[tokio::test]
    async fn refresh_path_fails_once_a_public_segment_is_evicted() {
        let up = up_segment(0);
        let fixture = Fixture::new(
            MockFetcher::with_up_segments(vec![up.clone()]),
            Duration::from_secs(10 * 24 * 3600),
        );
        fixture.grant_non_core(Vec::new(), at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the public segment yields a path");
        assert_eq!(
            used.segments.as_slice(),
            [SegmentSourceId::Store(store_id(&up))]
        );

        // Nothing holds the pair, so it goes once it has been idle for long enough.
        let evicted_at = at(IDLE_EVICTION_TIME.as_secs() + 1);
        fixture.segments.maintain(evicted_at).await;

        assert!(
            fixture.paths.refresh_path(&used, evicted_at).await.is_err(),
            "a path over an evicted public segment cannot be rebuilt"
        );
    }

    #[tokio::test]
    async fn best_path_fails_when_public_segments_cannot_be_fetched() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));
        fixture.grant_non_core(vec![up_segment(0)], at(0));
        fixture.fetcher.set_failing(true);

        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
                .await
                .is_err(),
            "a path cannot be computed without knowing the public segments"
        );

        fixture.fetcher.set_failing(false);
        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
                .await
                .expect("path combination succeeds")
                .is_some(),
            "and the failure leaves nothing behind that would keep it from succeeding later"
        );
    }

    #[tokio::test]
    async fn refresh_path_picks_up_a_later_expiration() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(10 * 24 * 3600));
        fixture.grant_non_core(vec![up_segment(0)], at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted segment yields a path");

        // A refresh brings the same segment, beaconed 600s later.
        let fresher = up_segment(600);
        assert_eq!(
            fresher.fingerprint(),
            up_segment(0).fingerprint(),
            "a fresher copy of a segment keeps its fingerprint"
        );
        fixture.grant_non_core(vec![fresher], at(0));

        let refreshed = fixture
            .paths
            .refresh_path(&used, at(0))
            .await
            .expect("refreshing succeeds");

        assert_eq!(
            refreshed.segments, used.segments,
            "the refreshed path uses the same segments"
        );
        assert_eq!(
            refreshed.path.fingerprint(),
            used.path.fingerprint(),
            "the refreshed path is the same path, so uplinks keep their key"
        );
        assert_eq!(
            refreshed.expiration(),
            used.expiration().map(|old| old + Duration::from_secs(600)),
            "the refreshed path lives 600s longer"
        );
    }

    #[tokio::test]
    async fn refresh_path_fails_once_the_grant_is_gone() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));
        fixture.grant_non_core(vec![up_segment(0)], at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), core_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("the granted segment yields a path");

        fixture.auth.clean(at(101));

        assert!(
            fixture.paths.refresh_path(&used, at(101)).await.is_err(),
            "a path over a segment whose grant is gone cannot be refreshed"
        );
    }

    #[tokio::test]
    async fn best_path_rejects_wildcards_and_handles_local_paths() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), IsdAsn(0), at(0))
                .await
                .is_err()
        );

        assert!(
            fixture
                .paths
                .best_path(client_ip(), &sni(), leaf_ia(), leaf_ia(), at(0))
                .await
                .is_err(),
            "an AS local path still requires a grant for the target"
        );

        fixture.grant_non_core(Vec::new(), at(0));

        let used = fixture
            .paths
            .best_path(client_ip(), &sni(), leaf_ia(), leaf_ia(), at(0))
            .await
            .expect("path combination succeeds")
            .expect("an AS local path always exists");
        assert!(used.segments.is_empty());
    }
}
