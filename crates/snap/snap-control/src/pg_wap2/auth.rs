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

//! IP based authorization.
//!
//! A grant is a promise that a client IP may use a target, and a set of private segments
//! towards it, until a point in time. Grants are only ever added and extended:
//!
//! - **Additive**: [`AuthService::authorize`] adds targets and segments to whatever the IP already
//!   has, and never shortens an existing grant.
//! - **Not revocable**: state leaves the service only via [`AuthService::clean`], and only once it
//!   has expired.
//! - **Observable**: every grant carries a [`CancellationToken`] that is cancelled when the grant
//!   is removed, so consumers can tear down or re-path. Cancellation is latched, so a waiter that
//!   has not been polled yet still observes it.
//!
//! A segment grant never outlives the segment it was granted on: `granted_until` is capped at
//! the segment's own expiry. Without that cap an expired segment would have to be pulled out
//! from under a live grant, which is indistinguishable from a revocation.
//!
//! The invariants we maintain are:
//! - A segment grant never outlives the segment it was granted on.
//! - A segment is removed from the authoritative store once its last grant is gone.
//! - A certain IP and SNI can only get grants for segments that which are granted for it.
//! - As soon as a grant is removed, it's connected cancellation token is cancelled.

use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime},
};

use sciparse::segment::{SegmentFp, SignedPathSegment};
use tokio_util::sync::CancellationToken;

use crate::pg_wap2::sni::{CustomerDomain, CustomerDomainRef};

/// Tracks which client IPs are authorized for which targets and segments.
#[derive(Clone)]
pub struct AuthService(Arc<AuthServiceShared>);

struct AuthServiceShared {
    /// The mutable authorization state.
    inner: RwLock<AuthServiceInner>,

    /// Duration a grant is handed out for. After this time, the client needs to
    /// reauthenticate.
    auth_duration: Duration,

    /// Lower bound on the sleep between two [`AuthService::clean`] runs, so a stream of short
    /// lived grants cannot spin the maintenance loop.
    min_clean_interval: Duration,
    /// Upper bound on the sleep between two [`AuthService::clean`] runs. `clean` only knows about
    /// the grants that exist when it runs, so this bounds how long a grant added right after it
    /// can outlive its expiry.
    max_clean_interval: Duration,
}

/// The mutable state of an [`AuthService`].
pub struct AuthServiceInner {
    /// Map of all authenticated IPs.
    auth_ips: HashMap<IpAddr, IpAuthInfo>,

    /// Authoritative, deduplicated list of all granted non-core segments for all IPs and dst
    /// domains.
    ///
    /// Segments are removed once their last grant is gone.
    private_non_core_segments: HashMap<SegmentFp, AuthSegmentEntry>,
    /// Same as `private_non_core_segments`, but for core segments.
    private_core_segments: HashMap<SegmentFp, AuthSegmentEntry>,
}

impl AuthService {
    /// Creates an empty service handing out grants valid for `auth_duration`.
    ///
    /// ### Parameters
    /// - `auth_duration`: How long a grant is handed out for.
    /// - `min_clean_interval`: Shortest sleep between two [`Self::clean`] runs.
    /// - `max_clean_interval`: Longest sleep between two [`Self::clean`] runs.
    pub fn new(
        auth_duration: Duration,
        min_clean_interval: Duration,
        max_clean_interval: Duration,
    ) -> Self {
        debug_assert!(
            min_clean_interval <= max_clean_interval,
            "the clean interval bounds are the wrong way around"
        );

        Self(Arc::new(AuthServiceShared {
            inner: RwLock::new(AuthServiceInner {
                auth_ips: HashMap::new(),
                private_non_core_segments: HashMap::new(),
                private_core_segments: HashMap::new(),
            }),
            auth_duration,
            min_clean_interval,
            max_clean_interval,
        }))
    }

    fn read(&self) -> RwLockReadGuard<'_, AuthServiceInner> {
        self.0.inner.read().unwrap()
    }

    fn write(&self) -> RwLockWriteGuard<'_, AuthServiceInner> {
        self.0.inner.write().unwrap()
    }

    /// Checks if the ip has any kind of auth.
    pub fn ip_is_authorized(&self, ip: IpAddr, now: SystemTime) -> bool {
        let this = self.read();

        this.auth_ips
            .get(&ip)
            .is_some_and(|ip_auth| ip_auth.auth_dsts.values().any(|dst| dst.is_valid(now)))
    }

    /// Authorizes the given IP address for the given destinations and segments.
    ///
    /// Grants are additive: after applying the operation, the set of authorized destinations and
    /// segments is a superset of the previous set. The expiration of an authorized segment is
    /// the maximum of an already existing authorization and the provided. Already expired
    /// segments are not inserted.
    ///
    /// A segment grant is capped at the expiry of the segment it is granted on, so refreshing
    /// only extends it as far as the freshest copy of that segment allows.
    ///
    /// Note: Segments are currently not being validated in this function.
    pub fn authorize(
        &self,
        ip: IpAddr,
        destinations: HashMap<CustomerDomain, AuthSegments>,
        now: SystemTime,
    ) {
        // TODO: Auth segments are client input and should be validated.

        let dst_granted_until = now + self.0.auth_duration;

        let mut this = self.write();
        let AuthServiceInner {
            auth_ips,
            private_non_core_segments,
            private_core_segments,
        } = &mut *this;

        let auth_entry = auth_ips.entry(ip).or_default();

        for (dst, auth_segments) in destinations {
            // Get the grant entry for this (ip, dst) pair, or create a new one if it doesn't
            // exist. An existing grant is only ever extended.
            let dst_entry = auth_entry
                .auth_dsts
                .entry(dst.clone())
                .and_modify(|dst_auth| {
                    dst_auth.granted_until = dst_auth.granted_until.max(dst_granted_until);
                })
                .or_insert_with(|| DstAuthInfo::new(dst_granted_until));

            let AuthSegments {
                core_segments,
                non_core_segments,
            } = auth_segments;

            let tagged = core_segments
                .into_iter()
                .map(|segment| (segment, true))
                .chain(
                    non_core_segments
                        .into_iter()
                        .map(|segment| (segment, false)),
                );

            for (segment, is_core) in tagged {
                let fp = segment.fingerprint();
                let segment_expiry = segment.expires_earliest();

                // A grant can never outlive the segment it is granted on, see the module docs.
                let granted_until = dst_granted_until.min(segment_expiry);
                if granted_until <= now {
                    tracing::debug!(
                        %ip, %dst, %fp,
                        "Ignoring grant for a segment that has already expired"
                    );
                    continue;
                }

                let (id, store) = if is_core {
                    (GrantedSegmentId::Core(fp), &mut *private_core_segments)
                } else {
                    (
                        GrantedSegmentId::NonCore(fp),
                        &mut *private_non_core_segments,
                    )
                };

                grant_segment(
                    &mut dst_entry.segment_grants,
                    store,
                    id,
                    fp,
                    segment,
                    segment_expiry,
                    granted_until,
                );
            }
        }

        return;

        /// Records a grant for `id` and inserts or refreshes the granted segment.
        ///
        /// The per-destination grant for `id` is only ever extended, never shortened. A segment's
        /// stored copy is replaced only by a longer-lived one, and its grant count grows by one
        /// whenever this call adds a grant that did not exist before.
        fn grant_segment(
            grants: &mut HashMap<GrantedSegmentId, SegmentGrant>,
            store: &mut HashMap<SegmentFp, AuthSegmentEntry>,
            id: GrantedSegmentId,
            fp: SegmentFp,
            segment: SignedPathSegment,
            segment_expiry: SystemTime,
            granted_until: SystemTime,
        ) {
            let is_new_grant = match grants.entry(id) {
                // Extend the existing grant.
                Entry::Occupied(mut existing) => {
                    let grant = existing.get_mut();
                    grant.granted_until = grant.granted_until.max(granted_until);
                    false
                }
                // Insert a new grant.
                Entry::Vacant(vacant) => {
                    vacant.insert(SegmentGrant::new(granted_until));
                    true
                }
            };

            match store.entry(fp) {
                // Segment already exists, extend its expiry, and increase the grant count if a new
                // grant was added above.
                Entry::Occupied(mut existing) => {
                    let existing = existing.get_mut();

                    // Keep the copy that lives longest, a refresh may carry a fresher one.
                    if existing.expiration < segment_expiry {
                        existing.segment = segment;
                        existing.expiration = segment_expiry;
                    }

                    if is_new_grant {
                        existing.grant_count += 1;
                    }
                }
                // Segment does not exist yet, insert it with a grant count of 1. For the new grant
                // added above
                Entry::Vacant(vacant) => {
                    debug_assert!(
                        is_new_grant,
                        "segment store was missing a segment that was already referenced by a grant"
                    );
                    vacant.insert(AuthSegmentEntry::new(segment, segment_expiry, 1));
                }
            }
        }
    }

    /// Checks if the IP has a grant for the given SNI.
    ///
    /// Returns `None` if no valid grant exists.
    /// Returns `DstGrant` with the segments currently granted for the given SNI if a valid
    /// grant exists.
    pub fn dst_grant(
        &self,
        ip: IpAddr,
        dst: CustomerDomainRef<'_>,
        now: SystemTime,
    ) -> Option<DstGrant> {
        let this = self.read();

        let dst_auth = this.auth_ips.get(&ip)?.auth_dsts.get(dst.as_str())?;

        // Grant has already expired, return None to indicate that the client needs to
        // reauthenticate.
        if !dst_auth.is_valid(now) {
            return None;
        }

        let mut granted_segments = DstGrant::default();

        for (id, grant) in dst_auth.segment_grants.iter() {
            // Skip expired grants, they will be cleaned up later.
            if !grant.is_valid(now) {
                continue;
            }

            let (store, out) = match id {
                GrantedSegmentId::Core(_) => {
                    (
                        &this.private_core_segments,
                        &mut granted_segments.core_segments,
                    )
                }
                GrantedSegmentId::NonCore(_) => {
                    (
                        &this.private_non_core_segments,
                        &mut granted_segments.non_core_segments,
                    )
                }
            };

            let Some(segment_entry) = store.get(&id.fp()) else {
                continue;
            };

            out.insert(id.fp(), segment_entry.segment.clone());
        }

        Some(granted_segments)
    }

    /// Returns the time when the grant for the given IP and destination expires
    /// Returns `None` if there is no valid grant for the given IP and destination.
    pub fn grant_expiry(
        &self,
        ip: IpAddr,
        dst: CustomerDomainRef<'_>,
        now: SystemTime,
    ) -> Option<SystemTime> {
        let this = self.read();

        this.auth_ips
            .get(&ip)?
            .auth_dsts
            .get(dst.as_str())
            .filter(|dst_auth| dst_auth.is_valid(now))
            .map(|dst_auth| dst_auth.granted_until)
    }

    /// Returns when the given IP's grant on the given segment for the given destination expires,
    /// if that grant is valid.
    pub fn segment_grant_expiry(
        &self,
        ip: IpAddr,
        dst: CustomerDomainRef<'_>,
        id: &GrantedSegmentId,
        now: SystemTime,
    ) -> Option<SystemTime> {
        let this = self.read();

        this.auth_ips
            .get(&ip)?
            .auth_dsts
            .get(dst.as_str())?
            .segment_grants
            .get(id)
            .filter(|grant| grant.is_valid(now))
            .map(|grant| grant.granted_until)
    }

    /// Returns the token that is cancelled once the grant for the given IP and destination is
    /// gone, or `None` if there is no valid grant to watch.
    pub fn watch_grant(
        &self,
        ip: IpAddr,
        customer_domain: CustomerDomainRef<'_>,
        now: SystemTime,
    ) -> Option<CancellationToken> {
        let this = self.read();

        let grant = this
            .auth_ips
            .get(&ip)
            .and_then(|auth_entry| auth_entry.auth_dsts.get(customer_domain.as_str()));

        let Some(grant) = grant else {
            tracing::debug!(%ip, %customer_domain, "No grant found");
            return None;
        };

        if !grant.is_valid(now) {
            tracing::debug!(%ip, %customer_domain, "Grant has already expired");
            return None;
        }

        Some(grant.expired.clone())
    }

    /// Returns the token that is cancelled once the given IP's grant on the given segment for the
    /// given destination is gone, or `None` if there is no valid grant to watch.
    pub fn watch_segment_grant(
        &self,
        ip: IpAddr,
        customer_domain: CustomerDomainRef<'_>,
        id: &GrantedSegmentId,
        now: SystemTime,
    ) -> Option<CancellationToken> {
        let this = self.read();

        let segment_grant = this
            .auth_ips
            .get(&ip)?
            .auth_dsts
            .get(customer_domain.as_str())?
            .segment_grants
            .get(id)?;

        if !segment_grant.is_valid(now) {
            tracing::debug!(%ip, %customer_domain, ?id, "Segment grant has already expired");
            return None;
        }

        Some(segment_grant.expired.clone())
    }

    /// Returns the segment `id` refers to, as long as any grant on it is still valid.
    ///
    /// Returns `None` if the segment is not in the authoritative store, or if it has no valid
    /// grants.
    pub fn segment(&self, id: &GrantedSegmentId, now: SystemTime) -> Option<SignedPathSegment> {
        let this: RwLockReadGuard<'_, AuthServiceInner> = self.read();

        let store = match id {
            GrantedSegmentId::Core(_) => &this.private_core_segments,
            GrantedSegmentId::NonCore(_) => &this.private_non_core_segments,
        };

        store
            .get(&id.fp())
            .filter(|segment_entry| segment_entry.expiration > now)
            .filter(|segment_entry| {
                debug_assert!(
                    segment_entry.grant_count > 0,
                    "segment {id:?} is in the store but has no grants referencing it, it should have been removed by clean()"
                );
                segment_entry.grant_count > 0
            })
            .map(|segment_entry| segment_entry.segment.clone())
    }

    /// Drops all expired authentication state and notifies everything that waited on it.
    ///
    /// Removal cascades from the outside in:
    /// - A destination grant is removed once its `granted_until` has passed. Removing it removes
    ///   all of its segment grants, regardless of their own expiry.
    /// - A segment grant is removed once its own `granted_until` has passed.
    /// - An IP is removed once it has no destination grants left, i.e. it is fully de-authed.
    /// - A segment is removed from the authoritative store once its last grant is gone. It cannot
    ///   outlive its grants, because a grant is capped at the segment's expiry.
    ///
    /// Every removed grant has its cancellation token cancelled before it is dropped, so the
    /// streams watching it via [`Self::watch_grant`] or [`Self::watch_segment_grant`] can tear
    /// down.
    ///
    /// Returns the time the next grant expires, i.e. when calling this again has an effect.
    /// The functions should be called regularely, to ensure newly added grants are cleaned up
    /// in time.
    pub fn clean(&self, now: SystemTime) -> SystemTime {
        let mut next_expiry = now + self.0.auth_duration;

        let mut this = self.write();
        let AuthServiceInner {
            auth_ips,
            private_non_core_segments,
            private_core_segments,
        } = &mut *this;

        auth_ips.retain(|ip, ip_auth| {
            ip_auth.auth_dsts.retain(|dst, dst_auth| {
                let dst_expired = !dst_auth.is_valid(now);

                dst_auth.segment_grants.retain(|id, segment_grant| {
                    // Retain if the dst is not expired and the segment grant is not expired.
                    // Otherwise, remove it.
                    if !dst_expired && segment_grant.is_valid(now) {
                        next_expiry = next_expiry.min(segment_grant.granted_until);
                        return true;
                    }

                    // Otherwise, clean up the grant.
                    let store = match id {
                        GrantedSegmentId::Core(_) => &mut *private_core_segments,
                        GrantedSegmentId::NonCore(_) => &mut *private_non_core_segments,
                    };

                    release_segment_grant(store, id.fp());
                    segment_grant.expired.cancel();

                    tracing::trace!(%ip, %dst, fp = %id.fp(), "Removed expired segment grant");
                    false
                });

                if dst_expired {
                    dst_auth.expired.cancel();
                    tracing::debug!(%ip, %dst, "Removed expired destination grant");
                } else {
                    next_expiry = next_expiry.min(dst_auth.granted_until);
                }

                !dst_expired
            });

            let ip_authorized = !ip_auth.auth_dsts.is_empty();
            if !ip_authorized {
                tracing::debug!(%ip, "IP has no grants left, de-authorizing");
            }

            ip_authorized
        });

        // Drop segments that lost their last grant above.
        for store in [private_core_segments, private_non_core_segments] {
            store.retain(|fp, segment_entry| {
                if segment_entry.grant_count > 0 {
                    debug_assert!(
                        segment_entry.expiration > now,
                        "segment {fp} outlived by a grant, grants must be capped at the \
                         segment expiry"
                    );
                    return true;
                }

                tracing::debug!(%fp, "Removed unreferenced segment from the authoritative store");
                false
            });
        }

        next_expiry
    }

    /// Periodically runs [`Self::clean`] so grant expiry is observed close to when it happens.
    ///
    /// Reads the wall clock itself, unlike every other entry point. Never returns.
    pub async fn run(&self) {
        loop {
            let now = SystemTime::now();
            let next = self.clean(now);
            let sleep = next
                .duration_since(now)
                .unwrap_or(Duration::ZERO)
                .max(self.0.min_clean_interval)
                .min(self.0.max_clean_interval);

            tracing::trace!("Next auth service cleanup in {:?}", sleep);
            tokio::time::sleep(sleep).await;
        }
    }
}

/// Decrements the grant count of the segment `fp` refers to.
///
/// The entry itself is left in place; it is dropped by the store sweep in
/// [`AuthService::clean`] once its count has reached zero.
fn release_segment_grant(store: &mut HashMap<SegmentFp, AuthSegmentEntry>, fp: SegmentFp) {
    let Some(segment_entry) = store.get_mut(&fp) else {
        debug_assert!(false, "segment {fp} has a grant but is not in the store");
        return;
    };

    debug_assert!(
        segment_entry.grant_count > 0,
        "segment {fp} is in the store but has no grants referencing it"
    );
    segment_entry.grant_count = segment_entry.grant_count.saturating_sub(1);
}

/// Identifies a segment from the authoritative store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantedSegmentId {
    /// A core segment with the given fingerprint.
    Core(SegmentFp),
    /// An up or down segment with the given fingerprint.
    NonCore(SegmentFp),
}

impl GrantedSegmentId {
    /// The fingerprint of the segment.
    pub fn fp(&self) -> SegmentFp {
        match self {
            Self::Core(fp) | Self::NonCore(fp) => *fp,
        }
    }

    /// Returns true if this identifies a core segment.
    pub fn is_core(&self) -> bool {
        matches!(self, Self::Core(_))
    }
}

/// A segment in the authoritative store, with the number of grants referencing it.
struct AuthSegmentEntry {
    segment: SignedPathSegment,
    expiration: SystemTime,
    grant_count: usize,
}

impl AuthSegmentEntry {
    fn new(segment: SignedPathSegment, expiration: SystemTime, initial_grant_count: usize) -> Self {
        Self {
            segment,
            expiration,
            grant_count: initial_grant_count,
        }
    }
}

/// Everything one IP is authorized for.
#[derive(Default)]
struct IpAuthInfo {
    auth_dsts: HashMap<CustomerDomain, DstAuthInfo>,
}

/// A grant for one (IP, destination) pair.
struct DstAuthInfo {
    segment_grants: HashMap<GrantedSegmentId, SegmentGrant>,
    granted_until: SystemTime,
    /// Cancelled by [`AuthService::clean`] when this grant is removed.
    expired: CancellationToken,
}

impl DstAuthInfo {
    fn new(granted_until: SystemTime) -> Self {
        Self {
            segment_grants: HashMap::new(),
            granted_until,
            expired: CancellationToken::new(),
        }
    }

    fn is_valid(&self, now: SystemTime) -> bool {
        now < self.granted_until
    }
}

/// A grant for one segment within a [`DstAuthInfo`].
struct SegmentGrant {
    granted_until: SystemTime,
    /// Cancelled by [`AuthService::clean`] when this grant is removed.
    expired: CancellationToken,
}

impl SegmentGrant {
    fn new(granted_until: SystemTime) -> Self {
        Self {
            granted_until,
            expired: CancellationToken::new(),
        }
    }

    fn is_valid(&self, now: SystemTime) -> bool {
        now < self.granted_until
    }
}

/// The segments to grant for one destination in [`AuthService::authorize`].
#[derive(Default)]
pub struct AuthSegments {
    core_segments: Vec<SignedPathSegment>,
    non_core_segments: Vec<SignedPathSegment>,
}

impl AuthSegments {
    /// Creates a new set of segments to grant.
    pub fn new(
        core_segments: Vec<SignedPathSegment>,
        non_core_segments: Vec<SignedPathSegment>,
    ) -> Self {
        Self {
            core_segments,
            non_core_segments,
        }
    }
}

// XXX: this should not copy the segments, just an iterator over the granted segments, but that
// would require locking magic.
/// A grany for one destination in [`AuthService::dst_grant`].
#[derive(Default)]
pub struct DstGrant {
    core_segments: HashMap<SegmentFp, SignedPathSegment>,
    non_core_segments: HashMap<SegmentFp, SignedPathSegment>,
}

impl DstGrant {
    /// Iterates over the granted core segments.
    pub fn iter_core_segments(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.core_segments.values()
    }

    /// Iterates over the granted up and down segments.
    pub fn iter_non_core_segments(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.non_core_segments.values()
    }

    /// Returns whether a core segment with the given fingerprint is granted.
    pub fn has_core_segment(&self, fp: SegmentFp) -> bool {
        self.core_segments.contains_key(&fp)
    }

    /// Returns whether an up or down segment with the given fingerprint is granted.
    pub fn has_non_core_segment(&self, fp: SegmentFp) -> bool {
        self.non_core_segments.contains_key(&fp)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::pg_wap2::test_util::{
        Fixture, MockFetcher, at, client_ip, granted_id, other_sni, other_up_segment,
        secs_since_epoch, sni, up_segment,
    };

    #[test]
    fn refreshing_a_grant_adds_to_it_without_shortening_it() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let first = up_segment(0);
        let second = other_up_segment(0);

        fixture.grant_non_core(vec![first.clone()], at(0));
        let first_expiry = fixture
            .auth
            .segment_grant_expiry(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&first),
                at(0),
            )
            .expect("the first segment is granted");

        // A refresh 10s later that only mentions the second segment must not take the first away.
        fixture.grant_non_core(vec![second.clone()], at(10));

        assert_eq!(
            fixture.auth.segment_grant_expiry(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&first),
                at(10)
            ),
            Some(first_expiry),
            "the first grant must be kept, with its original expiry"
        );
        assert_eq!(
            fixture.auth.segment_grant_expiry(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&second),
                at(10)
            ),
            Some(at(110)),
            "the second grant runs for the full auth duration from the refresh"
        );
        assert_eq!(
            fixture
                .auth
                .grant_expiry(client_ip(), sni().customer_domain(), at(10)),
            Some(at(110)),
            "the target grant is extended by the refresh"
        );
    }

    #[test]
    fn a_segment_grant_never_outlives_its_segment() {
        // The auth duration is far longer than the segment lives.
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(10 * 24 * 3600));

        let segment = up_segment(0);
        fixture.grant_non_core(vec![segment.clone()], at(0));

        assert_eq!(
            fixture.auth.segment_grant_expiry(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&segment),
                at(0)
            ),
            Some(segment.expires_earliest()),
            "the grant must be capped at the expiry of the segment it is granted on"
        );
    }

    #[test]
    fn a_grant_on_an_expired_segment_is_ignored() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let segment = up_segment(0);
        let expired = at(secs_since_epoch(segment.expires_earliest()) + 1);
        fixture.grant_non_core(vec![segment.clone()], expired);

        assert_eq!(
            fixture.auth.segment_grant_expiry(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&segment),
                expired
            ),
            None
        );
    }

    #[tokio::test]
    async fn expired_grants_are_cleaned_up_and_observable() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let segment = up_segment(0);
        fixture.grant_non_core(vec![segment.clone()], at(0));

        let target_expired = fixture
            .auth
            .watch_grant(client_ip(), sni().customer_domain(), at(0))
            .expect("the target grant is live");
        let segment_expired = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&segment),
                at(0),
            )
            .expect("the segment grant is live");

        assert!(fixture.auth.ip_is_authorized(client_ip(), at(0)));

        // Nothing has expired yet, so cleaning changes nothing.
        assert_eq!(
            fixture.auth.clean(at(0)),
            at(100),
            "clean reports when the next grant expires"
        );
        assert!(
            fixture
                .auth
                .dst_grant(client_ip(), sni().customer_domain(), at(0))
                .is_some()
        );

        fixture.auth.clean(at(101));

        // Both notifiers were handed out before the expiry and still resolve.
        target_expired.cancelled().await;
        segment_expired.cancelled().await;

        assert!(
            !fixture.auth.ip_is_authorized(client_ip(), at(101)),
            "an IP without grants is de-authorized"
        );
        assert!(
            fixture
                .auth
                .dst_grant(client_ip(), sni().customer_domain(), at(101))
                .is_none()
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&segment), at(101))
                .is_none()
        );
        assert!(
            fixture
                .auth
                .watch_grant(client_ip(), sni().customer_domain(), at(101))
                .is_none(),
            "there is no live grant left to wait on"
        );
    }

    /// One IP with two destination grants: [`sni`] runs until t=100 with a shared and a private
    /// segment, [`other_sni`] is refreshed at t=50 and runs until t=150 with only the shared one.
    ///
    /// Returns the fixture, the shared segment and the segment only [`sni`] is granted.
    fn two_destination_fixture() -> (Fixture, SignedPathSegment, SignedPathSegment) {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let shared = up_segment(0);
        let only_sni = other_up_segment(0);

        fixture.auth.authorize(
            client_ip(),
            HashMap::from([
                (
                    sni().customer_domain().into(),
                    AuthSegments::new(Vec::new(), vec![shared.clone(), only_sni.clone()]),
                ),
                (
                    other_sni().customer_domain().into(),
                    AuthSegments::new(Vec::new(), vec![shared.clone()]),
                ),
            ]),
            at(0),
        );

        // Only the second destination re-authenticates, so the first one lapses at t=100.
        fixture.auth.authorize(
            client_ip(),
            HashMap::from([(
                other_sni().customer_domain().into(),
                AuthSegments::new(Vec::new(), vec![shared.clone()]),
            )]),
            at(50),
        );

        (fixture, shared, only_sni)
    }

    #[test]
    fn an_expired_destination_takes_only_its_own_grants_with_it() {
        let (fixture, shared, only_sni) = two_destination_fixture();

        let sni_expired = fixture
            .auth
            .watch_grant(client_ip(), sni().customer_domain(), at(50))
            .expect("the lapsing destination is granted");
        let other_expired = fixture
            .auth
            .watch_grant(client_ip(), other_sni().customer_domain(), at(50))
            .expect("the refreshed destination is granted");
        let shared_for_sni_expired = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&shared),
                at(50),
            )
            .expect("the shared segment is granted for the lapsing destination");
        let shared_for_other_expired = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                other_sni().customer_domain(),
                &granted_id(&shared),
                at(50),
            )
            .expect("the shared segment is granted for the refreshed destination");

        assert_eq!(
            fixture.auth.clean(at(101)),
            at(150),
            "the remaining destination is the next thing to expire"
        );

        assert!(
            fixture
                .auth
                .dst_grant(client_ip(), sni().customer_domain(), at(101))
                .is_none(),
            "the lapsed destination is gone"
        );
        assert!(sni_expired.is_cancelled());
        assert!(
            shared_for_sni_expired.is_cancelled(),
            "an expiring destination takes its segment grants with it, however long they had left"
        );

        let other_grant = fixture
            .auth
            .dst_grant(client_ip(), other_sni().customer_domain(), at(101))
            .expect("the refreshed destination is untouched");
        assert_eq!(
            other_grant
                .iter_non_core_segments()
                .map(SignedPathSegment::fingerprint)
                .collect::<Vec<_>>(),
            vec![shared.fingerprint()]
        );
        assert!(!other_expired.is_cancelled());
        assert!(!shared_for_other_expired.is_cancelled());

        assert!(
            fixture.auth.ip_is_authorized(client_ip(), at(101)),
            "an IP with one destination left stays authorized"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&shared), at(101))
                .is_some(),
            "the shared segment is still held by the destination that refreshed"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&only_sni), at(101))
                .is_none(),
            "the segment only the lapsed destination held lost its last grant"
        );
    }

    #[test]
    fn an_ip_is_dropped_with_its_last_destination() {
        let (fixture, shared, _only_sni) = two_destination_fixture();

        // The first destination goes at t=100, the second one at t=150.
        fixture.auth.clean(at(101));
        assert!(fixture.auth.ip_is_authorized(client_ip(), at(101)));

        fixture.auth.clean(at(151));

        assert!(
            !fixture.auth.ip_is_authorized(client_ip(), at(151)),
            "the IP is de-authorized once its last destination is gone"
        );
        assert!(
            fixture
                .auth
                .dst_grant(client_ip(), other_sni().customer_domain(), at(151))
                .is_none(),
            "and so is that last destination"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&shared), at(151))
                .is_none(),
            "a segment cannot outlive the last grant referencing it"
        );
    }

    #[test]
    fn a_refresh_that_omits_a_segment_keeps_it_until_its_own_grant_expires() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let kept = up_segment(0);
        let omitted = other_up_segment(0);
        fixture.grant_non_core(vec![kept.clone(), omitted.clone()], at(0));

        let omitted_expired = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&omitted),
                at(0),
            )
            .expect("both segments are granted");

        // The re-auth carries only one of the two segments; the other keeps running out.
        fixture.grant_non_core(vec![kept.clone()], at(50));

        assert!(
            fixture
                .auth
                .segment(&granted_id(&omitted), at(50))
                .is_some(),
            "an omitted segment stays usable while its own grant is valid"
        );
        assert!(!omitted_expired.is_cancelled());

        fixture.auth.clean(at(101));

        assert!(
            omitted_expired.is_cancelled(),
            "the omitted segment's grant expires on its own schedule"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&omitted), at(101))
                .is_none(),
            "and the segment goes with its last grant"
        );

        let grant = fixture
            .auth
            .dst_grant(client_ip(), sni().customer_domain(), at(101))
            .expect("the destination was extended by the refresh");
        assert_eq!(
            grant
                .iter_non_core_segments()
                .map(SignedPathSegment::fingerprint)
                .collect::<Vec<_>>(),
            vec![kept.fingerprint()],
            "only the refreshed segment is left"
        );
        assert!(fixture.auth.segment(&granted_id(&kept), at(101)).is_some());
    }

    #[test]
    fn granted_segments_are_returned_per_target() {
        let fixture = Fixture::new(MockFetcher::empty(), Duration::from_secs(100));

        let granted = up_segment(0);
        let other = other_up_segment(0);
        fixture.auth.authorize(
            client_ip(),
            HashMap::from([
                (
                    sni().customer_domain().into(),
                    AuthSegments::new(Vec::new(), vec![granted.clone()]),
                ),
                (
                    other_sni().customer_domain().into(),
                    AuthSegments::new(vec![other.clone()], Vec::new()),
                ),
            ]),
            at(0),
        );

        let segments = fixture
            .auth
            .dst_grant(client_ip(), sni().customer_domain(), at(0))
            .expect("the target is granted");
        assert_eq!(
            segments
                .iter_non_core_segments()
                .map(SignedPathSegment::fingerprint)
                .collect::<Vec<_>>(),
            vec![granted.fingerprint()]
        );
        assert_eq!(segments.iter_core_segments().count(), 0);

        let other_segments = fixture
            .auth
            .dst_grant(client_ip(), other_sni().customer_domain(), at(0))
            .expect("the other target is granted");
        assert_eq!(
            other_segments
                .iter_core_segments()
                .map(SignedPathSegment::fingerprint)
                .collect::<Vec<_>>(),
            vec![other.fingerprint()],
            "a segment granted for another target is only visible there"
        );

        let ungranted =
            CustomerDomain::new("ungranted.example.com".to_owned()).expect("a valid domain");
        assert!(
            fixture
                .auth
                .dst_grant(client_ip(), ungranted.as_domain(), at(0))
                .is_none()
        );
    }
}
