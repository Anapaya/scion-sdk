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
//! towards it, until a point in time:
//!
//! - **Additive**: [`AuthService::authorize`] adds targets and segments to whatever the IP already
//!   has, and never shortens an existing grant.
//! - **Bounded**: an IP holds at most [`AuthServiceConfig::max_targets_per_ip`] target grants, and
//!   a target holds at most [`AuthServiceConfig::max_segments_per_target`] segment grants. Grants
//!   over a limit evict unguarded grants, or fail.
//! - **Not revocable**: apart from that eviction, state leaves the service only via
//!   [`AuthService::clean`], and only once it has expired.
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
//! - An IP never holds more than `max_targets_per_ip` target grants.
//! - A target never holds more than `max_segments_per_target` segment grants.
//! - A grant with a live [`SegmentGrantGuard`] or [`TargetGrantGuard`] is never evicted.

use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime},
};

use sciparse::segment::{SegmentFp, SignedPathSegment};
use tokio_util::sync::CancellationToken;

use crate::pg_wap2::{
    crpc::model::AuthSegments,
    sni::{CustomerDomain, CustomerDomainRef},
};

/// Tracks which client IPs are authorized for which targets and segments.
#[derive(Clone)]
pub struct AuthService(Arc<AuthServiceShared>);

struct AuthServiceShared {
    /// The mutable authorization state.
    inner: RwLock<AuthServiceInner>,
    config: AuthServiceConfig,
}

pub struct AuthServiceConfig {
    /// How long a grant is handed out for, after which the client has to re-authorize.
    pub auth_duration: Duration,
    /// Shortest sleep between two [`AuthService::clean`] runs.
    pub min_clean_interval: Duration,
    /// Longest sleep between two [`AuthService::clean`] runs.
    pub max_clean_interval: Duration,
    /// Maximum total number of segments a client may grant in one authorization request.
    pub max_segments_per_request: usize,
    /// Maximum number of segment grants one target holds per authorized IP.
    ///
    /// Grants over the limit are evicted by [`AuthService::authorize`].
    pub max_segments_per_target: usize,
    /// Maximum number of targets a client may grant in one authorization request.
    pub max_targets_per_request: usize,
    /// Maximum number of target grants one IP holds.
    ///
    /// Grants over the limit are evicted by [`AuthService::authorize`].
    pub max_targets_per_ip: usize,
}

impl AuthServiceConfig {
    const DEFAULT_MAX_SEGMENTS_PER_REQUEST: usize = 100;
    const DEFAULT_MAX_SEGMENTS_PER_TARGET: usize = 10;
    const DEFAULT_AUTH_DURATION: Duration = Duration::from_secs(2 * 60);
    const DEFAULT_MIN_CLEAN_INTERVAL: Duration = Duration::from_secs(10);
    const DEFAULT_MAX_CLEAN_INTERVAL: Duration = Duration::from_secs(30);
    const DEFAULT_MAX_TARGETS_PER_REQUEST: usize = 10;
    const DEFAULT_MAX_TARGETS_PER_IP: usize = 50;

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.min_clean_interval > self.max_clean_interval {
            anyhow::bail!(
                "min_clean_interval ({:?}) is greater than max_clean_interval ({:?})",
                self.min_clean_interval,
                self.max_clean_interval
            );
        }

        if self.max_segments_per_request == 0 {
            anyhow::bail!("max_segments_per_request must be greater than 0");
        }

        if self.max_segments_per_target == 0 {
            anyhow::bail!("max_segments_per_target must be greater than 0");
        }

        if self.max_targets_per_request == 0 {
            anyhow::bail!("max_targets_per_request must be greater than 0");
        }

        if self.max_targets_per_ip == 0 {
            anyhow::bail!("max_targets_per_ip must be greater than 0");
        }

        if self.auth_duration == Duration::ZERO {
            anyhow::bail!("auth_duration must be greater than 0");
        }

        if self.min_clean_interval == Duration::ZERO {
            anyhow::bail!("min_clean_interval must be greater than 0");
        }

        if self.max_clean_interval == Duration::ZERO {
            anyhow::bail!("max_clean_interval must be greater than 0");
        }

        Ok(())
    }
}

impl Default for AuthServiceConfig {
    fn default() -> Self {
        Self {
            auth_duration: Self::DEFAULT_AUTH_DURATION,
            min_clean_interval: Self::DEFAULT_MIN_CLEAN_INTERVAL,
            max_clean_interval: Self::DEFAULT_MAX_CLEAN_INTERVAL,
            max_segments_per_request: Self::DEFAULT_MAX_SEGMENTS_PER_REQUEST,
            max_segments_per_target: Self::DEFAULT_MAX_SEGMENTS_PER_TARGET,
            max_targets_per_request: Self::DEFAULT_MAX_TARGETS_PER_REQUEST,
            max_targets_per_ip: Self::DEFAULT_MAX_TARGETS_PER_IP,
        }
    }
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
    /// Creates an empty service handing out grants as `config` describes.
    ///
    /// Returns an error if `config` does not [`AuthServiceConfig::validate`].
    pub fn new(config: AuthServiceConfig) -> anyhow::Result<Self> {
        config.validate()?;

        Ok(Self(Arc::new(AuthServiceShared {
            inner: RwLock::new(AuthServiceInner {
                auth_ips: HashMap::new(),
                private_non_core_segments: HashMap::new(),
                private_core_segments: HashMap::new(),
            }),
            config,
        })))
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
    /// An IP holds at most [`AuthServiceConfig::max_targets_per_ip`] destination grants, and a
    /// destination holds at most [`AuthServiceConfig::max_segments_per_target`] segment grants.
    /// A request that does not fit evicts destination grants without a [`TargetGrantGuard`], and
    /// segment grants without a [`SegmentGrantGuard`]. Grants with the least time left are evicted
    /// first. Evicting a destination grant removes its segment grants as well.
    ///
    /// The request is rejected if eviction can not free enough room, or if it supplies too many
    /// destinations or segments at once. A rejection does not modify the state of the service.
    ///
    /// Note: Segments are currently not being validated in this function.
    pub fn authorize(
        &self,
        ip: IpAddr,
        destinations: HashMap<CustomerDomain, AuthSegments>,
        now: SystemTime,
    ) -> Result<(), AuthorizeError> {
        if destinations.len() > self.0.config.max_targets_per_request {
            return Err(AuthorizeError::TooManyTargetsInRequest {
                requested: destinations.len(),
                max: self.0.config.max_targets_per_request,
            });
        }

        if destinations.len() > self.0.config.max_targets_per_ip {
            return Err(AuthorizeError::TooManyTargetsForIp {
                requested: destinations.len(),
                max: self.0.config.max_targets_per_ip,
            });
        }

        let requested = destinations
            .values()
            .map(AuthSegments::count)
            .sum::<usize>();

        if requested > self.0.config.max_segments_per_request {
            return Err(AuthorizeError::TooManySegmentsInRequest {
                requested,
                max: self.0.config.max_segments_per_request,
            });
        }

        // TODO: Auth segments are client input and should be validated.

        let dst_granted_until = now + self.0.config.auth_duration;

        let mut this = self.write();

        // Plan against the current state, before changing any of it.
        let evicted_targets =
            plan_targets(&this, self.0.config.max_targets_per_ip, ip, &destinations)?;

        let plans = destinations
            .into_iter()
            .map(|(dst, auth_segments)| {
                plan_destination(
                    &this,
                    self.0.config.max_segments_per_target,
                    ip,
                    dst,
                    auth_segments,
                    dst_granted_until,
                    now,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let AuthServiceInner {
            auth_ips,
            private_non_core_segments,
            private_core_segments,
        } = &mut *this;

        let auth_entry = auth_ips.entry(ip).or_default();

        for dst in evicted_targets {
            evict_target_grant(
                &mut auth_entry.auth_dsts,
                private_core_segments,
                private_non_core_segments,
                &dst,
            );
            tracing::debug!(%ip, %dst, "Evicted an unused target grant");
        }

        for DstPlan {
            dst,
            grants,
            evictions,
        } in plans
        {
            // Get the grant entry for this (ip, dst) pair, or create a new one if it doesn't
            // exist. An existing grant is only ever extended.
            let dst_entry = auth_entry
                .auth_dsts
                .entry(dst.clone())
                .and_modify(|dst_auth| {
                    dst_auth.granted_until = dst_auth.granted_until.max(dst_granted_until);
                })
                .or_insert_with(|| DstAuthInfo::new(dst_granted_until));

            // Evict grants
            for id in evictions {
                evict_segment_grant(
                    &mut dst_entry.segment_grants,
                    segment_store(id, private_core_segments, private_non_core_segments),
                    id,
                );
                tracing::debug!(%ip, %dst, fp = %id.fp(), "Evicted an unused segment grant");
            }

            for PlannedGrant {
                id,
                segment,
                segment_expiry,
                granted_until,
            } in grants
            {
                grant_segment(
                    &mut dst_entry.segment_grants,
                    segment_store(id, private_core_segments, private_non_core_segments),
                    id,
                    segment,
                    segment_expiry,
                    granted_until,
                );
            }
        }

        Ok(())
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

    /// Guards the grant for the given IP and destination against eviction.
    ///
    /// Returns `None` if there is no valid grant to watch.
    pub fn watch_grant(
        &self,
        ip: IpAddr,
        customer_domain: CustomerDomainRef<'_>,
        now: SystemTime,
    ) -> Option<TargetGrantGuard> {
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

        Some(grant.guard())
    }

    /// Guards the given IP's grant on the given segment for the given destination.
    ///
    /// Returns `None` if there is no valid grant.
    pub fn watch_segment_grant(
        &self,
        ip: IpAddr,
        customer_domain: CustomerDomainRef<'_>,
        id: &GrantedSegmentId,
        now: SystemTime,
    ) -> Option<SegmentGrantGuard> {
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

        Some(segment_grant.guard())
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
        let mut next_expiry = now + self.0.config.auth_duration;

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
                .max(self.0.config.min_clean_interval)
                .min(self.0.config.max_clean_interval);

            tracing::trace!("Next auth service cleanup in {:?}", sleep);
            tokio::time::sleep(sleep).await;
        }
    }
}

/// Picks the target grants an [`AuthService::authorize`] call has to evict to fit `max_targets`.
///
/// Changes nothing, so a caller can plan every destination before applying any of them.
///
/// The IP holds the requested targets plus the ones the request does not name. Targets over
/// `max_targets` are evicted, by these rules:
/// - A requested target is never evicted. It is refreshed instead.
/// - A target with a live [`TargetGrantGuard`], or with a segment grant that a consumer holds, is
///   never evicted.
/// - Of the rest, the ones that expire first are evicted, until the IP fits.
///
/// Fails, and plans nothing, if evicting every evictable target still does not fit. Returns
/// [`AuthorizeError::IpTargetLimitReached`].
fn plan_targets(
    inner: &AuthServiceInner,
    max_targets: usize,
    ip: IpAddr,
    requested: &HashMap<CustomerDomain, AuthSegments>,
) -> Result<Vec<CustomerDomain>, AuthorizeError> {
    let Some(ip_auth) = inner.auth_ips.get(&ip) else {
        return Ok(Vec::new());
    };

    // The targets the request refreshes are already counted in `requested`.
    let untouched = ip_auth
        .auth_dsts
        .keys()
        .filter(|dst| !requested.contains_key(*dst))
        .count();
    let over = (untouched + requested.len()).saturating_sub(max_targets);

    if over == 0 {
        return Ok(Vec::new());
    }

    // The evictable targets, ordered by the rules above.
    let mut candidates = ip_auth
        .auth_dsts
        .iter()
        .filter(|(dst, dst_auth)| !requested.contains_key(*dst) && !dst_auth.is_in_use())
        .map(|(dst, dst_auth)| (dst_auth.granted_until, dst))
        .collect::<Vec<_>>();

    if candidates.len() < over {
        return Err(AuthorizeError::IpTargetLimitReached {
            in_use: untouched - candidates.len(),
            needed: over,
            max: max_targets,
        });
    }

    candidates.sort_unstable_by(|(left_expiry, left_dst), (right_expiry, right_dst)| {
        left_expiry
            .cmp(right_expiry)
            .then_with(|| left_dst.as_str().cmp(right_dst.as_str()))
    });

    Ok(candidates
        .into_iter()
        .take(over)
        .map(|(_, dst)| dst.clone())
        .collect())
}

/// Plans the changes one destination of an [`AuthService::authorize`] call turns into.
///
/// Changes nothing, so a caller can plan every destination before applying any of them.
///
/// The requested segments become the wanted grants:
/// - Up and down segments become non-core grants, core segments become core grants.
/// - The same [`GrantedSegmentId`] wanted more than once is one grant, on the longest lived copy.
/// - A segment that is already expired is dropped.
///
/// The destination then holds the wanted grants plus the ones the request does not name.
/// Grants over `max_grants` are evicted, by these rules:
/// - A wanted grant is never evicted. It is refreshed instead.
/// - A grant with a live [`SegmentGrantGuard`] is never evicted.
/// - Of the rest, the ones that expire first are evicted, until the destination fits.
///
/// Fails, and plans nothing, if:
/// - The request wants more than `max_grants` grants. Returns
///   [`AuthorizeError::TooManySegmentsForTarget`].
/// - Evicting every evictable grant still does not fit. Returns
///   [`AuthorizeError::TargetGrantLimitReached`].
fn plan_destination(
    inner: &AuthServiceInner,
    max_grants: usize,
    ip: IpAddr,
    dst: CustomerDomain,
    auth_segments: AuthSegments,
    dst_granted_until: SystemTime,
    now: SystemTime,
) -> Result<DstPlan, AuthorizeError> {
    let AuthSegments {
        up_segments,
        down_segments,
        core_segments,
    } = auth_segments;

    // Up and down segments both become non-core grants, see `GrantedSegmentId`.
    let tagged = core_segments
        .into_iter()
        .map(|segment| (segment, true))
        .chain(
            up_segments
                .into_iter()
                .chain(down_segments)
                .map(|segment| (segment, false)),
        );

    // Deduplicate segments.
    let mut wanted: HashMap<GrantedSegmentId, PlannedGrant> = HashMap::new();

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

        let id = if is_core {
            GrantedSegmentId::Core(fp)
        } else {
            GrantedSegmentId::NonCore(fp)
        };

        let planned = PlannedGrant {
            id,
            segment,
            segment_expiry,
            granted_until,
        };

        match wanted.entry(id) {
            // Keep the copy that lives longest.
            Entry::Occupied(mut existing) => {
                if existing.get().segment_expiry < segment_expiry {
                    existing.insert(planned);
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(planned);
            }
        }
    }

    if wanted.len() > max_grants {
        return Err(AuthorizeError::TooManySegmentsForTarget {
            dst,
            requested: wanted.len(),
            max: max_grants,
        });
    }

    let held = inner
        .auth_ips
        .get(&ip)
        .and_then(|ip_auth| ip_auth.auth_dsts.get(&dst));

    let mut evictions = Vec::new();

    if let Some(dst_auth) = held {
        // The grants the request refreshes are already counted in `wanted`.
        let untouched = dst_auth
            .segment_grants
            .keys()
            .filter(|id| !wanted.contains_key(id))
            .count();
        let over = (untouched + wanted.len()).saturating_sub(max_grants);

        if over > 0 {
            // The evictable grants, ordered by the rules above.
            let mut candidates = dst_auth
                .segment_grants
                .iter()
                .filter(|(id, grant)| !wanted.contains_key(id) && !grant.is_in_use())
                .map(|(id, grant)| (grant.granted_until, *id))
                .collect::<Vec<_>>();

            if candidates.len() < over {
                return Err(AuthorizeError::TargetGrantLimitReached {
                    dst,
                    in_use: untouched - candidates.len(),
                    needed: over,
                    max: max_grants,
                });
            }

            candidates.sort_unstable();
            evictions.extend(candidates.into_iter().take(over).map(|(_, id)| id));
        }
    }

    Ok(DstPlan {
        dst,
        grants: wanted.into_values().collect(),
        evictions,
    })
}

/// Picks the authoritative store `id` belongs to.
fn segment_store<'store>(
    id: GrantedSegmentId,
    core: &'store mut HashMap<SegmentFp, AuthSegmentEntry>,
    non_core: &'store mut HashMap<SegmentFp, AuthSegmentEntry>,
) -> &'store mut HashMap<SegmentFp, AuthSegmentEntry> {
    if id.is_core() { core } else { non_core }
}

/// Records a grant for `id` and inserts or refreshes the granted segment.
///
/// - The grant for `id` is only ever extended, never shortened.
/// - The stored copy of the segment is replaced only by a longer lived one.
/// - The grant count grows by one only if this call adds a grant that did not exist before.
fn grant_segment(
    grants: &mut HashMap<GrantedSegmentId, SegmentGrant>,
    store: &mut HashMap<SegmentFp, AuthSegmentEntry>,
    id: GrantedSegmentId,
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

    match store.entry(id.fp()) {
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

/// Drops the grant on `id` before it expired.
///
/// - Cancels the grant's token.
/// - Releases the grant's hold on the segment.
/// - Drops the segment from the store if it lost its last grant.
fn evict_segment_grant(
    grants: &mut HashMap<GrantedSegmentId, SegmentGrant>,
    store: &mut HashMap<SegmentFp, AuthSegmentEntry>,
    id: GrantedSegmentId,
) {
    let Some(grant) = grants.remove(&id) else {
        debug_assert!(
            false,
            "grant {id:?} was planned for eviction but is not there"
        );
        return;
    };

    drop_segment_grant(store, id.fp(), grant);
}

/// Drops the target grant on `dst`, and all of its segment grants, before they expired.
///
/// Cancels the token of the target grant and of every segment grant it held.
fn evict_target_grant(
    auth_dsts: &mut HashMap<CustomerDomain, DstAuthInfo>,
    core: &mut HashMap<SegmentFp, AuthSegmentEntry>,
    non_core: &mut HashMap<SegmentFp, AuthSegmentEntry>,
    dst: &CustomerDomain,
) {
    let Some(dst_auth) = auth_dsts.remove(dst) else {
        debug_assert!(
            false,
            "target {dst} was planned for eviction but is not there"
        );
        return;
    };

    for (id, grant) in dst_auth.segment_grants {
        drop_segment_grant(segment_store(id, core, non_core), id.fp(), grant);
    }

    dst_auth.expired.cancel();
}

/// Releases `grant`'s hold on the segment `fp` refers to and cancels the grant.
///
/// Drops the segment from the store if it lost its last grant. The caller has already taken the
/// grant out of the map that held it.
fn drop_segment_grant(
    store: &mut HashMap<SegmentFp, AuthSegmentEntry>,
    fp: SegmentFp,
    grant: SegmentGrant,
) {
    release_segment_grant(store, fp);

    // Drop the segment right away; there is no sweep after this, unlike in `clean`.
    if store
        .get(&fp)
        .is_some_and(|segment_entry| segment_entry.grant_count == 0)
    {
        store.remove(&fp);
        tracing::debug!(%fp, "Removed unreferenced segment from the authoritative store");
    }

    grant.expired.cancel();
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

/// Failures of [`AuthService::authorize`].
#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    /// The request is over [`AuthServiceConfig::max_segments_per_request`].
    #[error("request grants {requested} segments, at most {max} are allowed per request")]
    TooManySegmentsInRequest { requested: usize, max: usize },
    /// The request is over [`AuthServiceConfig::max_targets_per_request`].
    #[error("request has {requested} targets, at most {max} are allowed per request")]
    TooManyTargetsInRequest { requested: usize, max: usize },

    /// One destination of the request is over [`AuthServiceConfig::max_segments_per_target`].
    #[error("request grants {requested} segments for {dst}, at most {max} are allowed per target")]
    TooManySegmentsForTarget {
        dst: CustomerDomain,
        requested: usize,
        max: usize,
    },

    /// One destination is at its limit, and too many of its grants are guarded to evict.
    #[error(
        "target {dst} needs {needed} of its {max} segment grants freed, but {in_use} of the \
         candidates are in use"
    )]
    TargetGrantLimitReached {
        dst: CustomerDomain,
        in_use: usize,
        needed: usize,
        max: usize,
    },

    /// The request alone is over [`AuthServiceConfig::max_targets_per_ip`].
    #[error("request has {requested} targets, an IP may hold at most {max}")]
    TooManyTargetsForIp { requested: usize, max: usize },
    /// The IP is at its limit, and too many of its target grants are in use to evict.
    #[error(
        "the IP needs {needed} of its {max} target grants freed, but {in_use} of the candidates \
         are in use"
    )]
    IpTargetLimitReached {
        in_use: usize,
        needed: usize,
        max: usize,
    },
}

/// The changes [`AuthService::authorize`] applies to one destination.
struct DstPlan {
    dst: CustomerDomain,
    /// The grants to add or extend, deduplicated by id.
    grants: Vec<PlannedGrant>,
    /// The grants to evict first.
    evictions: Vec<GrantedSegmentId>,
}

/// One grant of a [`DstPlan`].
struct PlannedGrant {
    id: GrantedSegmentId,
    segment: SignedPathSegment,
    segment_expiry: SystemTime,
    granted_until: SystemTime,
}

/// Identification of a segment of the authoritative store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Cancelled when this grant is removed, either by [`AuthService::clean`] or by eviction.
    expired: CancellationToken,
    /// Holds one strong reference per live [`TargetGrantGuard`], plus the one kept here.
    in_use: Arc<()>,
}

impl DstAuthInfo {
    fn new(granted_until: SystemTime) -> Self {
        Self {
            segment_grants: HashMap::new(),
            granted_until,
            expired: CancellationToken::new(),
            in_use: Arc::new(()),
        }
    }

    fn is_valid(&self, now: SystemTime) -> bool {
        now < self.granted_until
    }

    /// Whether a consumer holds this grant, or one of the segment grants it would take with it.
    ///
    /// May stay true for a moment after the last guard is dropped.
    fn is_in_use(&self) -> bool {
        Arc::strong_count(&self.in_use) > 1
            || self.segment_grants.values().any(SegmentGrant::is_in_use)
    }

    /// Guards this grant from eviction.
    fn guard(&self) -> TargetGrantGuard {
        TargetGrantGuard {
            expired: self.expired.clone(),
            _in_use: Arc::clone(&self.in_use),
        }
    }
}

/// A grant for one segment within a [`DstAuthInfo`].
struct SegmentGrant {
    granted_until: SystemTime,
    /// Cancelled when this grant is removed, either by [`AuthService::clean`] or by eviction.
    expired: CancellationToken,
    /// Holds one strong reference per live [`SegmentGrantGuard`], plus the one kept here.
    in_use: Arc<()>,
}

impl SegmentGrant {
    fn new(granted_until: SystemTime) -> Self {
        Self {
            granted_until,
            expired: CancellationToken::new(),
            in_use: Arc::new(()),
        }
    }

    fn is_valid(&self, now: SystemTime) -> bool {
        now < self.granted_until
    }

    /// Whether a [`SegmentGrantGuard`] on this grant is alive.
    ///
    /// May stay true for a moment after the last guard is dropped.
    fn is_in_use(&self) -> bool {
        Arc::strong_count(&self.in_use) > 1
    }

    /// Guards this grant from eviction.
    fn guard(&self) -> SegmentGrantGuard {
        SegmentGrantGuard {
            expired: self.expired.clone(),
            _in_use: Arc::clone(&self.in_use),
        }
    }
}

/// Guards a target grant from eviction, and allows a client to observe expiry.
///
/// Handed out by [`AuthService::watch_grant`].
/// Use [`Self::expired`] to await expiry.
pub struct TargetGrantGuard {
    expired: CancellationToken,
    /// Counted by [`DstAuthInfo::is_in_use`] for as long as this guard lives.
    _in_use: Arc<()>,
}

impl TargetGrantGuard {
    /// The token that is cancelled once the grant is gone.
    ///
    /// Cancellation is latched.
    pub fn expired(&self) -> &CancellationToken {
        &self.expired
    }
}

/// Guards a segment grant from eviction, and allows a client to observe expiry.
///
/// Handed out by [`AuthService::watch_segment_grant`].
/// Use [`Self::expired`] to await expiry.
pub struct SegmentGrantGuard {
    expired: CancellationToken,
    /// Counted by [`SegmentGrant::is_in_use`] for as long as this guard lives.
    _in_use: Arc<()>,
}

impl SegmentGrantGuard {
    /// The token that is cancelled once the grant is gone.
    ///
    /// Cancellation is latched.
    pub fn expired(&self) -> &CancellationToken {
        &self.expired
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
        Fixture, MockFetcher, at, client_ip, granted_id, nth_sni, nth_up_segment, other_client_ip,
        other_sni, other_up_segment, secs_since_epoch, sni, up_segment,
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
        target_expired.expired().cancelled().await;
        segment_expired.expired().cancelled().await;

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

        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (
                        sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![shared.clone(), only_sni.clone()],
                            ..AuthSegments::default()
                        },
                    ),
                    (
                        other_sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![shared.clone()],
                            ..AuthSegments::default()
                        },
                    ),
                ]),
                at(0),
            )
            .expect("both destinations fit");

        // Only the second destination re-authenticates, so the first one lapses at t=100.
        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(
                    other_sni().customer_domain().into(),
                    AuthSegments {
                        up_segments: vec![shared.clone()],
                        ..AuthSegments::default()
                    },
                )]),
                at(50),
            )
            .expect("the refresh fits");

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
        assert!(sni_expired.expired().is_cancelled());
        assert!(
            shared_for_sni_expired.expired().is_cancelled(),
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
        assert!(!other_expired.expired().is_cancelled());
        assert!(!shared_for_other_expired.expired().is_cancelled());

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
        assert!(!omitted_expired.expired().is_cancelled());

        fixture.auth.clean(at(101));

        assert!(
            omitted_expired.expired().is_cancelled(),
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
        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (
                        sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![granted.clone()],
                            ..AuthSegments::default()
                        },
                    ),
                    (
                        other_sni().customer_domain().into(),
                        AuthSegments {
                            core_segments: vec![other.clone()],
                            ..AuthSegments::default()
                        },
                    ),
                ]),
                at(0),
            )
            .expect("both destinations fit");

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

    /// A fixture whose targets hold at most `max_grants` segment grants, with a 100s duration.
    fn capped_fixture(max_grants: usize) -> Fixture {
        Fixture::with_auth_config(
            MockFetcher::empty(),
            AuthServiceConfig {
                auth_duration: Duration::from_secs(100),
                max_segments_per_target: max_grants,
                ..Fixture::auth_config_defaults()
            },
        )
    }

    /// When the test client's grant on `segment` for [`sni`] expires, if it holds one.
    fn expiry_of(
        fixture: &Fixture,
        segment: &SignedPathSegment,
        now: SystemTime,
    ) -> Option<SystemTime> {
        fixture.auth.segment_grant_expiry(
            client_ip(),
            sni().customer_domain(),
            &granted_id(segment),
            now,
        )
    }

    #[test]
    fn a_target_at_its_limit_evicts_its_oldest_unused_grant() {
        let fixture = capped_fixture(2);

        let oldest = nth_up_segment(0);
        let newer = nth_up_segment(1);
        let extra = nth_up_segment(2);

        fixture.grant_non_core(vec![oldest.clone()], at(0));
        fixture.grant_non_core(vec![newer.clone()], at(10));

        // Watching a grant holds it, so keep only the token: this one is meant to be evictable.
        let watch = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&oldest),
                at(10),
            )
            .expect("the first segment is granted");
        let oldest_expired = watch.expired().clone();
        drop(watch);

        fixture.grant_non_core(vec![extra.clone()], at(20));

        assert_eq!(
            expiry_of(&fixture, &oldest, at(20)),
            None,
            "the grant with the least left to lose made room for the new one"
        );
        assert!(
            oldest_expired.is_cancelled(),
            "an evicted grant is cancelled, just like an expired one"
        );
        assert!(
            fixture.auth.segment(&granted_id(&oldest), at(20)).is_none(),
            "and the segment goes with its last grant"
        );

        assert_eq!(expiry_of(&fixture, &newer, at(20)), Some(at(110)));
        assert_eq!(expiry_of(&fixture, &extra, at(20)), Some(at(120)));
    }

    #[test]
    fn a_grant_a_consumer_holds_is_not_evicted() {
        let fixture = capped_fixture(2);

        let held = nth_up_segment(0);
        let unheld = nth_up_segment(1);
        let extra = nth_up_segment(2);

        // The held grant is the older of the two, so it would go first if nobody had it.
        fixture.grant_non_core(vec![held.clone()], at(0));
        fixture.grant_non_core(vec![unheld.clone()], at(10));

        let hold = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&held),
                at(10),
            )
            .expect("the first segment is granted");

        fixture.grant_non_core(vec![extra.clone()], at(20));

        assert_eq!(
            expiry_of(&fixture, &held, at(20)),
            Some(at(100)),
            "a grant a consumer still holds is spared, however little it has left"
        );
        assert!(!hold.expired().is_cancelled());
        assert_eq!(
            expiry_of(&fixture, &unheld, at(20)),
            None,
            "the next candidate goes instead"
        );
        assert_eq!(expiry_of(&fixture, &extra, at(20)), Some(at(120)));
    }

    #[test]
    fn dropping_a_hold_frees_the_grant_for_eviction_again() {
        let fixture = capped_fixture(1);

        let held = nth_up_segment(0);
        let extra = nth_up_segment(1);

        fixture.grant_non_core(vec![held.clone()], at(0));

        let hold = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                sni().customer_domain(),
                &granted_id(&held),
                at(0),
            )
            .expect("the segment is granted");

        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(
                    sni().customer_domain().into(),
                    AuthSegments {
                        up_segments: vec![extra.clone()],
                        ..AuthSegments::default()
                    },
                )]),
                at(10),
            )
            .expect_err("the only grant of the target is in use");

        drop(hold);

        fixture.grant_non_core(vec![extra.clone()], at(20));

        assert_eq!(expiry_of(&fixture, &held, at(20)), None);
        assert_eq!(expiry_of(&fixture, &extra, at(20)), Some(at(120)));
    }

    #[test]
    fn a_request_that_cannot_free_room_is_rejected_whole() {
        let fixture = capped_fixture(2);

        let first = nth_up_segment(0);
        let second = nth_up_segment(1);
        let extra = nth_up_segment(2);

        fixture.grant_non_core(vec![first.clone(), second.clone()], at(0));

        let holds = [&first, &second].map(|segment| {
            fixture
                .auth
                .watch_segment_grant(
                    client_ip(),
                    sni().customer_domain(),
                    &granted_id(segment),
                    at(0),
                )
                .expect("both segments are granted")
        });

        // The same request carries a second destination, which would have fit on its own.
        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (
                        sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![extra.clone()],
                            ..AuthSegments::default()
                        },
                    ),
                    (
                        other_sni().customer_domain().into(),
                        AuthSegments::default(),
                    ),
                ]),
                at(10),
            )
            .expect_err("a full target whose grants are all in use takes nothing more");

        assert!(
            matches!(
                error,
                AuthorizeError::TargetGrantLimitReached {
                    needed: 1,
                    in_use: 2,
                    max: 2,
                    ..
                }
            ),
            "{error:?}"
        );

        assert!(holds.iter().all(|hold| !hold.expired().is_cancelled()));
        assert_eq!(expiry_of(&fixture, &first, at(10)), Some(at(100)));
        assert_eq!(expiry_of(&fixture, &second, at(10)), Some(at(100)));
        assert_eq!(
            expiry_of(&fixture, &extra, at(10)),
            None,
            "the segment that did not fit was not granted"
        );
        assert_eq!(
            fixture
                .auth
                .grant_expiry(client_ip(), sni().customer_domain(), at(10)),
            Some(at(100)),
            "and the target grant it came with was not extended either"
        );
        assert!(
            fixture
                .auth
                .grant_expiry(client_ip(), other_sni().customer_domain(), at(10))
                .is_none(),
            "the destination that would have fit is rejected with the request it came in"
        );
    }

    #[test]
    fn a_request_granting_more_than_a_target_can_hold_is_rejected() {
        let fixture = capped_fixture(2);

        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(
                    sni().customer_domain().into(),
                    AuthSegments {
                        up_segments: vec![nth_up_segment(0), nth_up_segment(1)],
                        core_segments: vec![nth_up_segment(2)],
                        ..AuthSegments::default()
                    },
                )]),
                at(0),
            )
            .expect_err("three segments never fit into two grants");

        assert!(
            matches!(
                error,
                AuthorizeError::TooManySegmentsForTarget {
                    requested: 3,
                    max: 2,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(
            !fixture.auth.ip_is_authorized(client_ip(), at(0)),
            "a rejected request leaves the IP as unauthorized as it was"
        );
    }

    #[test]
    fn a_request_over_the_request_limit_is_rejected() {
        let fixture = Fixture::with_auth_config(
            MockFetcher::empty(),
            AuthServiceConfig {
                auth_duration: Duration::from_secs(100),
                max_segments_per_request: 1,
                ..Fixture::auth_config_defaults()
            },
        );

        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (
                        sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![up_segment(0)],
                            ..AuthSegments::default()
                        },
                    ),
                    (
                        other_sni().customer_domain().into(),
                        AuthSegments {
                            up_segments: vec![other_up_segment(0)],
                            ..AuthSegments::default()
                        },
                    ),
                ]),
                at(0),
            )
            .expect_err("one segment per destination is two over the whole request");

        assert!(
            matches!(
                error,
                AuthorizeError::TooManySegmentsInRequest {
                    requested: 2,
                    max: 1
                }
            ),
            "{error:?}"
        );
        assert!(!fixture.auth.ip_is_authorized(client_ip(), at(0)));
    }

    #[test]
    fn the_same_segment_granted_twice_costs_one_grant() {
        let fixture = capped_fixture(1);

        // Up and down segments both become the same non-core grant, see `GrantedSegmentId`.
        let segment = nth_up_segment(0);
        fixture.grant_for(
            client_ip(),
            sni().customer_domain(),
            AuthSegments {
                up_segments: vec![segment.clone()],
                down_segments: vec![segment.clone()],
                ..AuthSegments::default()
            },
            at(0),
        );

        assert_eq!(expiry_of(&fixture, &segment, at(0)), Some(at(100)));
    }

    #[test]
    fn a_core_and_a_non_core_grant_on_one_segment_are_two_grants() {
        let fixture = capped_fixture(1);

        let segment = nth_up_segment(0);
        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(
                    sni().customer_domain().into(),
                    AuthSegments {
                        up_segments: vec![segment.clone()],
                        core_segments: vec![segment.clone()],
                        ..AuthSegments::default()
                    },
                )]),
                at(0),
            )
            .expect_err("the two grants are told apart by more than the fingerprint");

        assert!(
            matches!(
                error,
                AuthorizeError::TooManySegmentsForTarget {
                    requested: 2,
                    max: 1,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn refreshing_a_target_at_its_limit_evicts_nothing() {
        let fixture = capped_fixture(2);

        let first = nth_up_segment(0);
        let second = nth_up_segment(1);

        fixture.grant_non_core(vec![first.clone(), second.clone()], at(0));
        fixture.grant_non_core(vec![first.clone(), second.clone()], at(10));

        assert_eq!(expiry_of(&fixture, &first, at(10)), Some(at(110)));
        assert_eq!(expiry_of(&fixture, &second, at(10)), Some(at(110)));
    }

    #[test]
    fn the_limit_is_per_target_not_per_ip() {
        let fixture = capped_fixture(1);

        let for_sni = nth_up_segment(0);
        let for_other = nth_up_segment(1);

        fixture.grant_for(
            client_ip(),
            sni().customer_domain(),
            AuthSegments {
                up_segments: vec![for_sni.clone()],
                ..AuthSegments::default()
            },
            at(0),
        );
        fixture.grant_for(
            client_ip(),
            other_sni().customer_domain(),
            AuthSegments {
                up_segments: vec![for_other.clone()],
                ..AuthSegments::default()
            },
            at(0),
        );

        assert_eq!(expiry_of(&fixture, &for_sni, at(0)), Some(at(100)));
        assert_eq!(
            fixture.auth.segment_grant_expiry(
                client_ip(),
                other_sni().customer_domain(),
                &granted_id(&for_other),
                at(0)
            ),
            Some(at(100))
        );
    }
    /// A fixture whose IPs hold at most `max_targets` target grants, with a 100s duration.
    fn target_capped_fixture(max_targets: usize) -> Fixture {
        Fixture::with_auth_config(
            MockFetcher::empty(),
            AuthServiceConfig {
                auth_duration: Duration::from_secs(100),
                max_targets_per_ip: max_targets,
                ..Fixture::auth_config_defaults()
            },
        )
    }

    /// Grants `ip` the `n`th target over the `n`th up segment.
    fn grant_nth_target(fixture: &Fixture, ip: IpAddr, n: usize, now: SystemTime) {
        fixture.grant_for(
            ip,
            nth_sni(n).customer_domain(),
            AuthSegments {
                up_segments: vec![nth_up_segment(n as u16)],
                ..AuthSegments::default()
            },
            now,
        );
    }

    /// When the test client's grant on the `n`th target expires, if it holds one.
    fn target_expiry_of(fixture: &Fixture, n: usize, now: SystemTime) -> Option<SystemTime> {
        fixture
            .auth
            .grant_expiry(client_ip(), nth_sni(n).customer_domain(), now)
    }

    #[test]
    fn an_ip_at_its_target_limit_evicts_its_oldest_unused_target() {
        let fixture = target_capped_fixture(2);

        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, client_ip(), 1, at(10));

        // Watching a target holds it, so keep only the token: this one is meant to be evictable.
        let watch = fixture
            .auth
            .watch_grant(client_ip(), nth_sni(0).customer_domain(), at(10))
            .expect("the first target is granted");
        let oldest_expired = watch.expired().clone();
        drop(watch);

        grant_nth_target(&fixture, client_ip(), 2, at(20));

        assert_eq!(
            target_expiry_of(&fixture, 0, at(20)),
            None,
            "the target with the least left to lose made room for the new one"
        );
        assert!(
            oldest_expired.is_cancelled(),
            "an evicted target is cancelled, just like an expired one"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&nth_up_segment(0)), at(20))
                .is_none(),
            "an evicted target takes its segment grants with it"
        );

        assert_eq!(target_expiry_of(&fixture, 1, at(20)), Some(at(110)));
        assert_eq!(target_expiry_of(&fixture, 2, at(20)), Some(at(120)));
    }

    #[test]
    fn a_target_a_consumer_holds_is_not_evicted() {
        let fixture = target_capped_fixture(2);

        // The held target is the older of the two, so it would go first if nobody had it.
        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, client_ip(), 1, at(10));

        let hold = fixture
            .auth
            .watch_grant(client_ip(), nth_sni(0).customer_domain(), at(10))
            .expect("the first target is granted");

        grant_nth_target(&fixture, client_ip(), 2, at(20));

        assert_eq!(
            target_expiry_of(&fixture, 0, at(20)),
            Some(at(100)),
            "a target a consumer still holds is spared, however little it has left"
        );
        assert!(!hold.expired().is_cancelled());
        assert_eq!(
            target_expiry_of(&fixture, 1, at(20)),
            None,
            "the next candidate goes instead"
        );
        assert_eq!(target_expiry_of(&fixture, 2, at(20)), Some(at(120)));
    }

    #[test]
    fn a_target_whose_segment_grant_is_in_use_is_not_evicted() {
        let fixture = target_capped_fixture(2);

        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, client_ip(), 1, at(10));

        // Only the segment grant is held, the target grant itself is not.
        let hold = fixture
            .auth
            .watch_segment_grant(
                client_ip(),
                nth_sni(0).customer_domain(),
                &granted_id(&nth_up_segment(0)),
                at(10),
            )
            .expect("the segment of the first target is granted");

        grant_nth_target(&fixture, client_ip(), 2, at(20));

        assert_eq!(
            target_expiry_of(&fixture, 0, at(20)),
            Some(at(100)),
            "evicting the target would evict a segment grant a consumer holds"
        );
        assert!(!hold.expired().is_cancelled());
        assert_eq!(target_expiry_of(&fixture, 1, at(20)), None);
        assert_eq!(target_expiry_of(&fixture, 2, at(20)), Some(at(120)));
    }

    #[test]
    fn dropping_a_target_hold_frees_it_for_eviction_again() {
        let fixture = target_capped_fixture(1);

        grant_nth_target(&fixture, client_ip(), 0, at(0));

        let hold = fixture
            .auth
            .watch_grant(client_ip(), nth_sni(0).customer_domain(), at(0))
            .expect("the target is granted");

        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(nth_sni(1).customer_domain().into(), AuthSegments::default())]),
                at(10),
            )
            .expect_err("the only target of the IP is in use");

        drop(hold);

        grant_nth_target(&fixture, client_ip(), 1, at(20));

        assert_eq!(target_expiry_of(&fixture, 0, at(20)), None);
        assert_eq!(target_expiry_of(&fixture, 1, at(20)), Some(at(120)));
    }

    #[test]
    fn a_request_that_cannot_free_a_target_is_rejected_whole() {
        let fixture = target_capped_fixture(2);

        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, client_ip(), 1, at(0));

        let holds = [0, 1].map(|n| {
            fixture
                .auth
                .watch_grant(client_ip(), nth_sni(n).customer_domain(), at(0))
                .expect("both targets are granted")
        });

        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([(
                    nth_sni(2).customer_domain().into(),
                    AuthSegments {
                        up_segments: vec![nth_up_segment(2)],
                        ..AuthSegments::default()
                    },
                )]),
                at(10),
            )
            .expect_err("a full IP whose targets are all in use takes nothing more");

        assert!(
            matches!(
                error,
                AuthorizeError::IpTargetLimitReached {
                    needed: 1,
                    in_use: 2,
                    max: 2,
                }
            ),
            "{error:?}"
        );

        assert!(holds.iter().all(|hold| !hold.expired().is_cancelled()));
        assert_eq!(target_expiry_of(&fixture, 0, at(10)), Some(at(100)));
        assert_eq!(target_expiry_of(&fixture, 1, at(10)), Some(at(100)));
        assert_eq!(
            target_expiry_of(&fixture, 2, at(10)),
            None,
            "the target that did not fit was not granted"
        );
        assert!(
            fixture
                .auth
                .segment(&granted_id(&nth_up_segment(2)), at(10))
                .is_none(),
            "and neither were the segments it came with"
        );
    }

    #[test]
    fn a_request_naming_more_targets_than_an_ip_can_hold_is_rejected() {
        let fixture = target_capped_fixture(2);

        let error = fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (nth_sni(0).customer_domain().into(), AuthSegments::default()),
                    (nth_sni(1).customer_domain().into(), AuthSegments::default()),
                    (nth_sni(2).customer_domain().into(), AuthSegments::default()),
                ]),
                at(0),
            )
            .expect_err("three targets never fit into two grants");

        assert!(
            matches!(
                error,
                AuthorizeError::TooManyTargetsForIp {
                    requested: 3,
                    max: 2
                }
            ),
            "{error:?}"
        );
        assert!(
            !fixture.auth.ip_is_authorized(client_ip(), at(0)),
            "a rejected request leaves the IP as unauthorized as it was"
        );
    }

    #[test]
    fn refreshing_the_targets_of_a_full_ip_evicts_nothing() {
        let fixture = target_capped_fixture(2);

        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, client_ip(), 1, at(0));

        fixture
            .auth
            .authorize(
                client_ip(),
                HashMap::from([
                    (nth_sni(0).customer_domain().into(), AuthSegments::default()),
                    (nth_sni(1).customer_domain().into(), AuthSegments::default()),
                ]),
                at(10),
            )
            .expect("a refresh of every target fits");

        assert_eq!(target_expiry_of(&fixture, 0, at(10)), Some(at(110)));
        assert_eq!(target_expiry_of(&fixture, 1, at(10)), Some(at(110)));
        assert!(
            fixture
                .auth
                .segment(&granted_id(&nth_up_segment(0)), at(10))
                .is_some(),
            "a refreshed target keeps the segment grants the refresh omits"
        );
    }

    #[test]
    fn the_target_limit_is_per_ip_not_global() {
        let fixture = target_capped_fixture(1);

        grant_nth_target(&fixture, client_ip(), 0, at(0));
        grant_nth_target(&fixture, other_client_ip(), 1, at(0));

        assert_eq!(target_expiry_of(&fixture, 0, at(0)), Some(at(100)));
        assert_eq!(
            fixture
                .auth
                .grant_expiry(other_client_ip(), nth_sni(1).customer_domain(), at(0)),
            Some(at(100)),
            "another IP at its own limit is untouched"
        );
    }
}
