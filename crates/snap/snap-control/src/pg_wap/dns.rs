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

//! Passthrough DNS resolution.
//!
//! [`DnsManager`] resolves a name to a SCION address. It answers from its [`DnsCache`], and asks
//! its [`DnsResolver`] if the cache holds no valid answer for the name.
//!
//! The cache maps a name to the SCION addresses it resolved to, to the answer that the name has no
//! SCION addresses, or to a failed lookup.
//!
//! DNS load balancing can answer each lookup with a different part of the gateway set.
//!
//! So the manager keeps the union of all answers, and each address stays for
//! [`DnsManagerConfig::ttl`] after a lookup last returned it.
//!
//! Once the refresh time of a name has passed, a request starts a refresh in the background and
//! answers from the cache. All requests for one name share one lookup. An expired answer is never
//! returned, and [`DnsCache::clean`] removes it.

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime},
};

use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use sciparse::address::ip_addr::ScionIpAddr;
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};

/// The timings a [`DnsManager`] caches, refreshes and cleans with.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsManagerConfig {
    /// How long an address stays in the cache after a lookup last returned it, independent of the
    /// TTL of the DNS records.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "DnsManagerConfig::default_ttl")]
    pub ttl: Duration,
    /// How long after a lookup a request re-resolves the name.
    ///
    /// Also how long the cache holds the answer that a name has no SCION addresses.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "DnsManagerConfig::default_refresh_interval")]
    pub refresh_interval: Duration,
    /// How long the [`DnsManager`] caches a failed lookup, for example a timeout.
    ///
    /// After a failed refresh, the cached addresses stay, and the next refresh waits this long.
    /// Zero disables the cache for failed lookups.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "DnsManagerConfig::default_lookup_failure_ttl")]
    pub lookup_failure_ttl: Duration,
    /// Interval between two [`DnsCache::clean`] runs.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "DnsManagerConfig::default_clean_interval")]
    pub clean_interval: Duration,
}

impl DnsManagerConfig {
    fn default_ttl() -> Duration {
        Duration::from_secs(300)
    }

    fn default_refresh_interval() -> Duration {
        Duration::from_secs(30)
    }

    fn default_lookup_failure_ttl() -> Duration {
        Duration::from_secs(15)
    }

    fn default_clean_interval() -> Duration {
        Duration::from_secs(60)
    }

    /// Returns the longest time the [`DnsResolver`] may cache an answer.
    ///
    /// Half of [`DnsManagerConfig::refresh_interval`], so that a refresh gets a new answer and not
    /// the copy the resolver still holds.
    pub fn resolver_max_ttl(&self) -> Duration {
        self.refresh_interval / 2
    }

    /// Checks that the config is valid.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.refresh_interval == Duration::ZERO {
            anyhow::bail!("refresh_interval must be greater than 0");
        }

        // Otherwise an address expires before a refresh can return it again.
        if self.ttl <= self.refresh_interval {
            anyhow::bail!("ttl must be greater than refresh_interval");
        }

        if self.clean_interval == Duration::ZERO {
            anyhow::bail!("clean_interval must be greater than 0");
        }

        Ok(())
    }
}

impl Default for DnsManagerConfig {
    fn default() -> Self {
        Self {
            ttl: Self::default_ttl(),
            refresh_interval: Self::default_refresh_interval(),
            lookup_failure_ttl: Self::default_lookup_failure_ttl(),
            clean_interval: Self::default_clean_interval(),
        }
    }
}

/// The error a DNS resolution returns.
#[derive(Debug, thiserror::Error)]
pub enum DnsResolveError {
    /// The lookup did not complete, for example on a timeout or a network error. A retry can
    /// succeed.
    #[error("dns lookup failed: {0}")]
    Lookup(#[source] anyhow::Error),
    /// The lookup completed, but the name has no SCION addresses.
    #[error("no SCION addresses for {0}")]
    NoAddresses(String),
}

/// Does the DNS lookups that the [`DnsManager`] cannot answer from its cache.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    /// Resolves `name` to SCION addresses.
    ///
    /// `name` must be normalized, see [`DnsCache`]. The [`DnsManager`] treats an empty list like
    /// [`DnsResolveError::NoAddresses`].
    ///
    /// An implementation that caches answers must not cache them longer than
    /// [`DnsManagerConfig::resolver_max_ttl`].
    async fn resolve(&self, name: &str) -> Result<Vec<ScionIpAddr>, DnsResolveError>;
}

/// Resolves names through a [`DnsCache`] and a [`DnsResolver`].
pub struct DnsManager<Resolver>(Arc<DnsManagerInner<Resolver>>);

// Not derived: the derive would require `Resolver: Clone`, which it need not be.
impl<Resolver> Clone for DnsManager<Resolver> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// The state shared by all clones of a [`DnsManager`].
struct DnsManagerInner<Resolver> {
    cache: DnsCache,
    resolver: Resolver,
    config: DnsManagerConfig,
    /// The lookup in flight for each name.
    in_flight: Mutex<HashMap<String, Lookup>>,
}

/// A lookup that all requests for one name share.
type Lookup = Shared<BoxFuture<'static, LookupOutcome>>;

/// The answer of a [`Lookup`].
#[derive(Clone)]
enum LookupOutcome {
    /// The name resolved to `addrs`, which is never empty.
    Addrs(Vec<ScionIpAddr>),
    /// The name has no SCION addresses.
    NoAddresses,
    /// The lookup failed with the message `error`.
    Failed(String),
}

impl<Resolver: DnsResolver> DnsManager<Resolver> {
    /// Creates a manager with an empty cache, doing lookups through `resolver`.
    ///
    /// Returns an error if `config` does not [`DnsManagerConfig::validate`].
    pub fn new(resolver: Resolver, config: DnsManagerConfig) -> anyhow::Result<Self> {
        config.validate()?;

        Ok(Self(Arc::new(DnsManagerInner {
            cache: DnsCache::new(),
            resolver,
            config,
            in_flight: Mutex::default(),
        })))
    }

    /// The cache the manager answers from.
    pub fn cache(&self) -> &DnsCache {
        &self.0.cache
    }

    /// Returns the address of `name` with the lowest priority, see [`DnsCache::get`].
    ///
    /// If the cache holds no valid answer for `name`, asks the [`DnsResolver`] and caches the
    /// answer. See [`DnsManagerConfig`] for how long each kind of answer stays.
    ///
    /// If the cache holds valid addresses and the refresh time of `name` has passed, re-resolves
    /// `name` in the background and adds the answer to them. The request answers from the cache
    /// and does not wait for the refresh. If the refresh fails, the cached addresses stay.
    ///
    /// Runs at most one lookup per name at a time. A request that finds a lookup of `name` in
    /// flight shares it. The lookup runs in its own task, and completes if the request is dropped.
    ///
    /// Returns `None` if `priority` rejects all addresses.
    ///
    /// `name` must be normalized, see [`DnsCache`].
    ///
    /// Returns [`DnsResolveError::NoAddresses`] if the name has no SCION addresses, from the cache
    /// or from the lookup.
    /// Returns [`DnsResolveError::Lookup`] if the lookup fails, or if the cache holds a failed
    /// lookup for the name.
    pub async fn resolve<P: Ord>(
        &self,
        name: &str,
        priority: impl Fn(&ScionIpAddr) -> Option<P>,
        now: SystemTime,
    ) -> Result<Option<ScionIpAddr>, DnsResolveError> {
        let refresh_due = self
            .0
            .cache
            .refresh_at(name)
            .is_some_and(|refresh_at| now >= refresh_at);

        match self.0.cache.get(name, &priority, now) {
            CacheLookup::Found(cached) => {
                // If a refresh is due, refresh in the background. The cache answers the request.
                if refresh_due {
                    drop(ensure_lookup(self, name, now));
                }

                return Ok(cached);
            }
            CacheLookup::NoAddresses => return Err(DnsResolveError::NoAddresses(name.to_string())),
            CacheLookup::LookupFailed(error) => {
                return Err(DnsResolveError::Lookup(anyhow::anyhow!(error)));
            }
            CacheLookup::Miss => {}
        }

        // Cache miss, await a lookup.
        let answer = match ensure_lookup(self, name, now).await {
            LookupOutcome::Addrs(addrs) => Ok(lowest_priority(addrs.iter(), priority)),
            LookupOutcome::NoAddresses => Err(DnsResolveError::NoAddresses(name.to_string())),
            LookupOutcome::Failed(error) => Err(DnsResolveError::Lookup(anyhow::anyhow!(error))),
        };

        return answer;

        /// Ensures that a lookup of `name` is in flight, and returns it.
        fn ensure_lookup<R: DnsResolver>(
            manager: &DnsManager<R>,
            name: &str,
            now: SystemTime,
        ) -> Lookup {
            let lookup = manager
                .0
                .in_flight
                .lock()
                .unwrap()
                .entry(name.to_string())
                .or_insert_with(|| start_lookup(manager.clone(), name.to_string(), now))
                .clone();

            return lookup;

            /// Spawns the lookup task, which writes the answer to the cache.
            fn start_lookup<R: DnsResolver>(
                manager: DnsManager<R>,
                name: String,
                now: SystemTime,
            ) -> Lookup {
                let task = tokio::spawn(async move {
                    let entry = InFlightEntry { manager, name };
                    let resolved =
                        AssertUnwindSafe(resolve_and_cache(&entry.manager, &entry.name, now))
                            .catch_unwind()
                            .await;

                    // A panic counts as a failed lookup, so the retry waits for
                    // `lookup_failure_ttl`.
                    resolved.unwrap_or_else(|_| {
                        let error = "the DNS resolver panicked".to_string();
                        cache_failure(&entry.manager, &entry.name, error, now)
                    })
                });

                return task
                    .map(|joined| {
                        joined.unwrap_or_else(|err| {
                            LookupOutcome::Failed(format!("dns lookup task failed: {err}"))
                        })
                    })
                    .boxed()
                    .shared();

                /// Asks the resolver, and writes the answer to the cache.
                ///
                /// A negative answer keeps valid cached addresses until they expire.
                async fn resolve_and_cache<R: DnsResolver>(
                    manager: &DnsManager<R>,
                    name: &str,
                    now: SystemTime,
                ) -> LookupOutcome {
                    let DnsManagerInner { cache, config, .. } = &*manager.0;
                    match manager.0.resolver.resolve(name).await {
                        Ok(addrs) if !addrs.is_empty() => {
                            cache.insert(name, addrs.iter().copied(), config.ttl, now);
                            cache.schedule_refresh(name, now + config.refresh_interval);
                            LookupOutcome::Addrs(addrs)
                        }
                        Ok(_) | Err(DnsResolveError::NoAddresses(_)) => {
                            cache.insert_no_addresses(name, config.refresh_interval, now);
                            cache.schedule_refresh(name, now + config.refresh_interval);
                            LookupOutcome::NoAddresses
                        }
                        Err(DnsResolveError::Lookup(err)) => {
                            cache_failure(manager, name, format!("{err:#}"), now)
                        }
                    }
                }

                /// Writes the failed lookup of `name` to the cache.
                ///
                /// Valid cached addresses stay, and the next refresh waits for
                /// `lookup_failure_ttl`.
                fn cache_failure<R: DnsResolver>(
                    manager: &DnsManager<R>,
                    name: &str,
                    error: String,
                    now: SystemTime,
                ) -> LookupOutcome {
                    let DnsManagerInner { cache, config, .. } = &*manager.0;
                    tracing::debug!(%name, %error, "DNS lookup failed");
                    cache.insert_lookup_failed(name, error.clone(), config.lookup_failure_ttl, now);
                    cache.schedule_refresh(name, now + config.lookup_failure_ttl);
                    LookupOutcome::Failed(error)
                }

                /// Removes the lookup of `name` from the map when the task ends, also on a panic.
                struct InFlightEntry<R> {
                    manager: DnsManager<R>,
                    name: String,
                }

                impl<R> Drop for InFlightEntry<R> {
                    fn drop(&mut self) {
                        // A panic in `drop` during a panic aborts the process, so ignore poison.
                        self.manager
                            .0
                            .in_flight
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(&self.name);
                    }
                }
            }
        }
    }

    /// Returns all valid addresses of `name`, in the order the cache learned them.
    ///
    /// Looks up and refreshes `name` like [`DnsManager::resolve`], and returns the same errors.
    pub async fn resolve_all(
        &self,
        name: &str,
        now: SystemTime,
    ) -> Result<Vec<ScionIpAddr>, DnsResolveError> {
        self.resolve(name, |_| Some(()), now).await?;
        Ok(self.0.cache.addrs(name, now))
    }

    /// Runs the clean loop for the cache.
    ///
    /// Reads the wall clock itself, unlike every other entry point. Never returns.
    pub async fn run(&self) {
        loop {
            self.0.cache.clean(SystemTime::now());
            tokio::time::sleep(self.0.config.clean_interval).await;
        }
    }
}

/// Returns the address of `addrs` with the lowest priority. Of equal priorities, the first wins.
fn lowest_priority<'a, P: Ord>(
    addrs: impl Iterator<Item = &'a ScionIpAddr>,
    priority: impl Fn(&ScionIpAddr) -> Option<P>,
) -> Option<ScionIpAddr> {
    addrs
        .filter_map(|addr| priority(addr).map(|p| (p, *addr)))
        .min_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, addr)| addr)
}

/// The answer of [`DnsCache::get`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheLookup {
    /// The cache holds no valid answer for the name.
    Miss,
    /// The cache holds the answer that the name has no SCION addresses.
    NoAddresses,
    /// The cache holds a failed lookup for the name, with its error message.
    LookupFailed(String),
    /// The cache holds valid addresses for the name.
    ///
    /// Holds the address with the lowest priority, or `None` if the priority rejects all of them.
    Found(Option<ScionIpAddr>),
}

/// Cache of DNS resolutions to SCION addresses.
///
/// The cache compares names byte for byte. The caller normalizes each name before
/// [`DnsCache::insert`] and [`DnsCache::get`], for example to lowercase without a trailing dot.
#[derive(Clone, Default)]
pub struct DnsCache(Arc<RwLock<HashMap<String, DnsCacheEntry>>>);

/// The answer for one name.
enum DnsCacheEntry {
    /// The name resolved to `addrs`, which is never empty.
    Addrs {
        addrs: Vec<CachedAddr>,
        /// The minimum `expires_at` of `addrs`, or earlier.
        ///
        /// [`DnsCache::clean`] only scans the entry once this time is reached.
        earliest_expiry: SystemTime,
        /// When a request re-resolves the name, see [`DnsCache::schedule_refresh`].
        refresh_at: SystemTime,
    },
    /// The name has no SCION addresses.
    NoAddresses { expires_at: SystemTime },
    /// The lookup failed with the message `error`.
    LookupFailed {
        error: String,
        expires_at: SystemTime,
    },
}

impl DnsCacheEntry {
    /// Checks if the entry can be returned for a request at `now`.
    fn is_valid(&self, now: SystemTime) -> bool {
        match self {
            Self::Addrs { addrs, .. } => addrs.iter().any(|cached| cached.is_valid(now)),
            Self::NoAddresses { expires_at } | Self::LookupFailed { expires_at, .. } => {
                now < *expires_at
            }
        }
    }
}

struct CachedAddr {
    addr: ScionIpAddr,
    expires_at: SystemTime,
}

impl CachedAddr {
    fn is_valid(&self, now: SystemTime) -> bool {
        now < self.expires_at
    }
}

impl DnsCache {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, DnsCacheEntry>> {
        self.0.read().unwrap()
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, DnsCacheEntry>> {
        self.0.write().unwrap()
    }

    /// Adds `addrs` to the addresses of `name`, valid for `ttl`.
    ///
    /// If `name` already holds an address, the new TTL replaces the old expiry. A new address goes
    /// after the known ones. If `name` holds another answer, `addrs` replaces it, with a refresh
    /// time at its expiry. If `addrs` is empty, changes nothing.
    pub fn insert(
        &self,
        name: impl Into<String>,
        addrs: impl IntoIterator<Item = ScionIpAddr>,
        ttl: Duration,
        now: SystemTime,
    ) {
        let expires_at = now + ttl;
        let mut addrs = addrs
            .into_iter()
            .map(|addr| CachedAddr { addr, expires_at })
            .peekable();
        if addrs.peek().is_none() {
            return;
        }

        let mut cache = self.write();
        let entry = cache.entry(name.into()).or_insert(DnsCacheEntry::Addrs {
            addrs: Vec::new(),
            earliest_expiry: expires_at,
            refresh_at: expires_at,
        });
        let DnsCacheEntry::Addrs {
            addrs: cached_addrs,
            earliest_expiry,
            ..
        } = entry
        else {
            *entry = DnsCacheEntry::Addrs {
                addrs: addrs.collect(),
                earliest_expiry: expires_at,
                refresh_at: expires_at,
            };
            return;
        };

        // A replaced expiry can be later than the old one. Then `earliest_expiry` is too early,
        // which only costs one extra scan in `clean`.
        *earliest_expiry = (*earliest_expiry).min(expires_at);

        for addr in addrs {
            match cached_addrs
                .iter_mut()
                .find(|cached| cached.addr == addr.addr)
            {
                Some(cached) => cached.expires_at = expires_at,
                None => cached_addrs.push(addr),
            }
        }
    }

    /// Sets when a request re-resolves `name`, if `name` holds addresses.
    pub fn schedule_refresh(&self, name: &str, at: SystemTime) {
        if let Some(DnsCacheEntry::Addrs { refresh_at, .. }) = self.write().get_mut(name) {
            *refresh_at = at;
        }
    }

    /// Returns when a request re-resolves `name`, or `None` if `name` holds no addresses.
    pub fn refresh_at(&self, name: &str) -> Option<SystemTime> {
        match self.read().get(name)? {
            DnsCacheEntry::Addrs { refresh_at, .. } => Some(*refresh_at),
            DnsCacheEntry::NoAddresses { .. } | DnsCacheEntry::LookupFailed { .. } => None,
        }
    }

    /// Records that `name` has no SCION addresses, valid for `ttl`.
    ///
    /// If `name` holds a valid answer, keeps it.
    pub fn insert_no_addresses(&self, name: impl Into<String>, ttl: Duration, now: SystemTime) {
        self.insert_negative(
            name.into(),
            DnsCacheEntry::NoAddresses {
                expires_at: now + ttl,
            },
            now,
        );
    }

    /// Records that the lookup of `name` failed with the message `error`, valid for `ttl`.
    ///
    /// If `name` holds a valid answer, keeps it.
    pub fn insert_lookup_failed(
        &self,
        name: impl Into<String>,
        error: impl Into<String>,
        ttl: Duration,
        now: SystemTime,
    ) {
        self.insert_negative(
            name.into(),
            DnsCacheEntry::LookupFailed {
                error: error.into(),
                expires_at: now + ttl,
            },
            now,
        );
    }

    /// Stores `entry` for `name`, unless `name` holds a valid answer.
    fn insert_negative(&self, name: String, entry: DnsCacheEntry, now: SystemTime) {
        let mut cache = self.write();
        if cache.get(&name).is_some_and(|cached| cached.is_valid(now)) {
            return;
        }

        cache.insert(name, entry);
    }

    /// Looks up the valid answer for `name`, and picks the address with the lowest priority.
    ///
    /// `priority` gives the priority of an address. If it returns `None`, the address is never
    /// returned. Of addresses with the same priority, the one inserted first wins.
    ///
    /// For example, to get only an address in ISD 64:
    ///
    /// ```ignore
    /// cache.get("example.com", |a| (a.isd_asn().isd() == Isd(64)).then_some(()), now);
    /// ```
    ///
    /// To prefer ISD 64, but fall back to any other ISD:
    ///
    /// ```ignore
    /// cache.get("example.com", |a| Some(a.isd_asn().isd() != Isd(64)), now);
    /// ```
    pub fn get<P: Ord>(
        &self,
        name: &str,
        priority: impl Fn(&ScionIpAddr) -> Option<P>,
        now: SystemTime,
    ) -> CacheLookup {
        let cache = self.read();
        let addrs = match cache.get(name) {
            None => return CacheLookup::Miss,
            Some(DnsCacheEntry::LookupFailed { error, expires_at }) => {
                return match now < *expires_at {
                    true => CacheLookup::LookupFailed(error.clone()),
                    false => CacheLookup::Miss,
                };
            }
            Some(DnsCacheEntry::NoAddresses { expires_at }) => {
                return match now < *expires_at {
                    true => CacheLookup::NoAddresses,
                    false => CacheLookup::Miss,
                };
            }
            Some(DnsCacheEntry::Addrs { addrs, .. }) => addrs,
        };

        let mut valid = addrs
            .iter()
            .filter(|cached| cached.is_valid(now))
            .map(|cached| &cached.addr)
            .peekable();
        if valid.peek().is_none() {
            return CacheLookup::Miss;
        }

        CacheLookup::Found(lowest_priority(valid, priority))
    }

    /// Returns the valid addresses of `name`, in the order the cache learned them.
    pub fn addrs(&self, name: &str, now: SystemTime) -> Vec<ScionIpAddr> {
        match self.read().get(name) {
            Some(DnsCacheEntry::Addrs { addrs, .. }) => {
                addrs
                    .iter()
                    .filter(|cached| cached.is_valid(now))
                    .map(|cached| cached.addr)
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Removes all expired answers.
    ///
    /// Scans only the names whose earliest expiry is reached. Returns the earliest expiry of the
    /// remaining answers, or `None` if the cache is empty.
    pub fn clean(&self, now: SystemTime) -> Option<SystemTime> {
        let mut next_expiry: Option<SystemTime> = None;

        self.write().retain(|_, entry| {
            let expiry = match entry {
                DnsCacheEntry::LookupFailed { expires_at, .. }
                | DnsCacheEntry::NoAddresses { expires_at } => {
                    if now >= *expires_at {
                        return false;
                    }
                    *expires_at
                }
                DnsCacheEntry::Addrs {
                    addrs,
                    earliest_expiry,
                    ..
                } => {
                    if now >= *earliest_expiry {
                        addrs.retain(|cached| cached.is_valid(now));
                        let Some(earliest) = addrs.iter().map(|cached| cached.expires_at).min()
                        else {
                            return false;
                        };
                        *earliest_expiry = earliest;
                    }
                    *earliest_expiry
                }
            };

            next_expiry = Some(next_expiry.map_or(expiry, |next| next.min(expiry)));
            true
        });

        next_expiry
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use sciparse::identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn};

    use super::*;

    fn addr(isd: u16, last_octet: u8) -> ScionIpAddr {
        ScionIpAddr::new(
            IsdAsn::new(Isd(isd), Asn::new(0xff00_0000_0110)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
        )
    }

    fn any(_: &ScionIpAddr) -> Option<()> {
        Some(())
    }

    fn addr_count(cache: &DnsCache, name: &str) -> usize {
        match &cache.read()[name] {
            DnsCacheEntry::Addrs { addrs, .. } => addrs.len(),
            _ => 0,
        }
    }

    fn only_isd(isd: u16) -> impl Fn(&ScionIpAddr) -> Option<()> {
        move |a| (a.isd_asn().isd() == Isd(isd)).then_some(())
    }

    #[test]
    fn get_skips_expired_addresses() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cache.insert("example.com", [addr(1, 1)], Duration::from_secs(10), t0);
        cache.insert("example.com", [addr(1, 2)], Duration::from_secs(20), t0);

        let t15 = t0 + Duration::from_secs(15);
        let t20 = t0 + Duration::from_secs(20);
        assert_eq!(
            cache.get("example.com", any, t0),
            CacheLookup::Found(Some(addr(1, 1)))
        );
        assert_eq!(
            cache.get("example.com", any, t15),
            CacheLookup::Found(Some(addr(1, 2)))
        );
        assert_eq!(cache.get("example.com", any, t20), CacheLookup::Miss);
        assert_eq!(cache.get("other.com", any, t0), CacheLookup::Miss);
    }

    #[test]
    fn get_uses_priority() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cache.insert(
            "example.com",
            [addr(1, 1), addr(64, 2), addr(2, 3)],
            Duration::from_secs(10),
            t0,
        );

        assert_eq!(
            cache.get("example.com", only_isd(64), t0),
            CacheLookup::Found(Some(addr(64, 2)))
        );
        assert_eq!(
            cache.get("example.com", only_isd(3), t0),
            CacheLookup::Found(None)
        );

        let prefer_2 = |a: &ScionIpAddr| Some(a.isd_asn().isd() != Isd(2));
        assert_eq!(
            cache.get("example.com", prefer_2, t0),
            CacheLookup::Found(Some(addr(2, 3)))
        );
    }

    #[test]
    fn get_returns_no_addresses_until_expiry() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cache.insert_no_addresses("example.com", Duration::from_secs(10), t0);

        let t10 = t0 + Duration::from_secs(10);
        assert_eq!(cache.get("example.com", any, t0), CacheLookup::NoAddresses);
        assert_eq!(cache.get("example.com", any, t10), CacheLookup::Miss);
        assert_eq!(cache.clean(t10), None);
        assert!(cache.read().is_empty());
    }

    #[test]
    fn insert_replaces_expiry_of_known_address() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cache.insert("example.com", [addr(1, 1)], Duration::from_secs(10), t0);
        cache.insert("example.com", [addr(1, 1)], Duration::from_secs(30), t0);

        let t20 = t0 + Duration::from_secs(20);
        assert_eq!(
            cache.get("example.com", any, t20),
            CacheLookup::Found(Some(addr(1, 1)))
        );
        assert_eq!(cache.clean(t20), Some(t0 + Duration::from_secs(30)));
        assert_eq!(addr_count(&cache, "example.com"), 1);
    }

    #[test]
    fn clean_removes_expired_addresses_and_names() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        cache.insert("a.com", [addr(1, 1)], Duration::from_secs(10), t0);
        cache.insert("a.com", [addr(1, 2)], Duration::from_secs(30), t0);
        cache.insert("b.com", [addr(1, 3)], Duration::from_secs(20), t0);

        assert_eq!(cache.clean(t0), Some(t0 + Duration::from_secs(10)));

        let t10 = t0 + Duration::from_secs(10);
        assert_eq!(cache.clean(t10), Some(t0 + Duration::from_secs(20)));
        assert_eq!(addr_count(&cache, "a.com"), 1);

        let t20 = t0 + Duration::from_secs(20);
        assert_eq!(cache.clean(t20), Some(t0 + Duration::from_secs(30)));
        assert!(!cache.read().contains_key("b.com"));

        let t30 = t0 + Duration::from_secs(30);
        assert_eq!(cache.clean(t30), None);
        assert!(cache.read().is_empty());
    }

    /// Gives the answer to the lookup with the given index, counting from 0.
    type Answer = fn(usize) -> Result<Vec<ScionIpAddr>, DnsResolveError>;

    /// Answers every lookup with `answer`, and counts the lookups.
    struct FakeResolver {
        answer: Answer,
        lookups: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DnsResolver for FakeResolver {
        async fn resolve(&self, _name: &str) -> Result<Vec<ScionIpAddr>, DnsResolveError> {
            let lookup = self.lookups.fetch_add(1, Ordering::Relaxed);
            (self.answer)(lookup)
        }
    }

    fn manager(answer: Answer) -> DnsManager<FakeResolver> {
        let resolver = FakeResolver {
            answer,
            lookups: AtomicUsize::new(0),
        };
        DnsManager::new(resolver, DnsManagerConfig::default()).expect("a valid DnsManagerConfig")
    }

    fn lookups(manager: &DnsManager<FakeResolver>) -> usize {
        manager.0.resolver.lookups.load(Ordering::Relaxed)
    }

    /// Waits until the lookups in flight, for example a background refresh, are done.
    async fn wait_for_lookups(manager: &DnsManager<FakeResolver>) {
        let in_flight: Vec<Lookup> = manager
            .0
            .in_flight
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for lookup in in_flight {
            lookup.await;
        }
    }

    #[tokio::test]
    async fn resolve_looks_up_on_cache_miss() {
        let manager = manager(|_| Ok(vec![addr(1, 1), addr(64, 2)]));
        let t0 = SystemTime::UNIX_EPOCH;

        let got = manager.resolve("example.com", only_isd(64), t0).await;
        assert_eq!(got.unwrap(), Some(addr(64, 2)));
        assert_eq!(lookups(&manager), 1);

        let got = manager.resolve("example.com", any, t0).await;
        assert_eq!(got.unwrap(), Some(addr(1, 1)));
        assert_eq!(lookups(&manager), 1);

        let got = manager.resolve("example.com", only_isd(3), t0).await;
        assert_eq!(got.unwrap(), None);
        assert_eq!(lookups(&manager), 1);

        let after_ttl = t0 + DnsManagerConfig::default().ttl;
        let got = manager.resolve("example.com", any, after_ttl).await;
        assert_eq!(got.unwrap(), Some(addr(1, 1)));
        assert_eq!(lookups(&manager), 2);
    }

    #[tokio::test]
    async fn resolve_caches_no_addresses() {
        let t0 = SystemTime::UNIX_EPOCH;
        let no_addresses: [Answer; 2] = [
            |_| Ok(Vec::new()),
            |_| Err(DnsResolveError::NoAddresses("example.com".to_string())),
        ];

        for answer in no_addresses {
            let manager = manager(answer);
            for _ in 0..2 {
                let got = manager.resolve("example.com", any, t0).await;
                assert!(
                    matches!(got, Err(DnsResolveError::NoAddresses(_))),
                    "{got:?}"
                );
            }
            assert_eq!(lookups(&manager), 1);
        }
    }

    #[tokio::test]
    async fn resolve_caches_lookup_failure_until_expiry() {
        let manager = manager(|_| Err(DnsResolveError::Lookup(anyhow::anyhow!("timeout"))));
        let t0 = SystemTime::UNIX_EPOCH;

        for _ in 0..2 {
            let got = manager.resolve("example.com", any, t0).await;
            assert!(matches!(got, Err(DnsResolveError::Lookup(_))), "{got:?}");
        }
        assert_eq!(lookups(&manager), 1);
        assert_eq!(
            manager.cache().get("example.com", any, t0),
            CacheLookup::LookupFailed("timeout".to_string())
        );

        let after_ttl = t0 + DnsManagerConfig::default().lookup_failure_ttl;
        assert_eq!(manager.cache().clean(after_ttl), None);
        let got = manager.resolve("example.com", any, after_ttl).await;
        assert!(matches!(got, Err(DnsResolveError::Lookup(_))), "{got:?}");
        assert_eq!(lookups(&manager), 2);
    }

    #[tokio::test]
    async fn resolve_with_zero_lookup_failure_ttl_does_not_cache_failure() {
        let resolver = FakeResolver {
            answer: |_| Err(DnsResolveError::Lookup(anyhow::anyhow!("timeout"))),
            lookups: AtomicUsize::new(0),
        };
        let config = DnsManagerConfig {
            lookup_failure_ttl: Duration::ZERO,
            ..DnsManagerConfig::default()
        };
        let manager = DnsManager::new(resolver, config).expect("a valid DnsManagerConfig");
        let t0 = SystemTime::UNIX_EPOCH;

        for _ in 0..2 {
            let got = manager.resolve("example.com", any, t0).await;
            assert!(matches!(got, Err(DnsResolveError::Lookup(_))), "{got:?}");
        }
        assert_eq!(lookups(&manager), 2);
    }

    #[test]
    fn insert_replaces_other_answers() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        let ttl = Duration::from_secs(10);

        cache.insert_lookup_failed("example.com", "timeout", ttl, t0);
        cache.insert("example.com", [addr(1, 1)], ttl, t0);
        assert_eq!(
            cache.get("example.com", any, t0),
            CacheLookup::Found(Some(addr(1, 1)))
        );

        let t10 = t0 + ttl;
        cache.insert_no_addresses("example.com", ttl, t10);
        cache.insert("example.com", [addr(1, 2)], ttl, t10);
        assert_eq!(
            cache.get("example.com", any, t10),
            CacheLookup::Found(Some(addr(1, 2)))
        );
        assert_eq!(addr_count(&cache, "example.com"), 1);
    }

    #[test]
    fn negative_insert_keeps_valid_answer() {
        let cache = DnsCache::new();
        let t0 = SystemTime::UNIX_EPOCH;
        let ttl = Duration::from_secs(10);

        cache.insert("example.com", [addr(1, 1)], ttl, t0);
        cache.insert_no_addresses("example.com", ttl, t0);
        cache.insert_lookup_failed("example.com", "timeout", ttl, t0);
        assert_eq!(
            cache.get("example.com", any, t0),
            CacheLookup::Found(Some(addr(1, 1)))
        );

        let t10 = t0 + ttl;
        cache.insert_no_addresses("example.com", ttl, t10);
        cache.insert_lookup_failed("example.com", "timeout", ttl, t10);
        assert_eq!(cache.get("example.com", any, t10), CacheLookup::NoAddresses);
    }

    #[test]
    fn config_rejects_unusable_timings() {
        assert!(DnsManagerConfig::default().validate().is_ok());

        let zero_refresh_interval = DnsManagerConfig {
            refresh_interval: Duration::ZERO,
            ..DnsManagerConfig::default()
        };
        assert!(zero_refresh_interval.validate().is_err());

        let ttl_not_above_refresh_interval = DnsManagerConfig {
            ttl: DnsManagerConfig::default().refresh_interval,
            ..DnsManagerConfig::default()
        };
        assert!(ttl_not_above_refresh_interval.validate().is_err());

        let zero_clean_interval = DnsManagerConfig {
            clean_interval: Duration::ZERO,
            ..DnsManagerConfig::default()
        };
        assert!(zero_clean_interval.validate().is_err());
    }

    /// Every lookup returns one gateway of three, round robin.
    fn round_robin(lookup: usize) -> Result<Vec<ScionIpAddr>, DnsResolveError> {
        Ok(vec![addr(1, lookup as u8 % 3 + 1)])
    }

    fn only(wanted: ScionIpAddr) -> impl Fn(&ScionIpAddr) -> Option<()> {
        move |a| (*a == wanted).then_some(())
    }

    #[tokio::test]
    async fn resolve_refreshes_once_the_refresh_interval_passed() {
        let manager = manager(round_robin);
        let config = DnsManagerConfig::default();
        let t0 = SystemTime::UNIX_EPOCH;

        let got = manager.resolve("example.com", any, t0).await;
        assert_eq!(got.unwrap(), Some(addr(1, 1)));

        let before_refresh = t0 + config.refresh_interval - Duration::from_secs(1);
        manager
            .resolve("example.com", any, before_refresh)
            .await
            .unwrap();
        assert_eq!(lookups(&manager), 1);

        let t1 = t0 + config.refresh_interval;
        let got = manager.resolve("example.com", any, t1).await;
        assert_eq!(
            got.unwrap(),
            Some(addr(1, 1)),
            "the cached gateway answers without waiting for the refresh"
        );
        assert_eq!(lookups(&manager), 1, "the refresh has not run yet");
        wait_for_lookups(&manager).await;
        assert_eq!(lookups(&manager), 2);
        assert_eq!(addr_count(manager.cache(), "example.com"), 2);

        // The first gateway was last returned at t0, and expires first.
        let after_first = t0 + config.ttl;
        assert_eq!(
            manager.cache().get("example.com", any, after_first),
            CacheLookup::Found(Some(addr(1, 2)))
        );
    }

    #[tokio::test]
    async fn resolve_waits_for_the_refresh_time_if_no_cached_address_fits() {
        let manager = manager(round_robin);
        let config = DnsManagerConfig::default();
        let t0 = SystemTime::UNIX_EPOCH;
        manager.resolve("example.com", any, t0).await.unwrap();

        for _ in 0..2 {
            let got = manager.resolve("example.com", only(addr(1, 2)), t0).await;
            assert_eq!(got.unwrap(), None);
        }
        assert_eq!(lookups(&manager), 1);

        let t1 = t0 + config.refresh_interval;
        let got = manager.resolve("example.com", only(addr(1, 2)), t1).await;
        assert_eq!(
            got.unwrap(),
            None,
            "the request does not wait for the refresh"
        );
        wait_for_lookups(&manager).await;
        assert_eq!(lookups(&manager), 2);

        let got = manager.resolve("example.com", only(addr(1, 2)), t1).await;
        assert_eq!(
            got.unwrap(),
            Some(addr(1, 2)),
            "the refresh returned the second gateway"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_cached_addresses() {
        let manager = manager(|lookup| {
            match lookup {
                0 => Ok(vec![addr(1, 1)]),
                _ => Err(DnsResolveError::Lookup(anyhow::anyhow!("timeout"))),
            }
        });
        let config = DnsManagerConfig::default();
        let t0 = SystemTime::UNIX_EPOCH;
        manager.resolve("example.com", any, t0).await.unwrap();

        let t1 = t0 + config.refresh_interval;
        let got = manager.resolve("example.com", any, t1).await;
        assert_eq!(got.unwrap(), Some(addr(1, 1)));
        wait_for_lookups(&manager).await;
        assert_eq!(lookups(&manager), 2);

        let before_retry = t1 + config.lookup_failure_ttl - Duration::from_secs(1);
        manager
            .resolve("example.com", any, before_retry)
            .await
            .unwrap();
        assert_eq!(
            lookups(&manager),
            2,
            "the next refresh waits for lookup_failure_ttl"
        );

        let retry = t1 + config.lookup_failure_ttl;
        manager.resolve("example.com", any, retry).await.unwrap();
        wait_for_lookups(&manager).await;
        assert_eq!(lookups(&manager), 3);
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_lookup() {
        let manager = manager(round_robin);
        let config = DnsManagerConfig::default();
        let t0 = SystemTime::UNIX_EPOCH;

        // Cache miss.
        let (a, b) = tokio::join!(
            manager.resolve("example.com", any, t0),
            manager.resolve("example.com", any, t0),
        );
        assert_eq!(a.unwrap(), Some(addr(1, 1)));
        assert_eq!(b.unwrap(), Some(addr(1, 1)));
        assert_eq!(lookups(&manager), 1);

        // Refresh.
        let t1 = t0 + config.refresh_interval;
        let (a, b) = tokio::join!(
            manager.resolve("example.com", any, t1),
            manager.resolve("example.com", any, t1),
        );
        assert_eq!(a.unwrap(), Some(addr(1, 1)));
        assert_eq!(b.unwrap(), Some(addr(1, 1)));
        wait_for_lookups(&manager).await;
        assert_eq!(lookups(&manager), 2);
        assert!(manager.0.in_flight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_panicking_lookup_leaves_no_entry() {
        let manager = manager(|lookup| {
            match lookup {
                0 => panic!("resolver bug"),
                _ => Ok(vec![addr(1, 1)]),
            }
        });
        let t0 = SystemTime::UNIX_EPOCH;

        let got = manager.resolve("example.com", any, t0).await;
        assert!(matches!(got, Err(DnsResolveError::Lookup(_))), "{got:?}");
        assert!(manager.0.in_flight.lock().unwrap().is_empty());

        let got = manager.resolve("example.com", any, t0).await;
        assert!(matches!(got, Err(DnsResolveError::Lookup(_))), "{got:?}");
        assert_eq!(
            lookups(&manager),
            1,
            "the panic is cached like a failed lookup"
        );

        let retry = t0 + DnsManagerConfig::default().lookup_failure_ttl;
        let got = manager.resolve("example.com", any, retry).await;
        assert_eq!(got.unwrap(), Some(addr(1, 1)));
        assert_eq!(lookups(&manager), 2);
    }

    #[tokio::test]
    async fn a_lookup_completes_if_the_request_is_dropped() {
        let manager = manager(|_| Ok(vec![addr(1, 1)]));
        let t0 = SystemTime::UNIX_EPOCH;

        // Start the lookup, then drop the request before the lookup runs.
        let request = std::pin::pin!(manager.resolve("example.com", any, t0));
        assert!(futures::poll!(request).is_pending());

        wait_for_lookups(&manager).await;
        assert_eq!(
            manager.cache().get("example.com", any, t0),
            CacheLookup::Found(Some(addr(1, 1)))
        );
    }

    #[tokio::test]
    async fn resolve_all_returns_every_valid_address() {
        let manager = manager(round_robin);
        let config = DnsManagerConfig::default();
        let t0 = SystemTime::UNIX_EPOCH;

        let got = manager.resolve_all("example.com", t0).await;
        assert_eq!(got.unwrap(), vec![addr(1, 1)]);

        // The refresh runs in the background, so the next request sees its answer.
        let t1 = t0 + config.refresh_interval;
        let got = manager.resolve_all("example.com", t1).await;
        assert_eq!(got.unwrap(), vec![addr(1, 1)]);
        wait_for_lookups(&manager).await;
        let got = manager.resolve_all("example.com", t1).await;
        assert_eq!(got.unwrap(), vec![addr(1, 1), addr(1, 2)]);

        let manager = super::tests::manager(|_| Ok(Vec::new()));
        let got = manager.resolve_all("example.com", t0).await;
        assert!(
            matches!(got, Err(DnsResolveError::NoAddresses(_))),
            "{got:?}"
        );
    }

    #[test]
    fn resolver_max_ttl_is_below_refresh_interval() {
        let config = DnsManagerConfig::default();
        assert!(config.resolver_max_ttl() < config.refresh_interval);
    }
}
