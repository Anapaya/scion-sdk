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
//! SNAPtun static identity registry.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use snap_tun::server::SnapTunAuthorization;

use crate::crpc_api::api_service::model::SnapTunIdentityRegistry;

type Identity = [u8; 32];

#[derive(Default, Clone)]
struct IdentityRegistryState {
    /// Map socket addresses to their associated identity and the time it was last active.
    // Note: We point to an IdentityRegistration in order to avoid copying the
    // values of the entries.
    pub associations: BTreeMap<Arc<str>, Arc<Identity>>,
    pub expiry: BTreeMap<Arc<Identity>, Instant>,
}

impl IdentityRegistryState {
    pub(crate) fn is_authorized(&self, now: Instant, ident: &Identity) -> bool {
        self.expiry
            .get(ident)
            .map(|expiry| *expiry > now)
            .unwrap_or(false)
    }

    /// Returns true if the identity existed before.
    pub(crate) fn add_identity<S: AsRef<str>>(
        &mut self,
        key: S,
        identity: Identity,
        expiry: Instant,
    ) -> bool {
        let key = Arc::<str>::from(key.as_ref().to_string());
        let ident = Arc::new(identity);
        if let Some(prev_ident) = self.associations.insert(key.clone(), ident.clone())
            && prev_ident != ident
        {
            self.expiry.remove(&ident);
        }
        self.expiry.insert(ident, expiry).is_none()
    }

    /// Removes all expired entries.
    pub(crate) fn clean_expired(&mut self, now: Instant) {
        let mut removed: HashSet<Arc<Identity>> = Default::default();
        self.expiry.retain(|ident, expiry| {
            if *expiry <= now {
                removed.insert(ident.clone());
                return false;
            }
            true
        });
        self.associations
            .retain(|_, ident| !removed.contains(ident));
    }
}

/// Registrar for SNAPtun static identities.
pub struct IdentityRegistry {
    // By using an ArcSwap we optimize for read latency at the (relatively
    // heavy) price of copying the entire map when doing an update. We assume
    // that this is ok for now, but recommend keeping track of latencies in
    // production.
    //
    // Alternatively, the size of this map should be kept small.
    state: arc_swap::ArcSwap<IdentityRegistryState>,
}

impl IdentityRegistry {
    /// Creates a new identity registry with the given keepalive interval.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: Default::default(),
        }
    }

    /// Returns `true` iff the `identity` is authorized to send packets at time
    /// `now`.
    ///
    /// Eventually, this method should return the PSK under which the identity
    /// is authorized.
    pub fn is_authorized(&self, now: Instant, identity: &Identity) -> bool {
        self.state.load().is_authorized(now, identity)
    }

    /// Registers a new identity, associated with key `key` and with the given
    /// lifetime. There can be at most one identity registered per key. If an
    /// identity already exists, it is overwritten. The method is indempotent.
    ///
    /// # Return value
    ///
    /// Returns true if no registration existed before; otherwise false.
    pub fn register<S: AsRef<str>>(
        &self,
        now: Instant,
        key: S,
        ident: Identity,
        lifetime: Duration,
    ) -> bool {
        let mut res = false;
        self.update_state(|state| {
            res = state.add_identity(key, ident, now + lifetime);
        });
        res
    }

    /// Removes all expired entries.
    pub fn remove_expired(&self, now: Instant) {
        self.update_state(|state| state.clean_expired(now));
    }

    fn update_state<F>(&self, modifier: F)
    where
        F: FnOnce(&mut IdentityRegistryState),
    {
        // As cache locality is lost when copying complex data structures, the
        // win in terms of being lock-less might actually be eaten up again.
        let mut state: IdentityRegistryState = (**self.state.load()).clone();
        (modifier)(&mut state);
        self.state.store(Arc::new(state))
    }

    #[cfg(test)]
    pub(crate) fn ident_exist(&self, ident: &Identity) -> bool {
        self.state
            .load()
            .associations
            .values()
            .any(|v| v.as_ref() == ident)
            || self.state.load().expiry.keys().any(|k| k.as_ref() == ident)
    }
}

impl SnapTunIdentityRegistry for IdentityRegistry {
    fn register(
        &self,
        now: Instant,
        key: &str,
        identity: Identity,
        _psk_share: Option<[u8; 32]>,
        lifetime: Duration,
    ) -> bool {
        self.register(now, key, identity, lifetime)
    }
}

impl SnapTunAuthorization for IdentityRegistry {
    fn is_authorized(&self, now: Instant, identity: &Identity) -> bool {
        self.is_authorized(now, identity)
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::PublicKey;

    use super::*;

    fn create_test_identity(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        PublicKey::from(bytes)
    }

    #[test]
    fn test_identity_not_registered() {
        let registry = IdentityRegistry::new();
        let now = Instant::now();
        let identity = create_test_identity(1);

        assert!(!registry.is_authorized(now, identity.as_bytes()));
    }

    #[test]
    fn test_identity_is_authorized_before_expires() {
        let registry = IdentityRegistry::new();
        let now = Instant::now();
        let identity = create_test_identity(1);

        registry.register(now, "", *identity.as_bytes(), Duration::from_secs(30));

        assert!(registry.is_authorized(now, identity.as_bytes()));
    }

    #[test]
    fn test_reregistering_identity_returns_false_but_succeeds() {
        let registry = IdentityRegistry::new();
        let now = Instant::now();
        let identity = create_test_identity(1);
        let delta_t = Duration::from_secs(10);

        registry.register(now, "", *identity.as_bytes(), delta_t);
        assert!(!registry.is_authorized(now + delta_t, identity.as_bytes()));
        assert!(!registry.register(now, "", *identity.as_bytes(), 2 * delta_t));
        assert!(registry.is_authorized(now + delta_t, identity.as_bytes()));
    }

    #[test]
    fn test_identity_is_unauthorized_at_expiry() {
        let registry = IdentityRegistry::new();
        let now = Instant::now();
        let identity = create_test_identity(1);
        let delta_t = Duration::from_secs(30);

        registry.register(now, "", *identity.as_bytes(), delta_t);

        assert!(!registry.is_authorized(now + delta_t, identity.as_bytes()));
    }

    #[test]
    fn test_identity_is_removed_after_expiry() {
        let registry = IdentityRegistry::new();
        let now = Instant::now();
        let identity = create_test_identity(1);
        let delta_t = Duration::from_secs(30);

        registry.register(now, "", *identity.as_bytes(), delta_t);
        assert!(registry.ident_exist(identity.as_bytes()));
        registry.remove_expired(now + delta_t);
        assert!(!registry.ident_exist(identity.as_bytes()));
    }
}
