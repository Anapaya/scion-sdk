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
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use x25519_dalek::PublicKey;

struct AssociatedIdentity {
    identity: [u8; 32],
    last_active: Instant,
}

struct IdentityRegistrarState {
    pub keepalive_interval: Duration,
    /// Map socket addresses to their associated identity and the time it was last active.
    pub associations: BTreeMap<SocketAddr, AssociatedIdentity>,
    /// Map all known identities to their lifetime expiration.
    pub identity_lifetime_expirations: BTreeMap<[u8; 32], Instant>,
}

impl IdentityRegistrarState {
    fn new(keepalive_interval: Duration) -> Self {
        Self {
            keepalive_interval,
            associations: BTreeMap::new(),
            identity_lifetime_expirations: BTreeMap::new(),
        }
    }
}

/// Registrar for SNAPtun static identities.
pub struct IdentityRegistry {
    state: Arc<Mutex<IdentityRegistrarState>>,
}

impl IdentityRegistry {
    /// Creates a new identity registry with the given keepalive interval.
    pub fn new(keepalive_interval: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(IdentityRegistrarState::new(keepalive_interval))),
        }
    }

    pub(crate) fn decide_socket_addr_use(
        &self,
        now: Instant,
        identity: PublicKey,
        socket_addr: SocketAddr,
    ) -> IdentityReportingDecision {
        let state = self.state.lock().expect("lock poisoned");

        // Reject if the identity will expire before two keepalive intervals.
        let identity_lifetime_expiration =
            state.identity_lifetime_expirations.get(identity.as_bytes());
        match identity_lifetime_expiration {
            Some(identity_lifetime_expiration) => {
                if (now + state.keepalive_interval * 2) >= *identity_lifetime_expiration {
                    return IdentityReportingDecision::Reject(
                        IdentityReportingRejectReason::LifetimeExpirationIsDue,
                    );
                }
            }
            None => {
                return IdentityReportingDecision::Reject(
                    IdentityReportingRejectReason::IdentityIsNotRegistered,
                );
            }
        }

        if let Some(associated_identity) = state.associations.get(&socket_addr) {
            if &associated_identity.identity == identity.as_bytes() {
                return IdentityReportingDecision::Accept(
                    IdentityReportingAcceptReason::ReassociatedIdentity,
                );
            } else {
                // Identity is occupied by another socket address.
                if associated_identity.last_active + 2 * state.keepalive_interval > now {
                    return IdentityReportingDecision::Reject(
                        IdentityReportingRejectReason::SocketAddressIsOccupied,
                    );
                }
            }
        }
        IdentityReportingDecision::Accept(IdentityReportingAcceptReason::AssociatedIdentity)
    }

    /// Checks if the given identity is associated with the given socket address and reports the use
    /// of the socket address. Returns true if:
    ///   - The identities lifetime is not expired or will not expire before two keepalive
    ///     intervals.
    ///   - The socket address is not occupied by another identity that has been active within the
    ///     last two keepalive intervals.
    pub fn report_socket_addr_use(
        &self,
        now: Instant,
        identity: PublicKey,
        socket_addr: SocketAddr,
    ) -> bool {
        let decision = self.decide_socket_addr_use(now, identity, socket_addr);
        tracing::debug!(?decision, "Reported data decision");
        match decision {
            IdentityReportingDecision::Accept(_) => {
                let mut state = self.state.lock().expect("lock poisoned");
                state.associations.insert(
                    socket_addr,
                    AssociatedIdentity {
                        identity: *identity.as_bytes(),
                        last_active: now,
                    },
                );
                true
            }
            IdentityReportingDecision::Reject(_) => false,
        }
    }

    /// Registers a new identity with the given lifetime.
    pub fn register(&self, now: Instant, ident: PublicKey, lifetime: Duration) {
        let mut state = self.state.lock().expect("lock poisoned");
        state
            .identity_lifetime_expirations
            .insert(*ident.as_bytes(), now + lifetime);
    }

    #[cfg(test)]
    /// Test helper to set up socket address association for testing.
    pub(crate) fn test_set_association(
        &self,
        socket_addr: SocketAddr,
        identity: PublicKey,
        last_active: Instant,
    ) {
        let mut state = self.state.lock().expect("lock poisoned");
        state.associations.insert(
            socket_addr,
            AssociatedIdentity {
                identity: *identity.as_bytes(),
                last_active,
            },
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityReportingRejectReason {
    /// The identity is rejected because it will expire before two keepalive intervals.
    LifetimeExpirationIsDue,
    /// The identity is rejected because the socket address is already occupied by another identity.
    SocketAddressIsOccupied,
    /// The identity is rejected because the identity is not registered.
    IdentityIsNotRegistered,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityReportingAcceptReason {
    /// The identity is successfully associated with the socket address.
    AssociatedIdentity,
    /// The identity is successfully reassociated with the socket address.
    ReassociatedIdentity,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityReportingDecision {
    #[allow(dead_code)]
    Reject(IdentityReportingRejectReason),
    #[allow(dead_code)]
    Accept(IdentityReportingAcceptReason),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        PublicKey::from(bytes)
    }

    #[test]
    fn test_identity_not_registered() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity = create_test_identity(1);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        let decision = registry.decide_socket_addr_use(now, identity, socket_addr);

        assert_eq!(
            decision,
            IdentityReportingDecision::Reject(
                IdentityReportingRejectReason::IdentityIsNotRegistered
            )
        );
    }

    #[test]
    fn test_identity_lifetime_expires_before_two_keepalive_intervals() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity = create_test_identity(1);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register identity with lifetime that expires before now + 2 * keepalive_interval
        // keepalive_interval is 30 seconds, so 2 * keepalive_interval = 60 seconds
        // Set lifetime to 30 seconds, so it expires before 60 seconds
        registry.register(now, identity, Duration::from_secs(30));

        let decision = registry.decide_socket_addr_use(now, identity, socket_addr);

        assert_eq!(
            decision,
            IdentityReportingDecision::Reject(
                IdentityReportingRejectReason::LifetimeExpirationIsDue
            )
        );
    }

    #[test]
    fn test_identity_lifetime_expires_exactly_at_two_keepalive_intervals() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity = create_test_identity(1);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register identity with lifetime expiring exactly at now + 2 * keepalive_interval
        // keepalive_interval is 30 seconds, so 2 * keepalive_interval = 60 seconds
        registry.register(now, identity, Duration::from_secs(60));

        let decision = registry.decide_socket_addr_use(now, identity, socket_addr);

        // Since condition is >= (not >), at exactly the boundary:
        // (now + 60) >= (now + 60) is true, so it should reject
        assert_eq!(
            decision,
            IdentityReportingDecision::Reject(
                IdentityReportingRejectReason::LifetimeExpirationIsDue
            )
        );
    }

    #[test]
    fn test_reassociation_with_same_identity() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity = create_test_identity(1);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register identity with valid lifetime
        registry.register(now, identity, Duration::from_secs(90));

        // Set up association with same identity
        registry.test_set_association(socket_addr, identity, now);

        let decision = registry.decide_socket_addr_use(now, identity, socket_addr);

        assert_eq!(
            decision,
            IdentityReportingDecision::Accept(IdentityReportingAcceptReason::ReassociatedIdentity)
        );
    }

    #[test]
    fn test_socket_address_occupied_by_different_active_identity() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity1 = create_test_identity(1);
        let identity2 = create_test_identity(2);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register both identities with valid lifetimes
        registry.register(now, identity1, Duration::from_secs(150));
        registry.register(now, identity2, Duration::from_secs(150));

        // Set up association with identity1, recently active (within 2 * keepalive_interval)
        // keepalive_interval is 30 seconds, so 2 * keepalive_interval = 60 seconds
        // We check at now + 50, so set last_active to now to ensure it's still active
        // now + 50 < now + (2 * 30), so it should be considered occupied
        let check_time = now + Duration::from_secs(50);
        registry.test_set_association(socket_addr, identity1, now);

        // Try to use identity2 with the same socket address
        let decision = registry.decide_socket_addr_use(check_time, identity2, socket_addr);

        assert_eq!(
            decision,
            IdentityReportingDecision::Reject(
                IdentityReportingRejectReason::SocketAddressIsOccupied
            )
        );
    }

    #[test]
    fn test_socket_address_occupied_by_expired_identity() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity1 = create_test_identity(1);
        let identity2 = create_test_identity(2);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register both identities with valid lifetimes
        registry.register(now, identity1, Duration::from_secs(90));
        registry.register(now, identity2, Duration::from_secs(90));

        // Set up association with identity1, but last_active was more than
        // 2 * keepalive_interval ago (60 seconds ago)
        // Set last_active to 61 seconds ago
        let expired_time = now - Duration::from_secs(61);
        registry.test_set_association(socket_addr, identity1, expired_time);

        // Try to use identity2 with the same socket address
        let decision = registry.decide_socket_addr_use(now, identity2, socket_addr);

        // Occupation has expired, so should accept
        assert_eq!(
            decision,
            IdentityReportingDecision::Accept(IdentityReportingAcceptReason::AssociatedIdentity)
        );
    }

    #[test]
    fn test_new_association_empty_socket_address() {
        let registry = IdentityRegistry::new(Duration::from_secs(30));
        let now = Instant::now();
        let identity = create_test_identity(1);
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 8080));

        // Register identity with valid lifetime
        registry.register(now, identity, Duration::from_secs(90));

        // No socket address associations set up
        let decision = registry.decide_socket_addr_use(now, identity, socket_addr);

        assert_eq!(
            decision,
            IdentityReportingDecision::Accept(IdentityReportingAcceptReason::AssociatedIdentity)
        );
    }
}
