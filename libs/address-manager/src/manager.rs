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
//! IP address registry.

use std::{
    collections::BTreeMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::IpAddr,
    time::{self, Duration},
};

use ipnet::IpNet;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::{EndhostAddr, IsdAsn};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::allocator::{AddressAllocator, AddressAllocatorError, AllocatorCreationError};

pub mod dto;

const DEFAULT_HOLD_DURATION: Duration = Duration::from_secs(600);
const MAX_ATTEMPTS: usize = 10;

/// Address registration errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressRegistrationError {
    /// Address already registered.
    #[error("requested address {0} already registered")]
    AddressAlreadyRegistered(EndhostAddr),
    /// ISD-AS of the requested address not in range.
    #[error("requested ISD-AS {0} not in allocation ISD-AS {1}")]
    IaNotInAllocationRange(IsdAsn, IsdAsn),
    /// Address allocation error.
    #[error("requested address before start time")]
    AddressAllocatorError(#[from] AddressAllocatorError),
}

/// AddressGrant is the result of a successful registration.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct AddressGrant {
    /// Unique identifier of the allocation.
    pub id: String,
    /// ISD-AS.
    pub isd_as: IsdAsn,
    /// Allocated prefix.
    pub prefix: ipnet::IpNet,
}

// Internal structure to keep track of grants
#[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone)]
struct AddressGrantEntry {
    /// The identity of the token that was used to retrieve this address grant.
    id: String,
    /// The endhost address that was allocated.
    endhost_address: EndhostAddr,
    // Time offset until the Grant will expire
    on_hold_expiry: Option<Duration>,
}

/// Simple single ISD-AS address registry.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressManager {
    /// Hash of isd_as and prefixes to identify the registry
    id: u64,
    isd_as: IsdAsn,
    hold_duration: time::Duration,
    /// Map between ID and Grant
    address_grants: BTreeMap<String, AddressGrantEntry>,
    free_ips: AddressAllocator,
    max_attempts: usize,
    prefixes: Vec<IpNet>,
}

impl AddressManager {
    /// Create a new address registry for the given ISD-AS and prefixes.
    pub fn new(
        isd_as: IsdAsn,
        prefixes: Vec<IpNet>,
        rng: ChaCha8Rng,
    ) -> Result<Self, AllocatorCreationError> {
        let free_ips = AddressAllocator::new(prefixes.clone(), rng)?;
        let id = {
            let mut hasher = DefaultHasher::new();
            isd_as.hash(&mut hasher);
            prefixes.hash(&mut hasher);
            hasher.finish()
        };

        Ok(Self {
            id,
            isd_as,
            hold_duration: DEFAULT_HOLD_DURATION,
            address_grants: Default::default(),
            max_attempts: MAX_ATTEMPTS,
            free_ips,
            prefixes,
        })
    }

    /// Get the unique identifier of this address registry
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Set the hold duration for address grants.
    pub fn with_hold_duration(mut self, hold_duration: time::Duration) -> Self {
        self.hold_duration = hold_duration;
        self
    }

    /// Set the maximum number of attempts to allocate an address.
    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Checks if the given ISD-AS matches the registry's ISD-AS.
    pub fn match_isd_as(&self, isd_as: IsdAsn) -> bool {
        if isd_as.isd().is_wildcard() && isd_as.asn().is_wildcard() {
            true
        } else if isd_as.isd().is_wildcard() {
            isd_as.asn() == self.isd_as.asn()
        } else if isd_as.asn().is_wildcard() {
            isd_as.isd() == self.isd_as.isd()
        } else {
            isd_as == self.isd_as
        }
    }

    /// Registers a new Address, will remove current grant if `id` is reused
    ///
    /// ### Parameters
    /// - `id`: Unique identifier of the allocation. One `id` can only have one Grant.
    /// - `isd_asn`: The IsdAsn associated with this address allocation.
    /// - `addr`: The requested IP address. Use [std::net::Ipv4Addr::UNSPECIFIED] or
    ///   [std::net::Ipv6Addr::UNSPECIFIED] to request any available address.
    pub fn register(
        &mut self,
        id: String,
        mut isd_asn: IsdAsn,
        addr: IpAddr,
    ) -> Result<AddressGrant, AddressRegistrationError> {
        if isd_asn.asn().is_wildcard() {
            isd_asn.set_asn(self.isd_as.asn());
        }
        if isd_asn.isd().is_wildcard() {
            isd_asn.set_isd(self.isd_as.isd());
        }

        if isd_asn != self.isd_as {
            return Err(AddressRegistrationError::IaNotInAllocationRange(
                isd_asn,
                self.isd_as,
            ));
        }

        let endhost_address = match (addr.is_unspecified(), self.address_grants.get(&id)) {
            // Reuse Existing
            (true, Some(existing))
                // Only if they are of the same type
                if existing.endhost_address.local_address().is_ipv4() == addr.is_ipv4() =>
            {
                existing.endhost_address
            }
            (false, Some(existing)) if existing.endhost_address.local_address() == addr => {
                existing.endhost_address
            }
            // Try allocate new,
            // if there was a different, existing alloc it will be removed further down
            (..) => {
                let ip = self.free_ips.allocate(addr)?;
                EndhostAddr::new(isd_asn, ip)
            }
        };

        let grant = AddressGrantEntry {
            id: id.clone(),
            on_hold_expiry: None,
            endhost_address,
        };

        // Insert/Overwrite existing entry
        if let Some(removed) = self.address_grants.insert(id, grant.clone()) {
            if removed.endhost_address != endhost_address {
                if let Err(e) = self.free_ips.free(removed.endhost_address.local_address()) {
                    tracing::error!(
                        error = %e,
                        "Allocator did not contain IP from removed entry - this should not happen"
                    )
                };
            };
        }

        Ok(AddressGrant {
            id: grant.id,
            isd_as: grant.endhost_address.isd_asn(),
            prefix: grant.endhost_address.local_address().into(),
        })
    }

    /// Puts a grant on hold for the default hold period
    ///
    /// After this period has passed, the address can be freed by the cleanup job.
    pub fn put_on_hold(&mut self, id: String, duration_since_start: Duration) -> bool {
        match self.address_grants.get_mut(&id) {
            Some(grant) => {
                grant.on_hold_expiry = Some(duration_since_start + self.hold_duration);

                true
            }
            None => false,
        }
    }

    /// Immediately frees an address
    ///
    /// Returns `true` if address existed and was freed, otherwise `false`
    pub fn free(&mut self, id: &String) -> bool {
        match self.address_grants.remove(id) {
            Some(removed) => {
                if let Err(e) = self.free_ips.free(removed.endhost_address.local_address()) {
                    tracing::warn!(
                        error = %e,
                        "Address allocator did not contain an existing address grant - this should never happen"
                    );
                };

                true
            }
            None => false,
        }
    }

    /// Get this address registries isd-asn
    pub fn isd_asn(&self) -> IsdAsn {
        self.isd_as
    }

    /// Get this address registries prefixes
    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    /// Get the minimal count of free addresses of this registry
    ///
    /// Call [Self::clean_expired] before this to get the actual count
    pub fn min_free_addresses(&self) -> u128 {
        self.free_ips.free_v4() + self.free_ips.free_v6()
    }

    /// Checks all grants and removes expired grants
    ///
    /// Should be called periodically
    ///
    /// Returns (grant_count_before, grant_count_after)
    pub fn clean_expired(&mut self, duration_since_start: Duration) -> (usize, usize) {
        let start_grant_count = self.address_grants.len();

        self.address_grants.retain(|_, grant| {
            let Some(on_hold_until) = grant.on_hold_expiry else {
                return true; // Skip not on hold grants
            };

            // If hold period has passed, clean
            if duration_since_start > on_hold_until {
                // Free IP alloc
                self.free_ips
                    .free(grant.endhost_address.local_address())
                    .unwrap();

                // Remove entry from grants
                return false;
            }

            true
        });

        let end_grant_count = self.address_grants.len();
        (start_grant_count, end_grant_count)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    fn duration(offset: u64) -> Duration {
        Duration::from_secs(offset)
    }

    fn get_registry() -> AddressManager {
        AddressManager::new(
            IsdAsn::from_str("1-ff00:0:110").unwrap(),
            vec![
                IpNet::from_str("192.168.0.0/24").unwrap(),
                IpNet::from_str("2001:db8::/64").unwrap(),
            ],
            ChaCha8Rng::seed_from_u64(42),
        )
        .unwrap()
    }

    fn id() -> String {
        "00000000-0000-0000-0000-000000000001".to_string()
    }

    fn get_request(ip: &str) -> (IsdAsn, IpAddr) {
        (
            IsdAsn::from_str("1-ff00:0:110").unwrap(),
            IpAddr::from_str(ip).unwrap(),
        )
    }

    fn register(
        id: String,
        request: (IsdAsn, IpAddr),
    ) -> Result<AddressGrant, AddressRegistrationError> {
        get_registry().register(id, request.0, request.1)
    }

    #[test]
    fn should_fail_on_isd_as_mismatch() {
        let result = register(
            id(),
            (
                IsdAsn::from_str("1-ff00:0:111").unwrap(),
                "192.168.0.0".parse().unwrap(),
            ),
        );
        assert_eq!(
            result,
            Err(AddressRegistrationError::IaNotInAllocationRange(
                IsdAsn::from_str("1-ff00:0:111").unwrap(),
                IsdAsn::from_str("1-ff00:0:110").unwrap()
            ))
        );
    }

    #[test]
    fn should_fail_if_ipv4_is_outside_range() {
        let result = register(id(), get_request("192.168.1.0"));
        assert_eq!(
            result,
            Err(AddressRegistrationError::AddressAllocatorError(
                AddressAllocatorError::AddressNotInPrefix("192.168.1.0".parse().unwrap())
            ))
        );
    }

    #[test]
    fn should_fail_if_ipv6_is_outside_range() {
        let result = register(id(), get_request("2001:db9::"));
        assert_eq!(
            result,
            Err(AddressRegistrationError::AddressAllocatorError(
                AddressAllocatorError::AddressNotInPrefix("2001:db9::".parse().unwrap())
            ))
        );
    }

    #[test]
    fn should_succeed_to_re_register_same_ip_and_fail_register_same_ip_with_different_id() {
        let isd_as = IsdAsn::from_str("1-ff00:0:110").unwrap();
        let mut registry = get_registry();
        // v4
        {
            let v4 = "192.168.0.0".parse().unwrap();
            registry.register(id(), isd_as, v4).expect("Should Succeed");

            // Register with the same id succeeds.
            registry.register(id(), isd_as, v4).expect("Should Succeed");

            // Register same address, with a different id fails.
            let other_id = "Other Id".to_string();
            let result = registry.register(other_id, isd_as, v4);
            assert_eq!(
                result,
                Err(AddressRegistrationError::AddressAllocatorError(
                    AddressAllocatorError::AddressAlreadyAllocated(v4)
                )),
                "got {result:?}"
            );
        }

        // v6
        {
            let mut registry = get_registry();
            let v6 = "2001:db8::".parse().unwrap();
            registry.register(id(), isd_as, v6).expect("Should Succeed");

            // Register with the same id succeeds.
            registry.register(id(), isd_as, v6).expect("Should Succeed");

            // Register same address, with a different id fails.
            let other_id = "Other Id".to_string();
            let result = registry.register(other_id, isd_as, v6);
            assert_eq!(
                result,
                Err(AddressRegistrationError::AddressAllocatorError(
                    AddressAllocatorError::AddressAlreadyAllocated(v6)
                ))
            );
        }
    }

    #[test]
    fn should_fail_if_no_address_is_available() {
        let isd_as = IsdAsn::from_str("1-ff00:0:110").unwrap();
        let mut registry = AddressManager::new(
            IsdAsn::from_str("1-ff00:0:110").unwrap(),
            vec![],
            ChaCha8Rng::seed_from_u64(42),
        )
        .unwrap();
        // v4
        let v4 = Ipv4Addr::UNSPECIFIED.into();
        let result = registry.register(id(), isd_as, v4);
        assert_eq!(
            result,
            Err(AddressRegistrationError::AddressAllocatorError(
                AddressAllocatorError::NoAddressesAvailable
            ))
        );

        // v6
        let v6 = Ipv6Addr::UNSPECIFIED.into();
        let result = registry.register(id(), isd_as, v6);
        assert_eq!(
            result,
            Err(AddressRegistrationError::AddressAllocatorError(
                AddressAllocatorError::NoAddressesAvailable
            ))
        );
    }

    #[test]
    fn should_succeed_allocation_with_specific_ip() {
        let isd_as = IsdAsn::from_str("1-ff00:0:110").unwrap();
        let mut registry = get_registry();
        // v4
        let v4 = "192.168.0.0".parse().unwrap();
        let result = registry.register(id(), isd_as, v4).expect("Should succeed");
        assert_eq!(result.prefix.addr(), v4, "Expected specific assignment");

        // v6
        let v6 = "2001:db8::".parse().unwrap();
        let result = registry.register(id(), isd_as, v6).expect("Should succeed");
        assert_eq!(result.prefix.addr(), v6, "Expected specific assignment");
    }

    #[test]
    fn should_succeed_allocation_with_wildcard() {
        let mut registry = get_registry();
        // v4
        let result = registry.register(id(), IsdAsn::WILDCARD, Ipv4Addr::UNSPECIFIED.into());
        assert!(result.is_ok());

        // v6
        let result = registry.register(id(), IsdAsn::WILDCARD, Ipv6Addr::UNSPECIFIED.into());
        assert!(result.is_ok());
    }

    #[test]
    fn should_clean_existing_grant_on_reallocation() {
        let mut registry = get_registry();
        let initial = "192.168.0.0".parse().unwrap();
        let other = "2001:db8::".parse().unwrap();

        assert!(
            registry.free_ips.is_free(initial),
            "Expected initial address to be free"
        );

        // Try it a few times
        for _ in 0..10 {
            let grant = registry
                .register(id(), IsdAsn::WILDCARD, initial)
                .expect("Should succeed");

            assert_eq!(
                grant.prefix.addr(),
                initial,
                "Expected assignment of given address"
            );

            assert!(
                !registry.free_ips.is_free(initial),
                "Expected initial address to not be free"
            );

            assert!(
                registry.free_ips.is_free(other),
                "Expected other address to be free"
            );
            // Reregister with different ip
            registry
                .register(id(), IsdAsn::WILDCARD, other)
                .expect("Should succeed");

            assert!(
                registry.free_ips.is_free(initial),
                "Expected initial address to have been freed"
            );
        }
    }

    #[test]
    fn should_not_assign_on_hold_address() {
        let mut registry = get_registry();
        let initial = "192.168.0.0".parse().unwrap();

        let _grant = registry
            .register(id(), IsdAsn::WILDCARD, initial)
            .expect("Should succeed");

        registry.put_on_hold(id(), duration(0));

        let other_id = "Other Id".to_string();
        let result = registry.register(other_id.clone(), IsdAsn::WILDCARD, initial);
        assert_eq!(
            result,
            Err(AddressRegistrationError::AddressAllocatorError(
                AddressAllocatorError::AddressAlreadyAllocated(initial)
            )),
            "Should have given AddressAlreadyAllocated got {result:?}"
        );
    }

    #[test]
    fn should_clean_expired_grants() {
        let mut registry = get_registry();
        let initial = "192.168.0.0".parse().unwrap();
        let grant = registry
            .register(id(), IsdAsn::WILDCARD, initial)
            .expect("Should succeed");

        assert!(registry.put_on_hold(grant.id, duration(0)));

        let (before, after) =
            registry.clean_expired(registry.hold_duration + Duration::from_nanos(1));
        assert_eq!(before, 1);
        assert_eq!(after, 0, "Expected grant to have been cleaned");
        assert!(
            registry.free_ips.is_free(initial),
            "Expected initial address to have been freed"
        );
    }

    #[test]
    fn should_keep_not_expired_grants() {
        let mut registry = get_registry();

        let initial = "192.168.0.0".parse().unwrap();
        let grant = registry
            .register(id(), IsdAsn::WILDCARD, initial)
            .expect("Should succeed");

        assert!(registry.put_on_hold(grant.id, duration(0)));

        let (before, after) = registry.clean_expired(registry.hold_duration);
        assert_eq!(before, 1);
        assert_eq!(after, 1);
    }

    #[test]
    fn should_remove_on_hold_on_reallocation() {
        let mut registry = get_registry();

        let initial = "192.168.0.0".parse().unwrap();
        // Register initial address
        let grant = registry
            .register(id(), IsdAsn::WILDCARD, initial)
            .expect("Should succeed");

        // Put on hold
        assert!(registry.put_on_hold(grant.id.clone(), duration(0)));

        // Re-register the same address
        let regrant = registry
            .register(id(), IsdAsn::WILDCARD, initial)
            .expect("Should succeed");

        // Assert that the re-granted address is the same as the original
        assert!(regrant.prefix == grant.prefix);

        // Assert that the original grant is no longer on hold
        let entry = registry.address_grants.get(&grant.id);
        assert!(entry.is_some());
        assert!(entry.unwrap().on_hold_expiry.is_none());
    }
}
