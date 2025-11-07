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
//! An IP address allocator.

use std::net::IpAddr;

use ipnet::IpNet;
use rand::Rng as _;
use rand_chacha::ChaCha8Rng;
use thiserror::Error;

use crate::allocator::addr_set::{AddrSet, AddrSetError};

mod addr_set;
pub(crate) mod dto;

/// An allocator of IP addresses.
// Impl Note:
// The AddrSets contain all free addresses.
// On Allocation - Address is removed from the Set
// On Free       - Address is added to the Set.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AddressAllocator {
    /// Non overlapping ranges sorted by start address.
    v4: Vec<AddrSet>,
    /// Non overlapping ranges sorted by start address.
    v6: Vec<AddrSet>,
    /// RNG for random address allocation.
    rng: ChaCha8Rng,
}

/// Address allocator creation errors.
#[derive(Debug, Error)]
pub enum AllocatorCreationError {
    /// Prefixes are too large.
    #[error("prefixes containing more than 2^128 addresses are not supported")]
    PrefixesTooLarge,
}

impl AddressAllocator {
    /// Creates a new AddressAllocator.
    ///
    /// # Arguments
    /// * `prefixes` - A list of non-overlapping prefixes to allocate from.
    /// * `rng` - A random number generator for random address allocation.
    pub fn new(prefixes: Vec<IpNet>, rng: ChaCha8Rng) -> Result<Self, AllocatorCreationError> {
        // Sort prefixes by network address.
        let mut prefixes = prefixes;
        prefixes.sort_by_key(|prefix| prefix.network());
        // assert: aggregated prefixes are non-overlapping
        let aggregated = IpNet::aggregate(&prefixes);
        // If the sum of all prefixes contain more than 2^128 addresses, return an error.
        if aggregated
            .iter()
            .map(|p| 2u128.pow(p.prefix_len() as u32))
            .try_fold(0_u128, |acc, x| acc.checked_add(x))
            .is_none()
        {
            return Err(AllocatorCreationError::PrefixesTooLarge);
        }

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        for prefix in aggregated {
            match prefix.network() {
                IpAddr::V4(_) => v4.push(AddrSet::new(prefix)),
                IpAddr::V6(_) => v6.push(AddrSet::new(prefix)),
            }
        }

        Ok(Self { v4, v6, rng })
    }

    /// Returns a mutable reference to the address set containing the given address.
    fn mut_address_set(&mut self, address: &IpAddr) -> Result<&mut AddrSet, AddressAllocatorError> {
        let res = match address {
            IpAddr::V4(_) => self.v4.iter_mut().find(|set| set.prefix.contains(address)),
            IpAddr::V6(_) => self.v6.iter_mut().find(|set| set.prefix.contains(address)),
        };

        res.ok_or(AddressAllocatorError::AddressNotInPrefix(*address))
    }

    /// Frees a certain Address
    ///
    /// Returns an error if the address is not in in Prefix
    pub fn free(&mut self, address: IpAddr) -> Result<(), AddressAllocatorError> {
        self.mut_address_set(&address)?.insert(address)?;
        Ok(())
    }

    /// Allocates a specific address
    ///
    /// Returns an error if the address is already allocated, or not in in Prefix
    fn allocate_specific(&mut self, address: IpAddr) -> Result<(), AddressAllocatorError> {
        self.mut_address_set(&address)?.remove(address)?;
        Ok(())
    }

    /// Check if an address is free
    pub fn is_free(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(_) => self.v4.iter().any(|set| set.contains(address)),
            IpAddr::V6(_) => self.v6.iter().any(|set| set.contains(address)),
        }
    }

    /// Allocate an address from the address allocator. If the requested address is unspecified, a
    /// random address of the given family is allocated.
    pub fn allocate(&mut self, requested: IpAddr) -> Result<IpAddr, AddressAllocatorError> {
        if requested.is_unspecified() {
            match requested {
                IpAddr::V4(_) => {
                    if self.free_v4() == 0 {
                        return Err(AddressAllocatorError::NoAddressesAvailable);
                    }
                    let mut n = self.rng.random_range(0..self.free_v4());
                    for set in self.v4.iter_mut() {
                        if n < set.len() {
                            let addr = set.nth_free(n).expect("Checked above");
                            self.allocate_specific(addr)?;
                            return Ok(addr);
                        }
                        n -= set.len();
                    }
                }
                IpAddr::V6(_) => {
                    if self.free_v6() == 0 {
                        return Err(AddressAllocatorError::NoAddressesAvailable);
                    }
                    let mut n = self.rng.random_range(0..self.free_v6());
                    for set in self.v6.iter_mut() {
                        if n < set.len() {
                            let addr = set.nth_free(n).expect("Checked above");
                            self.allocate_specific(addr)?;
                            return Ok(addr);
                        }
                        n -= set.len();
                    }
                }
            }
            Err(AddressAllocatorError::NoAddressesAvailable)
        } else {
            self.allocate_specific(requested)?;
            Ok(requested)
        }
    }

    pub(crate) fn free_v4(&self) -> u128 {
        self.v4.iter().map(|set| set.len()).sum::<u128>()
    }

    pub(crate) fn free_v6(&self) -> u128 {
        self.v6.iter().map(|set| set.len()).sum::<u128>()
    }
}

/// Address allocation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressAllocatorError {
    /// Address not in any allocation prefix.
    #[error("requested address {0} not in allocation prefixes")]
    AddressNotInPrefix(IpAddr),
    /// Address already allocated.
    #[error("address {0} already allocated")]
    AddressAlreadyAllocated(IpAddr),
    /// Address is already free.
    #[error("address is already freed")]
    AddressAlreadyFreed(IpAddr),
    /// All addresses are allocated.
    #[error("no addresses available")]
    NoAddressesAvailable,
}

impl From<AddrSetError> for AddressAllocatorError {
    fn from(err: AddrSetError) -> Self {
        match err {
            AddrSetError::AddressNotInPrefix(addr) => {
                AddressAllocatorError::AddressNotInPrefix(addr)
            }
            AddrSetError::AddressAlreadyInSet(addr) => {
                AddressAllocatorError::AddressAlreadyFreed(addr)
            }
            AddrSetError::AddressNotInSet(addr) => {
                AddressAllocatorError::AddressAlreadyAllocated(addr)
            }
            // This should never happen.
            AddrSetError::WrongIPVersion(_addr) => {
                unreachable!("Allocator always supports both IPv4 and IPv6")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use rand::SeedableRng;

    use super::*;

    // Function to check invariants
    fn check_allocator_invariants(allocator: &AddressAllocator) {
        // Check that intervals are disjoint and ordered
        for sets in [&allocator.v4, &allocator.v6] {
            for set in sets {
                for i in 1..set.free.ranges().len() {
                    // Intervals should be ordered
                    assert!(
                        set.free.ranges()[i - 1].start < set.free.ranges()[i].start,
                        "{:?} Interval not ordered: {:?} and {:?}",
                        set.prefix,
                        set.free.ranges()[i - 1],
                        set.free.ranges()[i]
                    );

                    // Intervals should be disjoint
                    assert!(
                        set.free.ranges()[i - 1].end < set.free.ranges()[i].start,
                        "{:?} Intervals not disjoint: {:?} and {:?}",
                        set.prefix,
                        set.free.ranges()[i - 1],
                        set.free.ranges()[i]
                    );
                }

                // Check that each interval is valid (start < end)
                for interval in set.free.ranges() {
                    assert!(
                        interval.start < interval.end,
                        "{:?} Invalid interval: {:?}",
                        set.prefix,
                        interval
                    );
                }
            }
        }
    }

    #[test]
    fn allocate_random_addresses_successfully() {
        let prefixes = vec![
            "192.168.0.0/24".parse().unwrap(),
            "10.0.0.0/16".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];

        let mut expected_length = 2u128.pow(8) + 2u128.pow(16) + 2u128.pow(64);

        let mut allocator = AddressAllocator::new(prefixes, ChaCha8Rng::seed_from_u64(42)).unwrap();
        let mut allocated = Vec::new();
        // IPv4 addresses
        for _ in 0..1000 {
            let addr = allocator
                .allocate(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .expect("Failed to allocate");
            check_allocator_invariants(&allocator);
            assert!(!allocator.is_free(addr));
            assert!(addr.is_ipv4());
            expected_length -= 1;
            assert_eq!(allocator.free_v4() + allocator.free_v6(), expected_length);
            allocated.push(addr);
        }
        // IPv6 addresses
        for _ in 0..1000 {
            let addr = allocator
                .allocate(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                .expect("Failed to allocate");
            check_allocator_invariants(&allocator);
            assert!(!allocator.is_free(addr));
            assert!(addr.is_ipv6());
            expected_length -= 1;
            assert_eq!(allocator.free_v4() + allocator.free_v6(), expected_length);
            allocated.push(addr);
        }
        // Insert the addresses back into the allocator
        for addr in allocated {
            allocator.free(addr).unwrap();
            check_allocator_invariants(&allocator);
            expected_length += 1;
            assert_eq!(allocator.free_v4() + allocator.free_v6(), expected_length);
            assert!(allocator.is_free(addr));
        }

        // Check that all prefix sets only have one range
        for set in &allocator.v4 {
            assert_eq!(1, set.free.ranges().len());
        }
        for set in &allocator.v6 {
            assert_eq!(1, set.free.ranges().len());
        }
    }

    #[test]
    fn allocate_boundary_addresses_validates_range() {
        let testcases = vec![
            // v4
            (
                // prefix
                "192.168.0.0/24".parse().unwrap(),
                // address outside lower boundary
                IpAddr::from_str("192.167.255.255").unwrap(),
                // address outside upper boundary
                IpAddr::from_str("192.168.1.0").unwrap(),
            ),
            // v6
            (
                // prefix
                "2001:db8::/64".parse().unwrap(),
                // address outside lower boundary
                IpAddr::from_str("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff").unwrap(),
                // address outside upper boundary
                IpAddr::from_str("2001:db9::0").unwrap(),
            ),
        ];

        for (prefix, lower, upper) in testcases {
            let mut allocator =
                AddressAllocator::new(vec![prefix], ChaCha8Rng::seed_from_u64(42)).unwrap();

            // lower end of the range
            let fail = allocator
                .allocate(lower)
                .expect_err("Should not be able to allocate");
            assert!(matches!(fail, AddressAllocatorError::AddressNotInPrefix(_)),);

            let addr = allocator
                .allocate(prefix.network())
                .expect("Failed to allocate");
            assert!(!allocator.is_free(addr));
            assert!(std::mem::discriminant(&addr) == std::mem::discriminant(&prefix.network()));

            let fail = allocator
                .allocate(prefix.network())
                .expect_err("Should not be able to allocate");
            assert!(matches!(
                fail,
                AddressAllocatorError::AddressAlreadyAllocated(_)
            ));

            // upper end of the range
            let fail = allocator
                .allocate(upper)
                .expect_err("Should not be able to allocate");
            assert!(matches!(fail, AddressAllocatorError::AddressNotInPrefix(_)));

            let addr = allocator
                .allocate(prefix.broadcast())
                .expect("Failed to allocate");
            assert!(!allocator.is_free(addr));
            assert!(std::mem::discriminant(&addr) == std::mem::discriminant(&prefix.network()));

            let fail = allocator
                .allocate(prefix.broadcast())
                .expect_err("Should not be able to allocate");
            assert!(matches!(
                fail,
                AddressAllocatorError::AddressAlreadyAllocated(_)
            ));
        }
    }

    #[test]
    fn allocate_exhausted_pool_returns_error() {
        let mut allocator = AddressAllocator::new(
            vec![
                "192.168.0.0/31".parse().unwrap(),
                "192.168.0.2/31".parse().unwrap(),
            ],
            ChaCha8Rng::seed_from_u64(42),
        )
        .unwrap();
        for _ in 0..4 {
            let addr = allocator
                .allocate(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .expect("Failed to allocate");
            assert!(addr.is_ipv4());
            check_allocator_invariants(&allocator);
        }
        assert_eq!(allocator.free_v4(), 0);
        let fail = allocator
            .allocate(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .expect_err("Should not be able to allocate");
        assert!(matches!(fail, AddressAllocatorError::NoAddressesAvailable));
    }
}
