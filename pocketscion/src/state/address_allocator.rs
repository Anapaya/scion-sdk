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
//! SNAP address allocator.

use std::{
    sync::RwLockWriteGuard,
    time::{Duration, SystemTime},
};

use ipnet::IpNet;
use scion_proto::address::{EndhostAddr, IsdAsn};
use scion_sdk_address_manager::manager::AddressManager;
use scion_sdk_token_validator::validator::Token;
use snap_tokens::snap_token::SnapTokenClaims;
use snap_tun::{AddressAllocation, AddressAllocationId};

use crate::state::{AllocationError, SharedPocketScionState, SnapDataPlaneId, SystemState};

/// An address allocator for a certain SNAP data plane.
pub(crate) struct StateSnapAddressAllocator {
    state: SharedPocketScionState,
    snap_data_plane_id: SnapDataPlaneId,
}

impl StateSnapAddressAllocator {
    pub(crate) fn new(state: SharedPocketScionState, snap_data_plane_id: SnapDataPlaneId) -> Self {
        Self {
            state,
            snap_data_plane_id,
        }
    }

    fn mut_registry_by_isd_as<'a>(
        &self,
        state_guard: &'a mut RwLockWriteGuard<'_, SystemState>,
        isd_as: IsdAsn,
    ) -> Result<&'a mut AddressManager, AllocationError> {
        let reg = state_guard
            .snaps
            .get_mut(&self.snap_data_plane_id.snap())
            .expect("SNAP not found")
            .data_planes
            .get_mut(&self.snap_data_plane_id.data_plane())
            .expect("SNAP data plane not found");

        let reg = reg
            .address_registries
            .values_mut()
            .find(|registry| registry.match_isd_as(isd_as))
            .ok_or(AllocationError::NoAddressManagerForIsdAs(isd_as))?;

        Ok(reg)
    }

    fn mut_registry_by_id<'a>(
        &self,
        state_guard: &'a mut RwLockWriteGuard<'_, SystemState>,
        registry_id: u64,
    ) -> Result<&'a mut AddressManager, AllocationError> {
        let reg = state_guard
            .snaps
            .get_mut(&self.snap_data_plane_id.snap())
            .expect("SNAP not found")
            .data_planes
            .get_mut(&self.snap_data_plane_id.data_plane())
            .expect("SNAP data plane not found");

        let reg = reg
            .address_registries
            .values_mut()
            .find(|registry| registry.id() == registry_id)
            .ok_or(AllocationError::NoAddressManagerForId(registry_id))?;

        Ok(reg)
    }

    fn allocate_internal(
        &self,
        isd_as: IsdAsn,
        prefix: IpNet,
        id: String,
    ) -> Result<AddressAllocation, AllocationError> {
        if prefix.prefix_len() != prefix.max_prefix_len() {
            return Err(AllocationError::PrefixAllocationNotSupported(prefix));
        }

        let mut state_guard = self.state.system_state.write().unwrap();

        let registry = self.mut_registry_by_isd_as(&mut state_guard, isd_as)?;

        let grant = registry.register(id.clone(), isd_as, prefix.addr())?;

        Ok(AddressAllocation {
            id: AddressAllocationId {
                registry_id: registry.id(),
                alloc_id: id,
            },
            address: EndhostAddr::new(grant.isd_as, grant.prefix.addr()),
        })
    }

    fn hold_internal(&self, id: snap_tun::AddressAllocationId) -> bool {
        let mut state_guard = self.state.system_state.write().unwrap();
        let start_time: SystemTime = state_guard.start_time;

        let Ok(registry) = self.mut_registry_by_id(&mut state_guard, id.registry_id) else {
            tracing::warn!(id= ?id, "Address allocation contained invalid registry id");
            return false;
        };

        registry.put_on_hold(
            id.alloc_id,
            SystemTime::now()
                .duration_since(start_time)
                .expect("system time went backwards"),
        )
    }

    fn deallocate_internal(&self, id: snap_tun::AddressAllocationId) -> bool {
        let mut state_guard = self.state.system_state.write().unwrap();

        let Ok(registry) = self.mut_registry_by_id(&mut state_guard, id.registry_id) else {
            tracing::warn!(id= ?id, "Address allocation contained invalid registry id");
            return false;
        };

        registry.free(&id.alloc_id)
    }
}

impl snap_tun::AddressAllocator<SnapTokenClaims> for StateSnapAddressAllocator {
    fn allocate(
        &self,
        isd_as: IsdAsn,
        prefix: IpNet,
        claims: SnapTokenClaims,
    ) -> Result<snap_tun::AddressAllocation, snap_tun::AddressAllocationError> {
        if claims.exp_time() < SystemTime::now() {
            return Err(snap_tun::AddressAllocationError::AddressAllocationRejected);
        }

        Ok(self.allocate_internal(isd_as, prefix, claims.id())?)
    }

    fn put_on_hold(&self, id: snap_tun::AddressAllocationId) -> bool {
        self.hold_internal(id)
    }

    fn deallocate(&self, id: snap_tun::AddressAllocationId) -> bool {
        self.deallocate_internal(id)
    }
}

impl SharedPocketScionState {
    /// Cleans all expired entries from address registries
    #[expect(unused)]
    fn clean_all_address_registries(&self, time_since_start: Duration) {
        let mut state_guard = self.system_state.write().unwrap();

        state_guard
            .snaps
            .values_mut()
            .flat_map(|s| s.data_planes.values_mut())
            .flat_map(|d| d.address_registries.values_mut())
            .for_each(|r| {
                r.clean_expired(time_since_start);
            });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
        time::{Duration, UNIX_EPOCH},
    };

    use ipnet::{Ipv4Net, Ipv6Net};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use snap_tokens::Pssid;
    use snap_tun::{AddressAllocation, AddressAllocator};
    use test_log::test;
    use uuid::Uuid;

    use super::*;

    const IPV4_PREFIX: IpNet = IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8));
    const IPV6_PREFIX: IpNet = IpNet::V6(Ipv6Net::new_assert(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        64,
    ));

    fn check_wildcard_allocation(
        res: Result<AddressAllocation, snap_tun::AddressAllocationError>,
        isd_as: IsdAsn,
        prefix: IpNet,
    ) {
        let grant = res.expect("Address allocation failed");
        assert_eq!(
            grant.address.isd_asn(),
            isd_as,
            "Allocated address ISD-AS does not match"
        );
        assert!(
            prefix.contains(&grant.address.local_address()),
            "Allocated address is not within the expected prefix, prefix: {prefix}, address: {}",
            grant.address.local_address()
        );
    }

    fn check_explicit_allocation(
        res: Result<AddressAllocation, snap_tun::AddressAllocationError>,
        isd_as: IsdAsn,
        expected: IpAddr,
    ) {
        let grant = res.expect("Address allocation failed");
        assert_eq!(
            grant.address.isd_asn(),
            isd_as,
            "Allocated address ISD-AS does not match"
        );
        assert_eq!(
            grant.address.local_address(),
            expected,
            "Allocated address is not the expected one"
        );
    }

    #[test(tokio::test)]
    async fn should_allocate_explicit_and_wildcard_addresses() {
        let now = SystemTime::now();
        let mut state = SharedPocketScionState::new(now);

        let isd_as = IsdAsn::from_str("1-ff00:0:110").unwrap();
        let prefixes: Vec<IpNet> = vec![IPV4_PREFIX, IPV6_PREFIX];
        let snap_id = state.add_snap();

        // Create a new snap
        let snap_dp_id =
            state.add_snap_data_plane(snap_id, isd_as, prefixes, ChaCha8Rng::from_os_rng());

        // Get address allocator for the snap
        let allocator = StateSnapAddressAllocator::new(state, snap_dp_id);

        let snap_token = SnapTokenClaims {
            pssid: Pssid(Uuid::new_v4()),
            exp: SystemTime::now()
                .checked_add(Duration::from_secs(1000000000))
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // explicit IPv4 allocation
        let requested_ipv4 = Ipv4Addr::new(10, 0, 0, 10);
        let result = allocator.allocate(
            isd_as,
            Ipv4Net::new_assert(requested_ipv4, 32).into(),
            snap_token.clone(),
        );
        check_explicit_allocation(result, isd_as, requested_ipv4.into());

        // explicit IPv6 allocation
        let requested_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let result = allocator.allocate(
            isd_as,
            Ipv6Net::new_assert(requested_ipv6, 128).into(),
            snap_token.clone(),
        );
        check_explicit_allocation(result, isd_as, requested_ipv6.into());

        // wildcard IPv4 allocation
        let result = allocator.allocate(
            isd_as,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED).into(),
            snap_token.clone(),
        );
        check_wildcard_allocation(result, isd_as, IPV4_PREFIX);

        // wildcard IPv6 allocation
        let result = allocator.allocate(
            isd_as,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED).into(),
            snap_token.clone(),
        );
        check_wildcard_allocation(result, isd_as, IPV6_PREFIX);

        // prefixes not yet supported
        let result = allocator.allocate(
            isd_as,
            Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 10), 30).into(),
            snap_token.clone(),
        );
        assert!(matches!(
            result,
            Err(snap_tun::AddressAllocationError::AddressAllocationRejected)
        ));

        let result = allocator.allocate(
            isd_as,
            Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10), 120).into(),
            snap_token.clone(),
        );
        assert!(matches!(
            result,
            Err(snap_tun::AddressAllocationError::AddressAllocationRejected)
        ));
    }
}
