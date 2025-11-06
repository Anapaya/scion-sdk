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
//! SNAP tunnel library.

pub mod cert_validator;
pub mod client;
pub mod metrics;
pub mod requests;
pub mod server;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use scion_proto::address::{EndhostAddr, IsdAsn};

/// The address assign connect RPC endpoint.
pub(crate) const PATH_ADDR_ASSIGNMENT: &str = "/connectrpc.v1.snaptun/assign_addresses";
/// The session renewal connect RPC endpoint.
pub(crate) const PATH_SESSION_RENEWAL: &str = "/connectrpc.v1.snaptun/renew_session";
pub(crate) const AUTH_HEADER: &str = "Authorization";

/// Placeholder IPv4-Address that should be used by callers to
/// [AddressAllocator::allocate] if the caller wants to request any of the
/// available IPv4-addresses.
pub const IPV4_WILDCARD: IpNet = IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 32));
/// Placeholder IPv6-Address that should be used by callers to
/// [AddressAllocator::allocate] if the caller wants to request any of the
/// available IPv4-addresses.
pub const IPV6_WILDCARD: IpNet = IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128));

/// Address allocation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressAllocationId {
    /// Registry identifier.
    pub registry_id: u64,
    /// Unique identifier for the allocation.
    pub alloc_id: String,
}

/// Address allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressAllocation {
    /// Address allocation identifier.
    pub id: AddressAllocationId,
    /// Allocated endhost address.
    pub address: EndhostAddr,
}

/// Address allocator trait.
pub trait AddressAllocator<Token>: Send + Sync {
    /// Allocate an address to a client.
    ///
    /// * The implementation SHOULD renew existing allocation, if the token claims matches an
    ///   existing allocation and return the corresponding address.
    ///
    /// * The implementation MUST attempt to return a concrete address if either [IPV4_WILDCARD] or
    ///   [IPV6_WILDCARD] is provided.
    fn allocate(
        &self,
        isd_as: IsdAsn,
        prefix: IpNet,
        claims: Token,
    ) -> Result<AddressAllocation, AddressAllocationError>;

    /// Sets an address on hold
    ///
    /// The hold prevents the address from being reallocated for a certain period of time.
    fn put_on_hold(&self, id: AddressAllocationId) -> bool;

    /// Immediately deallocates an address
    ///
    /// Returns `true` if allocation was found and removed, `false` if allocation was not found
    fn deallocate(&self, id: AddressAllocationId) -> bool;
}

/// Address allocation error.
#[derive(Debug, thiserror::Error)]
pub enum AddressAllocationError {
    /// No address manager for the given ISD-AS.
    #[error("no address registry for ISD-AS {0}")]
    NoAddressManagerForIsdAs(IsdAsn),
    /// Address already registered.
    #[error("address {0} already registered")]
    AddressAlreadyRegistered(EndhostAddr),
    /// Address not in allocation range.
    #[error("address {0} not in allocation range")]
    AddressNotInAllocationRange(IpAddr),
    /// IA not in allocation range.
    #[error("address {0} not in allocation ISD-AS {1}")]
    IaNotInAllocationRange(IsdAsn, IsdAsn),
    /// No addresses available.
    #[error("no addresses available")]
    NoAddressesAvailable,
    /// Prefix allocation rejected.
    #[error("prefix allocation rejected")]
    AddressAllocationRejected,
}
