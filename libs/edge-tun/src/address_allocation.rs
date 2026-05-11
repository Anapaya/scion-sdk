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
//! Allocate addresses.

use std::{net::IpAddr, ops::Deref};

use ipnet::IpNet;
use thiserror::Error;

/// Implementors of edgetun-servers control address allocation by implementing
/// this trait.
///
/// Authorization information is provided in the form of a token.
///
/// ## Limitations & future work
///
/// * While this interface allows for requesting prefixes, actual implementation currently only
///   support requesting actual addresses (max prefix length).
pub trait AddressAllocator<Token>: Send + Sync {
    /// Allocate an address to a client.
    ///
    /// * The implementation SHOULD renew existing allocation, if the token claims matches an
    ///   existing allocation and return the corresponding address.
    ///
    /// * The implementation MUST attempt to return a concrete address if a wildcard IP is provided.
    fn allocate(
        &self,
        prefix: IpNet,
        claims: Token,
    ) -> Result<AddressAllocation, AddressAllocationError>;

    /// Sets an address on hold.
    ///
    /// The hold prevents the address from being reallocated to a different entity for a certain
    /// period of time.
    fn put_on_hold(&self, id: AllocId) -> bool;

    /// Immediately deallocates an address.
    ///
    /// Returns `true` if allocation was found and removed, `false` if allocation was not found.
    fn deallocate(&self, id: AllocId) -> bool;
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Opaque identifier for an address allocation.
pub struct AllocId(pub String);
impl Deref for AllocId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl AllocId {
    /// Consume the [`AllocId`] and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// An allocated IP address together with its allocation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressAllocation {
    /// The identifier of this allocation.
    pub id: AllocId,
    /// The allocated IP address.
    pub address: IpAddr,
}

#[derive(Debug, Error)]
/// Error returned by [`AddressAllocator`] when an allocation fails.
pub enum AddressAllocationError {
    /// The requested address is already registered to another allocation.
    #[error("Requested address {0} already registered")]
    AddressAlreadyRegistered(IpAddr),
    /// The pool has no remaining addresses.
    #[error("No addresses available")]
    NoAddressesAvailable,
    /// The requested address falls outside the configured allocation range.
    #[error("Requested address {0} not in allocation range")]
    AddressNotInAllocationRange(IpAddr),
    /// Prefix allocations (non-host routes) are not yet supported.
    #[error("Prefix allocation not supported: {0}")]
    PrefixAllocationNotYetSupported(IpNet),
    /// The allocation was rejected by policy.
    #[error("Prefix allocation rejected")]
    AddressAllocationRejected,
}
