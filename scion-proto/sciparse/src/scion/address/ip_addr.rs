// Copyright 2025 Mysten Labs
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

//! SCION address combining [IsdAsn] and [IpAddr] explicitly disallowing
//! [Service Addresses](crate::address::host_addr::ServiceAddr) as Host Address.

use std::{fmt::Display, net::IpAddr, str::FromStr};

use serde_with::{DeserializeFromStr, SerializeDisplay};
use utoipa::{PartialSchema, ToSchema, openapi::Type};

use crate::{
    address::{
        addr::{ScionAddr, ScionAddrV4, ScionAddrV6},
        ip_socket_addr::ScionSocketIpAddr,
    },
    core::macros::impl_from,
    scion::{
        address::{AddressParseError, host_addr::ScionHostAddr},
        identifier::isd_asn::IsdAsn,
    },
};

/// SCION address combining [IsdAsn] and [IpAddr] explicitly disallowing
/// [Service Addresses](crate::address::host_addr::ServiceAddr) as Host Address.
///
/// See [ScionAddr](crate::address::addr::ScionAddr) to allow for Service Addresses as Host Address.
///
/// See [ScionSocketIpAddr](crate::address::ip_socket_addr::ScionSocketIpAddr) for a socket address
/// combining [IsdAsn], [IpAddr] and port.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub enum ScionIpAddr {
    /// IPv4 SCION address
    V4(ScionAddrV4),
    /// IPv6 SCION address
    V6(ScionAddrV6),
}
impl ScionIpAddr {
    /// Create a new SCION address
    pub const fn new(ia: IsdAsn, host: IpAddr) -> Self {
        match host {
            IpAddr::V4(host) => Self::V4(ScionAddrV4::new(ia, host)),
            IpAddr::V6(host) => Self::V6(ScionAddrV6::new(ia, host)),
        }
    }

    /// Returns the ISD-AS number
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            ScionIpAddr::V4(addr) => addr.isd_asn,
            ScionIpAddr::V6(addr) => addr.isd_asn,
        }
    }

    /// Sets the ISD-AS number
    pub fn set_isd_asn(&mut self, ia: IsdAsn) {
        match self {
            ScionIpAddr::V4(addr) => addr.isd_asn = ia,
            ScionIpAddr::V6(addr) => addr.isd_asn = ia,
        }
    }

    /// Returns the Host Address
    pub const fn host(&self) -> ScionHostAddr {
        match self {
            ScionIpAddr::V4(addr) => ScionHostAddr::V4(addr.host),
            ScionIpAddr::V6(addr) => ScionHostAddr::V6(addr.host),
        }
    }

    /// Sets the Host Address
    pub fn set_host(&mut self, host: IpAddr) {
        *self = Self::new(self.isd_asn(), host);
    }

    /// Returns the IpAddr
    pub const fn ip(&self) -> std::net::IpAddr {
        match self {
            ScionIpAddr::V4(addr) => std::net::IpAddr::V4(addr.host),
            ScionIpAddr::V6(addr) => std::net::IpAddr::V6(addr.host),
        }
    }
    /// Returns true if the SCION IP Address is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, ScionIpAddr::V4(_))
    }

    /// Returns true if the SCION IP Address is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, ScionIpAddr::V6(_))
    }

    /// Converts to a [ScionAddr]
    pub fn into_scion_addr(self) -> ScionAddr {
        match self {
            ScionIpAddr::V4(addr) => ScionAddr::V4(addr),
            ScionIpAddr::V6(addr) => ScionAddr::V6(addr),
        }
    }
}
impl FromStr for ScionIpAddr {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = ScionAddrV4::from_str(s) {
            Ok(ScionIpAddr::V4(addr))
        } else if let Ok(addr) = ScionAddrV6::from_str(s) {
            Ok(ScionIpAddr::V6(addr))
        } else {
            Err(AddressParseError::Scion)
        }
    }
}
impl Display for ScionIpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionIpAddr::V4(addr) => addr.fmt(f),
            ScionIpAddr::V6(addr) => addr.fmt(f),
        }
    }
}
impl_from!(ScionAddrV4, ScionIpAddr, |v| ScionIpAddr::V4(v));
impl_from!(ScionAddrV6, ScionIpAddr, |v| ScionIpAddr::V6(v));
impl_from!(ScionSocketIpAddr, ScionIpAddr, |v| {
    ScionIpAddr::new(v.isd_asn(), v.ip())
});
impl PartialSchema for ScionIpAddr {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .examples(["1-ff00:0:110,192.0.2.1", "1-ff00:0:110,2001:db8::1"])
            .schema_type(Type::String)
            .into()
    }
}
impl ToSchema for ScionIpAddr {}
