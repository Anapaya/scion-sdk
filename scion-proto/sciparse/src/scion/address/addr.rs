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

//! SCION network address (IsdAsn + HostAddr)

use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};
use utoipa::{PartialSchema, ToSchema, openapi::Type};

use crate::{
    core::macros::impl_from,
    scion::{
        address::{
            AddressParseError,
            host_addr::{ScionHostAddr, ServiceAddr},
            socket_addr::ScionSocketAddr,
        },
        identifier::isd_asn::IsdAsn,
    },
};

/// SCION address combining [IsdAsn] and [ScionHostAddr]
///
/// See [`ScionSocketAddr`](crate::address::socket_addr::ScionSocketAddr) for ([IsdAsn],
/// [HostAddr](crate::address::host_addr::ScionHostAddr) and Port).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub enum ScionAddr {
    /// IPv4 SCION address
    V4(ScionAddrV4),
    /// IPv6 SCION address
    V6(ScionAddrV6),
    /// Service SCION address
    Svc(ScionAddrSvc),
}
impl ScionAddr {
    /// Create a new SCION address
    pub const fn new(ia: IsdAsn, host: ScionHostAddr) -> Self {
        match host {
            ScionHostAddr::V4(host) => Self::V4(ScionAddrV4::new(ia, host)),
            ScionHostAddr::V6(host) => Self::V6(ScionAddrV6::new(ia, host)),
            ScionHostAddr::Svc(host) => Self::Svc(ScionAddrSvc::new(ia, host)),
        }
    }

    /// Returns the ISD-AS number
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            ScionAddr::V4(addr) => addr.isd_asn,
            ScionAddr::V6(addr) => addr.isd_asn,
            ScionAddr::Svc(addr) => addr.isd_asn,
        }
    }

    /// Sets the ISD-AS number
    pub fn set_isd_asn(&mut self, ia: IsdAsn) {
        match self {
            ScionAddr::V4(addr) => addr.isd_asn = ia,
            ScionAddr::V6(addr) => addr.isd_asn = ia,
            ScionAddr::Svc(addr) => addr.isd_asn = ia,
        }
    }

    /// Returns the Host Address
    pub const fn host(&self) -> ScionHostAddr {
        match self {
            ScionAddr::V4(addr) => ScionHostAddr::V4(addr.host),
            ScionAddr::V6(addr) => ScionHostAddr::V6(addr.host),
            ScionAddr::Svc(addr) => ScionHostAddr::Svc(addr.host),
        }
    }

    /// Sets the Host Address
    pub fn set_host(&mut self, host: ScionHostAddr) {
        *self = Self::new(self.isd_asn(), host);
    }

    /// Returns the IpAddr, or None if it is a service address.
    pub const fn ip(&self) -> Option<std::net::IpAddr> {
        match self {
            ScionAddr::V4(addr) => Some(std::net::IpAddr::V4(addr.host)),
            ScionAddr::V6(addr) => Some(std::net::IpAddr::V6(addr.host)),
            ScionAddr::Svc(_) => None,
        }
    }
}
impl FromStr for ScionAddr {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = ScionAddrSvc::from_str(s) {
            Ok(ScionAddr::Svc(addr))
        } else if let Ok(addr) = ScionAddrV4::from_str(s) {
            Ok(ScionAddr::V4(addr))
        } else if let Ok(addr) = ScionAddrV6::from_str(s) {
            Ok(ScionAddr::V6(addr))
        } else {
            Err(AddressParseError::Scion)
        }
    }
}
impl Display for ScionAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionAddr::V4(addr) => addr.fmt(f),
            ScionAddr::V6(addr) => addr.fmt(f),
            ScionAddr::Svc(addr) => addr.fmt(f),
        }
    }
}
impl_from!(ScionAddrV4, ScionAddr, |v| ScionAddr::V4(v));
impl_from!(ScionAddrV6, ScionAddr, |v| ScionAddr::V6(v));
impl_from!(ScionAddrSvc, ScionAddr, |v| ScionAddr::Svc(v));
impl_from!(ScionSocketAddr, ScionAddr, |v| {
    ScionAddr::new(v.isd_asn(), v.host())
});
impl PartialSchema for ScionAddr {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .examples([
                "1-ff00:0:110,192.0.2.1",
                "1-ff00:0:110,2001:db8::1",
                "1-ff00:0:110,CS",
            ])
            .schema_type(Type::String)
            .into()
    }
}
impl ToSchema for ScionAddr {}

/// An IPv4 SCION network address combining [IsdAsn] and [Ipv4Addr]
///
/// See also [ScionAddr] for the enum combining all address types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionAddrV4 {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// IPv4 Address
    pub host: Ipv4Addr,
}
impl ScionAddrV4 {
    /// Create a new SCION IPv4 address
    pub const fn new(isd_asn: IsdAsn, host: Ipv4Addr) -> Self {
        Self { isd_asn, host }
    }
}
impl FromStr for ScionAddrV4 {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (isd_asn, host) = parse_scion_addr::<Ipv4Addr>(s, AddressParseError::SocketV4)?;
        Ok(ScionAddrV4::new(isd_asn, host))
    }
}
impl Display for ScionAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_scion_addr(self.isd_asn, self.host, f)
    }
}
impl TryFrom<ScionAddr> for ScionAddrV4 {
    type Error = &'static str;
    fn try_from(value: ScionAddr) -> Result<Self, Self::Error> {
        match value {
            ScionAddr::V4(addr) => Ok(addr),
            _ => Err("not a ScionAddrV4"),
        }
    }
}
impl PartialSchema for ScionAddrV4 {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .examples(["1-ff00:0:110,192.0.2.1"])
            .schema_type(Type::String)
            .into()
    }
}
impl ToSchema for ScionAddrV4 {}

/// An IPv6 SCION network address combining [IsdAsn] and [Ipv6Addr]
///
/// See also [ScionAddr] for the enum combining all address types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionAddrV6 {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// IPv6 Address
    pub host: Ipv6Addr,
}
impl ScionAddrV6 {
    /// Create a new SCION IPv6 address
    pub const fn new(isd_asn: IsdAsn, host: Ipv6Addr) -> Self {
        Self { isd_asn, host }
    }
}
impl FromStr for ScionAddrV6 {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (isd_asn, host) = parse_scion_addr::<Ipv6Addr>(s, AddressParseError::SocketV6)?;
        Ok(ScionAddrV6::new(isd_asn, host))
    }
}
impl Display for ScionAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_scion_addr(self.isd_asn, self.host, f)
    }
}
impl TryFrom<ScionAddr> for ScionAddrV6 {
    type Error = &'static str;
    fn try_from(value: ScionAddr) -> Result<Self, Self::Error> {
        match value {
            ScionAddr::V6(addr) => Ok(addr),
            _ => Err("not a ScionAddrV6"),
        }
    }
}
impl PartialSchema for ScionAddrV6 {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .examples(["1-ff00:0:110,2001:db8::1"])
            .schema_type(Type::String)
            .into()
    }
}
impl ToSchema for ScionAddrV6 {}

/// A Service SCION network address combining [IsdAsn] and [ServiceAddr]
///
/// See also [ScionAddr] for the enum combining all address types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionAddrSvc {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// Service Address
    pub host: ServiceAddr,
}
impl ScionAddrSvc {
    /// Create a new SCION service address
    pub const fn new(isd_asn: IsdAsn, host: ServiceAddr) -> Self {
        Self { isd_asn, host }
    }
}
impl FromStr for ScionAddrSvc {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (isd_asn, host) = parse_scion_addr::<ServiceAddr>(s, AddressParseError::Service)?;
        Ok(ScionAddrSvc::new(isd_asn, host))
    }
}
impl Display for ScionAddrSvc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_scion_addr(self.isd_asn, self.host, f)
    }
}
impl TryFrom<ScionAddr> for ScionAddrSvc {
    type Error = &'static str;
    fn try_from(value: ScionAddr) -> Result<Self, Self::Error> {
        match value {
            ScionAddr::Svc(addr) => Ok(addr),
            _ => Err("not a ScionAddrSvc"),
        }
    }
}
impl PartialSchema for ScionAddrSvc {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .examples(["1-ff00:0:110,CS", "1-ff00:0:110,DS"])
            .schema_type(Type::String)
            .into()
    }
}
impl ToSchema for ScionAddrSvc {}

fn format_scion_addr<T: Display>(
    isd_asn: IsdAsn,
    host: T,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    write!(f, "{},{}", isd_asn, host)
}

fn parse_scion_addr<T: FromStr>(
    s: &str,
    err_type: AddressParseError,
) -> Result<(IsdAsn, T), AddressParseError> {
    let mut parts = s.splitn(2, ',');
    let isd_asn_str = parts.next().ok_or(AddressParseError::Scion)?;
    let host_str = parts.next().ok_or(AddressParseError::Scion)?;
    let isd_asn = isd_asn_str.parse::<IsdAsn>()?;
    let host = host_str.parse::<T>().map_err(|_| err_type)?;
    Ok((isd_asn, host))
}
