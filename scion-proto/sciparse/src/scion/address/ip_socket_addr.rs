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

//! SCION address combining [IsdAsn], [IpAddr] and a Port explicitly disallowing
//! [Service Addresses](crate::address::host_addr::ServiceAddr) as Host Address.

use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    address::{
        ip_addr::ScionIpAddr,
        socket_addr::{ScionSocketAddr, ScionSocketAddrV4, ScionSocketAddrV6},
    },
    core::macros::impl_from,
    scion::{
        address::{
            AddressParseError,
            addr::{ScionAddr, ScionAddrV4, ScionAddrV6},
        },
        identifier::isd_asn::IsdAsn,
    },
};

/// SCION address combining [IsdAsn], [IpAddr] and a Port explicitly disallowing
/// [Service Addresses](crate::address::host_addr::ServiceAddr) as Host Address.
///
/// See [ScionIpAddr](crate::address::ip_addr::ScionIpAddr) for ([IsdAsn] and [IpAddr]) without
/// Port.
///
/// See [ScionSocketAddr](crate::address::socket_addr::ScionSocketAddr) for ([IsdAsn],
/// [ScionHostAddr](crate::address::host_addr::ScionHostAddr) and Port) allowing Service Addresses.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub enum ScionSocketIpAddr {
    /// IPv4 SCION Socket Address
    V4(ScionSocketAddrV4),
    /// IPv6 SCION Socket Address
    V6(ScionSocketAddrV6),
}
impl ScionSocketIpAddr {
    /// Create a new SCION Socket Address
    pub const fn new(isd_asn: IsdAsn, host: IpAddr, port: u16) -> Self {
        match host {
            IpAddr::V4(host) => {
                Self::V4(ScionSocketAddrV4 {
                    isd_asn,
                    host,
                    port,
                })
            }
            IpAddr::V6(host) => {
                Self::V6(ScionSocketAddrV6 {
                    isd_asn,
                    host,
                    port,
                })
            }
        }
    }

    /// Create a SCION Socket Address from a standard Socket Address
    pub const fn from_socket_addr(isd_asn: IsdAsn, addr: std::net::SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => {
                Self::V4(ScionSocketAddrV4 {
                    isd_asn,
                    host: *v4.ip(),
                    port: v4.port(),
                })
            }
            SocketAddr::V6(v6) => {
                Self::V6(ScionSocketAddrV6 {
                    isd_asn,
                    host: *v6.ip(),
                    port: v6.port(),
                })
            }
        }
    }

    /// Create a SCION Socket Address from a SCION Address and a port number
    ///
    /// Returns an error if the SCION Address is a Service Address.
    pub const fn try_from_scion_addr(scion_addr: ScionAddr, port: u16) -> Result<Self, ScionAddr> {
        match scion_addr {
            ScionAddr::V4(addr) => {
                Ok(Self::V4(ScionSocketAddrV4 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                    port,
                }))
            }
            ScionAddr::V6(addr) => {
                Ok(Self::V6(ScionSocketAddrV6 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                    port,
                }))
            }
            ScionAddr::Svc(_) => Err(scion_addr),
        }
    }

    /// Returns a [SocketAddr] from the SCION Socket Address if it is an IPv4 or IPv6 address.
    /// Returns None if it is a Service Address.
    pub const fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            ScionSocketIpAddr::V4(addr) => {
                Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                    addr.host, addr.port,
                )))
            }
            ScionSocketIpAddr::V6(addr) => {
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    addr.host, addr.port, 0, 0,
                )))
            }
        }
    }

    /// Converts to a [ScionSocketAddr]
    pub fn into_scion_sock_addr(self) -> ScionSocketAddr {
        match self {
            ScionSocketIpAddr::V4(addr) => ScionSocketAddr::V4(addr),
            ScionSocketIpAddr::V6(addr) => ScionSocketAddr::V6(addr),
        }
    }

    /// Returns an [IpAddr] if the SCION Socket Address is an IPv4 or IPv6 address.
    /// Returns None if it is a Service Address.
    pub const fn ip(&self) -> IpAddr {
        match self {
            ScionSocketIpAddr::V4(addr) => IpAddr::V4(addr.host),
            ScionSocketIpAddr::V6(addr) => IpAddr::V6(addr.host),
        }
    }

    /// Returns true if the SCION Socket Address is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, ScionSocketIpAddr::V4(_))
    }

    /// Returns true if the SCION Socket Address is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, ScionSocketIpAddr::V6(_))
    }

    /// Sets the [IpAddr]
    pub fn set_ip(&mut self, host: IpAddr) {
        *self = Self::new(self.isd_asn(), host, self.port());
    }

    /// Returns a [ScionAddr] from the SCION Socket Address
    pub const fn scion_addr(&self) -> ScionAddr {
        match self {
            ScionSocketIpAddr::V4(addr) => {
                ScionAddr::V4(crate::scion::address::addr::ScionAddrV4 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
            ScionSocketIpAddr::V6(addr) => {
                ScionAddr::V6(crate::scion::address::addr::ScionAddrV6 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
        }
    }

    /// Returns the port number
    pub const fn port(&self) -> u16 {
        match self {
            ScionSocketIpAddr::V4(addr) => addr.port,
            ScionSocketIpAddr::V6(addr) => addr.port,
        }
    }

    /// Sets the port number
    pub fn set_port(&mut self, port: u16) {
        *self = Self::new(self.isd_asn(), self.ip(), port);
    }

    /// Returns the [ScionIpAddr]
    pub const fn host(&self) -> ScionIpAddr {
        match self {
            ScionSocketIpAddr::V4(addr) => {
                ScionIpAddr::V4(ScionAddrV4 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
            ScionSocketIpAddr::V6(addr) => {
                ScionIpAddr::V6(ScionAddrV6 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
        }
    }

    /// Sets the [ScionIpAddr], keeping the port number unchanged
    pub fn set_host(&mut self, host: ScionIpAddr) {
        *self = Self::new(host.isd_asn(), host.ip(), self.port());
    }

    /// Returns the ISD-AS number
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            ScionSocketIpAddr::V4(addr) => addr.isd_asn,
            ScionSocketIpAddr::V6(addr) => addr.isd_asn,
        }
    }

    /// Sets the ISD-AS number
    pub fn set_isd_asn(&mut self, isd_asn: IsdAsn) {
        match self {
            ScionSocketIpAddr::V4(addr) => addr.isd_asn = isd_asn,
            ScionSocketIpAddr::V6(addr) => addr.isd_asn = isd_asn,
        }
    }
}
impl Display for ScionSocketIpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionSocketIpAddr::V4(addr) => addr.fmt(f),
            ScionSocketIpAddr::V6(addr) => addr.fmt(f),
        }
    }
}
impl FromStr for ScionSocketIpAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ScionSocketAddrV4::from_str(s)
            .map(Self::V4)
            .or_else(|_| ScionSocketAddrV6::from_str(s).map(Self::V6))
            .map_err(|_| AddressParseError::Socket)
    }
}
impl_from!(ScionSocketAddrV4, ScionSocketIpAddr, |v| Self::V4(v));
impl_from!(ScionSocketAddrV6, ScionSocketIpAddr, |v| Self::V6(v));
impl TryFrom<ScionAddr> for ScionSocketIpAddr {
    type Error = ScionAddr;

    fn try_from(value: ScionAddr) -> Result<Self, Self::Error> {
        Self::try_from_scion_addr(value, 0)
    }
}
