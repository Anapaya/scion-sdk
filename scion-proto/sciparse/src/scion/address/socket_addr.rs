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

//! SCION network address (IsdAsn + HostAddr + Port)

use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    core::macros::impl_from,
    scion::{
        address::{
            AddressParseError,
            addr::{ScionAddr, ScionAddrSvc, ScionAddrV4, ScionAddrV6},
            host_addr::{ScionHostAddr, ServiceAddr},
        },
        identifier::isd_asn::IsdAsn,
    },
};

/// SCION address combining [IsdAsn], [ScionHostAddr] and a Port
/// See [ScionAddr](crate::address::addr::ScionAddr) for ([IsdAsn] and [ScionHostAddr]
/// without Port).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub enum ScionSocketAddr {
    /// IPv4 SCION Socket Address
    V4(ScionSocketAddrV4),
    /// IPv6 SCION Socket Address
    V6(ScionSocketAddrV6),
    /// Service SCION Socket Address
    Svc(ScionSocketAddrSvc),
}
impl ScionSocketAddr {
    /// Create a new SCION Socket Address
    pub const fn new(isd_asn: IsdAsn, host: ScionHostAddr, port: u16) -> Self {
        match host {
            ScionHostAddr::V4(host) => {
                Self::V4(ScionSocketAddrV4 {
                    isd_asn,
                    host,
                    port,
                })
            }
            ScionHostAddr::V6(host) => {
                Self::V6(ScionSocketAddrV6 {
                    isd_asn,
                    host,
                    port,
                })
            }
            ScionHostAddr::Svc(host) => {
                Self::Svc(ScionSocketAddrSvc {
                    isd_asn,
                    host,
                    port,
                })
            }
        }
    }

    /// Create a SCION Socket Address from a standard Socket Address
    pub const fn from_std(isd_asn: IsdAsn, addr: std::net::SocketAddr) -> Self {
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
    pub const fn from_scion_addr(scion_addr: ScionAddr, port: u16) -> Self {
        match scion_addr {
            ScionAddr::V4(addr) => {
                Self::V4(ScionSocketAddrV4 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                    port,
                })
            }
            ScionAddr::V6(addr) => {
                Self::V6(ScionSocketAddrV6 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                    port,
                })
            }
            ScionAddr::Svc(addr) => {
                Self::Svc(ScionSocketAddrSvc {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                    port,
                })
            }
        }
    }

    /// Returns a [SocketAddr] from the SCION Socket Address if it is an IPv4 or IPv6 address.
    /// Returns None if it is a Service Address.
    pub const fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            ScionSocketAddr::V4(addr) => {
                Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                    addr.host, addr.port,
                )))
            }
            ScionSocketAddr::V6(addr) => {
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    addr.host, addr.port, 0, 0,
                )))
            }
            ScionSocketAddr::Svc(_) => None,
        }
    }

    /// Returns an [IpAddr] if the SCION Socket Address is an IPv4 or IPv6 address.
    /// Returns None if it is a Service Address.
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            ScionSocketAddr::V4(addr) => Some(IpAddr::V4(addr.host)),
            ScionSocketAddr::V6(addr) => Some(IpAddr::V6(addr.host)),
            ScionSocketAddr::Svc(_) => None,
        }
    }

    /// Returns a [ScionAddr] from the SCION Socket Address
    pub const fn scion_addr(&self) -> ScionAddr {
        match self {
            ScionSocketAddr::V4(addr) => {
                ScionAddr::V4(crate::scion::address::addr::ScionAddrV4 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
            ScionSocketAddr::V6(addr) => {
                ScionAddr::V6(crate::scion::address::addr::ScionAddrV6 {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
            ScionSocketAddr::Svc(addr) => {
                ScionAddr::Svc(crate::scion::address::addr::ScionAddrSvc {
                    isd_asn: addr.isd_asn,
                    host: addr.host,
                })
            }
        }
    }

    /// Returns true if the Host Address is an IP address (IPv4 or IPv6)
    pub const fn is_ip(&self) -> bool {
        matches!(self, ScionSocketAddr::V4(_) | ScionSocketAddr::V6(_))
    }
    /// Returns true if the Host Address is a Service Address
    pub const fn is_service(&self) -> bool {
        matches!(self, ScionSocketAddr::Svc(_))
    }

    /// Returns the port number
    pub const fn port(&self) -> u16 {
        match self {
            ScionSocketAddr::V4(addr) => addr.port,
            ScionSocketAddr::V6(addr) => addr.port,
            ScionSocketAddr::Svc(addr) => addr.port,
        }
    }

    /// Sets the port number
    pub fn set_port(&mut self, port: u16) {
        match self {
            ScionSocketAddr::V4(addr) => addr.port = port,
            ScionSocketAddr::V6(addr) => addr.port = port,
            ScionSocketAddr::Svc(addr) => addr.port = port,
        }
    }

    /// Returns the [ScionHostAddr]
    pub const fn host(&self) -> ScionHostAddr {
        match self {
            ScionSocketAddr::V4(addr) => ScionHostAddr::V4(addr.host),
            ScionSocketAddr::V6(addr) => ScionHostAddr::V6(addr.host),
            ScionSocketAddr::Svc(addr) => ScionHostAddr::Svc(addr.host),
        }
    }

    /// Sets the [ScionHostAddr]
    pub fn set_host(&mut self, host: ScionHostAddr) {
        *self = Self::new(self.isd_asn(), host, self.port());
    }

    /// Returns the ISD-AS number
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            ScionSocketAddr::V4(addr) => addr.isd_asn,
            ScionSocketAddr::V6(addr) => addr.isd_asn,
            ScionSocketAddr::Svc(addr) => addr.isd_asn,
        }
    }

    /// Sets the ISD-AS number
    pub fn set_isd_asn(&mut self, isd_asn: IsdAsn) {
        match self {
            ScionSocketAddr::V4(addr) => addr.isd_asn = isd_asn,
            ScionSocketAddr::V6(addr) => addr.isd_asn = isd_asn,
            ScionSocketAddr::Svc(addr) => addr.isd_asn = isd_asn,
        }
    }
}
impl Display for ScionSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionSocketAddr::V4(addr) => addr.fmt(f),
            ScionSocketAddr::V6(addr) => addr.fmt(f),
            ScionSocketAddr::Svc(addr) => addr.fmt(f),
        }
    }
}
impl FromStr for ScionSocketAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ScionSocketAddrSvc::from_str(s)
            .map(Self::Svc)
            .or_else(|_| ScionSocketAddrV4::from_str(s).map(Self::V4))
            .or_else(|_| ScionSocketAddrV6::from_str(s).map(Self::V6))
            .map_err(|_| AddressParseError::Socket)
    }
}
impl_from!(ScionSocketAddrV4, ScionSocketAddr, |v| Self::V4(v));
impl_from!(ScionSocketAddrV6, ScionSocketAddr, |v| Self::V6(v));
impl_from!(ScionSocketAddrSvc, ScionSocketAddr, |v| Self::Svc(v));

/// SCION IPv4 Socket Address combining [IsdAsn], [Ipv4Addr] and a Port
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionSocketAddrV4 {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// IPv4 Address
    pub host: Ipv4Addr,
    /// Port number
    pub port: u16,
}
impl ScionSocketAddrV4 {
    /// Create a new SCION IPv4 Socket Address
    pub const fn new(isd_asn: IsdAsn, addr: Ipv4Addr, port: u16) -> Self {
        Self {
            isd_asn,
            host: addr,
            port,
        }
    }

    /// Returns a [ScionAddr] from the SCION Socket Address
    ///
    /// Discards the port number
    pub const fn to_scion_addr(&self) -> ScionAddr {
        ScionAddr::V4(ScionAddrV4 {
            isd_asn: self.isd_asn,
            host: self.host,
        })
    }
}
impl FromStr for ScionSocketAddrV4 {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, addr_port) =
            parse_socket_addr::<ScionAddrV4>(s).ok_or(AddressParseError::SocketV4)?;

        Ok(ScionSocketAddrV4 {
            isd_asn: addr.isd_asn,
            host: addr.host,
            port: addr_port,
        })
    }
}
impl Display for ScionSocketAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_socket_addr(self.isd_asn, ScionHostAddr::V4(self.host), self.port, f)
    }
}

/// SCION IPv6 Socket Address combining [IsdAsn], [Ipv6Addr] and a Port
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionSocketAddrV6 {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// IPv6 Address
    pub host: Ipv6Addr,
    /// Port number
    pub port: u16,
}
impl ScionSocketAddrV6 {
    /// Create a new SCION IPv6 Socket Address
    pub const fn new(isd_asn: IsdAsn, addr: Ipv6Addr, port: u16) -> Self {
        Self {
            isd_asn,
            host: addr,
            port,
        }
    }
}
impl FromStr for ScionSocketAddrV6 {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, addr_port) =
            parse_socket_addr::<ScionAddrV6>(s).ok_or(AddressParseError::SocketV6)?;
        Ok(ScionSocketAddrV6 {
            isd_asn: addr.isd_asn,
            host: addr.host,
            port: addr_port,
        })
    }
}
impl Display for ScionSocketAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_socket_addr(self.isd_asn, ScionHostAddr::V6(self.host), self.port, f)
    }
}

/// SCION Service Socket Address combining [IsdAsn], [ServiceAddr] and a Port
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct ScionSocketAddrSvc {
    /// ISD-AS number
    pub isd_asn: IsdAsn,
    /// Service Address
    pub host: ServiceAddr,
    /// Port number
    pub port: u16,
}
impl ScionSocketAddrSvc {
    /// Create a new SCION Service Socket Address
    pub const fn new(isd_asn: IsdAsn, addr: ServiceAddr, port: u16) -> Self {
        Self {
            isd_asn,
            host: addr,
            port,
        }
    }
}
impl FromStr for ScionSocketAddrSvc {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, addr_port) =
            parse_socket_addr::<ScionAddrSvc>(s).ok_or(AddressParseError::SocketSvc)?;
        Ok(ScionSocketAddrSvc {
            isd_asn: addr.isd_asn,
            host: addr.host,
            port: addr_port,
        })
    }
}
impl Display for ScionSocketAddrSvc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_socket_addr(self.isd_asn, ScionHostAddr::Svc(self.host), self.port, f)
    }
}

fn format_socket_addr(
    isd_asn: IsdAsn,
    host: ScionHostAddr,
    port: u16,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    write!(f, "{}-{}:{}", isd_asn, host, port)
}

fn parse_socket_addr<T: FromStr>(s: &str) -> Option<(T, u16)> {
    let (bracketed_addr, port) = s.rsplit_once(':')?;

    if !bracketed_addr.starts_with('[') && bracketed_addr.ends_with(']') {
        return None;
    }

    let scion_addr: T = bracketed_addr[1..bracketed_addr.len() - 1].parse().ok()?;
    let port: u16 = port.parse().ok()?;

    Some((scion_addr, port))
}
