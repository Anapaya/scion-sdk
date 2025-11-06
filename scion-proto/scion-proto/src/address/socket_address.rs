// Copyright 2025 Mysten Labs
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

use core::{fmt::Display, str::FromStr};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    AddressParseError, HostAddr, IsdAsn, ScionAddr, ScionAddrSvc, ScionAddrV4, ScionAddrV6,
    ServiceAddr, error::AddressKind,
};
use crate::packet::AddressInfo;

/// A SCION socket address.
///
/// SCION socket addresses consist of an ISD-AS number, a 16-bit port identifier, and either an
/// [IPv4 address][`Ipv4Addr`], an [IPv6 address][`Ipv6Addr`], or a [SCION service
/// address][`ServiceAddr`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum SocketAddr {
    /// An IPv4 socket address.
    V4(SocketAddrV4),
    /// An IPv6 socket address.
    V6(SocketAddrV6),
    /// A SCION service socket address.
    Svc(SocketAddrSvc),
}

impl SocketAddr {
    /// Creates a new SCION socket address from an ISD-AS number, SCION host, and port.
    pub const fn new(scion_addr: ScionAddr, port: u16) -> Self {
        match scion_addr {
            ScionAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, port)),
            ScionAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, port)),
            ScionAddr::Svc(addr) => SocketAddr::Svc(SocketAddrSvc::new(addr, port)),
        }
    }

    /// Construct a new SCION socket address from an ISD-AS number and standard rust socket address.
    pub const fn from_std(isd_asn: IsdAsn, address: std::net::SocketAddr) -> Self {
        match address {
            std::net::SocketAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::from_std(isd_asn, addr)),
            std::net::SocketAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::from_std(isd_asn, addr)),
        }
    }

    /// Returns a [`std::net::SocketAddr`] corresponding to the AS-local portion of the address,
    /// if it is not a service address.
    pub const fn local_address(&self) -> Option<std::net::SocketAddr> {
        match self {
            SocketAddr::V4(addr) => Some(std::net::SocketAddr::V4(addr.local_address())),
            SocketAddr::V6(addr) => Some(std::net::SocketAddr::V6(addr.local_address())),
            SocketAddr::Svc(_) => None,
        }
    }

    /// Returns the SCION address associated with this socket address.
    pub fn scion_address(&self) -> ScionAddr {
        match self {
            SocketAddr::V4(addr) => ScionAddr::V4(*addr.scion_addr()),
            SocketAddr::V6(addr) => ScionAddr::V6(*addr.scion_addr()),
            SocketAddr::Svc(addr) => ScionAddr::Svc(*addr.scion_addr()),
        }
    }

    /// Returns the host address associated with this socket address.
    pub fn host(&self) -> HostAddr {
        match self {
            SocketAddr::V4(addr) => HostAddr::V4(*addr.host()),
            SocketAddr::V6(addr) => HostAddr::V6(*addr.host()),
            SocketAddr::Svc(addr) => HostAddr::Svc(*addr.host()),
        }
    }

    /// Returns true if this socket address stores an IPv4 or IPv6 address, and false otherwise.
    pub const fn is_ip(&self) -> bool {
        !matches!(*self, Self::Svc(_))
    }

    /// Returns true if this socket address stores a SCION service address, and false otherwise.
    pub const fn is_service(&self) -> bool {
        matches!(*self, Self::Svc(_))
    }

    /// Returns the ISD-AS number associated with this socket address.
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            Self::V4(addr) => addr.isd_asn(),
            Self::V6(addr) => addr.isd_asn(),
            Self::Svc(addr) => addr.isd_asn(),
        }
    }

    /// Returns the port number associated with this socket address.
    pub const fn port(&self) -> u16 {
        match self {
            Self::V4(addr) => addr.port(),
            Self::V6(addr) => addr.port(),
            Self::Svc(addr) => addr.port(),
        }
    }

    /// Returns the address info corresponding to the socket address's address type.
    pub const fn address_info(&self) -> AddressInfo {
        match self {
            SocketAddr::V4(_) => AddressInfo::IPV4,
            SocketAddr::V6(_) => AddressInfo::IPV6,
            SocketAddr::Svc(_) => AddressInfo::SERVICE,
        }
    }

    /// Changes the port number associated with this socket address.
    pub fn set_port(&mut self, new_port: u16) {
        match self {
            Self::V4(addr) => addr.set_port(new_port),
            Self::V6(addr) => addr.set_port(new_port),
            Self::Svc(addr) => addr.set_port(new_port),
        }
    }
}

impl AsRef<IsdAsn> for SocketAddr {
    fn as_ref(&self) -> &IsdAsn {
        match self {
            SocketAddr::V4(addr) => addr.as_ref(),
            SocketAddr::V6(addr) => addr.as_ref(),
            SocketAddr::Svc(addr) => addr.as_ref(),
        }
    }
}

impl From<SocketAddrV4> for SocketAddr {
    /// Converts a [`SocketAddrV4`] into a [`SocketAddr::V4`].
    #[inline]
    fn from(value: SocketAddrV4) -> Self {
        SocketAddr::V4(value)
    }
}

impl From<SocketAddrV6> for SocketAddr {
    /// Converts a [`SocketAddrV6`] into a [`SocketAddr::V6`].
    #[inline]
    fn from(value: SocketAddrV6) -> Self {
        SocketAddr::V6(value)
    }
}

impl From<SocketAddrSvc> for SocketAddr {
    /// Converts a [`SocketAddrSvc`] into a [`SocketAddr::Svc`].
    #[inline]
    fn from(value: SocketAddrSvc) -> Self {
        SocketAddr::Svc(value)
    }
}

impl FromStr for SocketAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddrSvc::from_str(s)
            .map(SocketAddr::Svc)
            .or_else(|_| SocketAddrV4::from_str(s).map(SocketAddr::V4))
            .or_else(|_| SocketAddrV6::from_str(s).map(SocketAddr::V6))
            .or(Err(AddressKind::Socket.into()))
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketAddr::V4(addr) => addr.fmt(f),
            SocketAddr::V6(addr) => addr.fmt(f),
            SocketAddr::Svc(addr) => addr.fmt(f),
        }
    }
}

macro_rules! socket_address {
    (
        $(#[$outer:meta])*
        pub struct $name:ident{scion_addr: $type:ty, host_addr: $host_type:ty, kind: $kind:path};
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
        pub struct $name {
            scion_addr: $type,
            port: u16,
        }

        impl $name {
            /// Creates a new SCION socket address from an [ISD-AS number][`IsdAsn`],
            /// address, and port number.
            pub const fn new(scion_addr: $type, port: u16) -> Self {
                Self { scion_addr, port }
            }

            /// Returns the SCION address associated with this socket address.
            pub const fn scion_addr(&self) -> &$type {
                &self.scion_addr
            }

            /// Changes the SCION address to the provided address
            pub fn set_scion_addr(&mut self, scion_addr: $type) {
                self.scion_addr = scion_addr
            }

            /// Returns the address associated with this socket address.
            pub const fn host(&self) -> &$host_type {
                &self.scion_addr.host()
            }

            /// Changes the address associated with this socket address.
            pub fn set_host(&mut self, host: $host_type) {
                self.scion_addr.set_host(host)
            }

            /// Returns the ISD-AS number associated with this socket address.
            pub const fn isd_asn(&self) -> IsdAsn {
                self.scion_addr.isd_asn()
            }

            /// Changes the ISD-AS number associated with this socket address.
            pub fn set_isd_asn(&mut self, new_isd_asn: IsdAsn) {
                self.scion_addr.set_isd_asn(new_isd_asn);
            }

            /// Returns the port number associated with this socket address.
            pub const fn port(&self) -> u16 {
                self.port
            }

            /// Changes the port associated with this socket address.
            pub fn set_port(&mut self, new_port: u16) {
                self.port = new_port;
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "[{}]:{}", self.scion_addr, self.port())
            }
        }

        impl FromStr for $name {
            type Err = AddressParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (scion_addr, port) = s.rsplit_once(':')
                    .and_then(|(bracketed_addr, port)| {
                        if bracketed_addr.starts_with('[') && bracketed_addr.ends_with(']') {
                            let scion_addr = bracketed_addr[1..bracketed_addr.len()-1].parse().ok();
                            let port = port.parse().ok();
                            scion_addr.zip(port)
                        } else {
                            None
                        }
                    })
                    .ok_or(AddressParseError($kind))?;

                Ok(Self {scion_addr, port })
            }
        }

        impl AsRef<IsdAsn> for $name {
            fn as_ref(&self) -> &IsdAsn {
                self.scion_addr.as_ref()
            }
        }
    };
}

socket_address! {
    /// A SCION IPv4 socket address.
    ///
    /// SCION IPv4 socket addresses consist of a SCION ISD-AS number, an IPv4 address,
    /// and a 16-bit port number.
    ///
    /// See [`SocketAddr`] for a type encompassing IPv4, IPv6, and Service socket addresses.
    pub struct SocketAddrV4 {scion_addr: ScionAddrV4, host_addr: Ipv4Addr, kind: AddressKind::SocketV4};
}

impl SocketAddrV4 {
    /// Construct a new SCION v4 socket address from an ISD-AS number and standard
    /// rust socket address.
    pub const fn from_std(isd_asn: IsdAsn, socket_address: std::net::SocketAddrV4) -> Self {
        Self {
            scion_addr: ScionAddrV4::new(isd_asn, *socket_address.ip()),
            port: socket_address.port(),
        }
    }

    /// Returns a [`std::net::SocketAddrV4`] corresponding to the AS-local portion of the address.
    pub const fn local_address(&self) -> std::net::SocketAddrV4 {
        std::net::SocketAddrV4::new(*self.host(), self.port())
    }
}

socket_address! {
    /// A SCION IPv6 socket address.
    ///
    /// SCION IPv6 socket addresses consist of a SCION ISD-AS number, an IPv6 address,
    /// and a 16-bit port number.
    ///
    /// See [`SocketAddr`] for a type encompassing IPv6, IPv6, and Service socket addresses.
    pub struct SocketAddrV6 {scion_addr: ScionAddrV6, host_addr: Ipv6Addr, kind: AddressKind::SocketV6};
}

impl SocketAddrV6 {
    /// Construct a new SCION v6 socket address from an ISD-AS number and standard
    /// rust socket address.
    pub const fn from_std(isd_asn: IsdAsn, socket_address: std::net::SocketAddrV6) -> Self {
        Self {
            scion_addr: ScionAddrV6::new(isd_asn, *socket_address.ip()),
            port: socket_address.port(),
        }
    }

    /// Returns a [`std::net::SocketAddrV6`] corresponding to the AS-local portion of the address.
    pub const fn local_address(&self) -> std::net::SocketAddrV6 {
        std::net::SocketAddrV6::new(*self.host(), self.port(), 0, 0)
    }
}

socket_address! {
    /// A SCION service socket address.
    ///
    /// SCION service socket addresses consist of a SCION ISD-AS number, an SCION service address
    /// and a 16-bit port number.
    ///
    /// See [`SocketAddr`] for a type encompassing IPv6, IPv6, and Service socket addresses.
    pub struct SocketAddrSvc {scion_addr: ScionAddrSvc, host_addr: ServiceAddr, kind: AddressKind::SocketSvc};
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_str {
        use super::*;

        macro_rules! parse_ok {
            ($addr_type:ty, $name:ident, $string:literal, $expected:expr) => {
                #[test]
                fn $name() {
                    let parsed: $addr_type = $string.parse().expect("should succeed");
                    assert_eq!(parsed, $expected);
                }
            };
        }

        macro_rules! parse_errs {
            ($name:ident, $socket_type:ident, $string:literal, $err_kind:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        $socket_type::from_str($string),
                        Err(AddressParseError($err_kind))
                    );
                }
            };
            (IPv4 $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrV4, $string, AddressKind::SocketV4);
            };
            (IPv6 $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrV6, $string, AddressKind::SocketV6);
            };
            (Svc $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddrSvc, $string, AddressKind::SocketSvc);
            };
            (Enum $name:ident, $string:literal) => {
                parse_errs!($name, SocketAddr, $string, AddressKind::Socket);
            };
        }

        mod v4 {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrV4,
                valid,
                "[1-ff00:0:110,10.0.0.1]:8080",
                SocketAddrV4::new(parse!("1-ff00:0:110,10.0.0.1"), 8080)
            );

            parse_errs!(IPv4 invalid_ia, "[xxx,192.168.0.1]:80");
            parse_errs!(IPv4 invalid_address, "[1-ff00:0:110,CS_M]:80");
            parse_errs!(IPv4 port_too_large, "[1-ff00:0:110,192.168.0.1]:65536");
        }

        mod v6 {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrV6,
                valid,
                "[1-ff00:0:110,2001:db8::ff00:42:8329]:443",
                SocketAddrV6::new(parse!("1-ff00:0:110,2001:db8::ff00:42:8329"), 443)
            );

            parse_errs!(IPv6 invalid_ia, "[xxx,2001:db8::ff00:42:8329]:80");
            parse_errs!(IPv6 invalid_address, "[1-ff00:0:110,10.0.0.1]:80");
            parse_errs!(IPv6 port_too_large, "[1-ff00:0:110,2001:db8::ff00:42:8329]:65536");
        }

        mod service {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddrSvc,
                valid,
                "[1-ff00:0:110,CS_M]:443",
                SocketAddrSvc::new(parse!("1-ff00:0:110,CS_M"), 443)
            );

            parse_errs!(Svc invalid_ia, "[xxx,CS_M]:80");
            parse_errs!(Svc invalid_address, "[1-ff00:0:110,2001:db8::ff00:42:8329]:80");
            parse_errs!(Svc port_too_large, "[1-ff00:0:110,DS_A]:65536");
        }

        mod general {
            use super::*;
            use crate::test_utils::parse;

            parse_ok!(
                SocketAddr,
                valid_service,
                "[1-ff00:0:110,CS_M]:443",
                SocketAddr::Svc(SocketAddrSvc::new(parse!("1-ff00:0:110,CS_M"), 443))
            );
            parse_ok!(
                SocketAddr,
                valid_v6,
                "[1-ff00:0:110,2001:db8::ff00:42:8329]:443",
                SocketAddr::V6(SocketAddrV6::new(
                    parse!("1-ff00:0:110,2001:db8::ff00:42:8329"),
                    443
                ))
            );
            parse_ok!(
                SocketAddr,
                valid_v4,
                "[1-ff00:0:110,10.0.0.1]:8080",
                SocketAddr::V4(SocketAddrV4::new(parse!("1-ff00:0:110,10.0.0.1"), 8080))
            );

            parse_errs!(Enum invalid_ia, "[xxx,CS_M]:80");
            parse_errs!(Enum invalid_address, "[1-ff00:0:110,xxx]:80");
            parse_errs!(Enum port_too_large, "[1-ff00:0:110,DS_A]:65536");
        }
    }
}
