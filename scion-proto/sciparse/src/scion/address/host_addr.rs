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

//! SCION host address. (IpV4, IPv6, or service address)

use std::{
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use tinyvec::ArrayVec;

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        macros::impl_from,
    },
    scion::address::{AddressParseError, addr::ScionAddr},
};

/// Host Address for SCION packets. Conceptually [IpAddr] plus SCION specific address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScionHostAddr {
    /// IPv4 address.
    V4(Ipv4Addr),
    /// IPv6 address.
    V6(Ipv6Addr),
    /// SCION service address.
    Svc(ServiceAddr),
}
impl ScionHostAddr {
    /// Creates a HostAddr from an IpAddr.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => ScionHostAddr::V4(v4),
            IpAddr::V6(v6) => ScionHostAddr::V6(v6),
        }
    }

    /// Returns the address as an `IpAddr` if it is IPv4 or IPv6.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            ScionHostAddr::V4(v4) => Some(IpAddr::V4(*v4)),
            ScionHostAddr::V6(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        }
    }

    /// Returns the service address if it is a service address.
    pub fn service(&self) -> Option<ServiceAddr> {
        match self {
            ScionHostAddr::Svc(svc) => Some(*svc),
            _ => None,
        }
    }

    /// Returns the address as a [WireHostAddr] for encoding on the wire.
    pub fn to_wire_host_addr(&self) -> WireHostAddr {
        (*self).into()
    }
}
impl FromStr for ScionHostAddr {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ipv4) = s.parse::<Ipv4Addr>() {
            Ok(ScionHostAddr::V4(ipv4))
        } else if let Ok(ipv6) = s.parse::<Ipv6Addr>() {
            Ok(ScionHostAddr::V6(ipv6))
        } else if let Ok(svc) = s.parse::<ServiceAddr>() {
            Ok(ScionHostAddr::Svc(svc))
        } else {
            Err(AddressParseError::HostAddr)
        }
    }
}
impl Display for ScionHostAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionHostAddr::V4(v4) => write!(f, "{}", v4)?,
            ScionHostAddr::V6(v6) => write!(f, "{}", v6)?,
            ScionHostAddr::Svc(svc) => write!(f, "{}", svc)?,
        }
        Ok(())
    }
}
impl TryFrom<ScionHostAddr> for Ipv4Addr {
    type Error = &'static str;
    fn try_from(value: ScionHostAddr) -> Result<Self, Self::Error> {
        match value {
            ScionHostAddr::V4(v4) => Ok(v4),
            _ => Err("HostAddr is not an Ipv4Addr"),
        }
    }
}
impl TryFrom<ScionHostAddr> for Ipv6Addr {
    type Error = &'static str;
    fn try_from(value: ScionHostAddr) -> Result<Self, Self::Error> {
        match value {
            ScionHostAddr::V6(v6) => Ok(v6),
            _ => Err("HostAddr is not an Ipv6Addr"),
        }
    }
}
impl TryFrom<WireHostAddr> for ScionHostAddr {
    type Error = &'static str;
    fn try_from(value: WireHostAddr) -> Result<Self, Self::Error> {
        value
            .to_scion_host_addr()
            .ok_or("Can't convert WireHostAddr::Unknown to ScionHostAddr")
    }
}
impl_from!(IpAddr, ScionHostAddr, |value| ScionHostAddr::from_ip(value));
impl_from!(Ipv4Addr, ScionHostAddr, |value| ScionHostAddr::V4(value));
impl_from!(Ipv6Addr, ScionHostAddr, |value| ScionHostAddr::V6(value));
impl_from!(ServiceAddr, ScionHostAddr, |value| {
    ScionHostAddr::Svc(value)
});
impl_from!(ScionAddr, ScionHostAddr, |value| value.host());

/// A SCION service address.
///
/// Service addresses are 16-bit values used to identify services within a SCION AS.
/// They can be either anycast or multicast addresses.
#[derive(Eq, PartialEq, Copy, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct ServiceAddr(pub u16);
impl ServiceAddr {
    /// SCION daemon anycast service address (DS_A)
    pub const DAEMON: Self = Self(0x0001);
    /// SCION control-service anycast address (CS_A)
    pub const CONTROL: Self = Self(0x0002);
    /// Wildcard service address (Wildcard_A)
    pub const WILDCARD: Self = Self(0x0010);
    /// Special none service address value.
    pub const NONE: Self = Self(0xffff);

    /// Flag bit indicating whether the address includes multicast
    const MULTICAST_FLAG: u16 = 0x8000;

    /// Returns the raw u16 value of the service address.
    pub fn to_u16(&self) -> u16 {
        self.0
    }

    /// Returns true if the service address is multicast, false otherwise.
    pub fn is_multicast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == Self::MULTICAST_FLAG
    }

    /// Creates a new service address as multicast, disabling anycast.
    pub fn to_multicast(self) -> Self {
        Self(self.0 | Self::MULTICAST_FLAG)
    }

    /// Creates a new service address as anycast, disabling multicast.
    pub fn to_anycast(self) -> Self {
        Self(self.0 & !Self::MULTICAST_FLAG)
    }

    /// Returns true if the service address is anycast, false otherwise.
    pub fn is_anycast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == 0
    }
}
impl Display for ServiceAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.to_anycast() {
            ServiceAddr::DAEMON => write!(f, "DS")?,
            ServiceAddr::CONTROL => write!(f, "CS")?,
            ServiceAddr::WILDCARD => write!(f, "Wildcard")?,
            ServiceAddr(value) => write!(f, "<SVC:{value:#06x}>")?,
        }

        if self.is_multicast() {
            write!(f, "_M")?;
        }

        Ok(())
    }
}
impl FromStr for ServiceAddr {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ERR: &str = "invalid service address";
        let (service, suffix) = s.split_once('_').unwrap_or((s, "A"));

        let address = match service {
            "CS" => ServiceAddr::CONTROL,
            "DS" => ServiceAddr::DAEMON,
            "Wildcard" => ServiceAddr::WILDCARD,
            _ => return Err(ERR),
        };

        match suffix {
            "A" => Ok(address),
            "M" => Ok(address.to_multicast()),
            _ => Err(ERR),
        }
    }
}
impl TryFrom<ScionHostAddr> for ServiceAddr {
    type Error = &'static str;
    fn try_from(value: ScionHostAddr) -> Result<Self, Self::Error> {
        match value {
            ScionHostAddr::Svc(svc) => Ok(svc),
            _ => Err("HostAddr is not a ServiceAddr"),
        }
    }
}
impl_from!(u16, ServiceAddr, |value| ServiceAddr(value));
impl_from!(ServiceAddr, u16, |value| value.0);
impl_from!(ServiceAddr, WireHostAddr, |value| {
    WireHostAddr::Svc(value)
});

/// Host Address retrieved from the wire. Conceptually [IpAddr] plus SCION specific address types.
///
/// Includes the `Unknown` variant to represent address types that are not recognized by this
/// version of the library or are invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireHostAddr {
    /// IPv4 address.
    V4(Ipv4Addr),
    /// IPv6 address.
    V6(Ipv6Addr),
    /// Service address.
    Svc(ServiceAddr),
    /// Unknown address type. Raw bytes.
    Unknown {
        /// Address type identifier.
        id: u8,
        /// Raw address bytes.
        ///
        /// Must be 4, 8, 12, or 16 bytes.
        bytes: ArrayVec<[u8; 16]>,
    },
}
impl WireHostAddr {
    /// Attempts to create an Address from the given type and byte buffer.
    pub fn from_parts(
        addr_type: WireHostAddrType,
        buf: &[u8],
    ) -> Result<Self, HostAddressSizeError> {
        // Note: we are checking the length here, as the address type and advertised length
        // might not match.
        let addr = match addr_type {
            WireHostAddrType::IPV4 => {
                let buf: [u8; 4] = buf.try_into().map_err(|_| {
                    HostAddressSizeError {
                        address_type: addr_type,
                        expected_size: 4,
                        actual_size: buf.len(),
                    }
                })?;
                WireHostAddr::V4(Ipv4Addr::from(buf))
            }
            WireHostAddrType::IPV6 => {
                let buf: [u8; 16] = buf.try_into().map_err(|_| {
                    HostAddressSizeError {
                        address_type: addr_type,
                        expected_size: 16,
                        actual_size: buf.len(),
                    }
                })?;
                WireHostAddr::V6(Ipv6Addr::from(buf))
            }
            WireHostAddrType::Service => {
                let buf: [u8; 4] = buf.try_into().map_err(|_| {
                    HostAddressSizeError {
                        address_type: addr_type,
                        expected_size: 4,
                        actual_size: buf.len(),
                    }
                })?;

                let svc_addr = u16::from_be_bytes([buf[2], buf[3]]);
                let svc_addr = ServiceAddr(svc_addr);
                WireHostAddr::Svc(svc_addr)
            }
            WireHostAddrType::Unknown { id, size } => {
                let bytes = buf.try_into().map_err(|_| {
                    HostAddressSizeError {
                        address_type: addr_type,
                        expected_size: size as usize,
                        actual_size: buf.len(),
                    }
                })?;

                WireHostAddr::Unknown { id, bytes }
            }
        };

        Ok(addr)
    }

    /// Returns an `IpAddr` if the address is IPv4 or IPv6.
    pub fn to_ip(&self) -> Option<IpAddr> {
        match self {
            WireHostAddr::V4(v4) => Some(IpAddr::V4(*v4)),
            WireHostAddr::V6(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        }
    }

    /// Returns the service address bytes if the address is a service address.
    pub fn to_service(&self) -> Option<ServiceAddr> {
        match self {
            WireHostAddr::Svc(svc) => Some(*svc),
            _ => None,
        }
    }

    /// Returns the address as a [ScionHostAddr] if it is a recognized address type (IPv4, IPv6, or
    /// service). Returns None if the address type is unknown.
    pub fn to_scion_host_addr(&self) -> Option<ScionHostAddr> {
        match self {
            WireHostAddr::V4(v4) => Some(ScionHostAddr::V4(*v4)),
            WireHostAddr::V6(v6) => Some(ScionHostAddr::V6(*v6)),
            WireHostAddr::Svc(svc) => Some(ScionHostAddr::Svc(*svc)),
            WireHostAddr::Unknown { .. } => None,
        }
    }

    /// Returns the address type of the address.
    pub fn addr_type(&self) -> WireHostAddrType {
        match self {
            WireHostAddr::V4(_) => WireHostAddrType::IPV4,
            WireHostAddr::V6(_) => WireHostAddrType::IPV6,
            WireHostAddr::Svc(_) => WireHostAddrType::Service,
            WireHostAddr::Unknown { id, bytes } => {
                WireHostAddrType::Unknown {
                    id: *id,
                    size: bytes.len() as u8,
                }
            }
        }
    }
}
impl WireEncode for WireHostAddr {
    fn required_size(&self) -> usize {
        match self {
            WireHostAddr::V4(_) => 4,
            WireHostAddr::V6(_) => 16,
            WireHostAddr::Svc(_) => 4,
            WireHostAddr::Unknown { bytes, .. } => bytes.len(),
        }
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        match self {
            WireHostAddr::V4(_) => Ok(()),
            WireHostAddr::V6(_) => Ok(()),
            WireHostAddr::Svc(_) => Ok(()),
            WireHostAddr::Unknown { bytes, .. } => {
                if bytes.is_empty() {
                    Err("ScionHostAddr::Unknown bytes.len() must be non-zero".into())
                } else if !bytes.len().is_multiple_of(4) {
                    Err("ScionHostAddr::Unknown bytes.len() must be a multiple of 4".into())
                } else {
                    Ok(())
                }
            }
        }
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        match self {
            WireHostAddr::V4(v4) => {
                let bytes = v4.to_bits().to_be_bytes();
                unsafe {
                    buf.get_unchecked_mut(..4).copy_from_slice(&bytes);
                }
                4
            }
            WireHostAddr::V6(v6) => {
                let bytes = v6.to_bits().to_be_bytes();
                unsafe {
                    buf.get_unchecked_mut(..16).copy_from_slice(&bytes);
                }
                16
            }
            WireHostAddr::Svc(addr) => {
                let val = addr.to_u16().to_be_bytes();
                let bytes = [0, 0, val[0], val[1]]; //TODO: Validate left padding is correct
                unsafe {
                    buf.get_unchecked_mut(..4).copy_from_slice(&bytes);
                }
                4
            }
            WireHostAddr::Unknown { bytes, .. } => {
                let len = bytes.len();
                unsafe {
                    buf.get_unchecked_mut(..len).copy_from_slice(bytes);
                }
                len
            }
        }
    }
}
impl_from!(ScionHostAddr, WireHostAddr, |value| {
    match value {
        ScionHostAddr::V4(v4) => WireHostAddr::V4(v4),
        ScionHostAddr::V6(v6) => WireHostAddr::V6(v6),
        ScionHostAddr::Svc(svc) => WireHostAddr::Svc(svc),
    }
});

/// Host Address types on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireHostAddrType {
    /// IPv4 address.
    IPV4 = 0b0000,
    /// IPv6 address.
    IPV6 = 0b0011,
    /// Service address.
    Service = 0b0100,
    /// Unknown address type.
    Unknown {
        /// Address type identifier.
        id: u8,
        /// Address size in bytes.
        /// Must be 4, 8, 12, or 16.
        size: u8,
    },
}
impl WireHostAddrType {
    /// Returns the size of the address type in bytes.
    pub fn size(&self) -> u8 {
        match self {
            WireHostAddrType::IPV4 => 4,
            WireHostAddrType::IPV6 => 16,
            WireHostAddrType::Service => 4,
            WireHostAddrType::Unknown { size, .. } => *size,
        }
    }
}
impl From<u8> for WireHostAddrType {
    fn from(value: u8) -> Self {
        match value {
            0 => WireHostAddrType::IPV4,
            0b0011 => WireHostAddrType::IPV6,
            0b0100 => WireHostAddrType::Service,
            other => {
                let id = other >> 2;
                let size = ((other & 0b11) + 1) * 4;
                WireHostAddrType::Unknown { id, size }
            }
        }
    }
}
impl From<WireHostAddrType> for u8 {
    fn from(val: WireHostAddrType) -> Self {
        match val {
            WireHostAddrType::IPV4 => 0,
            WireHostAddrType::IPV6 => 0b0011,
            WireHostAddrType::Service => 0b0100,
            WireHostAddrType::Unknown { id: type_id, size } => {
                (type_id << 2) | (size / 4).saturating_sub(1)
            }
        }
    }
}

/// Error indicating a mismatch between expected and actual address sizes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "address size error: address type {address_type:?} expects {expected_size} bytes, got {actual_size} bytes"
)]
pub struct HostAddressSizeError {
    /// Address type
    pub address_type: WireHostAddrType,
    /// Expected buffer size in bytes
    pub expected_size: usize,
    /// Provided buffer size in bytes
    pub actual_size: usize,
}
