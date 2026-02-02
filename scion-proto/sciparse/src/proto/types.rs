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

/// SCION address types
pub mod address {
    use std::{
        fmt::Debug,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use tinyvec::ArrayVec;

    use crate::core::encode::{InvalidStructureError, WireEncode};

    // TODO: Fully implement address types
    /// ISD (Isolation Domain) identifier.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    pub struct Isd(pub u16);
    impl Isd {
        /// Creates a new ISD from the given u16 value.
        pub fn new(value: u16) -> Self {
            Isd(value)
        }

        /// Returns the u16 value of the ISD.
        pub fn value(&self) -> u16 {
            self.0
        }
    }

    /// ASN (Autonomous System Number) identifier.
    /// Maximum size is 48 bits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    pub struct Asn(pub u64);
    impl Asn {
        /// Creates a new ASN from the given u64 value.
        ///
        /// Will truncate to 48 bits.
        pub fn new(value: u64) -> Self {
            Asn(value & 0x0000_FFFF_FFFF_FFFF)
        }

        /// Creates a new ASN from the given u64 value.
        ///
        /// Will truncate to 48 bits.
        pub fn new_truncate(value: u64) -> Self {
            Asn(value & 0x0000_FFFF_FFFF_FFFF)
        }

        /// Returns the value of the ASN as u64.
        pub fn value(&self) -> u64 {
            self.0
        }
    }

    /// ISD-AS identifier.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    pub struct IsdAsn(pub u64);
    impl IsdAsn {
        /// Creates a new ISD-AS identifier from the given ISD and ASN.
        pub fn new(isd: Isd, asn: Asn) -> Self {
            IsdAsn(((isd.0 as u64) << 48) | (asn.0 & 0x0000_FFFF_FFFF_FFFF))
        }

        /// Creates a new ISD-AS identifier from the given ISD and ASN parts.
        ///
        /// Will truncate ASN to 48 bits.
        pub fn new_from_raw(isd: u16, asn: u64) -> Self {
            IsdAsn::new(Isd::new(isd), Asn::new(asn))
        }

        /// Returns the value of the ISD-AS identifier as u64.
        pub fn value(&self) -> u64 {
            self.0
        }

        /// Returns the ISD part of the ISD-AS identifier.
        pub fn isd(&self) -> Isd {
            Isd((self.0 >> 48) as u16)
        }

        /// Returns the ASN part of the ISD-AS identifier.
        pub fn asn(&self) -> Asn {
            Asn(self.0 & 0x0000_FFFF_FFFF_FFFF)
        }
    }
    impl Debug for IsdAsn {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}-{}", self.isd().0, self.asn().0)
        }
    }

    /// Address types used in SCION packets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum ScionHostAddrType {
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
    impl ScionHostAddrType {
        /// Returns the size of the address type in bytes.
        pub fn size(&self) -> u8 {
            match self {
                ScionHostAddrType::IPV4 => 4,
                ScionHostAddrType::IPV6 => 16,
                ScionHostAddrType::Service => 4,
                ScionHostAddrType::Unknown { size, .. } => *size,
            }
        }
    }
    impl From<u8> for ScionHostAddrType {
        fn from(value: u8) -> Self {
            match value {
                0 => ScionHostAddrType::IPV4,
                0b0011 => ScionHostAddrType::IPV6,
                0b0100 => ScionHostAddrType::Service,
                other => {
                    let id = other >> 2;
                    let size = ((other & 0b11) + 1) * 4;
                    ScionHostAddrType::Unknown { id, size }
                }
            }
        }
    }
    impl From<ScionHostAddrType> for u8 {
        fn from(val: ScionHostAddrType) -> Self {
            match val {
                ScionHostAddrType::IPV4 => 0,
                ScionHostAddrType::IPV6 => 0b0011,
                ScionHostAddrType::Service => 0b0100,
                ScionHostAddrType::Unknown { id: type_id, size } => {
                    (type_id << 2) | (size / 4).saturating_sub(1)
                }
            }
        }
    }

    /// Addresses used in SCION packets.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ScionHostAddr {
        /// IPv4 address.
        Ipv4(Ipv4Addr),
        /// IPv6 address.
        Ipv6(Ipv6Addr),
        /// Service address.
        // TODO: service address struct
        Service([u8; 4]),
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
    impl ScionHostAddr {
        /// Attempts to create an Address from the given type and byte buffer.
        pub fn from_parts(
            addr_type: ScionHostAddrType,
            buf: &[u8],
        ) -> Result<Self, HostAddressSizeError> {
            // Note: we are checking the length here, as the address type and advertised length
            // might not match.
            let addr = match addr_type {
                ScionHostAddrType::IPV4 => {
                    let buf: [u8; 4] = buf.try_into().map_err(|_| {
                        HostAddressSizeError {
                            address_type: addr_type,
                            expected_size: 4,
                            actual_size: buf.len(),
                        }
                    })?;
                    ScionHostAddr::Ipv4(Ipv4Addr::from(buf))
                }
                ScionHostAddrType::IPV6 => {
                    let buf: [u8; 16] = buf.try_into().map_err(|_| {
                        HostAddressSizeError {
                            address_type: addr_type,
                            expected_size: 16,
                            actual_size: buf.len(),
                        }
                    })?;
                    ScionHostAddr::Ipv6(Ipv6Addr::from(buf))
                }
                ScionHostAddrType::Service => {
                    let buf: [u8; 4] = buf.try_into().map_err(|_| {
                        HostAddressSizeError {
                            address_type: addr_type,
                            expected_size: 4,
                            actual_size: buf.len(),
                        }
                    })?;
                    ScionHostAddr::Service(buf)
                }
                ScionHostAddrType::Unknown { id, size } => {
                    let bytes = buf.try_into().map_err(|_| {
                        HostAddressSizeError {
                            address_type: addr_type,
                            expected_size: size as usize,
                            actual_size: buf.len(),
                        }
                    })?;

                    ScionHostAddr::Unknown { id, bytes }
                }
            };

            Ok(addr)
        }

        /// Returns an `IpAddr` if the address is IPv4 or IPv6.
        pub fn to_ip(&self) -> Option<IpAddr> {
            match self {
                ScionHostAddr::Ipv4(v4) => Some(IpAddr::V4(*v4)),
                ScionHostAddr::Ipv6(v6) => Some(IpAddr::V6(*v6)),
                _ => None,
            }
        }

        /// Returns the service address bytes if the address is a service address.
        pub fn to_service(&self) -> Option<[u8; 4]> {
            match self {
                ScionHostAddr::Service(bytes) => Some(*bytes),
                _ => None,
            }
        }

        /// Returns the address type of the address.
        pub fn addr_type(&self) -> ScionHostAddrType {
            match self {
                ScionHostAddr::Ipv4(_) => ScionHostAddrType::IPV4,
                ScionHostAddr::Ipv6(_) => ScionHostAddrType::IPV6,
                ScionHostAddr::Service(_) => ScionHostAddrType::Service,
                ScionHostAddr::Unknown { id, bytes } => {
                    ScionHostAddrType::Unknown {
                        id: *id,
                        size: bytes.len() as u8,
                    }
                }
            }
        }
    }
    impl WireEncode for ScionHostAddr {
        fn required_size(&self) -> usize {
            match self {
                ScionHostAddr::Ipv4(_) => 4,
                ScionHostAddr::Ipv6(_) => 16,
                ScionHostAddr::Service(bytes) => bytes.len(),
                ScionHostAddr::Unknown { bytes, .. } => bytes.len(),
            }
        }

        fn wire_valid(&self) -> Result<(), InvalidStructureError> {
            match self {
                ScionHostAddr::Ipv4(_) => Ok(()),
                ScionHostAddr::Ipv6(_) => Ok(()),
                ScionHostAddr::Service(_) => Ok(()),
                ScionHostAddr::Unknown { bytes, .. } => {
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
                ScionHostAddr::Ipv4(v4) => {
                    let bytes = v4.to_bits().to_be_bytes();
                    unsafe {
                        buf.get_unchecked_mut(..4).copy_from_slice(&bytes);
                    }
                    4
                }
                ScionHostAddr::Ipv6(v6) => {
                    let bytes = v6.to_bits().to_be_bytes();
                    unsafe {
                        buf.get_unchecked_mut(..16).copy_from_slice(&bytes);
                    }
                    16
                }
                ScionHostAddr::Service(bytes) => {
                    let len = bytes.len();
                    unsafe {
                        buf.get_unchecked_mut(..len).copy_from_slice(bytes);
                    }
                    len
                }
                ScionHostAddr::Unknown { bytes, .. } => {
                    let len = bytes.len();
                    unsafe {
                        buf.get_unchecked_mut(..len).copy_from_slice(bytes);
                    }
                    len
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
        pub address_type: ScionHostAddrType,
        /// Expected buffer size in bytes
        pub expected_size: usize,
        /// Provided buffer size in bytes
        pub actual_size: usize,
    }
}
