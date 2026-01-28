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

//! SCION types.

/// SCION path types
pub mod path {
    use std::{fmt::Debug, time::Duration};

    /// Path types used in SCION packets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum PathType {
        /// The empty path type.
        Empty = 0,
        /// The standard SCION path type.
        Scion = 1,
        /// One-hop paths between neighboring border routers.
        OneHop = 2,
        /// Experimental Epic path type.
        Epic = 3,
        /// Experimental Colibri path type.
        Colibri = 4,
        /// Other, unrecognized path types.
        Other(u8),
    }
    impl From<u8> for PathType {
        fn from(value: u8) -> Self {
            match value {
                0 => PathType::Empty,
                1 => PathType::Scion,
                2 => PathType::OneHop,
                3 => PathType::Epic,
                4 => PathType::Colibri,
                other => PathType::Other(other),
            }
        }
    }
    impl From<PathType> for u8 {
        fn from(val: PathType) -> Self {
            match val {
                PathType::Empty => 0,
                PathType::Scion => 1,
                PathType::OneHop => 2,
                PathType::Epic => 3,
                PathType::Colibri => 4,
                PathType::Other(other) => other,
            }
        }
    }

    /// MAC (Message Authentication Code) used in HopFields.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HopFieldMac(pub [u8; 6]);
    impl HopFieldMac {
        /// Creates a new HopFieldMac from the given byte array.
        pub fn new(bytes: [u8; 6]) -> Self {
            HopFieldMac(bytes)
        }

        /// Returns the byte array representation of the HopFieldMac.
        pub fn as_bytes(&self) -> &[u8; 6] {
            &self.0
        }
    }
    impl From<[u8; 6]> for HopFieldMac {
        fn from(bytes: [u8; 6]) -> Self {
            HopFieldMac::new(bytes)
        }
    }
    impl Debug for HopFieldMac {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
            )
        }
    }

    // InfoFieldFlags
    bitflags::bitflags! {
        /// InfoField flags.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct InfoFieldFlags: u8 {
            /// If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
            /// (i.e. Core AS where the beacon originated )
            const CONS_DIR= 0b0000_0001;

            /// If set to true then the path is a peering path requiring special handling on the dataplane
            const PEERING = 0b0000_0010;

            // Other bits are reserved.
            const _ = !0;
        }
    }

    // HopFieldFlags
    bitflags::bitflags! {
        /// HopField flags.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct HopFieldFlags: u8 {
            /// If ConsIngress Router Alert is set, the ingress router in construction direction will process the L4 payload in the packet.
            const CONS_INGRESS_ROUTER_ALERT = 0b0000_0001;
            /// If ConsEgress Router Alert is set, the egress router in construction direction will process the L4 payload in the packet.
            const CONS_EGRESS_ROUTER_ALERT = 0b0000_0010;

            // Other bits are reserved.
            const _ = !0;
        }
    }
    impl HopFieldFlags {
        /// Returns true if the ConsIngress Router Alert flag is set.
        pub fn cons_ingress_router_alert(&self) -> bool {
            self.contains(HopFieldFlags::CONS_INGRESS_ROUTER_ALERT)
        }

        /// Returns true if the ConsEgress Router Alert flag is set.
        pub fn cons_egress_router_alert(&self) -> bool {
            self.contains(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT)
        }

        /// Returns the normalized router alert flag based on the construction direction.
        ///
        /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
        /// is reversed.
        pub fn normalized_ingress_router_alert(&self, cons_dir: bool) -> bool {
            if cons_dir {
                self.cons_ingress_router_alert()
            } else {
                self.cons_egress_router_alert()
            }
        }

        /// Returns the normalized router alert flag based on the construction direction.
        ///
        /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
        /// is reversed.
        pub fn normalized_egress_router_alert(&self, cons_dir: bool) -> bool {
            if cons_dir {
                self.cons_egress_router_alert()
            } else {
                self.cons_ingress_router_alert()
            }
        }
    }

    // MaxTTL / 256 (5m38.5s) see the following for reference:
    // https://datatracker.ietf.org/doc/html/draft-dekater-scion-dataplane#name-hop-field
    /// Expiration Duration per ExpTime unit on a HopField.
    pub const EXP_TIME_UNIT: Duration = Duration::new(337, 500_000_000);
}

/// SCION address types
pub mod address {
    use std::{
        fmt::Debug,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use tinyvec::ArrayVec;

    use crate::traits::WireEncode;

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
        IPV4 = 0,
        /// IPv6 address.
        IPV6 = 0b0011,
        /// Service address.
        Service = 0b0100,
        /// Unknown address type.
        Unknown(u8),
    }
    impl From<u8> for ScionHostAddrType {
        fn from(value: u8) -> Self {
            match value {
                0 => ScionHostAddrType::IPV4,
                0b0011 => ScionHostAddrType::IPV6,
                0b0100 => ScionHostAddrType::Service,
                other => ScionHostAddrType::Unknown(other),
            }
        }
    }
    impl From<ScionHostAddrType> for u8 {
        fn from(val: ScionHostAddrType) -> Self {
            match val {
                ScionHostAddrType::IPV4 => 0,
                ScionHostAddrType::IPV6 => 0b0011,
                ScionHostAddrType::Service => 0b0100,
                ScionHostAddrType::Unknown(other) => other,
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
                ScionHostAddrType::Unknown(id) => {
                    let bytes = buf.try_into().map_err(|_| {
                        HostAddressSizeError {
                            address_type: addr_type,
                            expected_size: 16,
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
        pub fn to_service_bytes(&self) -> Option<&[u8]> {
            match self {
                ScionHostAddr::Service(bytes) => Some(bytes),
                _ => None,
            }
        }

        /// Returns the size of the address in 4-byte units minus one.
        ///
        /// Used for encoding the address length in SCION headers.
        pub(crate) fn size_units(&self) -> u8 {
            debug_assert!(
                self.required_size().is_multiple_of(4),
                "address size must be a multiple of 4"
            );

            (self.required_size() / 4) as u8 - 1
        }
    }
    impl WireEncode for ScionHostAddr {
        fn required_size(&self) -> usize {
            let size = match self {
                ScionHostAddr::Ipv4(_) => 4,
                ScionHostAddr::Ipv6(_) => 16,
                ScionHostAddr::Service(bytes) => bytes.len(),
                ScionHostAddr::Unknown { bytes, .. } => bytes.len(),
            };

            debug_assert!(
                size.is_multiple_of(4),
                "address size must be a multiple of 4, got {}",
                size
            );

            size
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
