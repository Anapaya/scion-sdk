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
//
// This file incorporates code from mullvad/gotatun:
// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//! SCION packet abstractions.
//!
//! This module contains a minimal definition of the SCION packet structure
//! following the conventions used by Anapaya/gotatun. It is primarily used for
//! testing purposes as in production code, scion-proto/sciparse is used.

#![allow(clippy::doc_markdown)]
#![allow(unused)]

use core::fmt;

use ana_gotatun::packet::IpNextProtocol;
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

/// A SCION packet: fixed common header followed by variable-length payload.
///
/// This mirrors the layout pattern used for IPv6 packets in this crate:
/// a header struct plus a generic payload. It does not model the full SCION
/// header. The path header is contained in the payload.
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Scion<Payload: ?Sized = [u8]> {
    pub header: ScionHeader,
    pub payload: Payload,
}

/// SCION common header (simplified).
///
/// This is not a full SCION header implementation; it captures the
/// main fields in a compact layout similar to the IPv6 header in this crate:
///
/// - version (4 bits)
/// - traffic class / DSCP-like (8 bits)
/// - flow id (20 bits)
/// - payload_len (16 bits)
/// - next_header (8 bits, reusing IpNextProtocol)
/// - hop_count (8 bits)
/// - source and destination identifiers (64 bits each, placeholder)
///
/// Adjust to your actual SCION common header spec as needed.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct ScionHeader {
    /// Version, traffic class, and flow ID, packed into a 32-bit field.
    pub version_traffic_flow: ScionVersionTrafficFlow,

    /// Length of the SCION payload in bytes (excluding this common header).
    pub payload_length: big_endian::U16,

    /// Next header / L4 protocol identifier.
    ///
    /// We reuse `IpNextProtocol` for convenience, since SCION also carries
    /// familiar transports like UDP/TCP/QUIC, etc. If you want a distinct
    /// namespace, define a `ScionNextHeader` type instead.
    pub next_header: IpNextProtocol,

    /// Remaining hop count.
    pub hop_count: u8,

    /// Source identifier (placeholder layout).
    ///
    /// In real SCION, these are ISD-AS and host parts, with length
    /// and type information. Here we simply use a 64-bit field for
    /// each endpoint as a compact stand-in.
    pub source_id: big_endian::U64,

    /// Destination identifier (placeholder layout).
    pub destination_id: big_endian::U64,
}

impl fmt::Debug for ScionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Unpack the version/traffic/flow bitfield
        let vtf = self.version_traffic_flow;

        f.debug_struct("ScionHeader")
            .field("version", &vtf.version())
            .field("traffic_class", &vtf.traffic_class())
            .field("flow_id", &vtf.flow_id())
            .field("payload_length", &self.payload_length.get())
            .field("next_header", &self.next_header)
            .field("hop_count", &self.hop_count)
            .field("source_id", &format_args!("{:#018x}", self.source_id.get()))
            .field(
                "destination_id",
                &format_args!("{:#018x}", self.destination_id.get()),
            )
            .finish()
    }
}

/// A bitfield struct containing the SCION fields
/// `flow_id`, `traffic_class` and `version`.
///
/// This mirrors the `Ipv6VersionTrafficFlow` bitfield style:
///
/// ```text
///  31           12  11          4  3     0
/// +---------------+--------------+--------+
/// |   flow_id     | traffic_cls  |  ver   |
/// +---------------+--------------+--------+
/// ```
///
/// - `version`: 4 bits
/// - `traffic_class`: 8 bits
/// - `flow_id`: 20 bits
#[bitfield(
    u32,
    repr = big_endian::U32,
    from = big_endian::U32::new,
    into = big_endian::U32::get
)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct ScionVersionTrafficFlow {
    #[bits(20)]
    pub flow_id: u32,
    #[bits(8)]
    pub traffic_class: u8,
    #[bits(4)]
    pub version: u8,
}

impl ScionHeader {
    /// Construct a new `ScionHeader` with the given components.
    ///
    /// `payload_len` is the length of the SCION payload in bytes (not including this header).
    pub fn new(
        version: u8,
        traffic_class: u8,
        flow_id: u32,
        payload_len: u16,
        next_header: IpNextProtocol,
        hop_count: u8,
        source_id: u64,
        destination_id: u64,
    ) -> Self {
        let vtf = ScionVersionTrafficFlow::new()
            .with_version(version)
            .with_traffic_class(traffic_class)
            .with_flow_id(flow_id & 0x000F_FFFF); // 20-bit mask

        ScionHeader {
            version_traffic_flow: vtf, // big_endian::U32::new(vtf.flow_id()).into(),
            payload_length: big_endian::U16::new(payload_len),
            next_header,
            hop_count,
            source_id: big_endian::U64::new(source_id),
            destination_id: big_endian::U64::new(destination_id),
        }
    }

    /// Get the SCION version field.
    pub fn version(&self) -> u8 {
        self.version_traffic_flow.version()
    }

    /// Get the traffic class field.
    pub fn traffic_class(&self) -> u8 {
        self.version_traffic_flow.traffic_class()
    }

    /// Get the flow ID field.
    pub fn flow_id(&self) -> u32 {
        self.version_traffic_flow.flow_id()
    }

    /// Get payload length (in bytes).
    pub fn payload_length(&self) -> u16 {
        self.payload_length.get()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn scion_header_layout() {
        assert_eq!(size_of::<ScionHeader>(), 4 + 2 + 1 + 1 + 8 + 8);

        let hdr = ScionHeader::new(
            1,       // version
            0xAA,    // traffic_class
            0xABCDE, // flow_id (20 bits)
            1200,    // payload_len
            IpNextProtocol::Udp,
            7, // hop_count
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
        );

        assert_eq!(hdr.version(), 1);
        assert_eq!(hdr.traffic_class(), 0xAA);
        assert_eq!(hdr.flow_id(), 0xABCDE & 0x000F_FFFF);
        assert_eq!(hdr.payload_length(), 1200);
        assert_eq!(hdr.next_header, IpNextProtocol::Udp);
        assert_eq!(hdr.hop_count, 7);
    }
}
