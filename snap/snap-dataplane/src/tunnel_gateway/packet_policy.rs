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
//! # SCION package policy enforcement.
//!
//! This module provides a function [inbound_datagram_check] to check whether
//! incoming SCION packet conform to the SNAP packet policies.

use std::net::IpAddr;

use sciparse::{
    core::view::{View, ViewConversionError},
    dataplane_path::types::PathType,
    packet::view::ScionPacketView,
};
use thiserror::Error;

/// Enforce policies for the inbound SCION packet.
///
/// Returns a zero-copy view over `datagram` on success; the view's lifetime is
/// tied to the input slice so no allocation is required.
///
/// The policies that are currently enforced are:
/// - The packet (SCION common header, address header, data plane path) can be parsed correctly.
/// - The SCION source address is an IP address that matches `expected_ip`.
/// - The data plane path is a standard or empty path.
pub fn inbound_datagram_check<'a>(
    datagram: &'a [u8],
    expected_ip: IpAddr,
) -> Result<&'a ScionPacketView, PacketPolicyError<'a>> {
    let (view, _) = ScionPacketView::from_slice(datagram)
        .map_err(|e| PacketPolicyError::MalformedPacket(datagram, e))?;

    // Check if the SCION source address matches the expected socket address (IP part).
    let src_ip = view
        .header()
        .src_host_addr()
        .ok()
        .and_then(|w| w.ip())
        .ok_or(PacketPolicyError::InvalidSourceAddress(view))?;
    if src_ip != expected_ip {
        return Err(PacketPolicyError::InvalidSourceAddress(view));
    }

    // Only standard and empty paths are supported.
    match view.header().path_type() {
        PathType::Scion | PathType::Empty => {}
        pt => return Err(PacketPolicyError::InvalidPathType(view, pt)),
    }

    Ok(view)
}

#[derive(Error)]
pub enum PacketPolicyError<'a> {
    #[error("malformed packet: {1}")]
    MalformedPacket(&'a [u8], ViewConversionError),
    #[error("packet with invalid path type: {1:?}")]
    InvalidPathType(&'a ScionPacketView, PathType),
    #[error("packet does not have a valid source address")]
    InvalidSourceAddress(&'a ScionPacketView),
}

impl std::fmt::Debug for PacketPolicyError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketPolicyError::MalformedPacket(_, e) => {
                f.debug_tuple("MalformedPacket").field(e).finish()
            }
            PacketPolicyError::InvalidPathType(_, pt) => {
                f.debug_tuple("InvalidPathType").field(pt).finish()
            }
            PacketPolicyError::InvalidSourceAddress(_) => {
                f.debug_tuple("InvalidSourceAddress").finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use sciparse::{
        address::addr::ScionAddr,
        core::{encode::WireEncode, view::View},
        dataplane_path::{model::DpPath, standard::model::StandardPath},
        identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
        packet::model::ScionRawPacket,
        util::ToValue,
    };
    use test_log::test;

    use super::*;

    fn standard_path() -> DpPath {
        DpPath::Standard(StandardPath::arbitrary_value(0))
    }

    fn example_source_addrs() -> Vec<ScionAddr> {
        let ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
        vec![
            ScionAddr::new(ia, Ipv4Addr::new(127, 0, 0, 1).into()),
            ScionAddr::new(
                ia,
                Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
                )
                .into(),
            ),
        ]
    }

    fn get_valid_packet(source: ScionAddr, dp_path: DpPath) -> Vec<u8> {
        let packet = ScionRawPacket::new(
            source,
            example_source_addrs()[0],
            dp_path,
            sciparse::payload::ProtocolNumber::Udp,
            b"my SCION packet".to_vec(),
        );

        packet.encode_to_vec().unwrap()
    }

    #[test]
    fn inbound_datagram_valid_packet_accepted() {
        let source_addrs = example_source_addrs();

        let packet = get_valid_packet(source_addrs[0], standard_path());

        let res = inbound_datagram_check(&packet, source_addrs[0].ip().unwrap());
        assert!(res.is_ok());
        assert_eq!(&packet[..], res.unwrap().as_bytes());
    }

    #[test]
    fn inbound_datagram_invalid_packet_rejected() {
        let source_addrs = example_source_addrs();
        let invalid_packet: &[u8; 4] = &[1, 2, 3, 4];

        let res = inbound_datagram_check(invalid_packet, source_addrs[0].ip().unwrap());
        assert!(matches!(res, Err(PacketPolicyError::MalformedPacket(..))));
    }

    #[test]
    fn inbound_datagram_invalid_source_addr_rejected() {
        let source_addrs = example_source_addrs();
        let packet = get_valid_packet(source_addrs[0], standard_path());
        let wrong_source = Ipv4Addr::new(127, 0, 0, 2);

        let res = inbound_datagram_check(&packet, wrong_source.into());
        assert!(matches!(
            res,
            Err(PacketPolicyError::InvalidSourceAddress(_))
        ));
    }
}
