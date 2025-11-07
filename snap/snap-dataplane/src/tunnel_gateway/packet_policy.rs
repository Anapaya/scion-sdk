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

use bytes::{Buf, Bytes};
use scion_proto::{
    address::EndhostAddr,
    packet::{self, AddressHeader, CommonHeader, ScionHeaders, ScionPacketRaw},
    path::{DataPlanePath, PathType},
    wire_encoding::{WireDecode, WireDecodeWithContext, WireEncodeVec},
};
use thiserror::Error;
use tracing::error;

/// Enforce policies for the inbound SCION packet.
///
/// The policies that are currently enforced are:
/// - The packet (SCION common header, address header, data plane path) can be decoded correctly.
/// - The SCION source address is set.
/// - The data plane path is a standard path (not empty).
/// - The SCION source address matches the assigned address for the tunnel.
#[allow(unused)]
pub fn inbound_datagram_check(
    mut datagram: &[u8],
    possible_source_addrs: &[EndhostAddr],
) -> Result<ScionPacketRaw, PacketPolicyError> {
    let common_header = match CommonHeader::decode(&mut datagram) {
        Ok(headers) => headers,
        Err(err) => return Err(PacketPolicyError::InvalidCommonHeader(err)),
    };

    let mut header_data = datagram.take(common_header.remaining_header_length());
    let address_header =
        match AddressHeader::decode_with_context(&mut header_data, common_header.address_info) {
            Ok(headers) => headers,
            Err(err) => return Err(PacketPolicyError::InvalidAddressHeader(err)),
        };

    // check if the SCION source address matches the assigned address for the tunnel
    match address_header.source() {
        Some(packet_source_addr) => {
            let packet_source_addr = match EndhostAddr::try_from(packet_source_addr) {
                Ok(addr) => addr,
                Err(e) => {
                    return Err(PacketPolicyError::InvalidSourceAddress);
                }
            };
            if !possible_source_addrs.contains(&packet_source_addr) {
                return Err(PacketPolicyError::InvalidSourceAddress);
            }
        }
        _ => return Err(PacketPolicyError::InvalidSourceAddress),
    }

    let path_offset: u16 = (CommonHeader::LENGTH + address_header.total_length()) as u16;
    let mut path_bytes = header_data.copy_to_bytes(header_data.remaining());
    let context = (common_header.path_type, path_bytes.len());

    let dp_path = match DataPlanePath::decode_with_context(&mut path_bytes, context) {
        Ok(path) => path,
        Err(err) => return Err(PacketPolicyError::InvalidPath(err, path_offset)),
    };

    // check if the data plane path is a standard path (not empty)
    match &dp_path {
        scion_proto::path::DataPlanePath::Standard(_path) => {}
        // only standard paths are allowed (first hop required)
        _ => return Err(PacketPolicyError::InvalidPathType(common_header.path_type)),
    }

    if path_bytes.has_remaining() {
        Err(PacketPolicyError::InconsistentPathLength(path_offset))
    } else if datagram.remaining() < common_header.payload_size() {
        Err(PacketPolicyError::PacketEmptyOrTruncated(path_offset))
    } else {
        let payload_start = datagram.len() - common_header.payload_size();
        let payload: Bytes = datagram[payload_start..].to_vec().into();

        Ok(ScionPacketRaw {
            headers: ScionHeaders {
                common: common_header,
                address: address_header,
                path: dp_path,
            },
            payload,
        })
    }
}

#[derive(Debug, Error)]
pub enum PacketPolicyError {
    #[error("packet with invalid common header: {0}")]
    InvalidCommonHeader(packet::DecodeError),
    #[error("packet with invalid address header: {0}")]
    InvalidAddressHeader(packet::DecodeError),
    #[error("packet with invalid data plane path (offset: {1}): {0}")]
    InvalidPath(packet::DecodeError, u16),
    #[error("packet with invalid path type: {0:?}")]
    InvalidPathType(PathType),
    #[error("packet with inconsistent path length (offset: {0})")]
    InconsistentPathLength(u16),
    #[error("packet is empty or truncated (offset: {0})")]
    PacketEmptyOrTruncated(u16),
    #[error("packet does not have a valid source address")]
    InvalidSourceAddress,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::{BufMut, Bytes, BytesMut};
    use scion_proto::{
        address::{Asn, Isd, IsdAsn, ScionAddr},
        packet::{ByEndpoint, FlowId, ScionPacketRaw},
        path::{DataPlanePath, encoded::EncodedStandardPath},
        wire_encoding::WireEncodeVec,
    };
    use test_log::test;

    use super::*;

    fn standard_path() -> DataPlanePath {
        let mut path_raw = BytesMut::with_capacity(36);
        path_raw.put_u32(0x0000_2000);
        path_raw.put_slice(&[0_u8; 32]);
        DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap())
    }

    fn example_source_addrs() -> Vec<EndhostAddr> {
        let ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
        vec![
            EndhostAddr::new(ia, Ipv4Addr::new(127, 0, 0, 1).into()),
            EndhostAddr::new(
                ia,
                Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
                )
                .into(),
            ),
        ]
    }

    fn get_valid_packet(source: EndhostAddr, dp_path: DataPlanePath) -> Vec<u8> {
        let _ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
        let endpoints: ByEndpoint<ScionAddr> = ByEndpoint {
            source: source.into(),
            destination: example_source_addrs()[0].into(),
        };

        let packet = ScionPacketRaw::new(
            endpoints,
            dp_path,
            Bytes::from_static("my SCION packet".as_bytes()),
            0,
            FlowId::new(0).unwrap(),
        )
        .unwrap();

        packet.encode_to_bytes_vec().concat()
    }

    #[test]
    fn inbound_datagram_valid_packet_accepted() {
        let source_addrs = example_source_addrs();

        let packet = get_valid_packet(source_addrs[0], standard_path());

        let res = inbound_datagram_check(&packet, &source_addrs);
        assert!(res.is_ok());
        assert_eq!(packet, res.unwrap().encode_to_bytes_vec().concat());
    }

    #[test]
    fn inbound_datagram_invalid_packet_rejected() {
        let source_addrs = example_source_addrs();
        let datagram: &[u8; 4] = &[1, 2, 3, 4];

        let res = inbound_datagram_check(datagram, &source_addrs);
        assert!(matches!(
            res,
            Err(PacketPolicyError::InvalidCommonHeader(_))
        ));
    }

    #[test]
    fn inbound_datagram_empty_path_rejected() {
        let source_addrs = example_source_addrs();
        let packet = get_valid_packet(source_addrs[0], DataPlanePath::EmptyPath);

        let res = inbound_datagram_check(&packet, &source_addrs);
        assert!(matches!(
            res,
            Err(PacketPolicyError::InvalidPathType(PathType::Empty))
        ));
    }

    #[test]
    fn inbound_datagram_invalid_source_addr_rejected() {
        let source_addrs = example_source_addrs();
        let packet = get_valid_packet(source_addrs[0], standard_path());

        let wrong_source_addrs = vec![EndhostAddr::new(
            IsdAsn::new(Isd(2), Asn::new(0xff00_0000_0110)),
            Ipv4Addr::new(127, 0, 0, 1).into(),
        )];

        let res = inbound_datagram_check(&packet, &wrong_source_addrs);
        assert!(matches!(res, Err(PacketPolicyError::InvalidSourceAddress)));
    }
}
