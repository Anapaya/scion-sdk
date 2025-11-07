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

//! Classification of SCION packets based on protocol headers.
//!
//! This module provides functionality to classify SCION packets into different types
//! (UDP, SCMP with/without destination, or other) based on their protocol headers.

use bytes::BytesMut;

use crate::{
    address::SocketAddr,
    datagram::{UdpDecodeError, UdpMessage},
    packet::{ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
    scmp::{SCMP_PROTOCOL_NUMBER, ScmpDecodeError, ScmpMessage},
    wire_encoding::{WireDecode, WireEncodeVec as _},
};

/// Result of classifying a SCION packet by its protocol type.
#[derive(Debug)]
pub enum PacketClassification {
    /// UDP packet
    Udp(ScionPacketUdp),
    /// SCMP packet with extractable destination port
    ScmpWithDestination(u16, ScionPacketScmp),
    /// SCMP packet without extractable destination port
    ScmpWithoutDestination(ScionPacketScmp),
    /// Other packet type (raw SCION packet)
    Other(ScionPacketRaw),
}

/// Error that can occur during packet classification.
#[derive(Debug, thiserror::Error)]
pub enum PacketClassificationError {
    /// Error during UDP packet decoding.
    #[error("decoding UDP packet: {0}")]
    UdpPacketDecodeError(#[from] UdpDecodeError),
    /// Error during SCMP packet decoding.
    #[error("decoding SCMP packet: {0}")]
    ScmpPacketDecodeError(#[from] ScmpDecodeError),
}

/// Classifies a SCION packet based on its protocol headers.
///
/// This function examines the next_header field of a SCION packet and decodes
/// the packet if necessary to determine the packet type. For SCMP packets, it also tries to
/// extract a destination port using [`scmp_port`].
///
/// # Arguments
/// * `packet` - The SCION packet to classify.
pub fn classify_scion_packet(
    packet: ScionPacketRaw,
) -> Result<PacketClassification, PacketClassificationError> {
    match packet.headers.common.next_header {
        UdpMessage::PROTOCOL_NUMBER => {
            let udp_packet: ScionPacketUdp = packet.try_into()?;
            Ok(PacketClassification::Udp(udp_packet))
        }
        SCMP_PROTOCOL_NUMBER => {
            let scmp_packet: ScionPacketScmp = packet.try_into()?;
            Ok(match scmp_port(&scmp_packet.message) {
                Some(port) => PacketClassification::ScmpWithDestination(port, scmp_packet),
                None => PacketClassification::ScmpWithoutDestination(scmp_packet),
            })
        }
        _ => Ok(PacketClassification::Other(packet)),
    }
}

/// Tries to extract the port from an SCMP message.
///
/// For informational SCMP messages (echo, traceroute), the identifier field is used as the port.
/// For error messages that quote an offending packet, this function attempts to parse the
/// offending packet as a UDP packet and extract the source port.
pub fn scmp_port(message: &ScmpMessage) -> Option<u16> {
    let offending_packet = match message {
        // Informational messages take the port from the identifier
        ScmpMessage::EchoRequest(r) => return Some(r.identifier),
        ScmpMessage::EchoReply(r) => return Some(r.identifier),
        ScmpMessage::TracerouteRequest(r) => return Some(r.identifier),
        ScmpMessage::TracerouteReply(r) => return Some(r.identifier),
        // Error messages
        ScmpMessage::DestinationUnreachable(r) => r.get_offending_packet(),
        ScmpMessage::PacketTooBig(r) => r.get_offending_packet(),
        ScmpMessage::ParameterProblem(r) => r.get_offending_packet(),
        ScmpMessage::ExternalInterfaceDown(r) => r.get_offending_packet(),
        ScmpMessage::InternalConnectivityDown(r) => r.get_offending_packet(),
        // Unknown error messages
        ScmpMessage::UnknownError(_) => return None,
    };
    // Try parsing the offending packet as a UDP packet.
    match ScionPacketUdp::decode(&mut BytesMut::from(offending_packet)) {
        Ok(packet) => Some(packet.src_port()),
        Err(_) => None,
    }
}

impl PacketClassification {
    /// Extracts the destination port from the classified packet, if available.
    pub fn port(&self) -> Option<u16> {
        match self {
            PacketClassification::Udp(udp) => Some(udp.datagram.port.destination),
            PacketClassification::ScmpWithDestination(port, _) => Some(*port),
            _ => None,
        }
    }

    /// Extracts the destination address from the classified packet, if available.
    pub fn destination(&self) -> Option<SocketAddr> {
        match self {
            PacketClassification::Udp(udp) => udp.destination(),
            PacketClassification::ScmpWithDestination(port, scmp) => {
                scmp.headers
                    .address
                    .destination()
                    .map(|addr| SocketAddr::new(addr, *port))
            }
            _ => None,
        }
    }

    /// Encode as bytes vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        match self {
            PacketClassification::Udp(udp) => udp.encode_to_bytes_vec().concat(),
            PacketClassification::ScmpWithDestination(_, scmp) => {
                scmp.encode_to_bytes_vec().concat()
            }
            PacketClassification::ScmpWithoutDestination(scmp) => {
                scmp.encode_to_bytes_vec().concat()
            }
            PacketClassification::Other(raw) => raw.encode_to_bytes_vec().concat(),
        }
    }

    /// Tries to convert the classification to a SCMP packet if it is one.
    #[allow(clippy::result_large_err)]
    pub fn try_into_scmp(self) -> Result<ScionPacketScmp, Self> {
        match self {
            PacketClassification::ScmpWithDestination(_, scmp) => Ok(scmp),
            PacketClassification::ScmpWithoutDestination(scmp) => Ok(scmp),
            _ => Err(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        address::SocketAddr,
        packet::{ByEndpoint, FlowId, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
        path::DataPlanePath,
        scmp::{
            DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpEchoReply, ScmpMessage,
        },
        wire_encoding::WireEncodeVec,
    };

    fn test_path() -> DataPlanePath {
        DataPlanePath::EmptyPath
    }

    fn test_addresses() -> ByEndpoint<SocketAddr> {
        ByEndpoint {
            source: "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap(),
            destination: "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap(),
        }
    }

    #[test]
    fn classify_udp_packet_succeeds() {
        let endpoints = test_addresses();
        let dp_path = test_path();

        let udp_packet =
            ScionPacketUdp::new(endpoints, dp_path, Bytes::from_static(b"test payload")).unwrap();

        let result = classify_scion_packet(udp_packet.into()).unwrap();

        match result {
            PacketClassification::Udp(_) => {
                // Check destination address
                let dst = result.destination().unwrap();
                assert_eq!(dst, endpoints.destination);
            }
            _ => panic!("Expected UDP classification"),
        }
    }

    #[test]
    fn classify_scmp_echo_reply_with_port_succeeds() {
        let endpoints = test_addresses();
        let dp_path = test_path();

        let echo_reply = ScmpMessage::EchoReply(ScmpEchoReply::new(
            54321, // identifier used as port
            1,
            Bytes::from_static(b"echo data"),
        ));

        let scmp_packet = ScionPacketScmp::new(
            endpoints.map(|addr| addr.scion_address()),
            dp_path.clone(),
            echo_reply,
        )
        .unwrap();

        let result = classify_scion_packet(scmp_packet.into()).unwrap();

        match result {
            PacketClassification::ScmpWithDestination(..) => {
                assert_eq!(endpoints.destination, result.destination().unwrap());
            }
            _ => panic!("Expected SCMP with destination classification"),
        }
    }

    #[test]
    fn classify_scmp_destination_unreachable_with_parsable_payload() {
        let endpoints = test_addresses();
        let mut endpoints_reversed = test_addresses();
        endpoints_reversed.reverse();
        let dp_path = test_path();

        // Create a UDP packet that was sent in the reversed direction
        // of the received SCMP error.
        let quoted_udp = ScionPacketUdp::new(
            endpoints_reversed,
            dp_path.clone(),
            Bytes::from_static(b"quoted payload"),
        )
        .unwrap();
        let quoted_udp_data = quoted_udp.encode_to_bytes_vec().concat();

        let dest_unreach = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            quoted_udp_data.into(),
        ));

        let scmp_packet = ScionPacketScmp::new(
            endpoints.map(|addr| addr.scion_address()),
            dp_path.clone(),
            dest_unreach,
        )
        .unwrap();

        let result = classify_scion_packet(scmp_packet.into()).unwrap();

        match result {
            PacketClassification::ScmpWithDestination(..) => {
                // Check destination address
                assert_eq!(endpoints.destination, result.destination().unwrap());
            }
            _ => panic!("Expected SCMP with destination classification"),
        }
    }

    #[test]
    fn classify_scmp_destination_unreachable_without_parsable_payload() {
        let endpoints = test_addresses();
        let dp_path = test_path();

        // Create SCMP error with garbage data that can't be parsed as UDP
        let dest_unreach = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"invalid UDP packet"),
        ));

        let scmp_packet = ScionPacketScmp::new(
            endpoints.map(|addr| addr.scion_address()),
            dp_path.clone(),
            dest_unreach,
        )
        .unwrap();

        let result = classify_scion_packet(scmp_packet.into()).unwrap();

        match result {
            PacketClassification::ScmpWithoutDestination(_) => {
                // Should not have a destination since the quoted packet can't be parsed
                assert!(result.destination().is_none());
            }
            _ => panic!("Expected SCMP without destination classification"),
        }
    }

    #[test]
    fn classify_scion_packet_with_invalid_payload() {
        let endpoints = test_addresses();
        let dp_path = test_path();

        // Create a raw SCION packet with an unknown protocol number
        let packet = ScionPacketRaw::new(
            endpoints.map(|addr| addr.scion_address()),
            dp_path,
            Bytes::from_static(b"garbage payload"),
            99, // Unknown protocol number
            FlowId::new(0).unwrap(),
        )
        .unwrap();

        let result = classify_scion_packet(packet).unwrap();

        match result {
            PacketClassification::Other(_) => {
                // Should not have a destination for unknown protocols
                assert!(result.destination().is_none());
            }
            _ => panic!("Expected Other classification"),
        }
    }
}
