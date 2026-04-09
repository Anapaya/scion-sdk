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

//! Classification of SCION packets by payload protocol.
//!
//! [`ScionPacketView::classify`] inspects the `next_header` field of a [`ScionPacketView`] and, for
//! UDP and SCMP payloads, extracts the destination port without copying the packet or constructing
//! an owned representation.

use crate::{
    address::socket_addr::ScionSocketAddr,
    identifier::isd_asn::IsdAsn,
    packet::{
        model::{ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
        view::{ScionPacketView, ScionRawPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
};

/// The result of classifying a SCION packet by its payload protocol.
///
/// Each variant wraps a reference to the original [`ScionPacketView`] together with any port
/// information that could be deduced. The reference allows callers to access the raw packet bytes
/// (via [`View::as_bytes`](crate::core::view::View::as_bytes)) without a copy.
///
/// Use [`ClassifiedPacketView::dst_socket_addr`] to obtain the destination [`ScionSocketAddr`].
pub enum ClassifiedPacketView<'a> {
    /// A SCION/UDP packet.  `dst_port` is taken from the UDP header.
    Udp(&'a ScionUdpPacketView),
    /// A SCION/SCMP packet.
    ///
    /// For informational messages (echo, traceroute) the identifier field is used as the port.
    /// For error messages the source port of the quoted inner UDP datagram is used when it can be
    /// parsed.
    Scmp(&'a ScionScmpPacketView),
    /// A SCION packet whose payload protocol is neither UDP nor SCMP.
    Other(&'a ScionPacketView),
}
impl<'a> ClassifiedPacketView<'a> {
    /// Returns the destination [`ScionSocketAddr`], combining the SCION destination ISD-AS and host
    /// address from the packet header with the deduced port.
    ///
    /// Returns `None` for SCMP packets without a deduced port, for the
    /// [`ClassifiedPacketView::Other`] variant, and when the destination host address cannot be
    /// parsed.
    pub fn dst_socket_addr(&self) -> Option<ScionSocketAddr> {
        let (packet, dst_port): (&ScionRawPacketView, u16) = match self {
            ClassifiedPacketView::Udp(udp) => ((*udp).into(), udp.udp().dst_port()),
            ClassifiedPacketView::Scmp(scmp) => ((*scmp).into(), scmp.scmp().dst_port()?),
            ClassifiedPacketView::Other(_) => return None,
        };

        let isd_asn: IsdAsn = packet.header().dst_ia();
        let host = packet.header().dst_host_addr().ok()?.scion_host_addr()?;

        Some(ScionSocketAddr::new(isd_asn, host, dst_port))
    }
}

/// The result of classifying a SCION packet by its payload protocol.
pub enum ClassifiedPacket {
    /// A SCMP packet with a parsed SCMP message as payload.
    Scmp(ScionPacketScmp),
    /// A UDP packet with a parsed UDP datagram as payload.
    Udp(ScionPacketUdp),
    /// A SCION packet whose payload protocol is neither UDP nor SCMP.
    Other(ScionPacketRaw),
}
impl ClassifiedPacket {
    /// Returns the destination [`ScionSocketAddr`], combining the SCION destination ISD-AS and host
    /// address from the packet header with the deduced port.
    ///
    /// Returns `None` for SCMP packets without a deduced port, for the
    /// [`ClassifiedPacket::Other`] variant, and when the destination host address cannot be
    /// parsed.
    pub fn dst_socket_addr(&self) -> Option<ScionSocketAddr> {
        let (header, dst_port) = match self {
            ClassifiedPacket::Udp(packet) => (&packet.header, packet.payload.dst_port),
            ClassifiedPacket::Scmp(packet) => (&packet.header, packet.payload.dst_port()?),
            ClassifiedPacket::Other(_) => return None,
        };

        let isd_asn: IsdAsn = header.address.dst_ia;
        let host = header.address.dst_host_addr.scion_host_addr()?;

        Some(ScionSocketAddr::new(isd_asn, host, dst_port))
    }
}

/// Error returned when a SCION packet cannot be classified.
#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    /// The UDP header in the payload is malformed or truncated.
    #[error("malformed UDP payload: {0}")]
    MalformedUdp(crate::core::view::ViewConversionError),
    /// The SCMP payload is malformed or truncated.
    #[error("malformed SCMP payload: {0}")]
    MalformedScmp(crate::core::view::ViewConversionError),
}

#[cfg(test)]
mod tests {
    use scion_proto::{
        packet::{ByEndpoint, FlowId, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
        path::DataPlanePath,
        scmp::{
            DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpEchoReply, ScmpMessage,
        },
        wire_encoding::WireEncodeVec,
    };

    use crate::{
        address::socket_addr::ScionSocketAddr,
        core::view::View,
        packet::{classify::ClassifiedPacketView, view::ScionPacketView},
    };

    fn make_scion_udp_bytes(dst_port: u16) -> Vec<u8> {
        let ep = ByEndpoint {
            source: "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap(),
            destination: scion_proto::address::SocketAddr::new(
                "1-ff00:0:111,10.0.0.2".parse().unwrap(),
                dst_port,
            ),
        };
        ScionPacketUdp::new(
            ep,
            DataPlanePath::EmptyPath,
            bytes::Bytes::from_static(b"payload"),
        )
        .unwrap()
        .encode_to_bytes_vec()
        .concat()
        .to_vec()
    }

    #[test]
    fn classify_udp_packet_succeeds() {
        let buf = make_scion_udp_bytes(54321);
        let (view, _) = ScionPacketView::from_slice(&buf).unwrap();
        let classified = view.classify().unwrap();
        match &classified {
            ClassifiedPacketView::Udp { .. } => {}
            _ => panic!("expected Udp variant"),
        }
        assert_eq!(
            "[1-ff00:0:111,10.0.0.2]:54321"
                .parse::<ScionSocketAddr>()
                .unwrap(),
            classified.dst_socket_addr().unwrap()
        );
    }

    #[test]
    fn classify_scmp_echo_reply_with_port() {
        let echo_reply = ScmpMessage::EchoReply(ScmpEchoReply::new(
            54321, // identifier used as port
            1,
            bytes::Bytes::from_static(b"echo data"),
        ));
        let scmp_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: "1-ff00:0:110,10.0.0.1".parse().unwrap(),
                destination: "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            },
            DataPlanePath::EmptyPath,
            echo_reply,
        )
        .unwrap();
        let buf = scmp_packet.encode_to_bytes_vec().concat().to_vec();
        let (view, _) = ScionPacketView::from_slice(&buf).unwrap();
        let classified = view.classify().unwrap();
        match &classified {
            ClassifiedPacketView::Scmp(scmp) => {
                assert_eq!(Some(54321), scmp.scmp().dst_port());
            }
            _ => panic!("expected Scmp variant"),
        }
        assert_eq!(
            "[1-ff00:0:111,10.0.0.2]:54321"
                .parse::<ScionSocketAddr>()
                .unwrap(),
            classified.dst_socket_addr().unwrap()
        );
    }

    #[test]
    fn classify_scmp_destination_unreachable_with_parsable_payload() {
        // Create a UDP packet that was sent in the reversed direction.
        let quoted_udp = ScionPacketUdp::new(
            ByEndpoint {
                source: "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap(),
                destination: "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap(),
            },
            DataPlanePath::EmptyPath,
            bytes::Bytes::from_static(b"quoted payload"),
        )
        .unwrap();
        let quoted_udp_data = quoted_udp.encode_to_bytes_vec().concat();

        let dest_unreach = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            quoted_udp_data.into(),
        ));

        let scmp_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: "1-ff00:0:110,10.0.0.1".parse().unwrap(),
                destination: "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            },
            DataPlanePath::EmptyPath,
            dest_unreach,
        )
        .unwrap();
        let buf = scmp_packet.encode_to_bytes_vec().concat().to_vec();
        let (view, _) = ScionPacketView::from_slice(&buf).unwrap();
        let classified = view.classify().unwrap();
        match &classified {
            ClassifiedPacketView::Scmp(scmp) => {
                assert!(scmp.scmp().dst_port().is_some());
            }
            _ => panic!("expected Scmp variant"),
        }
        assert_eq!(
            "[1-ff00:0:111,10.0.0.2]:54321"
                .parse::<ScionSocketAddr>()
                .unwrap(),
            classified.dst_socket_addr().unwrap()
        );
    }

    #[test]
    fn classify_scmp_destination_unreachable_without_parsable_payload() {
        let dest_unreach = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            bytes::Bytes::from_static(b"invalid UDP packet"),
        ));

        let scmp_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: "1-ff00:0:110,10.0.0.1".parse().unwrap(),
                destination: "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            },
            DataPlanePath::EmptyPath,
            dest_unreach,
        )
        .unwrap();
        let buf = scmp_packet.encode_to_bytes_vec().concat().to_vec();
        let (view, _) = ScionPacketView::from_slice(&buf).unwrap();
        let classified = view.classify().unwrap();
        match &classified {
            ClassifiedPacketView::Scmp(scmp) => {
                assert!(scmp.scmp().dst_port().is_none());
            }
            _ => panic!("expected Scmp variant"),
        }
        assert!(classified.dst_socket_addr().is_none());
    }

    #[test]
    fn classify_unknown_next_header_returns_other() {
        let bytes = ScionPacketRaw::new(
            ByEndpoint {
                source: "1-ff00:0:110,10.0.0.1".parse().unwrap(),
                destination: "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            },
            DataPlanePath::EmptyPath,
            bytes::Bytes::from_static(b"raw"),
            0xFE, // unknown next header
            FlowId::new(0).unwrap(),
        )
        .unwrap()
        .encode_to_bytes_vec()
        .concat()
        .to_vec();
        let (view, _) = ScionPacketView::from_slice(&bytes).unwrap();
        assert!(matches!(
            view.classify().unwrap(),
            ClassifiedPacketView::Other(_)
        ));
        assert!(view.classify().unwrap().dst_socket_addr().is_none());
    }
}
