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
    core::encode::WireEncode,
    identifier::isd_asn::IsdAsn,
    packet::{
        model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
        view::{ScionPacketView, ScionRawPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
};

/// The result of classifying a SCION packet by its payload protocol.
///
/// Each variant wraps a reference to the original [`ScionPacketView`] together with any port
/// information that could be deduced. The reference allows callers to access the raw packet bytes
/// (via [`View::as_slice`](crate::core::view::View::as_slice)) without a copy.
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
        let dst_port = self.dst_port()?;
        let scion_addr = self.into_raw().dst_scion_addr().ok()?;

        Some(ScionSocketAddr::new(
            scion_addr.isd_asn(),
            scion_addr.host(),
            dst_port,
        ))
    }

    /// Returns the destination port if it could be deduced from the packet.
    ///
    /// Returns `None` if the packet is neither a UDP nor a SCMP packet, or if the SCMP packet does
    /// not contain a port.
    pub fn dst_port(&self) -> Option<u16> {
        match self {
            ClassifiedPacketView::Udp(udp) => Some(udp.udp().dst_port()),
            ClassifiedPacketView::Scmp(scmp) => scmp.scmp().dst_port(),
            ClassifiedPacketView::Other(_) => None,
        }
    }

    /// Returns `true` if the classified packet is a UDP packet.
    pub fn is_udp(&self) -> bool {
        matches!(self, ClassifiedPacketView::Udp(_))
    }

    /// Returns `true` if the classified packet is a SCMP packet.
    pub fn is_scmp(&self) -> bool {
        matches!(self, ClassifiedPacketView::Scmp(_))
    }

    /// Returns `true` if the classified packet is neither a UDP nor a SCMP packet.
    pub fn is_other(&self) -> bool {
        matches!(self, ClassifiedPacketView::Other(_))
    }

    /// Returns a reference to the underlying raw packet view.
    pub fn into_raw(&self) -> &'a ScionRawPacketView {
        match self {
            ClassifiedPacketView::Udp(udp) => udp.into_raw(),
            ClassifiedPacketView::Scmp(scmp) => scmp.into_raw(),
            ClassifiedPacketView::Other(other) => other,
        }
    }
}

/// The result of classifying a SCION packet by its payload protocol.
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum ClassifiedPacket {
    /// A SCMP packet with a parsed SCMP message as payload.
    Scmp(ScionScmpPacket),
    /// A UDP packet with a parsed UDP datagram as payload.
    Udp(ScionUdpPacket),
    /// A SCION packet whose payload protocol is neither UDP nor SCMP.
    Other(ScionRawPacket),
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
        let host = header.address.dst_host_addr.scion_host_addr().ok()?;

        Some(ScionSocketAddr::new(isd_asn, host, dst_port))
    }

    /// Converts the classified packet back into a raw packet.
    #[inline]
    pub fn into_raw(self) -> ScionRawPacket {
        match self {
            ClassifiedPacket::Udp(packet) => packet.into_raw(),
            ClassifiedPacket::Scmp(packet) => packet.into_raw(),
            ClassifiedPacket::Other(packet) => packet,
        }
    }

    /// Converts the classified packet into a UDP packet if it is a UDP packet, or returns the
    /// original classified packet if it is not.
    #[inline]
    #[allow(clippy::result_large_err)]
    pub fn try_into_udp(self) -> Result<ScionUdpPacket, Self> {
        match self {
            ClassifiedPacket::Udp(packet) => Ok(packet),
            _ => Err(self),
        }
    }

    /// Converts the classified packet into a SCMP packet if it is a SCMP packet, or returns the
    /// original classified packet if it is not.
    #[inline]
    #[allow(clippy::result_large_err)]
    pub fn try_into_scmp(self) -> Result<ScionScmpPacket, Self> {
        match self {
            ClassifiedPacket::Scmp(packet) => Ok(packet),
            _ => Err(self),
        }
    }

    /// Returns a reference to the SCION packet header.
    pub fn header(&self) -> &crate::header::model::ScionPacketHeader {
        match self {
            ClassifiedPacket::Udp(packet) => &packet.header,
            ClassifiedPacket::Scmp(packet) => &packet.header,
            ClassifiedPacket::Other(packet) => &packet.header,
        }
    }
}
impl WireEncode for ClassifiedPacket {
    fn wire_valid(&self) -> Result<(), crate::core::encode::InvalidStructureError> {
        match self {
            ClassifiedPacket::Udp(packet) => packet.wire_valid(),
            ClassifiedPacket::Scmp(packet) => packet.wire_valid(),
            ClassifiedPacket::Other(packet) => packet.wire_valid(),
        }
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            match self {
                ClassifiedPacket::Udp(packet) => packet.encode_unchecked(buf),
                ClassifiedPacket::Scmp(packet) => packet.encode_unchecked(buf),
                ClassifiedPacket::Other(packet) => packet.encode_unchecked(buf),
            }
        }
    }

    fn required_size(&self) -> usize {
        match self {
            ClassifiedPacket::Udp(packet) => packet.required_size(),
            ClassifiedPacket::Scmp(packet) => packet.required_size(),
            ClassifiedPacket::Other(packet) => packet.required_size(),
        }
    }
}
impl From<ClassifiedPacket> for ScionRawPacket {
    fn from(packet: ClassifiedPacket) -> Self {
        packet.into_raw()
    }
}
impl TryFrom<ClassifiedPacket> for ScionUdpPacket {
    type Error = ClassifiedPacket;
    fn try_from(packet: ClassifiedPacket) -> Result<Self, Self::Error> {
        packet.try_into_udp()
    }
}
impl TryFrom<ClassifiedPacket> for ScionScmpPacket {
    type Error = ClassifiedPacket;
    fn try_from(packet: ClassifiedPacket) -> Result<Self, Self::Error> {
        packet.try_into_scmp()
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
/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        header::model::ScionPacketHeader,
        packet::model::ScionPacket,
        payload::{ProtocolNumber, scmp::model::ScmpMessage, udp::model::UdpDatagram},
    };

    /// Configuration for generating arbitrary [`ClassifiedPacket`] values.
    ///
    /// Controls the relative probability of each classified packet variant.
    ///
    /// Default weights: `udp = 1, scmp = 1, other = 1`.
    #[derive(Debug, Clone)]
    pub struct ArbitraryClassifiedPacketParams {
        /// Weight for generating UDP packets.
        pub udp: u32,
        /// Weight for generating SCMP packets.
        pub scmp: u32,
        /// Weight for generating raw (other) packets.
        pub other: u32,
        /// Parameters for generating the underlying SCION packet header.
        pub header_params: <ScionPacketHeader as Arbitrary>::Parameters,
        /// Parameters for generating SCMP payloads.
        pub scmp_params: <ScmpMessage as Arbitrary>::Parameters,
    }
    impl Default for ArbitraryClassifiedPacketParams {
        fn default() -> Self {
            Self {
                udp: 1,
                scmp: 1,
                other: 1,
                header_params: Default::default(),
                scmp_params: Default::default(),
            }
        }
    }

    impl Arbitrary for ClassifiedPacket {
        type Parameters = ArbitraryClassifiedPacketParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            let hp = params.header_params;
            prop_oneof![
                params.udp => (
                    ScionPacketHeader::arbitrary_with(hp.clone()),
                    any::<UdpDatagram>(),
                )
                    .prop_map(|(mut header, payload)| {
                        header.common.next_header = ProtocolNumber::Udp;
                        ClassifiedPacket::Udp(ScionPacket { header, payload })
                    }),
                params.scmp => (
                    ScionPacketHeader::arbitrary_with(hp.clone()),
                    ScmpMessage::arbitrary_with(params.scmp_params),
                )
                    .prop_map(|(mut header, payload)| {
                        header.common.next_header = ProtocolNumber::Scmp;
                        ClassifiedPacket::Scmp(ScionPacket { header, payload })
                    }),
                params.other => (
                    ScionPacketHeader::arbitrary_with(hp),
                    proptest::collection::vec(any::<u8>(), 0..2048),
                )
                    .prop_map(|(mut header, payload)| {
                        header.common.next_header = match header.common.next_header {
                            ProtocolNumber::Udp => ProtocolNumber::Other(255), // Avoid generating UDP next_header for the Other variant
                            ProtocolNumber::Scmp => ProtocolNumber::Other(255), // Avoid generating SCMP next_header for the Other variant
                            v => v,
                        };
                        ClassifiedPacket::Other(ScionPacket { header, payload })
                    }),
            ]
            .boxed()
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        address::socket_addr::ScionSocketAddr,
        core::{encode::WireEncode, view::View},
        dataplane_path::model::DpPath,
        packet::{
            classify::ClassifiedPacketView,
            model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
            view::ScionPacketView,
        },
        payload::{
            ProtocolNumber,
            scmp::model::{ScmpDestinationUnreachable, ScmpEchoReply},
        },
    };

    #[test]
    fn classify_udp_packet_succeeds() {
        let buf = ScionUdpPacket::new(
            "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap(),
            "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap(),
            DpPath::Empty,
            b"payload".to_vec(),
        )
        .encode_to_vec()
        .expect("failed to encode SCION UDP packet");

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
        let scion_scmp_packet = ScionScmpPacket::new(
            "1-ff00:0:110,10.0.0.1".parse().unwrap(),
            "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            DpPath::Empty,
            ScmpEchoReply::new(
                54321, // identifier used as port
                1,
                b"echo data".to_vec(),
            )
            .into(),
        );

        let buf = scion_scmp_packet
            .encode_to_vec()
            .expect("failed to encode SCION SCMP packet");

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
        let quoted_udp = ScionUdpPacket::new(
            "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap(),
            "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap(),
            DpPath::Empty,
            b"quoted payload".to_vec(),
        );

        let quoted_udp_data = quoted_udp
            .encode_to_vec()
            .expect("failed to encode quoted UDP packet");

        let scmp_packet = ScionScmpPacket::new(
            "1-ff00:0:110,10.0.0.1".parse().unwrap(),
            "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            DpPath::Empty,
            ScmpDestinationUnreachable::new(
                crate::payload::scmp::types::ScmpDestinationUnreachableCode::AddressUnreachable,
                quoted_udp_data,
            )
            .into(),
        );

        let buf = scmp_packet.encode_to_vec().unwrap();
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
        let scmp_packet = ScionScmpPacket::new(
            "1-ff00:0:110,10.0.0.1".parse().unwrap(),
            "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            DpPath::Empty,
            ScmpDestinationUnreachable::new(
                crate::payload::scmp::types::ScmpDestinationUnreachableCode::AddressUnreachable,
                b"not a valid quoted UDP packet".to_vec(),
            )
            .into(),
        );

        let buf = scmp_packet.encode_to_vec().unwrap();
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
        let bytes = ScionRawPacket::new(
            "1-ff00:0:110,10.0.0.1".parse().unwrap(),
            "1-ff00:0:111,10.0.0.2".parse().unwrap(),
            DpPath::Empty,
            ProtocolNumber::Other(0xFE),
            b"rawr".to_vec(),
        )
        .encode_to_vec()
        .expect("failed to encode SCION raw packet");

        let (view, _) = ScionPacketView::from_slice(&bytes).unwrap();
        assert!(matches!(
            view.classify().unwrap(),
            ClassifiedPacketView::Other(_)
        ));
        assert!(view.classify().unwrap().dst_socket_addr().is_none());
    }
}
