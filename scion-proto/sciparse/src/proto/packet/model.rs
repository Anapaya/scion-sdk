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

//! SCION packet models

use std::{fmt::Debug, ops::Deref};

use crate::{
    address::{addr::ScionAddr, host_addr::UnknownAddressTypeError, socket_addr::ScionSocketAddr},
    core::{
        convert::{TryFromModel, TryFromView},
        encode::{EncodeError, InvalidStructureError, WireEncode},
        macros::impl_from,
        model::Model,
        view::{View, ViewConversionError},
    },
    dataplane_path::model::DpPath,
    header::{
        model::{AddressHeader, CommonHeader, ScionPacketHeader},
        view::ScionHeaderView,
    },
    packet::{
        classify::{ClassifiedPacket, ClassifyError},
        view::{ScionPacketView, ScionRawPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
    payload::{
        ProtocolNumber, encode::PayloadEncode, scmp::model::ScmpMessage, udp::model::UdpDatagram,
    },
};

/// A Complete SCION Packet
#[derive(Clone, PartialEq, Hash)]
pub struct ScionPacket<T: PayloadEncode> {
    /// SCION Packet Header
    pub header: ScionPacketHeader,
    /// Payload
    pub payload: T,
}
// Methods for all packet types
impl<T: PayloadEncode> ScionPacket<T> {
    /// Converts this packet into a raw packet with an owned `Vec<u8>` payload by encoding the
    /// payload
    pub fn into_raw(self) -> ScionRawPacket {
        let header_size = self.header.required_size();
        let payload_size = self.payload.required_size(header_size);
        let mut buf = vec![0u8; payload_size];
        let size = self
            .payload
            .encode(&mut buf[..], &self.header.address, header_size)
            .expect("Buffer size must be sufficient based on required_size");

        debug_assert_eq!(
            size, payload_size,
            "Encoded payload size must match required_size calculation"
        );

        ScionPacket {
            header: self.header,
            payload: buf,
        }
    }

    /// Returns the source SCION address of the packet.
    ///
    /// If a unknown address type is encountered in the source host address, an error is returned.
    pub fn src_scion_addr(&self) -> Result<ScionAddr, UnknownAddressTypeError> {
        let host = self.header.address.src_host_addr.scion_host_addr()?;
        Ok(ScionAddr::new(self.header.address.src_ia, host))
    }

    /// Sets the source SCION address of the packet by updating the appropriate fields in the
    /// header.
    pub fn set_src_scion_addr(&mut self, addr: ScionAddr) {
        self.header.address.src_ia = addr.isd_asn();
        self.header.address.src_host_addr = addr.host().into();
    }

    /// Returns the destination SCION address of the packet.
    ///
    /// If a unknown address type is encountered in the destination host address, an error is
    /// returned.
    pub fn dst_scion_addr(&self) -> Result<ScionAddr, UnknownAddressTypeError> {
        let host = self.header.address.dst_host_addr.scion_host_addr()?;
        Ok(ScionAddr::new(self.header.address.dst_ia, host))
    }

    /// Sets the destination SCION address of the packet by updating the appropriate fields in the
    pub fn set_dst_scion_addr(&mut self, addr: ScionAddr) {
        self.header.address.dst_ia = addr.isd_asn();
        self.header.address.dst_host_addr = addr.host().into();
    }
}
impl<T: PayloadEncode> WireEncode for ScionPacket<T> {
    fn required_size(&self) -> usize {
        self.header.required_size() + self.payload.required_size(self.header.required_size())
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.header.wire_valid()?;
        self.payload.wire_valid()?;
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        let header_size = self.header.required_size();
        let payload_size = self.payload.required_size(header_size);

        unsafe {
            // Encode header
            {
                let header_buf = buf.get_unchecked_mut(0..header_size);
                self.header
                    .encode_unchecked(header_buf, payload_size as u16);
            }
            // Encode payload
            let payload_buf = buf.get_unchecked_mut(header_size..(header_size + payload_size));
            self.payload
                .encode_unchecked(payload_buf, &self.header.address, header_size);
        }

        self.required_size()
    }
}

/// Raw SCION packet
pub type ScionRawPacket = ScionPacket<Vec<u8>>;
impl ScionRawPacket {
    /// Constructs a [ScionRawPacket] from the given source and destination addresses, path, and
    /// payload.
    ///
    /// Traffic class and flow ID are set to 0, and `next_header` is set according to the provided
    /// protocol.
    pub fn new(
        src: ScionAddr,
        dst: ScionAddr,
        path: DpPath,
        next_header: ProtocolNumber,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header,
                },
                address: AddressHeader::new(src, dst),
                path,
            },
            payload,
        }
    }

    /// Classifies the raw packet by inspecting its `next_header` field and attempting to parse the
    /// payload accordingly.
    ///
    /// Returns [`ClassifiedPacket::Other`] for unknown `next_header` values, otherwise returns
    /// a more specific variant with the parsed payload.
    ///
    /// If the payload cannot be parsed according to the expected protocol for the given
    /// `next_header`, an error is returned.
    ///
    /// This method will truncate any data in the payload that is not part of the parsed message.
    /// Meaning if the payload contains a valid UDP datagram followed by extra bytes, the extra
    /// bytes will be ignored.
    pub fn classify(self) -> Result<ClassifiedPacket, ClassifyError> {
        match self.header.common.next_header {
            ProtocolNumber::Scmp => {
                ScionScmpPacket::try_from_raw(self)
                    .map_err(ClassifyError::MalformedScmp)
                    .map(ClassifiedPacket::Scmp)
            }
            ProtocolNumber::Udp => {
                ScionUdpPacket::try_from_raw(self)
                    .map_err(ClassifyError::MalformedUdp)
                    .map(ClassifiedPacket::Udp)
            }
            _ => Ok(ClassifiedPacket::Other(self.to_owned())),
        }
    }
}
impl Debug for ScionRawPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionPacket")
            .field("header", &self.header)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .finish()
    }
}
impl Model for ScionRawPacket {
    type ViewType = ScionRawPacketView;
}
impl TryFromModel for ScionRawPacketView {
    type ModelType = ScionRawPacket;
}
impl TryFromView for ScionRawPacket {
    type ViewType = ScionPacketView;

    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        ScionRawPacketRef::from_view(view).map(|packet_ref| packet_ref.to_owned())
    }
}
impl_from!(ScionPacket<ScmpMessage>, ScionRawPacket, |scmp_packet| {
    scmp_packet.into_raw()
});
impl_from!(ScionPacket<UdpDatagram>, ScionRawPacket, |udp_packet| {
    udp_packet.into_raw()
});

/// Raw SCION packet with referenced payload
pub type ScionRawPacketRef<'a> = ScionPacket<&'a [u8]>;
impl<'a> ScionPacket<&'a [u8]> {
    /// Constructs a [ScionPacket] from a [ScionHeaderView] and payload slice
    pub fn from_view(view: &'a ScionPacketView) -> Result<Self, ViewConversionError> {
        Ok(Self {
            header: ScionPacketHeader::try_from_view(view.header())?,
            payload: view.payload(),
        })
    }

    /// Parses a [ScionPacket] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ViewConversionError> {
        let payload_size = ScionHeaderView::from_slice(buf)?.0.payload_len();
        let (header, rest) = ScionPacketHeader::try_from_slice(buf)?;
        let (payload, rest) = rest.split_at_checked(payload_size as usize).ok_or(
            ViewConversionError::BufferTooSmall {
                at: "Payload",
                required: payload_size as usize,
                actual: rest.len(),
            },
        )?;

        Ok((ScionPacket { header, payload }, rest))
    }
}
impl Debug for ScionPacket<&[u8]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionRawPacketRef")
            .field("header", &self.header)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .finish()
    }
}

// Methods for all RAW packet types
impl<'a, RawT: PayloadEncode + Deref<Target = [u8]>> ScionPacket<RawT> {
    /// Clones the packet, converting the payload to an owned `Vec<u8>`.
    pub fn to_owned(self) -> ScionRawPacket {
        ScionPacket {
            header: self.header,
            payload: self.payload.to_vec(),
        }
    }

    /// Clones the packet header, keeping the payload as a reference.
    pub fn to_ref(&'a self) -> ScionRawPacketRef<'a> {
        ScionPacket {
            header: self.header.clone(),
            payload: self.payload.deref(),
        }
    }
}

/// SCMP SCION packet
pub type ScionScmpPacket = ScionPacket<ScmpMessage>;
impl ScionScmpPacket {
    /// Constructs a [ScionScmpPacket] from the given source and destination addresses, path, and
    /// payload.
    ///
    /// Traffic class and flow ID are set to 0, and `next_header` is set to the appropriate value
    /// for SCMP.
    pub fn new(src: ScionAddr, dst: ScionAddr, path: DpPath, payload: ScmpMessage) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header: ProtocolNumber::Scmp,
                },
                address: AddressHeader::new(src, dst),
                path,
            },
            payload,
        }
    }

    /// Attempts to construct a `ScionScmpPacket` from a `ScionRawPacket` by parsing the payload as
    /// a SCMP message.
    ///
    /// Ignores the `next_header` field of the packet header.
    ///
    /// Returns an error if the payload cannot be parsed as a valid SCMP message.
    pub fn try_from_raw(packet: ScionRawPacket) -> Result<Self, ViewConversionError> {
        let payload = packet.payload;
        let (scmp_message, _rest) = ScmpMessage::from_slice(&payload)?;
        Ok(Self {
            header: packet.header,
            payload: scmp_message,
        })
    }
}
impl Debug for ScionScmpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionScmpPacket")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
    }
}
impl Model for ScionScmpPacket {
    type ViewType = ScionScmpPacketView;
}
impl TryFromModel for ScionScmpPacketView {
    type ModelType = ScionScmpPacket;
}
impl TryFromView for ScionScmpPacket {
    type ViewType = ScionScmpPacketView;

    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::try_from_view(view.header())?;
        let payload = ScmpMessage::from_view(&view.scmp().message());

        Ok(Self { header, payload })
    }
}
impl TryFrom<ScionRawPacket> for ScionScmpPacket {
    type Error = ViewConversionError;
    fn try_from(raw_packet: ScionRawPacket) -> Result<Self, Self::Error> {
        Self::try_from_raw(raw_packet)
    }
}

/// UDP SCION packet
pub type ScionUdpPacket = ScionPacket<UdpDatagram>;
impl ScionUdpPacket {
    /// Constructs a [ScionUdpPacket] from the given source and destination socket addresses, path,
    /// and payload.
    ///
    /// Traffic class and flow ID are set to 0, and `next_header` is set to the appropriate value
    /// for UDP.
    pub fn new(src: ScionSocketAddr, dst: ScionSocketAddr, path: DpPath, payload: Vec<u8>) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header: ProtocolNumber::Udp,
                },
                address: AddressHeader::new(src.scion_addr(), dst.scion_addr()),
                path,
            },
            payload: UdpDatagram::new(src.port(), dst.port(), payload),
        }
    }

    /// Constructs a [ScionUdpPacket] from the given parts, inferring header fields as needed.
    pub fn new_from_parts(address: AddressHeader, path: DpPath, payload: UdpDatagram) -> Self {
        let header = ScionPacketHeader {
            common: CommonHeader {
                traffic_class: 0,
                flow_id: 0,
                next_header: ProtocolNumber::Udp,
            },
            address,
            path,
        };
        Self { header, payload }
    }

    /// Attempts to construct a `ScionUdpPacket` from a `ScionRawPacket` by parsing the payload as
    /// a UDP datagram. Bytes past the end of the UDP datagram are truncated.
    ///
    /// Ignores the `next_header` field of the packet header.
    ///
    /// Returns an error if the payload cannot be parsed as a valid UDP datagram.
    pub fn try_from_raw(packet: ScionRawPacket) -> Result<Self, ViewConversionError> {
        let payload = packet.payload;
        let (udp_datagram, _rest) = UdpDatagram::from_slice(&payload)?;
        Ok(Self {
            header: packet.header,
            payload: udp_datagram,
        })
    }
}
impl Debug for ScionUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionUdpPacket")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
    }
}
impl Model for ScionUdpPacket {
    type ViewType = ScionUdpPacketView;
}
impl TryFromModel for ScionUdpPacketView {
    type ModelType = ScionUdpPacket;
}
impl TryFromView for ScionUdpPacket {
    type ViewType = ScionUdpPacketView;

    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::try_from_view(view.header())?;
        let payload = UdpDatagram::from_view(view.udp());

        Ok(Self { header, payload })
    }
}
impl TryFrom<ScionRawPacket> for ScionUdpPacket {
    type Error = ViewConversionError;

    fn try_from(packet: ScionRawPacket) -> Result<Self, Self::Error> {
        Self::try_from_raw(packet)
    }
}

impl ScionUdpPacket {
    /// Encodes this packet into a Boxed `ScionUdpPacketView`
    ///
    /// Returns an error if encoding fails, which can occur if the packet structure is invalid.
    pub fn encode_to_udp_view(&self) -> Result<Box<ScionUdpPacketView>, EncodeError> {
        let encoded = self.encode_to_vec()?;
        let view = ScionUdpPacketView::from_boxed(encoded.into())
            .expect("All encodeable packets should be valid views");

        Ok(view)
    }

    /// Returns the source SCION socket address of the packet.
    ///
    /// If a unknown address type is encountered in the source host address, an error is returned.
    pub fn src_socket_addr(&self) -> Result<ScionSocketAddr, UnknownAddressTypeError> {
        let src_port = self.payload.as_ref().src_port;
        let isd_asn = self.header.address.src_ia;
        let scion_addr = self.header.address.src_host_addr.scion_host_addr()?;

        Ok(ScionSocketAddr::new(isd_asn, scion_addr, src_port))
    }

    /// Sets the source SCION socket address of the packet by updating the appropriate fields in the
    /// header and payload.
    pub fn set_src_socket_addr(&mut self, socket_addr: ScionSocketAddr) {
        self.header.address.src_ia = socket_addr.isd_asn();
        self.header.address.src_host_addr = socket_addr.host().into();
        self.payload.as_mut().src_port = socket_addr.port();
    }

    /// Returns the destination SCION socket address of the packet.
    ///
    /// If a unknown address type is encountered in the destination host address, an error is
    /// returned.
    pub fn dst_socket_addr(&self) -> Result<ScionSocketAddr, UnknownAddressTypeError> {
        let dst_port = self.payload.as_ref().dst_port;
        let isd_asn = self.header.address.dst_ia;
        let scion_addr = self.header.address.dst_host_addr.scion_host_addr()?;

        Ok(ScionSocketAddr::new(isd_asn, scion_addr, dst_port))
    }

    /// Sets the destination SCION socket address of the packet by updating the appropriate fields
    /// in the header and payload.
    pub fn set_dst_socket_addr(&mut self, socket_addr: ScionSocketAddr) {
        self.header.address.dst_ia = socket_addr.isd_asn();
        self.header.address.dst_host_addr = socket_addr.host().into();
        self.payload.as_mut().dst_port = socket_addr.port();
    }
}
/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;
    use proptest::collection;

    use super::*;

    /// Configuration for generating arbitrary [`ScionRawPacket`] values.
    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryScionRawPacketParams {
        /// Parameters for generating the SCION packet header.
        pub header: <ScionPacketHeader as Arbitrary>::Parameters,
    }

    impl Arbitrary for ScionRawPacket {
        type Parameters = ArbitraryScionRawPacketParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            (
                ScionPacketHeader::arbitrary_with(params.header),
                collection::vec(any::<u8>(), 0..2048),
            )
                .prop_map(|(header, payload)| ScionPacket { header, payload })
                .boxed()
        }
    }

    /// Configuration for generating arbitrary [`ScionUdpPacket`] values.
    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryScionUdpPacketParams {
        /// Parameters for generating the SCION packet header.
        pub header: <ScionPacketHeader as Arbitrary>::Parameters,
    }

    impl Arbitrary for ScionUdpPacket {
        type Parameters = ArbitraryScionUdpPacketParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            (
                ScionPacketHeader::arbitrary_with(params.header),
                any::<UdpDatagram>(),
            )
                .prop_map(|(mut header, payload)| {
                    header.common.next_header = ProtocolNumber::Udp;
                    ScionPacket { header, payload }
                })
                .boxed()
        }
    }

    /// Configuration for generating arbitrary [`ScionScmpPacket`] values.
    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryScionScmpPacketParams {
        /// Parameters for generating the SCION packet header.
        pub header: <ScionPacketHeader as Arbitrary>::Parameters,
        /// Parameters for generating the SCMP message payload.
        pub scmp_message: <ScmpMessage as Arbitrary>::Parameters,
    }

    impl Arbitrary for ScionScmpPacket {
        type Parameters = ArbitraryScionScmpPacketParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            (
                ScionPacketHeader::arbitrary_with(params.header),
                ScmpMessage::arbitrary_with(params.scmp_message),
            )
                .prop_map(|(mut header, payload)| {
                    header.common.next_header = ProtocolNumber::Scmp;
                    ScionPacket { header, payload }
                })
                .boxed()
        }
    }
}
