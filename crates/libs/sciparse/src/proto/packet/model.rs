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

use std::fmt::Debug;

use crate::{
    address::{addr::ScionAddr, host_addr::UnknownAddressTypeError, socket_addr::ScionSocketAddr},
    core::{
        convert::{TryFromModel, TryFromView},
        encode::{InvalidStructureError, WireEncode},
        macros::impl_from,
        model::Model,
        view::ViewConversionError,
    },
    dataplane_path::{model::DpPath, view::ScionDpPathViewRef},
    header::model::{AddressHeader, CommonHeader, ScionPacketHeader, ScionPacketHeaderRef},
    packet::{
        classify::{ClassifiedPacket, ClassifyError},
        view::{ScionPacketView, ScionRawPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
    payload::{
        ProtocolNumber,
        encode::PayloadEncode,
        scmp::model::ScmpMessage,
        udp::model::{UdpDatagram, UdpDatagramRef},
    },
};

/// A Complete SCION Packet
#[derive(Clone, PartialEq, Eq, Hash)]
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
    #[inline]
    pub fn into_raw(self) -> ScionRawPacket {
        let header_size = self.header.required_size();
        let payload_size = self.payload.required_size(header_size);
        let mut buf = vec![0u8; payload_size];
        let size = self
            .payload
            .try_encode(&mut buf[..], &self.header.address, header_size)
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
}
impl<T: PayloadEncode> ScionPacketExt for ScionPacket<T> {
    #[inline]
    fn address_header(&self) -> &AddressHeader {
        &self.header.address
    }
}
impl<T: PayloadEncode> ScionPacketExtMut for ScionPacket<T> {
    #[inline]
    fn address_header_mut(&mut self) -> &mut AddressHeader {
        &mut self.header.address
    }
}
impl<T: PayloadEncode> WireEncode for ScionPacket<T> {
    #[inline]
    fn required_size(&self) -> usize {
        self.header.required_size() + self.payload.required_size(self.header.required_size())
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.header.wire_valid()?;
        self.payload.wire_valid()?;
        validate_payload_size(self.payload.required_size(self.header.required_size()))
    }

    #[inline]
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

/// A SCION packet that borrows its path and its payload.
///
/// Use it to encode a packet without a [`DpPath`] model and without a copy of the payload.
#[derive(Clone, PartialEq, Eq)]
pub struct ScionPacketRef<'a, T: PayloadEncode> {
    /// SCION Packet Header
    pub header: ScionPacketHeaderRef<'a>,
    /// Payload
    pub payload: T,
}
impl<'a, T: PayloadEncode> ScionPacketRef<'a, T> {
    #[inline]
    fn from_parts(
        next_header: ProtocolNumber,
        address: AddressHeader,
        path: ScionDpPathViewRef<'a>,
        payload: T,
    ) -> Self {
        let header = ScionPacketHeaderRef {
            common: CommonHeader {
                traffic_class: 0,
                flow_id: 0,
                next_header,
            },
            address,
            path,
        };

        Self { header, payload }
    }
}
impl<T: PayloadEncode> ScionPacketExt for ScionPacketRef<'_, T> {
    #[inline]
    fn address_header(&self) -> &AddressHeader {
        &self.header.address
    }
}
impl<T: PayloadEncode> WireEncode for ScionPacketRef<'_, T> {
    #[inline]
    fn required_size(&self) -> usize {
        let header_size = self.header.required_size();
        header_size + self.payload.required_size(header_size)
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.header.wire_valid()?;
        self.payload.wire_valid()?;
        validate_payload_size(self.payload.required_size(self.header.required_size()))
    }

    #[inline]
    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        // Sizes
        let header_size = self.header.required_size();
        let payload_size = self.payload.required_size(header_size);

        unsafe {
            // Header
            let header_buf = buf.get_unchecked_mut(0..header_size);
            self.header
                .encode_unchecked(header_buf, payload_size as u16);

            // Payload
            let payload_buf = buf.get_unchecked_mut(header_size..(header_size + payload_size));
            self.payload
                .encode_unchecked(payload_buf, &self.header.address, header_size);
        }

        header_size + payload_size
    }
}

/// Read access to a SCION packet.
pub trait ScionPacketExt {
    /// Returns the address header of the packet.
    fn address_header(&self) -> &AddressHeader;

    /// Returns the source SCION address of the packet, see [`AddressHeader::src_scion_addr`].
    #[inline]
    fn src_scion_addr(&self) -> Result<ScionAddr, UnknownAddressTypeError> {
        self.address_header().src_scion_addr()
    }

    /// Returns the destination SCION address of the packet, see
    /// [`AddressHeader::dst_scion_addr`].
    #[inline]
    fn dst_scion_addr(&self) -> Result<ScionAddr, UnknownAddressTypeError> {
        self.address_header().dst_scion_addr()
    }
}
/// Write access to a SCION packet.
pub trait ScionPacketExtMut: ScionPacketExt {
    /// Returns the address header of the packet for changes.
    fn address_header_mut(&mut self) -> &mut AddressHeader;

    /// Sets the source SCION address in the address header.
    #[inline]
    fn set_src_scion_addr(&mut self, addr: ScionAddr) {
        self.address_header_mut().set_src_scion_addr(addr);
    }

    /// Sets the destination SCION address in the address header.
    #[inline]
    fn set_dst_scion_addr(&mut self, addr: ScionAddr) {
        self.address_header_mut().set_dst_scion_addr(addr);
    }
}

/// Checks that the payload size fits into the 16-bit payload length field of the common header.
#[inline]
fn validate_payload_size(payload_size: usize) -> Result<(), InvalidStructureError> {
    if payload_size > usize::from(u16::MAX) {
        return Err("payload size exceeds maximum encodable value of 65535 bytes".into());
    }

    Ok(())
}

/// Raw SCION packet
pub type ScionRawPacket = ScionPacket<Vec<u8>>;
impl ScionRawPacket {
    /// Constructs a [ScionRawPacket] from the given source and destination addresses, path, and
    /// payload.
    ///
    /// Traffic class and flow ID are set to 0, and `next_header` is set according to the provided
    /// protocol.
    #[inline]
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
    #[inline]
    pub fn try_classify(self) -> Result<ClassifiedPacket, ClassifyError> {
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
            _ => Ok(ClassifiedPacket::Other(self)),
        }
    }

    /// Attempts to convert this raw packet into a SCMP packet by parsing the payload as a SCMP
    /// message.
    #[inline]
    pub fn try_into_scmp(self) -> Result<ScionScmpPacket, ViewConversionError> {
        ScionScmpPacket::try_from_raw(self)
    }

    /// Attempts to convert this raw packet into a UDP packet by parsing the payload as a UDP
    /// datagram.
    #[inline]
    pub fn try_into_udp(self) -> Result<ScionUdpPacket, ViewConversionError> {
        ScionUdpPacket::try_from_raw(self)
    }
}
impl Debug for ScionRawPacket {
    #[inline]
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

    #[inline]
    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::try_from_view(view.header())?;
        let payload = view.payload().to_vec();

        Ok(Self { header, payload })
    }
}
impl_from!(ScionPacket<ScmpMessage>, ScionRawPacket, |scmp_packet| {
    scmp_packet.into_raw()
});
impl_from!(ScionPacket<UdpDatagram>, ScionRawPacket, |udp_packet| {
    udp_packet.into_raw()
});

/// Raw SCION packet that borrows its path and its payload.
pub type ScionRawPacketRef<'a> = ScionPacketRef<'a, &'a [u8]>;
impl<'a> ScionRawPacketRef<'a> {
    /// Constructs a [ScionRawPacketRef] from the given source and destination addresses, path,
    /// and payload.
    ///
    /// `next_header` is the given protocol.
    #[inline]
    pub fn new(
        src: ScionAddr,
        dst: ScionAddr,
        path: ScionDpPathViewRef<'a>,
        next_header: ProtocolNumber,
        payload: &'a [u8],
    ) -> Self {
        let address = AddressHeader::new(src, dst);
        Self::from_parts(next_header, address, path, payload)
    }
}
impl Model for ScionRawPacketRef<'_> {
    type ViewType = ScionRawPacketView;
}
impl Debug for ScionRawPacketRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionRawPacketRef")
            .field("header", &self.header)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .finish()
    }
}

/// SCMP SCION packet
pub type ScionScmpPacket = ScionPacket<ScmpMessage>;
impl ScionScmpPacket {
    /// Constructs a [ScionScmpPacket]
    #[inline]
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
    /// Returns an error if the payload cannot be parsed as a valid SCMP message or if the
    /// `next_header` field is not set to the appropriate value for SCMP.
    #[inline]
    pub fn try_from_raw(packet: ScionRawPacket) -> Result<Self, ViewConversionError> {
        if packet.header.common.next_header != ProtocolNumber::Scmp {
            return Err(ViewConversionError::Other("next header not SCMP"));
        }

        let payload = packet.payload;
        let (scmp_message, _rest) = ScmpMessage::try_from_slice(&payload)?;
        Ok(Self {
            header: packet.header,
            payload: scmp_message,
        })
    }
}
impl Debug for ScionScmpPacket {
    #[inline]
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

    #[inline]
    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::try_from_view(view.header())?;
        let payload = ScmpMessage::from_view(&view.scmp().message());

        Ok(Self { header, payload })
    }
}
impl TryFrom<ScionRawPacket> for ScionScmpPacket {
    type Error = ViewConversionError;
    #[inline]
    fn try_from(raw_packet: ScionRawPacket) -> Result<Self, Self::Error> {
        Self::try_from_raw(raw_packet)
    }
}

/// SCMP SCION packet that borrows its path and its payload.
pub type ScionScmpPacketRef<'a> = ScionPacketRef<'a, &'a ScmpMessage>;
impl<'a> ScionScmpPacketRef<'a> {
    /// Constructs a [ScionScmpPacketRef]
    #[inline]
    pub fn new(
        src: ScionAddr,
        dst: ScionAddr,
        path: ScionDpPathViewRef<'a>,
        payload: &'a ScmpMessage,
    ) -> Self {
        let address = AddressHeader::new(src, dst);
        Self::from_parts(ProtocolNumber::Scmp, address, path, payload)
    }
}
impl Model for ScionScmpPacketRef<'_> {
    type ViewType = ScionScmpPacketView;
}
impl Debug for ScionScmpPacketRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionScmpPacketRef")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
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
    #[inline]
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
    #[inline]
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
    /// Returns an error if the payload cannot be parsed as a valid UDP datagram or if the
    /// `next_header` field is not set to the appropriate value for UDP.
    #[inline]
    pub fn try_from_raw(packet: ScionRawPacket) -> Result<Self, ViewConversionError> {
        if packet.header.common.next_header != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        let payload = packet.payload;
        let (udp_datagram, _rest) = UdpDatagram::try_from_slice(&payload)?;
        Ok(Self {
            header: packet.header,
            payload: udp_datagram,
        })
    }
}
impl Debug for ScionUdpPacket {
    #[inline]
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

    #[inline]
    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::try_from_view(view.header())?;
        let payload = UdpDatagram::from_view(view.udp());

        Ok(Self { header, payload })
    }
}
impl TryFrom<ScionRawPacket> for ScionUdpPacket {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(packet: ScionRawPacket) -> Result<Self, Self::Error> {
        Self::try_from_raw(packet)
    }
}
impl ScionUdpPacketExt for ScionUdpPacket {
    #[inline]
    fn udp_datagram(&self) -> UdpDatagramRef<'_> {
        self.payload.to_ref()
    }
}
impl ScionUdpPacketExtMut for ScionUdpPacket {
    #[inline]
    fn udp_datagram_mut(&mut self) -> &mut UdpDatagram {
        &mut self.payload
    }
}

/// UDP SCION packet that borrows its path and its payload.
pub type ScionUdpPacketRef<'a> = ScionPacketRef<'a, UdpDatagramRef<'a>>;
impl<'a> ScionUdpPacketRef<'a> {
    /// Constructs a [ScionUdpPacketRef] from the given source and destination socket addresses,
    /// path, and payload.
    ///
    /// `next_header` is UDP.
    #[inline]
    pub fn new(
        src: ScionSocketAddr,
        dst: ScionSocketAddr,
        path: ScionDpPathViewRef<'a>,
        payload: &'a [u8],
    ) -> Self {
        let address = AddressHeader::new(src.scion_addr(), dst.scion_addr());
        let datagram = UdpDatagramRef {
            src_port: src.port(),
            dst_port: dst.port(),
            payload,
        };

        Self::from_parts(ProtocolNumber::Udp, address, path, datagram)
    }
}
impl Model for ScionUdpPacketRef<'_> {
    type ViewType = ScionUdpPacketView;
}
impl Debug for ScionUdpPacketRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionUdpPacketRef")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
    }
}
impl ScionUdpPacketExt for ScionUdpPacketRef<'_> {
    #[inline]
    fn udp_datagram(&self) -> UdpDatagramRef<'_> {
        self.payload
    }
}

/// Read access to a SCION UDP packet.
pub trait ScionUdpPacketExt: ScionPacketExt {
    /// Returns the UDP datagram of the packet.
    fn udp_datagram(&self) -> UdpDatagramRef<'_>;

    /// Returns the source SCION socket address of the packet, see
    /// [`AddressHeader::src_scion_addr`].
    #[inline]
    fn src_socket_addr(&self) -> Result<ScionSocketAddr, UnknownAddressTypeError> {
        let addr = self.address_header().src_scion_addr()?;
        Ok(ScionSocketAddr::from_scion_addr(
            addr,
            self.udp_datagram().src_port,
        ))
    }

    /// Returns the destination SCION socket address of the packet, see
    /// [`AddressHeader::dst_scion_addr`].
    #[inline]
    fn dst_socket_addr(&self) -> Result<ScionSocketAddr, UnknownAddressTypeError> {
        let addr = self.address_header().dst_scion_addr()?;
        Ok(ScionSocketAddr::from_scion_addr(
            addr,
            self.udp_datagram().dst_port,
        ))
    }
}
/// Write access to a SCION UDP packet.
pub trait ScionUdpPacketExtMut: ScionUdpPacketExt + ScionPacketExtMut {
    /// Returns the UDP datagram of the packet for changes.
    fn udp_datagram_mut(&mut self) -> &mut UdpDatagram;

    /// Sets the source SCION socket address in the address header and the UDP header.
    #[inline]
    fn set_src_socket_addr(&mut self, socket_addr: ScionSocketAddr) {
        self.set_src_scion_addr(socket_addr.scion_addr());
        self.udp_datagram_mut().src_port = socket_addr.port();
    }

    /// Sets the destination SCION socket address in the address header and the UDP header.
    #[inline]
    fn set_dst_socket_addr(&mut self, socket_addr: ScionSocketAddr) {
        self.set_dst_scion_addr(socket_addr.scion_addr());
        self.udp_datagram_mut().dst_port = socket_addr.port();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::host_addr::{WireHostAddr, WireHostAddrType},
        core::encode::EncodeError,
        dataplane_path::types::PathType,
        payload::scmp::model::ScmpEchoRequest,
    };

    fn src() -> ScionSocketAddr {
        "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap()
    }

    fn dst() -> ScionSocketAddr {
        "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap()
    }

    mod udp_packet_ref_new {
        use super::*;

        #[test]
        fn should_set_next_header_to_udp_and_take_the_ports_from_the_socket_addresses() {
            let packet = ScionUdpPacketRef::new(src(), dst(), ScionDpPathViewRef::Empty, b"data");

            assert_eq!(packet.header.common.next_header, ProtocolNumber::Udp);
            assert_eq!(packet.payload.src_port, src().port());
            assert_eq!(packet.payload.dst_port, dst().port());
        }
    }

    mod scmp_packet_ref_new {
        use super::*;

        #[test]
        fn should_set_next_header_to_scmp() {
            let message = ScmpMessage::from(ScmpEchoRequest::new(1, 2, b"ping".to_vec()));
            let packet = ScionScmpPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                ScionDpPathViewRef::Empty,
                &message,
            );

            assert_eq!(packet.header.common.next_header, ProtocolNumber::Scmp);
        }
    }

    mod raw_packet_ref_new {
        use super::*;

        #[test]
        fn should_keep_the_given_next_header() {
            let packet = ScionRawPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                ScionDpPathViewRef::Empty,
                ProtocolNumber::Other(99),
                b"data",
            );

            assert_eq!(packet.header.common.next_header, ProtocolNumber::Other(99));
        }
    }

    mod try_encode {
        use super::*;

        #[test]
        fn should_return_buffer_too_small_and_leave_the_buffer_untouched_if_it_is_one_byte_short() {
            let packet = ScionUdpPacketRef::new(src(), dst(), ScionDpPathViewRef::Empty, b"data");
            let required = packet.required_size();
            let mut buf = vec![0xAAu8; required - 1];

            let result = packet.try_encode(&mut buf);

            assert_eq!(result, Err(EncodeError::BufferTooSmall(required)));
            assert!(buf.iter().all(|byte| *byte == 0xAA));
        }

        #[test]
        fn should_return_invalid_structure_and_leave_the_buffer_untouched_if_the_header_exceeds_1020_bytes()
         {
            // 12 bytes common header, 24 bytes address header with IPv4 hosts, and 988 bytes path
            // give a header of 1024 bytes.
            let path_data = [0u8; 988];
            let path = ScionDpPathViewRef::Unsupported {
                path_type: PathType::Other(9),
                data: &path_data,
            };
            let packet = ScionRawPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                path,
                ProtocolNumber::Other(99),
                b"data",
            );
            let mut buf = vec![0xAAu8; packet.required_size()];

            let result = packet.try_encode(&mut buf);

            assert!(matches!(result, Err(EncodeError::InvalidStructure(_))));
            assert!(buf.iter().all(|byte| *byte == 0xAA));
        }

        #[test]
        fn should_encode_a_header_of_exactly_1020_bytes() {
            // 12 bytes common header, 24 bytes address header with IPv4 hosts, and 984 bytes path
            // give a header of 1020 bytes.
            let path_data = [0u8; 984];
            let path = ScionDpPathViewRef::Unsupported {
                path_type: PathType::Other(9),
                data: &path_data,
            };
            let packet = ScionRawPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                path,
                ProtocolNumber::Other(99),
                b"data",
            );
            let mut buf = vec![0u8; packet.required_size()];

            let written = packet.try_encode(&mut buf);

            assert_eq!(written, Ok(1020 + 4));
        }

        #[test]
        fn should_encode_a_payload_of_exactly_65535_bytes() {
            let payload = vec![0u8; usize::from(u16::MAX)];
            let packet = ScionRawPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                ScionDpPathViewRef::Empty,
                ProtocolNumber::Other(99),
                &payload,
            );
            let owned = ScionRawPacket::new(
                src().scion_addr(),
                dst().scion_addr(),
                DpPath::Empty,
                ProtocolNumber::Other(99),
                payload.clone(),
            );

            let mut buf = vec![0u8; packet.required_size()];

            assert_eq!(packet.try_encode(&mut buf), Ok(buf.len()));
            assert!(owned.try_encode_to_vec().is_ok());
        }

        #[test]
        fn should_return_invalid_structure_if_the_payload_exceeds_65535_bytes() {
            let payload = vec![0u8; usize::from(u16::MAX) + 1];
            let packet = ScionRawPacketRef::new(
                src().scion_addr(),
                dst().scion_addr(),
                ScionDpPathViewRef::Empty,
                ProtocolNumber::Other(99),
                &payload,
            );
            let owned = ScionRawPacket::new(
                src().scion_addr(),
                dst().scion_addr(),
                DpPath::Empty,
                ProtocolNumber::Other(99),
                payload.clone(),
            );
            let mut buf = vec![0u8; packet.required_size()];

            assert!(matches!(
                packet.try_encode(&mut buf),
                Err(EncodeError::InvalidStructure(_))
            ));
            assert!(owned.wire_valid().is_err());
        }
    }

    mod try_classify {
        use super::*;

        #[test]
        fn should_return_udp_for_a_raw_packet_with_next_header_udp() {
            let udp = ScionUdpPacket::new(src(), dst(), DpPath::Empty, b"data".to_vec());
            let raw = udp.clone().into_raw();

            let classified = raw.try_classify().unwrap();

            assert_eq!(classified, ClassifiedPacket::Udp(udp));
        }

        #[test]
        fn should_return_other_with_the_same_packet_for_an_unknown_next_header() {
            let raw = ScionRawPacket::new(
                src().scion_addr(),
                dst().scion_addr(),
                DpPath::Empty,
                ProtocolNumber::Other(99),
                b"data".to_vec(),
            );

            let classified = raw.clone().try_classify().unwrap();

            assert_eq!(classified, ClassifiedPacket::Other(raw));
        }
    }

    mod try_encode_to_view {
        use super::*;

        #[test]
        fn should_return_a_typed_view_over_the_written_bytes() {
            let packet = ScionUdpPacketRef::new(src(), dst(), ScionDpPathViewRef::Empty, b"data");
            let mut buf = vec![0u8; packet.required_size()];

            let (view, rest) = packet.try_encode_to_view(&mut buf).unwrap();

            assert!(rest.is_empty());
            assert_eq!(view.header().next_header(), ProtocolNumber::Udp);
            assert_eq!(view.udp().src_port(), src().port());
            assert_eq!(view.udp().dst_port(), dst().port());
            assert_eq!(view.udp().payload(), b"data");
        }
    }

    mod address_traits {
        use super::*;

        #[test]
        fn should_read_the_addresses_from_the_address_header_and_the_ports_from_the_datagram() {
            let owned = ScionUdpPacket::new(src(), dst(), DpPath::Empty, b"data".to_vec());
            let borrowed = ScionUdpPacketRef::new(src(), dst(), ScionDpPathViewRef::Empty, b"data");

            assert_eq!(owned.src_scion_addr().unwrap(), src().scion_addr());
            assert_eq!(owned.dst_scion_addr().unwrap(), dst().scion_addr());
            assert_eq!(owned.src_socket_addr().unwrap(), src());
            assert_eq!(owned.dst_socket_addr().unwrap(), dst());
            assert_eq!(borrowed.src_socket_addr().unwrap(), src());
            assert_eq!(borrowed.dst_socket_addr().unwrap(), dst());
        }

        #[test]
        fn should_return_unknown_address_type_error_for_a_host_address_of_unknown_type() {
            let unknown = WireHostAddr::try_from_parts(
                WireHostAddrType::Unknown { id: 1, size: 4 },
                &[1, 2, 3, 4],
            )
            .unwrap();
            let mut packet = ScionUdpPacket::new(src(), dst(), DpPath::Empty, b"data".to_vec());
            packet.header.address.src_host_addr = unknown.clone();
            packet.header.address.dst_host_addr = unknown;

            assert!(packet.src_scion_addr().is_err());
            assert!(packet.dst_scion_addr().is_err());
            assert!(packet.src_socket_addr().is_err());
            assert!(packet.dst_socket_addr().is_err());
        }

        #[test]
        fn should_change_the_addresses_and_the_ports_with_the_setters() {
            let mut packet = ScionUdpPacket::new(src(), dst(), DpPath::Empty, b"data".to_vec());

            packet.set_src_socket_addr(dst());
            packet.set_dst_socket_addr(src());

            assert_eq!(packet.src_socket_addr().unwrap(), dst());
            assert_eq!(packet.dst_socket_addr().unwrap(), src());

            packet.set_src_scion_addr(src().scion_addr());
            packet.set_dst_scion_addr(dst().scion_addr());

            assert_eq!(packet.src_scion_addr().unwrap(), src().scion_addr());
            assert_eq!(packet.dst_scion_addr().unwrap(), dst().scion_addr());
            assert_eq!(packet.udp_datagram().src_port, dst().port());
        }
    }
}
