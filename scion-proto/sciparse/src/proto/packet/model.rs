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
    address::{addr::ScionAddr, socket_addr::ScionSocketAddr},
    core::{
        encode::{EncodeError, InvalidStructureError, WireEncode},
        view::{View, ViewConversionError},
    },
    header::{
        model::{AddressHeader, CommonHeader, ScionPacketHeader},
        view::ScionHeaderView,
    },
    packet::{
        classify::{ClassifiedPacket, ClassifyError},
        view::{ScionPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
    path::model::Path,
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
impl<T: PayloadEncode> ScionPacket<T> {
    /// Converts this packet into a raw packet with an owned `Vec<u8>` payload by encoding the
    /// payload
    pub fn into_raw(self) -> Result<ScionRawPacket, EncodeError> {
        let header_size = self.header.required_size();
        let payload_size = self.payload.required_size(header_size);
        let mut buf = vec![0u8; payload_size];
        let size = self
            .payload
            .encode(&mut buf[..], &self.header.address, header_size)?;

        debug_assert_eq!(
            size, payload_size,
            "Encoded payload size does not match expected size"
        );

        Ok(ScionPacket {
            header: self.header,
            payload: buf,
        })
    }
}
impl Debug for ScionPacket<Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionPacket")
            .field("header", &self.header)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .finish()
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
        path: Path,
        next_header: ProtocolNumber,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header: next_header.into(),
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
        match self.header.common.next_header.into() {
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

    /// Constructs a [ScionPacket] from a [ScionHeaderView]
    pub fn from_view(view: &ScionPacketView) -> Result<Self, ViewConversionError> {
        ScionRawPacketRef::from_view(view).map(|packet_ref| packet_ref.to_owned())
    }

    /// Parses a [ScionPacket] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        ScionRawPacketRef::from_slice(buf).map(|(packet_ref, rest)| (packet_ref.to_owned(), rest))
    }
}
impl TryFrom<&ScionPacketView> for ScionRawPacket {
    type Error = ViewConversionError;

    fn try_from(view: &ScionPacketView) -> Result<Self, Self::Error> {
        Self::from_view(view)
    }
}

/// Raw SCION packet with referenced payload
pub type ScionRawPacketRef<'a> = ScionPacket<&'a [u8]>;
impl<'a> ScionPacket<&'a [u8]> {
    /// Constructs a [ScionPacket] from a [ScionHeaderView] and payload slice
    pub fn from_view(view: &'a ScionPacketView) -> Result<Self, ViewConversionError> {
        Ok(Self {
            header: ScionPacketHeader::from_view(view.header())?,
            payload: view.payload(),
        })
    }

    /// Parses a [ScionPacket] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ViewConversionError> {
        let payload_size = ScionHeaderView::from_slice(buf)?.0.payload_len();
        let (header, rest) = ScionPacketHeader::from_slice(buf)?;
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
impl<'a, BytePayload: PayloadEncode + Deref<Target = [u8]>> ScionPacket<BytePayload> {
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
    pub fn new(src: ScionAddr, dst: ScionAddr, path: Path, payload: ScmpMessage) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header: ProtocolNumber::Scmp.into(),
                },
                address: AddressHeader::new(src, dst),
                path,
            },
            payload,
        }
    }

    /// Parses a `ScionScmpPacket` from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (packet_ref, rest) = ScionScmpPacketView::from_slice(buf)?;
        let packet = Self::from_view(packet_ref)?;
        Ok((packet, rest))
    }

    /// Constructs a `ScionScmpPacket` from a `ScionScmpPacketView`
    pub fn from_view(view: &ScionScmpPacketView) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::from_view(view.header())?;
        let payload = ScmpMessage::from_view(&view.scmp().message());

        Ok(Self { header, payload })
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
impl TryFrom<&ScionScmpPacketView> for ScionScmpPacket {
    type Error = ViewConversionError;

    fn try_from(view: &ScionScmpPacketView) -> Result<Self, Self::Error> {
        Self::from_view(view)
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

/// SCMP SCION packet with referenced payload
pub type ScionScmpPacketRef<'a> = ScionPacket<&'a ScmpMessage>;
impl<'a> ScionPacket<&'a ScmpMessage> {
    /// Constructs a [ScionScmpPacketRef] from the given parts, inferring header fields as needed.
    pub fn new_from_parts(address: AddressHeader, path: Path, payload: &'a ScmpMessage) -> Self {
        let header = ScionPacketHeader {
            common: CommonHeader {
                traffic_class: 0,
                flow_id: 0,
                next_header: ProtocolNumber::Scmp.into(),
            },
            address,
            path,
        };
        Self { header, payload }
    }
}
impl Debug for ScionScmpPacketRef<'_> {
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
    pub fn new(src: ScionSocketAddr, dst: ScionSocketAddr, path: Path, payload: Vec<u8>) -> Self {
        Self {
            header: ScionPacketHeader {
                common: CommonHeader {
                    traffic_class: 0,
                    flow_id: 0,
                    next_header: ProtocolNumber::Udp.into(),
                },
                address: AddressHeader::new(src.scion_addr(), dst.scion_addr()),
                path,
            },
            payload: UdpDatagram::new(src.port(), dst.port(), payload),
        }
    }

    /// Constructs a [ScionUdpPacket] from the given parts, inferring header fields as needed.
    pub fn new_from_parts(address: AddressHeader, path: Path, payload: UdpDatagram) -> Self {
        let header = ScionPacketHeader {
            common: CommonHeader {
                traffic_class: 0,
                flow_id: 0,
                next_header: ProtocolNumber::Udp.into(),
            },
            address,
            path,
        };
        Self { header, payload }
    }

    /// Parses a [ScionUdpPacket] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (packet_ref, rest) = ScionUdpPacketView::from_slice(buf)?;
        let packet = Self::from_view(packet_ref)?;
        Ok((packet, rest))
    }

    /// Constructs a [ScionUdpPacket] from a [ScionUdpPacketView]
    pub fn from_view(view: &ScionUdpPacketView) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::from_view(view.header())?;
        let payload = UdpDatagram::from_view(view.udp());

        Ok(Self { header, payload })
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
impl TryFrom<&ScionUdpPacketView> for ScionUdpPacket {
    type Error = ViewConversionError;

    fn try_from(view: &ScionUdpPacketView) -> Result<Self, Self::Error> {
        Self::from_view(view)
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
                    header.common.next_header = ProtocolNumber::Udp.into();
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
                    header.common.next_header = ProtocolNumber::Scmp.into();
                    ScionPacket { header, payload }
                })
                .boxed()
        }
    }
}
