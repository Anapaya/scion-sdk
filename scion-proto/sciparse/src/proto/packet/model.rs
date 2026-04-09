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

use std::ops::Deref;

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        view::{View, ViewConversionError},
    },
    header::{
        model::{AddressHeader, CommonHeader, Path, ScionPacketHeader},
        view::ScionHeaderView,
    },
    packet::{
        classify::{ClassifiedPacket, ClassifyError},
        view::{ScionPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
    payload::{
        ProtocolNumber, encode::PayloadEncode, scmp::model::ScmpMessage, udp::model::UdpDatagram,
    },
};

/// A Complete SCION Packet
pub struct ScionPacket<T: PayloadEncode> {
    /// SCION Packet Header
    pub header: ScionPacketHeader,
    /// Payload
    pub payload: T,
}
impl<T: PayloadEncode> ScionPacket<T> {
    /// Constructs a `ScionPacket` from a `ScionPacketHeader` and a payload
    pub fn new(header: ScionPacketHeader, payload: T) -> Self {
        Self { header, payload }
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
pub type ScionPacketRaw = ScionPacket<Vec<u8>>;
impl ScionPacketRaw {
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
                let (payload, _rest) = ScmpMessage::from_slice(self.payload.deref())
                    .map_err(ClassifyError::MalformedScmp)?;

                Ok(ClassifiedPacket::Scmp(ScionPacketScmp {
                    header: self.header,
                    payload,
                }))
            }
            ProtocolNumber::Udp => {
                let (payload, _rest) = UdpDatagram::from_slice(self.payload.deref())
                    .map_err(ClassifyError::MalformedUdp)?;

                Ok(ClassifiedPacket::Udp(ScionPacketUdp {
                    header: self.header,
                    payload,
                }))
            }
            _ => Ok(ClassifiedPacket::Other(self.to_owned())),
        }
    }

    /// Constructs a [ScionPacket] from a [ScionHeaderView]
    pub fn from_view(view: &ScionPacketView) -> Result<Self, ViewConversionError> {
        ScionPacketRawRef::from_view(view).map(|packet_ref| packet_ref.to_owned())
    }

    /// Parses a [ScionPacket] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        ScionPacketRawRef::from_slice(buf).map(|(packet_ref, rest)| (packet_ref.to_owned(), rest))
    }
}

/// Raw SCION packet with referenced payload
pub type ScionPacketRawRef<'a> = ScionPacket<&'a [u8]>;
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

// Methods for all RAW packet types
impl<'a, BytePayload: PayloadEncode + Deref<Target = [u8]>> ScionPacket<BytePayload> {
    /// Clones the packet, converting the payload to an owned `Vec<u8>`.
    pub fn to_owned(self) -> ScionPacketRaw {
        ScionPacket {
            header: self.header,
            payload: self.payload.to_vec(),
        }
    }

    /// Clones the packet header, keeping the payload as a reference.
    pub fn to_ref(&'a self) -> ScionPacketRawRef<'a> {
        ScionPacket {
            header: self.header.clone(),
            payload: self.payload.deref(),
        }
    }
}

/// SCMP SCION packet
pub type ScionPacketScmp = ScionPacket<ScmpMessage>;
impl ScionPacketScmp {
    /// Parses a `ScionPacketScmp` from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (packet_ref, rest) = ScionScmpPacketView::from_slice(buf)?;
        let packet = Self::from_view(packet_ref)?;
        Ok((packet, rest))
    }

    /// Constructs a `ScionPacketScmp` from a `ScionScmpPacketView`
    pub fn from_view(view: &ScionScmpPacketView) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::from_view(view.header())?;
        let payload = ScmpMessage::from_view(&view.scmp().message());

        Ok(Self { header, payload })
    }
}

/// SCMP SCION packet with referenced payload
pub type ScionPacketScmpRef<'a> = ScionPacket<&'a ScmpMessage>;
impl<'a> ScionPacket<&'a ScmpMessage> {
    /// Constructs a [ScionPacketScmpRef] from the given parts, inferring header fields as needed.
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

/// UDP SCION packet
pub type ScionPacketUdp = ScionPacket<UdpDatagram>;
impl ScionPacketUdp {
    /// Constructs a [ScionPacketUdp] from the given parts, inferring header fields as needed.
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

    /// Parses a [ScionPacketUdp] from a byte slice, returning the packet and any remaining bytes.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (packet_ref, rest) = ScionUdpPacketView::from_slice(buf)?;
        let packet = Self::from_view(packet_ref)?;
        Ok((packet, rest))
    }

    /// Constructs a [ScionPacketUdp] from a [ScionUdpPacketView]
    pub fn from_view(view: &ScionUdpPacketView) -> Result<Self, ViewConversionError> {
        let header = ScionPacketHeader::from_view(view.header())?;
        let payload = UdpDatagram::from_view(view.udp());

        Ok(Self { header, payload })
    }
}
