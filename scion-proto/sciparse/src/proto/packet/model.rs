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

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        view::{View, ViewConversionError},
    },
    header::{
        model::{AddressHeader, CommonHeader, Path, ScionPacketHeader},
        view::ScionHeaderView,
    },
    packet::view::ScionPacketView,
    payload::{
        ProtocolNumber, encode::PayloadEncode, scmp::model::ScmpMessage, udp::model::UdpDatagram,
    },
};

/// Raw SCION packet
pub type ScionPacketRaw = ScionPacket<Vec<u8>>;
/// Raw SCION packet with referenced payload
pub type ScionPacketRawRef<'a> = ScionPacket<&'a [u8]>;
/// UDP SCION packet
pub type ScionPacketUdp = ScionPacket<UdpDatagram>;
/// SCMP SCION packet
pub type ScionPacketScmp = ScionPacket<ScmpMessage>;
/// SCMP SCION packet with referenced payload
pub type ScionPacketScmpRef<'a> = ScionPacket<&'a ScmpMessage>;

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

impl<'a> ScionPacket<&'a [u8]> {
    /// Constructs a `ScionPacket` from a `ScionHeaderView` and payload slice
    pub fn from_view(view: &'a ScionPacketView) -> Self {
        Self {
            header: ScionPacketHeader::from_view(view.header()),
            payload: view.payload(),
        }
    }

    /// Attempts to construct a `ScionPacket` from a byte slice
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
impl<'a> ScionPacket<&'a ScmpMessage> {
    /// Constructs a `ScionPacket` from the given parts, inferring header fields as needed.
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
