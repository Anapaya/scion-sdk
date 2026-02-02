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
        view::ViewConversionError,
    },
    header::model::ScionPacketHeader,
    packet::view::ScionPacketView,
};

/// A Complete SCION Packet
pub struct ScionPacket {
    /// SCION Packet Header
    pub header: ScionPacketHeader,
    /// Payload
    pub payload: Vec<u8>,
}
impl ScionPacket {
    /// Constructs a `ScionPacket` from a `ScionHeaderView` and payload slice
    pub fn from_view(view: &ScionPacketView) -> Self {
        ScionPacket {
            header: ScionPacketHeader::from_view(view.header()),
            payload: view.payload().to_vec(),
        }
    }

    /// Attempts to construct a `ScionPacket` from a byte slice
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (header, rest) = ScionPacketHeader::from_slice(buf)?;
        let (payload, rest) = rest
            .split_at_checked(header.common.payload_size as usize)
            .ok_or(ViewConversionError::BufferTooSmall {
                at: "Payload",
                required: header.common.payload_size as usize,
                actual: rest.len(),
            })?;

        Ok((
            ScionPacket {
                header,
                payload: payload.to_vec(),
            },
            rest,
        ))
    }
}
impl WireEncode for ScionPacket {
    fn required_size(&self) -> usize {
        self.header.required_size() + self.payload.len()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.header.wire_valid()?;

        if self.payload.len() != self.header.common.payload_size as usize {
            return Err("Payload size does not match header's payload_size field".into());
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        let header_size = self.header.required_size();

        unsafe {
            // Encode header
            {
                let header_buf = buf.get_unchecked_mut(0..header_size);
                self.header.encode_unchecked(header_buf);
            }
            // Encode payload
            buf.get_unchecked_mut(header_size..(header_size + self.payload.len()))
                .copy_from_slice(&self.payload);
        }

        self.required_size()
    }
}
