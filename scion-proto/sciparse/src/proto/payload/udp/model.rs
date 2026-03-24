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

//! UDP payload models.

use crate::{
    checksum::ChecksumDigest,
    core::{encode::InvalidStructureError, write::unchecked_bit_range_be_write},
    header::model::AddressHeader,
    payload::{
        ProtocolNumber,
        encode::PayloadEncode,
        udp::{layout::UdpDatagramLayout, view::UdpDatagramView},
    },
};

/// A UDP message.
#[derive(Debug, Clone, PartialEq)]
pub struct UdpDatagram {
    /// The source port.
    pub src_port: u16,
    /// The destination port.
    pub dst_port: u16,
    /// The payload.
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// Creates a new UDP message.
    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        Self {
            src_port,
            dst_port,
            payload,
        }
    }

    /// Creates a new UDP message from a view.
    pub fn from_view(view: &UdpDatagramView) -> Self {
        Self {
            src_port: view.src_port(),
            dst_port: view.dst_port(),
            payload: view.payload().to_vec(),
        }
    }
}

impl PayloadEncode for UdpDatagram {
    fn required_size(&self, _header_and_extensions_size: usize) -> usize {
        UdpDatagramLayout::HEADER_SIZE_BYTES + self.payload.len()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        Ok(())
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use UdpDatagramLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u16>(buf, L::SRC_PORT_RNG, self.src_port);
            unchecked_bit_range_be_write::<u16>(buf, L::DST_PORT_RNG, self.dst_port);
            unchecked_bit_range_be_write::<u16>(buf, L::LENGTH_RNG, self.payload.len() as u16);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);

            let payload_buf = buf.get_unchecked_mut(
                L::HEADER_SIZE_BYTES..(L::HEADER_SIZE_BYTES + self.payload.len()),
            );
            std::ptr::copy_nonoverlapping(
                self.payload.as_ptr(),
                payload_buf.as_mut_ptr(),
                self.payload.len(),
            );

            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                ProtocolNumber::Udp.into(),
                &buf[0..self.required_size(header_and_extensions_size)],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
        }

        self.required_size(header_and_extensions_size)
    }
}
