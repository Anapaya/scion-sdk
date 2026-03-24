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

//! Zero-copy UDP datagram view.

use std::mem::transmute;

use crate::{
    core::view::{
        View, ViewConversionError,
        macros::{gen_field_read, gen_field_write},
    },
    payload::udp::layout::UdpDatagramLayout,
};

/// A zero-copy view over a UDP datagram (header + payload).
#[repr(transparent)]
pub struct UdpDatagramView([u8]);

impl View for UdpDatagramView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        if buf.len() < UdpDatagramLayout::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "UdpHeader",
                required: UdpDatagramLayout::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(buf.len())
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl UdpDatagramView {
    gen_field_read!(src_port, UdpDatagramLayout::SRC_PORT_RNG, u16);
    gen_field_read!(dst_port, UdpDatagramLayout::DST_PORT_RNG, u16);
    gen_field_read!(length, UdpDatagramLayout::LENGTH_RNG, u16);
    gen_field_read!(checksum, UdpDatagramLayout::CHECKSUM_RNG, u16);

    gen_field_write!(set_src_port, UdpDatagramLayout::SRC_PORT_RNG, u16);
    gen_field_write!(set_dst_port, UdpDatagramLayout::DST_PORT_RNG, u16);
    gen_field_write!(set_length, UdpDatagramLayout::LENGTH_RNG, u16);
    gen_field_write!(set_checksum, UdpDatagramLayout::CHECKSUM_RNG, u16);

    /// Returns the UDP payload (bytes after the 8-byte header).
    #[inline]
    pub fn payload(&self) -> &[u8] {
        // SAFETY: On construction we check that the buffer is larger than
        // the header size.
        unsafe { self.0.get_unchecked(UdpDatagramLayout::HEADER_SIZE_BYTES..) }
    }

    /// Returns a mutable slice of the UDP payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // SAFETY: On construction we check that the buffer is larger than
        // the header size.
        unsafe {
            self.0
                .get_unchecked_mut(UdpDatagramLayout::HEADER_SIZE_BYTES..)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&src.to_be_bytes());
        buf.extend_from_slice(&dst.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // checksum
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn udp_packet_view_valid_header() {
        let buf = make_udp(1234, 5678, b"hello");
        let (view, _) = UdpDatagramView::from_slice(&buf).unwrap();
        assert_eq!(view.src_port(), 1234);
        assert_eq!(view.dst_port(), 5678);
        assert_eq!(view.length(), 13);
        assert_eq!(view.payload(), b"hello");
    }

    #[test]
    fn udp_packet_view_truncated_input() {
        let buf = [0u8; 7]; // shorter than 8 bytes
        assert!(UdpDatagramView::from_slice(&buf).is_err());
    }

    #[test]
    fn udp_packet_view_exact_header_no_payload() {
        let buf = make_udp(80, 443, &[]);
        let (view, _) = UdpDatagramView::from_slice(&buf).unwrap();
        assert_eq!(view.src_port(), 80);
        assert_eq!(view.dst_port(), 443);
        assert_eq!(view.payload(), b"");
    }
}
