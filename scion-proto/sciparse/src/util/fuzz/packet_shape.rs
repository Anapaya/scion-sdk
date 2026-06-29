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

//! Structure-aware input shaping for SCION packet fuzzing.

use crate::{core::view::View, header::view::ScionHeaderView};

/// Minimum number of bytes a buffer must have before it is worth shaping.
///
/// This is the size of the smallest valid SCION header (common header plus an
/// address header carrying the smallest host addresses). Shorter buffers are
/// left untouched so the "buffer too small" code paths keep getting exercised.
const MIN_SHAPEABLE_LEN: usize = 36;

/// Largest header length we will synthesize, kept well below the protocol
/// maximum of `255 * 4 = 1020` bytes and aligned down to a multiple of four.
const MAX_SYNTH_HEADER_LEN: usize = 1000;

/// SCION protocol number for UDP payloads.
const NEXT_HEADER_UDP: u8 = 17;
/// SCION protocol number for SCMP payloads.
const NEXT_HEADER_SCMP: u8 = 202;

/// Biases arbitrary input bytes toward a structurally-plausible SCION packet.
pub fn bias_to_packet_shape(data: &mut [u8]) {
    if data.len() < MIN_SHAPEABLE_LEN {
        return;
    }

    let len = data.len();

    // Derive all structural decisions from the input
    let rand_byte = len % data[5].max(1) as usize;

    // SAFETY: we just checked that `data` holds at least `MIN_SHAPEABLE_LEN`
    // bytes, which covers the common header accessed by the constructor and by
    // every getter/setter used below.
    let view = unsafe { ScionHeaderView::from_mut_slice_unchecked(data) };

    // SCION only defines version 0; any other value is rejected immediately, so
    // always pin it to keep the input parseable.
    view.set_version(0);

    // Point the header length at a 4-byte-aligned offset inside the buffer so
    // the payload-offset checks pass more often.
    if rand_byte.is_multiple_of(3) {
        let header_len = ((len.min(MAX_SYNTH_HEADER_LEN) / 4) * 4) as u16;
        // SAFETY: `header_len` is a multiple of 4, at most `MAX_SYNTH_HEADER_LEN`
        // (well under the 1020-byte protocol maximum), and never exceeds `len`,
        // so the header stays within the buffer.
        unsafe {
            view.set_header_len(header_len);
        }
    }

    // Occasionally declare a payload that covers the rest of the buffer.
    if rand_byte.is_multiple_of(5) {
        let header_len = view.header_len() as usize;
        let remaining = len.saturating_sub(header_len);
        // SAFETY: `remaining` is `len - header_len`, so `header_len + payload_len`
        // never exceeds `len` and the declared payload stays within the buffer.
        unsafe {
            view.set_payload_len(remaining.min(u16::MAX as usize) as u16);
        }
    }

    // Occasionally select a known L4 protocol so the typed UDP / SCMP packet
    // views become constructible.
    if rand_byte.is_multiple_of(7) {
        let proto = if rand_byte.is_multiple_of(2) {
            NEXT_HEADER_UDP
        } else {
            NEXT_HEADER_SCMP
        };
        view.set_next_header(proto.into());
    }
}
