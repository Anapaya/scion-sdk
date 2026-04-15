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

//! Tests for full SCION packet encoding, decoding, and fuzz-style view resilience.
//!
//! Wire-level strategic breaking of encoded packets must not panic during parsing or view
//! manipulation.

mod helpers;

use std::panic::catch_unwind;

use proptest::{
    collection::vec,
    prelude::{BoxedStrategy, ProptestConfig, Strategy, any, prop},
    prop_assert, proptest,
};
use sciparse::{
    core::{
        encode::WireEncode,
        view::{View, ViewConversionError},
    },
    header::view::ScionHeaderView,
    packet::{classify::ClassifiedPacket, view::ScionRawPacketView},
};

use crate::helpers::view_function_checks;

/// Strategically breaks important packet fields on the wire and ensures no panics occur during
/// parsing or view manipulation
#[test]
fn broken_wire_packets_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(breaking_opts: wire_manipulation::PacketBreakingOptions)| {
            broken_wire_packets_must_not_panic_impl(breaking_opts)?;
        }
    );

    fn broken_wire_packets_must_not_panic_impl(
        breaking_opts: wire_manipulation::PacketBreakingOptions,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let mut broken_buf = breaking_opts.apply();

            match ScionRawPacketView::from_mut_slice(&mut broken_buf) {
                Ok((view, _rest)) => {
                    view_function_checks::packet::exec_every_view_function(view);
                }
                Err(ViewConversionError::BufferTooSmall { .. })
                | Err(ViewConversionError::Other(_)) => {
                    return Ok(());
                }
            }

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!(
                    "Panic during invalid packet parsing with breaking options: {:#?}",
                    breaking_opts
                );
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>());

                prop_assert!(false, "Panic during invalid packet parsing");
                Ok(())
            }
        }
    }
}

/// Wire-level manipulation of encoded packets to break them strategically
mod wire_manipulation {
    use proptest::prelude::Arbitrary;
    use sciparse::path::view::ScionPathViewMut;

    use super::*;

    /// Options for breaking a valid encoded SCION packet on the wire
    ///
    /// First encodes a valid packet, then applies strategic mutations to the raw bytes.
    /// Fields are applied in an order that ensures the view is still constructible for
    /// as many mutations as possible (header-structure mutations first, then truncation).
    #[derive(Debug)]
    pub struct PacketBreakingOptions {
        /// The valid packet to encode and then break
        base: ClassifiedPacket,

        // ── Header-level breaking (same as header_en_decode) ──────────
        /// Overflow current hop field by this amount
        hop_field_overflow: Option<u8>,
        /// Overflow current info field
        info_field_overflow: Option<u8>,
        /// Override segment lengths
        segment_len: Option<(u8, u8, u8)>,
        /// Override path type
        path_type: Option<u8>,
        /// Override header length
        header_len: Option<usize>,
        /// Override src_addr_type
        src_addr: Option<u8>,
        /// Override dst_addr_type
        dst_addr: Option<u8>,

        // ── Payload-level breaking ────────────────────────────────────
        /// Override the next_header byte to a different protocol
        next_header: Option<u8>,
        /// Override payload_len field
        payload_len: Option<u16>,
        /// Corrupt payload bytes at given positions (offset, value)
        corrupt_payload_bytes: Vec<(usize, u8)>,

        // ── Buffer-level breaking ─────────────────────────────────────
        /// Number of bytes to remove from the end
        remove_trailing_bytes: usize,
        /// Bytes to remove at a random position (start, length)
        remove_random_bytes: (usize, usize),
    }

    impl PacketBreakingOptions {
        pub fn apply(&self) -> Vec<u8> {
            // Encode the valid packet
            if self.base.wire_valid().is_err() {
                panic!("Base packet is not wire-valid, cannot apply breaking options");
            }

            let mut buf = vec![0u8; self.base.required_size()];
            if self.base.encode(&mut buf).is_err() {
                return vec![];
            }

            if let Ok((view, _rest)) = ScionHeaderView::from_mut_slice(&mut buf) {
                // ── Payload-level header field mutations ──────────────
                if let Some(nh) = self.next_header {
                    view.set_next_header(nh);
                }

                if let Some(pl) = self.payload_len {
                    unsafe {
                        view.set_payload_len(pl);
                    }
                }

                // ── Path-level mutations ──────────────────────────────
                if let ScionPathViewMut::Standard(path_view) = view.path_mut() {
                    if let Some(hf_overflow) = self.hop_field_overflow {
                        let curr = path_view.curr_hop_field();
                        let overflow = curr.saturating_add(hf_overflow).min(255 >> 2);
                        path_view.set_curr_hop_field(overflow);
                    }

                    if let Some(overflow) = self.info_field_overflow {
                        path_view.set_curr_info_field(overflow);
                    }

                    if let Some((seg0, seg1, seg2)) = self.segment_len {
                        unsafe {
                            path_view.set_seg0_len(seg0);
                            path_view.set_seg1_len(seg1);
                            path_view.set_seg2_len(seg2);
                        }
                    }
                }

                // ── Header field mutations ───────────────────────────
                if let Some(pt) = self.path_type {
                    unsafe {
                        view.set_path_type(pt.into());
                    }
                }

                if let Some(hl) = self.header_len {
                    unsafe {
                        view.set_header_len(((hl / 4) * 4) as u16);
                    }
                }

                if let Some(sa) = self.src_addr {
                    unsafe {
                        view.set_src_addr_type(sa.into());
                    }
                }

                if let Some(da) = self.dst_addr {
                    unsafe {
                        view.set_dst_addr_type(da.into());
                    }
                }
            }

            // ── Raw payload byte corruption ──────────────────────────
            for &(offset, value) in &self.corrupt_payload_bytes {
                if offset < buf.len() {
                    buf[offset] = value;
                }
            }

            // ── Buffer truncation ────────────────────────────────────
            let final_len = buf.len().saturating_sub(self.remove_trailing_bytes);
            buf.truncate(final_len);

            // ── Random byte removal ──────────────────────────────────
            let (start, length) = self.remove_random_bytes;
            if buf.len() > length && length > 0 {
                let wrapped_start = start % (buf.len() - length);
                let end = wrapped_start + length;
                let mut new_buf = Vec::with_capacity(buf.len() - length);
                new_buf.extend_from_slice(&buf[..wrapped_start]);
                new_buf.extend_from_slice(&buf[end..]);
                buf = new_buf;
            }
            buf
        }
    }

    impl Arbitrary for PacketBreakingOptions {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            (
                any::<ClassifiedPacket>(),
                // Header-level breaking (group 1)
                (
                    prop::option::of(1u8..=16),                       // hop_field_overflow
                    prop::option::of(1u8..=16),                       // info_field_overflow
                    prop::option::of((0u8..=63, 0u8..=63, 0u8..=63)), // segment_len
                    prop::option::of(0u8..=255),                      // path_type
                    prop::option::of(1usize..=64),                    // header_len_words
                    prop::option::of(0u8..=7),                        // src_addr
                    prop::option::of(0u8..=7),                        // dst_addr
                ),
                // Payload + buffer breaking (group 2)
                (
                    prop::option::of(0u8..=255),              // next_header
                    prop::option::of(any::<u16>()),           // payload_len
                    vec((0usize..=2048, any::<u8>()), 0..=8), // corrupt_payload_bytes
                    0usize..=128,                             // remove_trailing_bytes
                    (0usize..=1280, 0usize..=128),            // remove_random_bytes
                ),
            )
                .prop_map(
                    |(
                        base,
                        (
                            hop_field_overflow,
                            info_field_overflow,
                            segment_len,
                            path_type,
                            header_len_words,
                            src_addr,
                            dst_addr,
                        ),
                        (
                            next_header,
                            payload_len,
                            corrupt_payload_bytes,
                            remove_trailing_bytes,
                            remove_random_bytes,
                        ),
                    )| {
                        PacketBreakingOptions {
                            base,
                            hop_field_overflow,
                            info_field_overflow,
                            segment_len,
                            path_type,
                            header_len: header_len_words.map(|w| w * 4),
                            src_addr,
                            dst_addr,
                            next_header,
                            payload_len,
                            corrupt_payload_bytes,
                            remove_trailing_bytes,
                            remove_random_bytes,
                        }
                    },
                )
                .boxed()
        }
    }
}
