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

//! Brute-force random data must not panic during parsing or view manipulation.

mod helpers;

use std::panic::catch_unwind;

use proptest::{
    collection::vec,
    prelude::{ProptestConfig, Strategy, any},
    prop_assert, prop_oneof, proptest,
};
use sciparse::{
    core::view::{View, ViewConversionError},
    header::view::ScionHeaderView,
    packet::view::ScionRawPacketView,
};

use crate::helpers::view_function_checks;

/// Brute force checks over random data to ensure no panics occur during parsing or view
/// manipulation of full packets
#[test]
fn parsing_random_packet_data_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        | (data in rand_packet_data()) | {
            random_packet_data_must_not_panic_impl(data)?;
        }
    );

    fn random_packet_data_must_not_panic_impl(
        data: Vec<u8>,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let mut data = data;
            match ScionRawPacketView::from_mut_slice(&mut data) {
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
                println!("{:?}", panic.downcast_ref::<&str>());
                prop_assert!(false, "Panic during random packet data parsing");
                Ok(())
            }
        }
    }

    /// Strategy for generating random packet data biased to look like a valid SCION packet
    fn rand_packet_data() -> impl Strategy<Value = Vec<u8>> {
        fn bias_to_packet_shape(mut data: Vec<u8>) -> Vec<u8> {
            if data.len() < 36 {
                return data;
            }

            let rand_byte = data.len() % data[5].max(1) as usize;
            let len = data.len();

            // SAFETY: We know that data is 36 bytes at least which is enough for the common
            // header.
            let view = unsafe { ScionHeaderView::from_mut_slice_unchecked(&mut data) };
            view.set_version(0);

            // Set some header/payload lengths to reasonable values so we pass more static checks
            if rand_byte.is_multiple_of(3) {
                let header_len = ((len.min(1000) / 4) * 4) as u16;
                unsafe {
                    view.set_header_len(header_len);
                }
            }

            // Occasionally set the payload_len to cover the rest of the buffer
            if rand_byte.is_multiple_of(5) {
                let hl = view.header_len() as usize;
                let remaining = len.saturating_sub(hl);
                unsafe {
                    view.set_payload_len(remaining.min(u16::MAX as usize) as u16);
                }
            }

            // Occasionally set next_header to UDP (17) or SCMP (202)
            if rand_byte.is_multiple_of(7) {
                let proto = if rand_byte.is_multiple_of(2) {
                    17u8
                } else {
                    202u8
                };
                view.set_next_header(proto);
            }

            data
        }

        prop_oneof![
            // Biased towards packet shape with enough bytes for header + small payload
            6 => vec(any::<u8>(), 36..=256).prop_map(bias_to_packet_shape),
            3 => vec(any::<u8>(), 36..=1024).prop_map(bias_to_packet_shape),
            // Completely random data
            1 => vec(any::<u8>(), 0..=1024),
        ]
    }
}
