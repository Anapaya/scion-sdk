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

use std::panic::catch_unwind;

use proptest::{
    collection::vec,
    prelude::{ProptestConfig, Strategy, any},
    prop_assert, prop_oneof, proptest,
};
use sciparse::{
    core::view::{View, ViewConversionError},
    packet::view::ScionRawPacketView,
    util::fuzz::packet_shape::bias_to_packet_shape,
};

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
            match ScionRawPacketView::try_from_mut_slice(&mut data) {
                Ok((view, _rest)) => {
                    sciparse::util::fuzz::view_function_checks::packet::exec_every_view_function(
                        view,
                    );
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
        /// Shapes a freshly generated buffer toward a valid SCION packet using
        /// the same structure-aware biasing the fuzzer applies.
        fn shape(mut data: Vec<u8>) -> Vec<u8> {
            bias_to_packet_shape(&mut data);
            data
        }

        prop_oneof![
            // Biased towards packet shape with enough bytes for header + small payload
            6 => vec(any::<u8>(), 36..=256).prop_map(shape),
            3 => vec(any::<u8>(), 36..=1024).prop_map(shape),
            // Completely random data
            1 => vec(any::<u8>(), 0..=1024),
        ]
    }
}
