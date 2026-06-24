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

//! Basic fuzzing of SCION packet parsing and view manipulation.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use sciparse::{
    core::view::{View, ViewConversionError},
    packet::view::ScionRawPacketView,
    util::fuzz::{
        packet_shape::bias_to_packet_shape, view_function_checks::packet::exec_every_view_function,
    },
};

fuzz_target!(|data: &[u8]| {
    // `from_mut_slice` needs `&mut [u8]`; the copy only satisfies that API, the
    // bytes themselves are exactly the corpus entry under test.
    let mut data = data.to_vec();

    match ScionRawPacketView::from_mut_slice(&mut data) {
        Ok((view, _rest)) => {
            exec_every_view_function(view);
        }
        Err(ViewConversionError::BufferTooSmall { .. }) | Err(ViewConversionError::Other(_)) => {}
    }
});

// Structure-aware mutator (the idiomatic cargo-fuzz approach for parsers).
//
// Mirrors the Rust Fuzz Book's "decompress -> mutate -> recompress" pattern. We
// have no decode step (a SCION packet's structure is in-band in the raw bytes),
// so the two steps are:
//
//   1. mutate the bytes with libFuzzer's default mutator, then
//   2. re-impose the SCION structural invariants as the FINAL step.
//
// The fixup must run last: whatever is in `data` when we return becomes the
// input that gets executed and potentially saved to the corpus. Mutating again
// after the fixup would just scramble the structure we restored.
fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        // Mutate the bytes with libFuzzer's default mutator
        let new_size = fuzzer_mutate(data, size, max_size);

        // Re-impose SCION structure on the mutated bytes so the fuzzer's corpus
        // contains valid packets.
        bias_to_packet_shape(&mut data[..new_size]);

        new_size
    }
);
