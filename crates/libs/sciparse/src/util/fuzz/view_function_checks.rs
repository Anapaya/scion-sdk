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

//! Exhaustive view-function exercisers for SCION packet views.
//!
//! Every public getter and setter on each view type is called to verify that
//! no access causes UB (e.g. out-of-bounds reads/writes) on validly-constructed
//! views.

#![allow(dead_code, unused_imports)]

// Every getter result and setter input below is routed through `black_box`, so
// the exercisers are *not* optimized away even though cargo-fuzz compiles this
// crate with optimizations enabled. We still require debug assertions to stay
// enabled so the views' internal `debug_assert!`s and overflow checks remain
// active while fuzzing; refuse to build otherwise. This is gated on `cfg(fuzzing)`
// (set by cargo-fuzz) so that release builds enabling the `fuzz` feature for other
// reasons — e.g. `cargo bench`, whose dev-dependency graph turns the feature on —
// still compile.
#[cfg(all(fuzzing, not(debug_assertions)))]
compile_error!("view function exercisers must be compiled with debug assertions enabled");

pub mod header;
pub mod packet;
pub mod path;
pub mod payload;

/// Re-exported so the exercisers can `use super::black_box` and wrap every
/// getter result / setter input, guaranteeing the optimizer cannot elide the
/// access.
pub use std::hint::black_box;

/// Reads the first and last byte of a slice to ensure the entire range is
/// backed by valid, accessible memory. Both reads are routed through
/// [`black_box`] so the optimizer cannot elide them.
#[inline]
pub fn read_slice_bounds(s: &[u8]) {
    if let Some(first) = s.first() {
        black_box(first);
    }
    if let Some(last) = s.last() {
        black_box(last);
    }
}

/// Mutable variant: reads the first and last byte through [`black_box`] and
/// writes the resulting opaque value back, forcing both the load and the store
/// to actually happen.
#[inline]
pub fn touch_slice_bounds(s: &mut [u8]) {
    if let Some(first) = s.first_mut() {
        *first = black_box(*first);
    }
    if let Some(last) = s.last_mut() {
        *last = black_box(*last);
    }
}
