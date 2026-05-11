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
//!
//! - [`packet`]: top-level [`ScionRawPacketView`] and typed packet views.
//! - [`header`]: [`ScionHeaderView`] and its sub-views.
//! - [`path`]: path views (standard, one-hop).
//! - [`payload`]: payload views (UDP, SCMP).

#![allow(dead_code, unused_imports)]

// Tests utilizing the exercisers must be compiled without optimizations to ensure
// that all view functions are exercised as intended.
#[cfg(not(debug_assertions))]
compile_error!("view function exercisers must be compiled without optimizations");

pub mod header;
pub mod packet;
pub mod path;
pub mod payload;

/// Reads the first and last byte of a slice to ensure the entire range is
/// backed by valid, accessible memory.
#[inline]
pub fn read_slice_bounds(s: &[u8]) {
    if let Some(first) = s.first() {
        std::hint::black_box(first);
    }
    if let Some(last) = s.last() {
        std::hint::black_box(last);
    }
}

/// Mutable variant: writes the first and last byte back to themselves.
#[inline]
#[allow(clippy::self_assignment)]
pub fn touch_slice_bounds(s: &mut [u8]) {
    if let Some(first) = s.first_mut() {
        *first = *first;
    }
    if let Some(last) = s.last_mut() {
        *last = *last;
    }
}
