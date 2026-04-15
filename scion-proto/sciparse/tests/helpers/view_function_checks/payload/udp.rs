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

//! Exhaustive exerciser for [`UdpDatagramView`].

#![allow(dead_code, unused_imports)]

use sciparse::{core::view::View, payload::udp::view::UdpDatagramView};

use super::super::{read_slice_bounds, touch_slice_bounds};

/// Exercises every getter on a [`UdpDatagramView`] (immutable).
pub fn exec_every_view_function_ref(view: &UdpDatagramView) {
    let _ = view.src_port();
    let _ = view.dst_port();
    let _ = view.length();
    let _ = view.checksum();
    read_slice_bounds(view.payload());
    read_slice_bounds(view.as_bytes());
}

/// Exercises every getter and setter on a [`UdpDatagramView`].
///
/// Setters are called with the current value to keep the view consistent.
pub fn exec_every_view_function(view: &mut UdpDatagramView) {
    exec_every_view_function_ref(view);

    view.set_src_port(view.src_port());
    view.set_dst_port(view.dst_port());
    view.set_length(view.length());
    view.set_checksum(view.checksum());
    touch_slice_bounds(view.payload_mut());
}
