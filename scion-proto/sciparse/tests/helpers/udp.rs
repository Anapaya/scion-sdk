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

//! Test helpers for UDP datagram views.

#![allow(dead_code, unused_imports)]

use sciparse::payload::udp::view::UdpDatagramView;

/// Exercises every function on a [`UdpDatagramView`] to ensure none panic on valid data.
pub fn exec_every_view_function(view: &mut UdpDatagramView) {
    let _ = view.src_port();
    let _ = view.dst_port();
    let _ = view.length();
    let _ = view.checksum();
    let _ = view.payload();
    view.set_src_port(view.src_port());
    view.set_dst_port(view.dst_port());
    view.set_length(view.length());
    view.set_checksum(view.checksum());
    let _ = view.payload_mut();
}
