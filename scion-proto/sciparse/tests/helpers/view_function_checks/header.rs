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

//! Exhaustive exerciser for [`ScionHeaderView`] and its sub-views.

#![allow(dead_code, unused_imports)]

use sciparse::{
    core::view::View,
    header::view::ScionHeaderView,
    path::{
        standard::view::{HopFieldView, InfoFieldView},
        view::{ScionPathView, ScionPathViewMut},
    },
};

use super::{path, read_slice_bounds, touch_slice_bounds};

/// Exercises every getter and setter on [`ScionHeaderView`], including the
/// embedded address header and path sub-views.
///
/// Mutable setters are called with the current value so the view stays
/// consistent.
pub fn exec_every_view_function(view: &mut ScionHeaderView) {
    // ── Common header ─────────────────────────────────────────────────
    let _ = view.version();
    let _ = view.traffic_class();
    let _ = view.flow_id();
    let _ = view.next_header();
    let _ = view.payload_len();
    let _ = view.header_len();
    let _ = view.path_type();
    let _ = view.path_type_range();
    let _ = view.dst_addr_type();
    let _ = view.src_addr_type();

    view.set_version(view.version());
    view.set_traffic_class(view.traffic_class());
    view.set_flow_id(view.flow_id());
    view.set_next_header(view.next_header());
    // Safety: setting to the same value that was already there.
    unsafe {
        view.set_payload_len(view.payload_len());
        view.set_header_len(view.header_len());
        view.set_path_type(view.path_type());
        view.set_dst_addr_type(view.dst_addr_type());
        view.set_src_addr_type(view.src_addr_type());
    }

    // ── Address header ────────────────────────────────────────────────
    let _ = view.dst_ia();
    let _ = view.dst_isd();
    let _ = view.dst_as();
    let _ = view.src_ia();
    let _ = view.src_isd();
    let _ = view.src_as();
    let _ = view.dst_host_addr();
    let _ = view.src_host_addr();
    let _ = view.src_host_addr_range();

    view.set_src_isd(view.src_isd());
    view.set_src_as(view.src_as());
    view.set_dst_isd(view.dst_isd());
    view.set_dst_as(view.dst_as());

    // ── Path (immutable) ──────────────────────────────────────────────
    match view.path() {
        ScionPathView::Standard(p) => path::exec_standard_path_view(p),
        ScionPathView::OneHop(p) => path::exec_onehop_path_view(p),
        ScionPathView::Unsupported { path_type: _, data } => {
            read_slice_bounds(data);
        }
        ScionPathView::Empty => {}
    }

    // ── Path (mutable) ────────────────────────────────────────────────
    match view.path_mut() {
        ScionPathViewMut::Standard(p) => path::exec_standard_path_view_mut(p),
        ScionPathViewMut::OneHop(p) => path::exec_onehop_path_view_mut(p),
        ScionPathViewMut::Unsupported { path_type: _, buf } => {
            touch_slice_bounds(buf);
        }
        ScionPathViewMut::Empty => {}
    }
}
