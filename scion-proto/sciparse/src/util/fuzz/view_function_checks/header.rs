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

use super::{black_box, path, read_slice_bounds, touch_slice_bounds};
use crate::{
    core::view::View,
    dataplane_path::{
        standard::view::{HopFieldView, InfoFieldView},
        view::{ScionDpPathView, ScionDpPathViewRef, ScionDpPathViewRefMut},
    },
    header::view::ScionHeaderView,
};

/// Exercises every getter and setter on [`ScionHeaderView`], including the
/// embedded address header and path sub-views.
///
/// Mutable setters are called with the current value so the view stays
/// consistent.
pub fn exec_every_view_function(view: &mut ScionHeaderView) {
    // ── Common header ─────────────────────────────────────────────────
    black_box(view.version());
    black_box(view.traffic_class());
    black_box(view.flow_id());
    black_box(view.next_header());
    black_box(view.payload_len());
    black_box(view.header_len());
    black_box(view.path_type());
    black_box(view.path_type_range());
    black_box(view.dst_addr_type());
    black_box(view.src_addr_type());

    view.set_version(black_box(view.version()));
    view.set_traffic_class(black_box(view.traffic_class()));
    view.set_flow_id(black_box(view.flow_id()));
    view.set_next_header(black_box(view.next_header()));
    // Safety: setting to the same value that was already there.
    unsafe {
        view.set_payload_len(black_box(view.payload_len()));
        view.set_header_len(black_box(view.header_len()));
        view.set_path_type(black_box(view.path_type()));
        view.set_dst_addr_type(black_box(view.dst_addr_type()));
        view.set_src_addr_type(black_box(view.src_addr_type()));
    }

    // ── Address header ────────────────────────────────────────────────
    black_box(view.dst_ia());
    black_box(view.dst_isd());
    black_box(view.dst_as());
    black_box(view.src_ia());
    black_box(view.src_isd());
    black_box(view.src_as());
    // `*_host_addr` return a `#[must_use]` `Result`; `black_box` still forces
    // the read, the `let _` only discards the (intentionally ignored) result.
    let _ = black_box(view.dst_host_addr());
    let _ = black_box(view.src_host_addr());
    black_box(view.src_host_addr_range());

    view.set_src_isd(black_box(view.src_isd()));
    view.set_src_as(black_box(view.src_as()));
    view.set_dst_isd(black_box(view.dst_isd()));
    view.set_dst_as(black_box(view.dst_as()));

    // ── Path (immutable) ──────────────────────────────────────────────
    match view.path() {
        ScionDpPathViewRef::Standard(p) => path::exec_standard_path_view(p),
        ScionDpPathViewRef::OneHop(p) => path::exec_onehop_path_view(p),
        ScionDpPathViewRef::Unsupported { path_type: _, data } => {
            read_slice_bounds(data);
        }
        ScionDpPathViewRef::Empty => {}
    }

    // ── Path (mutable) ────────────────────────────────────────────────
    match view.path_mut() {
        ScionDpPathViewRefMut::Standard(p) => path::exec_standard_path_view_mut(p),
        ScionDpPathViewRefMut::OneHop(p) => path::exec_onehop_path_view_mut(p),
        ScionDpPathViewRefMut::Unsupported { path_type: _, buf } => {
            touch_slice_bounds(buf);
        }
        ScionDpPathViewRefMut::Empty => {}
    }
}
