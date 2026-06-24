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

//! Exhaustive exercisers for SCION path views (standard and one-hop).

#![allow(dead_code, unused_imports)]

use super::{black_box, read_slice_bounds};
use crate::{
    core::view::View,
    dataplane_path::{
        onehop::view::OneHopPathView,
        standard::{
            mac::ForwardingKey,
            types::HopFieldMac,
            view::{HopFieldView, InfoFieldView, StandardPathView},
        },
    },
};

// ── Info field ─────────────────────────────────────────────────────────

/// Exercises every getter on an [`InfoFieldView`] (immutable).
pub fn exec_info_field_view(view: &InfoFieldView) {
    black_box(view.flags());
    black_box(view.segment_id());
    black_box(view.timestamp());
    read_slice_bounds(view.as_bytes());
}

/// Exercises every getter and setter on an [`InfoFieldView`] (mutable).
pub fn exec_info_field_view_mut(view: &mut InfoFieldView) {
    exec_info_field_view(view);

    view.set_flags(black_box(view.flags()));
    view.set_segment_id(black_box(view.segment_id()));
    view.set_timestamp(black_box(view.timestamp()));
}

// ── Hop field ──────────────────────────────────────────────────────────

/// Exercises every getter on a [`HopFieldView`] (immutable).
pub fn exec_hop_field_view(view: &HopFieldView) {
    black_box(view.flags());
    black_box(view.exp_time());
    black_box(view.cons_ingress());
    black_box(view.cons_egress());
    black_box(view.mac());
    read_slice_bounds(view.as_bytes());
}

/// Exercises every getter and setter on a [`HopFieldView`] (mutable).
pub fn exec_hop_field_view_mut(view: &mut HopFieldView) {
    exec_hop_field_view(view);

    view.set_flags(black_box(view.flags()));
    view.set_exp_time(black_box(view.exp_time()));
    view.set_cons_ingress(black_box(view.cons_ingress()));
    view.set_cons_egress(black_box(view.cons_egress()));
    view.set_mac(black_box(view.mac()));
}

// ── Standard path ──────────────────────────────────────────────────────

/// Exercises every getter on a [`StandardPathView`] (immutable).
pub fn exec_standard_path_view(view: &StandardPathView) {
    black_box(view.curr_info_field());
    black_box(view.curr_hop_field());
    black_box(view.seg0_len());
    black_box(view.seg1_len());
    black_box(view.seg2_len());
    black_box(view.info_field_count());
    black_box(view.hop_field_count());
    read_slice_bounds(view.as_bytes());

    // Iterate info fields via slice accessor
    for info_field in view.info_fields() {
        exec_info_field_view(info_field);
    }

    // Iterate hop fields via slice accessor
    for hop_field in view.hop_fields() {
        exec_hop_field_view(hop_field);
    }

    // Indexed access
    for idx in 0..view.info_field_count() as usize {
        if let Some(f) = view.info_field(idx) {
            exec_info_field_view(f);
        }
    }
    for idx in 0..view.hop_field_count() as usize {
        if let Some(f) = view.hop_field(idx) {
            exec_hop_field_view(f);
        }
    }

    // Out-of-bounds access must return None
    assert!(view.info_field(view.info_field_count() as usize).is_none());
    assert!(view.hop_field(view.hop_field_count() as usize).is_none());

    // checked_hop_field_range – valid and out-of-bounds
    for idx in 0..view.hop_field_count() as usize {
        assert!(view.checked_hop_field_range(idx).is_some());
    }
    // Out of bounds
    assert!(
        view.checked_hop_field_range(view.hop_field_count() as usize)
            .is_none()
    );

    // ingress_interface / egress_interface – requires an info field reference
    if let Some(info) = view.info_fields().first() {
        for hop_field in view.hop_fields() {
            black_box(hop_field.ingress_interface(info));
            black_box(hop_field.egress_interface(info));
        }
    }
}

/// Exercises every getter and setter on a [`StandardPathView`] (mutable).
pub fn exec_standard_path_view_mut(view: &mut StandardPathView) {
    exec_standard_path_view(view);

    // Meta header setters (safe ones)
    view.set_curr_info_field(black_box(view.curr_info_field_idx()));
    view.set_curr_hop_field(black_box(view.curr_hop_field_idx()));

    // Safety: setting to the same value.
    unsafe {
        view.set_seg0_len(black_box(view.seg0_len()));
        view.set_seg1_len(black_box(view.seg1_len()));
        view.set_seg2_len(black_box(view.seg2_len()));
    }

    // Mutable slice accessors
    for info_field in view.info_fields_mut() {
        exec_info_field_view_mut(info_field);
    }
    for hop_field in view.hop_fields_mut() {
        exec_hop_field_view_mut(hop_field);
    }

    // Indexed mutable access
    for idx in 0..view.info_field_count() as usize {
        if let Some(f) = view.info_field_mut(idx) {
            exec_info_field_view_mut(f);
        }
        // Out-of-bounds access must return None
        assert!(
            view.info_field_mut(view.info_field_count() as usize)
                .is_none()
        );
    }
    for idx in 0..view.hop_field_count() as usize {
        if let Some(f) = view.hop_field_mut(idx) {
            exec_hop_field_view_mut(f);
        }
        // Out-of-bounds access must return None
        assert!(
            view.hop_field_mut(view.hop_field_count() as usize)
                .is_none()
        );
    }
}

// ── One-hop path ───────────────────────────────────────────────────────

/// Exercises every getter on a [`OneHopPathView`] (immutable).
pub fn exec_onehop_path_view(view: &OneHopPathView) {
    let info = view.info_field();
    exec_info_field_view(info);

    let [hop1, hop2] = view.hop_fields();
    exec_hop_field_view(hop1);
    exec_hop_field_view(hop2);

    // ingress_interface / egress_interface
    black_box(hop1.ingress_interface(info));
    black_box(hop1.egress_interface(info));
    black_box(hop2.ingress_interface(info));
    black_box(hop2.egress_interface(info));

    read_slice_bounds(view.as_bytes());
}

/// Exercises every getter and setter on a [`OneHopPathView`] (mutable).
pub fn exec_onehop_path_view_mut(view: &mut OneHopPathView) {
    exec_onehop_path_view(view);

    let info = view.info_field_mut();
    exec_info_field_view_mut(info);

    let [hop1, hop2] = view.mut_hop_fields();
    let h2 = hop2.as_bytes().to_vec();
    exec_hop_field_view_mut(hop1);
    exec_hop_field_view_mut(hop2);

    // set_second_hop with a static forwarding key
    static DUMMY_KEY: ForwardingKey = [0u8; 16];
    let ingress = black_box(view.hop_fields()[1].cons_ingress());
    view.set_second_hop(ingress, DUMMY_KEY, black_box(false));
    view.set_second_hop(ingress, DUMMY_KEY, black_box(true));

    // Reset the second hop to the original values to avoid leaving the view in a modified state.
    unsafe {
        let [_, hop2] = view.mut_hop_fields();
        hop2.as_bytes_mut().copy_from_slice(&h2);
    }
}
