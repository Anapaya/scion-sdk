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

//! Exhaustive exerciser for [`ScionRawPacketView`] and typed packet views.

#![allow(dead_code, unused_imports)]

use sciparse::{
    core::view::View,
    packet::{
        classify::ClassifiedPacketView,
        view::{ScionRawPacketView, ScionScmpPacketView, ScionUdpPacketView},
    },
    payload::{scmp::view::ScmpPayloadView, udp::view::UdpDatagramView},
};

use super::{header, payload, read_slice_bounds, touch_slice_bounds};

/// Exercises every getter and setter on a [`ScionRawPacketView`] and all
/// reachable sub-views (header, path, payload).
///
/// Aggressively attempts to construct every typed view regardless of the
/// `next_header` field. A view that successfully constructs must be safe
/// to access — if it isn't, that's a bug we want to catch.
pub fn exec_every_view_function(view: &mut ScionRawPacketView) {
    // ── Packet-level accessors ────────────────────────────────────────
    read_slice_bounds(view.payload());
    touch_slice_bounds(view.payload_mut());
    read_slice_bounds(view.as_bytes());

    // ── Header sub-view ───────────────────────────────────────────────
    let _ = view.header();
    header::exec_every_view_function(view.header_mut());

    // ── Classification ────────────────────────────────────────────────

    if let Ok(class) = view.classify() {
        let _ = class.dst_socket_addr();

        match class {
            ClassifiedPacketView::Udp(udp_view) => {
                exec_udp_packet_view(udp_view);
            }
            ClassifiedPacketView::Scmp(scmp_view) => {
                exec_scmp_packet_view(scmp_view);
            }
            ClassifiedPacketView::Other(_raw) => {}
        }
    }

    // ── Try every typed view regardless of next_header ────────────────
    // If construction succeeds the view MUST be safe to use. Exercise
    // everything we can on it to surface any out-of-bounds access.

    // Immutable UDP
    if let Ok(udp_view) = view.try_into_udp() {
        exec_udp_packet_view(udp_view);
    }
    // Immutable SCMP
    if let Ok(scmp_view) = view.try_into_scmp() {
        exec_scmp_packet_view(scmp_view);
    }

    // Mutable UDP
    if let Ok(udp_view_mut) = view.try_into_udp_mut() {
        exec_udp_packet_view_mut(udp_view_mut);
    }
    // Mutable SCMP
    if let Ok(scmp_view_mut) = view.try_into_scmp_mut() {
        exec_scmp_packet_view_mut(scmp_view_mut);
    }
}

/// Exercises getters on an immutable [`ScionUdpPacketView`].
fn exec_udp_packet_view(view: &ScionUdpPacketView) {
    let _ = view.header();
    read_slice_bounds(view.payload());
    read_slice_bounds(view.as_bytes());

    let udp = view.udp();
    let _ = udp.src_port();
    let _ = udp.dst_port();
    let _ = udp.length();
    let _ = udp.checksum();
    read_slice_bounds(udp.payload());
    read_slice_bounds(udp.as_bytes());

    // Round-trip back to raw
    let raw = view.into_raw();
    let _ = raw.header();
    read_slice_bounds(raw.payload());
    read_slice_bounds(raw.as_bytes());
}

/// Exercises getters and setters on a mutable [`ScionUdpPacketView`].
fn exec_udp_packet_view_mut(view: &mut ScionUdpPacketView) {
    exec_udp_packet_view(view);

    header::exec_every_view_function(view.header_mut());

    // Exercise the UDP payload through the mutable typed view
    {
        let udp = view.udp();
        payload::udp::exec_every_view_function_ref(udp);
    }

    let raw = view.into_raw_mut();
    touch_slice_bounds(raw.payload_mut());
}

/// Exercises getters on an immutable [`ScionScmpPacketView`].
fn exec_scmp_packet_view(view: &ScionScmpPacketView) {
    let _ = view.header();
    read_slice_bounds(view.payload());
    read_slice_bounds(view.as_bytes());

    let scmp = view.scmp();
    let _ = scmp.message_type();
    let _ = scmp.code();
    let _ = scmp.checksum();
    let _ = scmp.dst_port();
    let _ = scmp.message();
    read_slice_bounds(scmp.as_bytes());

    // Round-trip back to raw
    let raw = view.into_raw();
    let _ = raw.header();
    read_slice_bounds(raw.payload());
    read_slice_bounds(raw.as_bytes());
}

/// Exercises getters and setters on a mutable [`ScionScmpPacketView`].
fn exec_scmp_packet_view_mut(view: &mut ScionScmpPacketView) {
    exec_scmp_packet_view(view);

    header::exec_every_view_function(view.header_mut());

    // Exercise the SCMP payload through the mutable typed view
    {
        let scmp = view.scmp();
        let _ = scmp.message_type();
        let _ = scmp.code();
        let _ = scmp.checksum();
        let _ = scmp.dst_port();
        let _ = scmp.message();
    }

    // Safety: we don't mutate in a way that invalidates the view.
    let raw = unsafe { view.into_raw_mut() };
    touch_slice_bounds(raw.payload_mut());
}
