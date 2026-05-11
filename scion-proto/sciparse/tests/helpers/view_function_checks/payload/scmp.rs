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

//! Exhaustive exerciser for [`ScmpPayloadView`] and all SCMP message sub-views.

#![allow(dead_code, unused_imports)]

use sciparse::{
    core::view::View,
    payload::scmp::view::{
        ScmpDestinationUnreachableMessageView, ScmpEchoReplyMessageView,
        ScmpEchoRequestMessageView, ScmpExternalInterfaceDownMessageView,
        ScmpInternalConnectivityDownMessageView, ScmpMessageView, ScmpMessageViewMut,
        ScmpPacketTooBigMessageView, ScmpParameterProblemMessageView, ScmpPayloadView,
        ScmpTracerouteReplyMessageView, ScmpTracerouteRequestMessageView, ScmpUnknownMessageView,
    },
};

use super::super::{read_slice_bounds, touch_slice_bounds};

/// Exercises every getter and setter on a [`ScmpPayloadView`] and all its
/// message sub-views.
///
/// Mutable setters are called with the current value so the view stays
/// consistent.
pub fn exec_every_view_function(view: &mut ScmpPayloadView) {
    // ── Top-level payload fields ──────────────────────────────────────
    let _ = view.message_type();
    let _ = view.code();
    let _ = view.checksum();
    let _ = view.dst_port();
    read_slice_bounds(view.as_bytes());

    view.set_code(view.code());
    view.set_checksum(view.checksum());
    // Safety: setting to the same value.
    unsafe { view.set_message_type(view.message_type()) };

    // ── Immutable message dispatch ────────────────────────────────────
    match view.message() {
        ScmpMessageView::DestinationUnreachable(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::PacketTooBig(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            let _ = v.mtu();
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::ParameterProblem(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            let _ = v.pointer();
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::ExternalInterfaceDown(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.isd_asn();
            let _ = v.interface_id();
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::InternalConnectivityDown(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.isd_asn();
            let _ = v.ingress_interface_id();
            let _ = v.egress_interface_id();
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::EchoRequest(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            read_slice_bounds(v.data());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::EchoReply(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            read_slice_bounds(v.data());
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::TracerouteRequest(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.isd_asn();
            let _ = v.interface_id();
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::TracerouteReply(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.isd_asn();
            let _ = v.interface_id();
            read_slice_bounds(v.as_bytes());
        }
        ScmpMessageView::Unknown(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            read_slice_bounds(v.message_specific_data());
            read_slice_bounds(v.as_bytes());
        }
    }

    // ── Mutable message dispatch ──────────────────────────────────────
    match view.message_mut() {
        ScmpMessageViewMut::DestinationUnreachable(v) => {
            // Safety: setting to the same value.
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::PacketTooBig(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            v.set_mtu(v.mtu());
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::ParameterProblem(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            v.set_pointer(v.pointer());
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::ExternalInterfaceDown(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::InternalConnectivityDown(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_isd_asn(v.isd_asn());
            v.set_ingress_interface_id(v.ingress_interface_id());
            v.set_egress_interface_id(v.egress_interface_id());
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::EchoRequest(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            touch_slice_bounds(v.data_mut());
        }
        ScmpMessageViewMut::EchoReply(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            touch_slice_bounds(v.data_mut());
        }
        ScmpMessageViewMut::TracerouteRequest(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
        }
        ScmpMessageViewMut::TracerouteReply(v) => {
            unsafe { v.set_message_type(v.message_type()) };
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
        }
        ScmpMessageViewMut::Unknown(v) => {
            v.set_message_type(v.message_type());
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            touch_slice_bounds(v.message_specific_data_mut());
        }
    }
}
