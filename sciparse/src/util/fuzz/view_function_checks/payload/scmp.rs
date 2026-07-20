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

use super::super::{black_box, read_slice_bounds, touch_slice_bounds};
use crate::{
    core::view::View,
    payload::scmp::view::{
        ScmpDestinationUnreachableMessageView, ScmpEchoReplyMessageView,
        ScmpEchoRequestMessageView, ScmpExternalInterfaceDownMessageView,
        ScmpInternalConnectivityDownMessageView, ScmpMessageView, ScmpMessageViewMut,
        ScmpPacketTooBigMessageView, ScmpParameterProblemMessageView, ScmpPayloadView,
        ScmpTracerouteReplyMessageView, ScmpTracerouteRequestMessageView, ScmpUnknownMessageView,
    },
};

/// Exercises every getter and setter on a [`ScmpPayloadView`] and all its
/// message sub-views.
///
/// Mutable setters are called with the current value so the view stays
/// consistent.
pub fn exec_every_view_function(view: &mut ScmpPayloadView) {
    // ── Top-level payload fields ──────────────────────────────────────
    black_box(view.message_type());
    black_box(view.code());
    black_box(view.checksum());
    black_box(view.dst_port());
    read_slice_bounds(view.as_slice());

    view.set_code(black_box(view.code()));
    view.set_checksum(black_box(view.checksum()));
    // Safety: setting to the same value.
    unsafe { view.set_message_type(black_box(view.message_type())) };

    // ── Immutable message dispatch ────────────────────────────────────
    match view.message() {
        ScmpMessageView::DestinationUnreachable(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.reserved());
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::PacketTooBig(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.reserved());
            black_box(v.mtu());
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::ParameterProblem(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.reserved());
            black_box(v.pointer());
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::ExternalInterfaceDown(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.isd_asn());
            black_box(v.interface_id());
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::InternalConnectivityDown(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.isd_asn());
            black_box(v.ingress_interface_id());
            black_box(v.egress_interface_id());
            read_slice_bounds(v.offending_packet());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::EchoRequest(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.identifier());
            black_box(v.sequence_number());
            read_slice_bounds(v.data());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::EchoReply(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.identifier());
            black_box(v.sequence_number());
            read_slice_bounds(v.data());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::TracerouteRequest(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.identifier());
            black_box(v.sequence_number());
            black_box(v.isd_asn());
            black_box(v.interface_id());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::TracerouteReply(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            black_box(v.identifier());
            black_box(v.sequence_number());
            black_box(v.isd_asn());
            black_box(v.interface_id());
            read_slice_bounds(v.as_slice());
        }
        ScmpMessageView::Unknown(v) => {
            black_box(v.message_type());
            black_box(v.code());
            black_box(v.checksum());
            read_slice_bounds(v.message_specific_data());
            read_slice_bounds(v.as_slice());
        }
    }

    // ── Mutable message dispatch ──────────────────────────────────────
    match view.message_mut() {
        ScmpMessageViewMut::DestinationUnreachable(v) => {
            // Safety: setting to the same value.
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_reserved(black_box(v.reserved()));
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::PacketTooBig(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_reserved(black_box(v.reserved()));
            v.set_mtu(black_box(v.mtu()));
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::ParameterProblem(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_reserved(black_box(v.reserved()));
            v.set_pointer(black_box(v.pointer()));
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::ExternalInterfaceDown(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_isd_asn(black_box(v.isd_asn()));
            v.set_interface_id(black_box(v.interface_id()));
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::InternalConnectivityDown(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_isd_asn(black_box(v.isd_asn()));
            v.set_ingress_interface_id(black_box(v.ingress_interface_id()));
            v.set_egress_interface_id(black_box(v.egress_interface_id()));
            touch_slice_bounds(v.offending_packet_mut());
        }
        ScmpMessageViewMut::EchoRequest(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_identifier(black_box(v.identifier()));
            v.set_sequence_number(black_box(v.sequence_number()));
            touch_slice_bounds(v.data_mut());
        }
        ScmpMessageViewMut::EchoReply(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_identifier(black_box(v.identifier()));
            v.set_sequence_number(black_box(v.sequence_number()));
            touch_slice_bounds(v.data_mut());
        }
        ScmpMessageViewMut::TracerouteRequest(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_identifier(black_box(v.identifier()));
            v.set_sequence_number(black_box(v.sequence_number()));
            v.set_isd_asn(black_box(v.isd_asn()));
            v.set_interface_id(black_box(v.interface_id()));
        }
        ScmpMessageViewMut::TracerouteReply(v) => {
            unsafe { v.set_message_type(black_box(v.message_type())) };
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            v.set_identifier(black_box(v.identifier()));
            v.set_sequence_number(black_box(v.sequence_number()));
            v.set_isd_asn(black_box(v.isd_asn()));
            v.set_interface_id(black_box(v.interface_id()));
        }
        ScmpMessageViewMut::Unknown(v) => {
            v.set_message_type(black_box(v.message_type()));
            v.set_code(black_box(v.code()));
            v.set_checksum(black_box(v.checksum()));
            touch_slice_bounds(v.message_specific_data_mut());
        }
    }
}
