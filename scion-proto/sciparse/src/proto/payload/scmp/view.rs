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

use crate::{
    core::{
        macros::impl_from_ref,
        view::{
            View, ViewConversionError,
            macros::{
                gen_field_read, gen_field_read_and_write, gen_field_write, gen_unsafe_field_write,
                gen_view_impl,
            },
        },
    },
    identifier::isd_asn::IsdAsn,
    packet::view::ScionPacketView,
    payload::{
        ProtocolNumber,
        scmp::{
            layout::{
                ScmpDestinationUnreachableLayout, ScmpEchoReplyLayout, ScmpEchoRequestLayout,
                ScmpExternalInterfaceDownLayout, ScmpInternalConnectivityDownLayout,
                ScmpMessageLayout, ScmpPacketTooBigLayout, ScmpParameterProblemLayout,
                ScmpTracerouteReplyLayout, ScmpTracerouteRequestLayout, ScmpUnknownMessageLayout,
            },
            types::{ScmpDestinationUnreachableCode, ScmpMessageType, ScmpParameterProblemCode},
        },
        udp::view::UdpDatagramView,
    },
};

/// A view over a valid SCMP payload.
/// This types has_required_size ensures that the buffer is large enough to contain the SCMP
/// message.
#[repr(transparent)]
pub struct ScmpPayloadView([u8]);
gen_view_impl!(ScmpPayloadView, ScmpMessageLayout);
impl_from_ref!(
    ScmpDestinationUnreachableMessageView,
    ScmpMessageView<'a>,
    |v| ScmpMessageView::DestinationUnreachable(v)
);
impl_from_ref!(ScmpPacketTooBigMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::PacketTooBig(v)
});
impl_from_ref!(ScmpParameterProblemMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::ParameterProblem(v)
});
impl_from_ref!(
    ScmpExternalInterfaceDownMessageView,
    ScmpMessageView<'a>,
    |v| ScmpMessageView::ExternalInterfaceDown(v)
);
impl_from_ref!(
    ScmpInternalConnectivityDownMessageView,
    ScmpMessageView<'a>,
    |v| ScmpMessageView::InternalConnectivityDown(v)
);
impl_from_ref!(ScmpEchoRequestMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::EchoRequest(v)
});
impl_from_ref!(ScmpEchoReplyMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::EchoReply(v)
});
impl_from_ref!(ScmpTracerouteRequestMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::TracerouteRequest(v)
});
impl_from_ref!(ScmpTracerouteReplyMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::TracerouteReply(v)
});
impl_from_ref!(ScmpUnknownMessageView, ScmpMessageView<'a>, |v| {
    ScmpMessageView::UnknownMessage(v)
});
impl ScmpPayloadView {
    gen_field_read!(
        message_type,
        ScmpUnknownMessageLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpUnknownMessageLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpUnknownMessageLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpUnknownMessageLayout::CHECKSUM_RNG,
        u16
    );

    /// Returns a view over the SCMP message.
    pub fn message<'a>(&'a self) -> ScmpMessageView<'a> {
        // Safety: The buffer is checked to be large enough when the ScmpPayloadView was
        // created.
        use ScmpMessageType as T;
        unsafe {
            match self.message_type() {
                T::DestinationUnreachable => {
                    ScmpDestinationUnreachableMessageView::from_slice_unchecked(&self.0).into()
                }
                T::PacketTooBig => {
                    ScmpPacketTooBigMessageView::from_slice_unchecked(&self.0).into()
                }
                T::ParameterProblem => {
                    ScmpParameterProblemMessageView::from_slice_unchecked(&self.0).into()
                }
                T::ExternalInterfaceDown => {
                    ScmpExternalInterfaceDownMessageView::from_slice_unchecked(&self.0).into()
                }
                T::InternalConnectivityDown => {
                    ScmpInternalConnectivityDownMessageView::from_slice_unchecked(&self.0).into()
                }
                T::EchoRequest => ScmpEchoRequestMessageView::from_slice_unchecked(&self.0).into(),
                T::EchoReply => ScmpEchoReplyMessageView::from_slice_unchecked(&self.0).into(),
                T::TracerouteRequest => {
                    ScmpTracerouteRequestMessageView::from_slice_unchecked(&self.0).into()
                }
                T::TracerouteReply => {
                    ScmpTracerouteReplyMessageView::from_slice_unchecked(&self.0).into()
                }
                T::Unknown(_) => ScmpUnknownMessageView::from_slice_unchecked(&self.0).into(),
            }
        }
    }

    /// Returns a mutable view over the SCMP message.
    pub fn message_mut<'a>(&'a mut self) -> ScmpMessageViewMut<'a> {
        use ScmpMessageType as T;
        use ScmpMessageViewMut as V;
        // Safety: The buffer is checked to be large enough when the ScmpPayloadView was
        // created.
        match self.message_type() {
            T::DestinationUnreachable => {
                V::DestinationUnreachable(unsafe {
                    ScmpDestinationUnreachableMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::PacketTooBig => {
                V::PacketTooBig(unsafe {
                    ScmpPacketTooBigMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::ParameterProblem => {
                V::ParameterProblem(unsafe {
                    ScmpParameterProblemMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::ExternalInterfaceDown => {
                V::ExternalInterfaceDown(unsafe {
                    ScmpExternalInterfaceDownMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::InternalConnectivityDown => {
                V::InternalConnectivityDown(unsafe {
                    ScmpInternalConnectivityDownMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::EchoRequest => {
                V::EchoRequest(unsafe {
                    ScmpEchoRequestMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::EchoReply => {
                V::EchoReply(unsafe {
                    ScmpEchoReplyMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::TracerouteRequest => {
                V::TracerouteRequest(unsafe {
                    ScmpTracerouteRequestMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::TracerouteReply => {
                V::TracerouteReply(unsafe {
                    ScmpTracerouteReplyMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
            T::Unknown(_) => {
                V::UnknownMessage(unsafe {
                    ScmpUnknownMessageView::from_mut_slice_unchecked(&mut self.0)
                })
            }
        }
    }

    /// Extracts a destination port from this SCMP message.
    ///
    /// - Informational messages: returns the identifier field.
    /// - Error messages: parses the offending packet as UDP and returns its source port.
    /// - Unknown error messages: returns `None`.
    pub fn dst_port(&self) -> Option<u16> {
        let udp_src_port = |offending_packet: &[u8]| {
            let (inner, _) = ScionPacketView::from_slice(offending_packet).ok()?;
            if <u8 as Into<ProtocolNumber>>::into(inner.header().next_header())
                != ProtocolNumber::Udp
            {
                return None;
            }
            let (udp, _) = UdpDatagramView::from_slice(inner.payload()).ok()?;
            Some(udp.src_port())
        };
        match self.message() {
            ScmpMessageView::EchoRequest(v) => Some(v.identifier()),
            ScmpMessageView::EchoReply(v) => Some(v.identifier()),
            ScmpMessageView::TracerouteRequest(v) => Some(v.identifier()),
            ScmpMessageView::TracerouteReply(v) => Some(v.identifier()),
            ScmpMessageView::DestinationUnreachable(v) => udp_src_port(v.offending_packet()),
            ScmpMessageView::PacketTooBig(v) => udp_src_port(v.offending_packet()),
            ScmpMessageView::ParameterProblem(v) => udp_src_port(v.offending_packet()),
            ScmpMessageView::ExternalInterfaceDown(v) => udp_src_port(v.offending_packet()),
            ScmpMessageView::InternalConnectivityDown(v) => udp_src_port(v.offending_packet()),
            ScmpMessageView::UnknownMessage(_) => None,
        }
    }
}

/// A view over an SCMP message.
pub enum ScmpMessageView<'a> {
    /// A view over an SCMP DestinationUnreachable message.
    DestinationUnreachable(&'a ScmpDestinationUnreachableMessageView),
    /// A view over an SCMP PacketTooBig message.
    PacketTooBig(&'a ScmpPacketTooBigMessageView),
    /// A view over an SCMP ParameterProblem message.
    ParameterProblem(&'a ScmpParameterProblemMessageView),
    /// A view over an SCMP ExternalInterfaceDown message.
    ExternalInterfaceDown(&'a ScmpExternalInterfaceDownMessageView),
    /// A view over an SCMP InternalConnectivityDown message.
    InternalConnectivityDown(&'a ScmpInternalConnectivityDownMessageView),
    /// A view over an SCMP EchoRequest message.
    EchoRequest(&'a ScmpEchoRequestMessageView),
    /// A view over an SCMP EchoReply message.
    EchoReply(&'a ScmpEchoReplyMessageView),
    /// A view over an SCMP TracerouteRequest message.
    TracerouteRequest(&'a ScmpTracerouteRequestMessageView),
    /// A view over an SCMP TracerouteReply message.
    TracerouteReply(&'a ScmpTracerouteReplyMessageView),
    /// A view over an SCMP UnknownMessage message.
    UnknownMessage(&'a ScmpUnknownMessageView),
}

/// A mutable view over an SCMP message.
pub enum ScmpMessageViewMut<'a> {
    /// A mutable view over an SCMP DestinationUnreachable message.
    DestinationUnreachable(&'a mut ScmpDestinationUnreachableMessageView),
    /// A mutable view over an SCMP PacketTooBig message.
    PacketTooBig(&'a mut ScmpPacketTooBigMessageView),
    /// A mutable view over an SCMP ParameterProblem message.
    ParameterProblem(&'a mut ScmpParameterProblemMessageView),
    /// A mutable view over an SCMP ExternalInterfaceDown message.
    ExternalInterfaceDown(&'a mut ScmpExternalInterfaceDownMessageView),
    /// A mutable view over an SCMP InternalConnectivityDown message.
    InternalConnectivityDown(&'a mut ScmpInternalConnectivityDownMessageView),
    /// A mutable view over an SCMP EchoRequest message.
    EchoRequest(&'a mut ScmpEchoRequestMessageView),
    /// A mutable view over an SCMP EchoReply message.
    EchoReply(&'a mut ScmpEchoReplyMessageView),
    /// A mutable view over an SCMP TracerouteRequest message.
    TracerouteRequest(&'a mut ScmpTracerouteRequestMessageView),
    /// A mutable view over an SCMP TracerouteReply message.
    TracerouteReply(&'a mut ScmpTracerouteReplyMessageView),
    /// A mutable view over an SCMP UnknownMessage message.
    UnknownMessage(&'a mut ScmpUnknownMessageView),
}

/// A view over an SCMP DestinationUnreachable message.
#[repr(transparent)]
pub struct ScmpDestinationUnreachableMessageView([u8]);
gen_view_impl!(
    ScmpDestinationUnreachableMessageView,
    ScmpDestinationUnreachableLayout
);
impl ScmpDestinationUnreachableMessageView {
    gen_field_read!(
        message_type,
        ScmpDestinationUnreachableLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpDestinationUnreachableLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(
        code,
        set_code,
        ScmpDestinationUnreachableLayout::CODE_RNG,
        ScmpDestinationUnreachableCode
    );
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpDestinationUnreachableLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        reserved,
        set_reserved,
        ScmpDestinationUnreachableLayout::RESERVED_RNG,
        u32
    );

    /// Returns a slice over the offending packet of the message.
    pub fn offending_packet(&self) -> &[u8] {
        let range = ScmpDestinationUnreachableLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the offending packet of the message.
    pub fn offending_packet_mut(&mut self) -> &mut [u8] {
        let range = ScmpDestinationUnreachableLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP PacketTooBig message.
#[repr(transparent)]
pub struct ScmpPacketTooBigMessageView([u8]);
gen_view_impl!(ScmpPacketTooBigMessageView, ScmpPacketTooBigLayout);
impl ScmpPacketTooBigMessageView {
    gen_field_read!(
        message_type,
        ScmpPacketTooBigLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpPacketTooBigLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpPacketTooBigLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpPacketTooBigLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        reserved,
        set_reserved,
        ScmpPacketTooBigLayout::RESERVED_RNG,
        u16
    );
    gen_field_read_and_write!(mtu, set_mtu, ScmpPacketTooBigLayout::MTU_RNG, u16);

    /// Returns a slice over the offending packet of the message.
    pub fn offending_packet(&self) -> &[u8] {
        let range = ScmpPacketTooBigLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the offending packet of the message.
    pub fn offending_packet_mut(&mut self) -> &mut [u8] {
        let range = ScmpPacketTooBigLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP ParameterProblem message.
#[repr(transparent)]
pub struct ScmpParameterProblemMessageView([u8]);
gen_view_impl!(ScmpParameterProblemMessageView, ScmpParameterProblemLayout);
impl ScmpParameterProblemMessageView {
    gen_field_read!(
        message_type,
        ScmpParameterProblemLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpParameterProblemLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(
        code,
        set_code,
        ScmpParameterProblemLayout::CODE_RNG,
        ScmpParameterProblemCode
    );
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpParameterProblemLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        reserved,
        set_reserved,
        ScmpParameterProblemLayout::RESERVED_RNG,
        u16
    );
    gen_field_read_and_write!(
        pointer,
        set_pointer,
        ScmpParameterProblemLayout::POINTER_RNG,
        u16
    );

    /// Returns a slice over the offending packet of the message.
    pub fn offending_packet(&self) -> &[u8] {
        let range = ScmpParameterProblemLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the offending packet of the message.
    pub fn offending_packet_mut(&mut self) -> &mut [u8] {
        let range = ScmpParameterProblemLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP ExternalInterfaceDown message.
#[repr(transparent)]
pub struct ScmpExternalInterfaceDownMessageView([u8]);
gen_view_impl!(
    ScmpExternalInterfaceDownMessageView,
    ScmpExternalInterfaceDownLayout
);
impl ScmpExternalInterfaceDownMessageView {
    gen_field_read!(
        message_type,
        ScmpExternalInterfaceDownLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpExternalInterfaceDownLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(
        code,
        set_code,
        ScmpExternalInterfaceDownLayout::CODE_RNG,
        u8
    );
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpExternalInterfaceDownLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        isd_asn,
        set_isd_asn,
        ScmpExternalInterfaceDownLayout::ISD_AS_RNG,
        IsdAsn
    );
    gen_field_read_and_write!(
        interface_id,
        set_interface_id,
        ScmpExternalInterfaceDownLayout::INTERFACE_ID_RNG,
        u64
    );

    /// Returns a slice over the offending packet of the message.
    pub fn offending_packet(&self) -> &[u8] {
        let range = ScmpExternalInterfaceDownLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the offending packet of the message.
    pub fn offending_packet_mut(&mut self) -> &mut [u8] {
        let range = ScmpExternalInterfaceDownLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP InternalConnectivityDown message.
#[repr(transparent)]
pub struct ScmpInternalConnectivityDownMessageView([u8]);
gen_view_impl!(
    ScmpInternalConnectivityDownMessageView,
    ScmpInternalConnectivityDownLayout
);
impl ScmpInternalConnectivityDownMessageView {
    gen_field_read!(
        message_type,
        ScmpInternalConnectivityDownLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpInternalConnectivityDownLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(
        code,
        set_code,
        ScmpInternalConnectivityDownLayout::CODE_RNG,
        u8
    );
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpInternalConnectivityDownLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        isd_asn,
        set_isd_asn,
        ScmpInternalConnectivityDownLayout::ISD_AS_RNG,
        IsdAsn
    );
    gen_field_read_and_write!(
        ingress_interface_id,
        set_ingress_interface_id,
        ScmpInternalConnectivityDownLayout::INGRESS_INTERFACE_ID_RNG,
        u64
    );
    gen_field_read_and_write!(
        egress_interface_id,
        set_egress_interface_id,
        ScmpInternalConnectivityDownLayout::EGRESS_INTERFACE_ID_RNG,
        u64
    );

    /// Returns a slice over the offending packet of the message.
    pub fn offending_packet(&self) -> &[u8] {
        let range = ScmpInternalConnectivityDownLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the offending packet of the message.
    pub fn offending_packet_mut(&mut self) -> &mut [u8] {
        let range = ScmpInternalConnectivityDownLayout::new(self.0.len())
            .offending_packet_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP EchoRequest message.
#[repr(transparent)]
pub struct ScmpEchoRequestMessageView([u8]);
gen_view_impl!(ScmpEchoRequestMessageView, ScmpEchoRequestLayout);
impl ScmpEchoRequestMessageView {
    gen_field_read!(
        message_type,
        ScmpEchoRequestLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpEchoRequestLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpEchoRequestLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpEchoRequestLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        identifier,
        set_identifier,
        ScmpEchoRequestLayout::IDENTIFIER_RNG,
        u16
    );
    gen_field_read_and_write!(
        sequence_number,
        set_sequence_number,
        ScmpEchoRequestLayout::SEQUENCE_NUMBER_RNG,
        u16
    );

    /// Returns a slice over the messages data.
    pub fn data(&self) -> &[u8] {
        let range = ScmpEchoRequestLayout::new(self.0.len())
            .data_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the messages data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = ScmpEchoRequestLayout::new(self.0.len())
            .data_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP EchoReply message.
#[repr(transparent)]
pub struct ScmpEchoReplyMessageView([u8]);
gen_view_impl!(ScmpEchoReplyMessageView, ScmpEchoReplyLayout);
impl ScmpEchoReplyMessageView {
    gen_field_read!(message_type, ScmpEchoReplyLayout::TYPE_RNG, ScmpMessageType);
    gen_unsafe_field_write!(
        set_message_type,
        ScmpEchoReplyLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpEchoReplyLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpEchoReplyLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        identifier,
        set_identifier,
        ScmpEchoReplyLayout::IDENTIFIER_RNG,
        u16
    );
    gen_field_read_and_write!(
        sequence_number,
        set_sequence_number,
        ScmpEchoReplyLayout::SEQUENCE_NUMBER_RNG,
        u16
    );

    /// Returns a slice over the messages data.
    pub fn data(&self) -> &[u8] {
        let range = ScmpEchoReplyLayout::new(self.0.len())
            .data_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the messages data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = ScmpEchoReplyLayout::new(self.0.len())
            .data_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}

/// A view over an SCMP TracerouteRequest message.
#[repr(transparent)]
pub struct ScmpTracerouteRequestMessageView([u8]);
gen_view_impl!(
    ScmpTracerouteRequestMessageView,
    ScmpTracerouteRequestLayout
);
impl ScmpTracerouteRequestMessageView {
    gen_field_read!(
        message_type,
        ScmpTracerouteRequestLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpTracerouteRequestLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpTracerouteRequestLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpTracerouteRequestLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        identifier,
        set_identifier,
        ScmpTracerouteRequestLayout::IDENTIFIER_RNG,
        u16
    );
    gen_field_read_and_write!(
        sequence_number,
        set_sequence_number,
        ScmpTracerouteRequestLayout::SEQUENCE_NUMBER_RNG,
        u16
    );
    gen_field_read_and_write!(
        isd_asn,
        set_isd_asn,
        ScmpTracerouteRequestLayout::ISD_AS_RNG,
        IsdAsn
    );
    gen_field_read_and_write!(
        interface_id,
        set_interface_id,
        ScmpTracerouteRequestLayout::INTERFACE_ID_RNG,
        u64
    );
}

/// A view over an SCMP TracerouteReply message.
#[repr(transparent)]
pub struct ScmpTracerouteReplyMessageView([u8]);
gen_view_impl!(ScmpTracerouteReplyMessageView, ScmpTracerouteReplyLayout);
impl ScmpTracerouteReplyMessageView {
    gen_field_read!(
        message_type,
        ScmpTracerouteReplyLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_unsafe_field_write!(
        set_message_type,
        ScmpTracerouteReplyLayout::TYPE_RNG,
        ScmpMessageType
    );
    gen_field_read_and_write!(code, set_code, ScmpTracerouteReplyLayout::CODE_RNG, u8);
    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpTracerouteReplyLayout::CHECKSUM_RNG,
        u16
    );

    gen_field_read_and_write!(
        identifier,
        set_identifier,
        ScmpTracerouteReplyLayout::IDENTIFIER_RNG,
        u16
    );
    gen_field_read_and_write!(
        sequence_number,
        set_sequence_number,
        ScmpTracerouteReplyLayout::SEQUENCE_NUMBER_RNG,
        u16
    );
    gen_field_read_and_write!(
        isd_asn,
        set_isd_asn,
        ScmpTracerouteReplyLayout::ISD_AS_RNG,
        IsdAsn
    );
    gen_field_read_and_write!(
        interface_id,
        set_interface_id,
        ScmpTracerouteReplyLayout::INTERFACE_ID_RNG,
        u64
    );
}

/// A view over an SCMP UnknownMessage message.
#[repr(transparent)]
pub struct ScmpUnknownMessageView([u8]);
gen_view_impl!(ScmpUnknownMessageView, ScmpUnknownMessageLayout);
impl ScmpUnknownMessageView {
    gen_field_read_and_write!(
        message_type,
        set_message_type,
        ScmpUnknownMessageLayout::TYPE_RNG,
        u8
    );

    gen_field_read_and_write!(code, set_code, ScmpUnknownMessageLayout::CODE_RNG, u8);

    gen_field_read_and_write!(
        checksum,
        set_checksum,
        ScmpUnknownMessageLayout::CHECKSUM_RNG,
        u16
    );

    /// Returns a slice over the messages specific data.
    pub fn message_specific_data(&self) -> &[u8] {
        let range = ScmpUnknownMessageLayout::new(self.0.len())
            .message_specific_data_rng()
            .aligned_byte_range();
        &self.0[range]
    }

    /// Returns a mutable slice over the messages specific data.
    pub fn message_specific_data_mut(&mut self) -> &mut [u8] {
        let range = ScmpUnknownMessageLayout::new(self.0.len())
            .message_specific_data_rng()
            .aligned_byte_range();
        &mut self.0[range]
    }
}
