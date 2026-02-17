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

//! SCMP message models.

use crate::{
    core::{encode::EncodeError, layout::Layout as _, write::unchecked_bit_range_be_write},
    header::model::AddressHeader,
    identifier::isd_asn::IsdAsn,
    payload::scmp::{
        SCMP_PROTOCOL_NUMBER,
        encode::ScmpWireEncode,
        layout::{
            ScmpDestinationUnreachableLayout, ScmpEchoReplyLayout, ScmpEchoRequestLayout,
            ScmpExternalInterfaceDownLayout, ScmpInternalConnectivityDownLayout,
            ScmpPacketTooBigLayout, ScmpParameterProblemLayout, ScmpTracerouteReplyLayout,
            ScmpTracerouteRequestLayout, ScmpUnknownMessageLayout,
        },
        types::{ScmpDestinationUnreachableCode, ScmpMessageType, ScmpParameterProblemCode},
        view::{
            ScmpDestinationUnreachableMessageView, ScmpEchoReplyMessageView,
            ScmpEchoRequestMessageView, ScmpExternalInterfaceDownMessageView,
            ScmpInternalConnectivityDownMessageView, ScmpMessageView, ScmpPacketTooBigMessageView,
            ScmpParameterProblemMessageView, ScmpTracerouteReplyMessageView,
            ScmpTracerouteRequestMessageView, ScmpUnknownMessageView,
        },
    },
    scion::checksum::ChecksumDigest,
};

/// Represents an SCMP message.
///
/// Fully decoded SCMP message with an appropriate format.
///
/// The different variants correspond to the SCMP message type variants.
///
/// There is an unknown error variant [`ScmpMessage::Unknown`], but no `UnknownInformational`,
/// because
/// the specification states:
/// "If an SCMP informational message of unknown type is received, it MUST be silently dropped."
///
/// There are separate enum types [`ScmpErrorMessage`] and [`ScmpInformationalMessage`] that only
/// include error and informational messages, respectively.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum ScmpMessage {
    /// An SCMP DestinationUnreachable message.
    ///
    /// See [`ScmpDestinationUnreachable`] for further details.
    DestinationUnreachable(ScmpDestinationUnreachable),
    /// An SCMP PacketTooBig message.
    ///
    /// See [`ScmpPacketTooBig`] for further details.
    PacketTooBig(ScmpPacketTooBig),
    /// An SCMP ParameterProblem message.
    ///
    /// See [`ScmpParameterProblem`] for further details.
    ParameterProblem(ScmpParameterProblem),
    /// An SCMP ExternalInterfaceDown message.
    ///
    /// See [`ScmpExternalInterfaceDown`] for further details.
    ExternalInterfaceDown(ScmpExternalInterfaceDown),
    /// An SCMP InternalConnectivityDown message.
    ///
    /// See [`ScmpInternalConnectivityDown`] for further details.
    InternalConnectivityDown(ScmpInternalConnectivityDown),
    /// An SCMP EchoRequest message.
    ///
    /// See [`ScmpEchoRequest`] for further details.
    EchoRequest(ScmpEchoRequest),
    /// An SCMP EchoReply message.
    ///
    /// See [`ScmpEchoReply`] for further details.
    EchoReply(ScmpEchoReply),
    /// An SCMP TracerouteRequest message.
    ///
    /// See [`ScmpTracerouteRequest`] for further details.
    TracerouteRequest(ScmpTracerouteRequest),
    /// An SCMP TracerouteReply message.
    ///
    /// See [`ScmpTracerouteReply`] for further details.
    TracerouteReply(ScmpTracerouteReply),
    /// An SCMP error message whose type is unknown.
    ///
    /// This is needed because the specification states:
    /// "If an SCMP error message of unknown type is received at its destination, it MUST be passed
    /// to the upper-layer process that originated the packet that caused the error, if it can be
    /// identified."
    Unknown(ScmpMessageUnknown),
}
impl ScmpMessage {
    /// Get the type of the SCMP message.
    pub fn message_type(&self) -> ScmpMessageType {
        match self {
            Self::DestinationUnreachable(_) => ScmpMessageType::DestinationUnreachable,
            Self::PacketTooBig(_) => ScmpMessageType::PacketTooBig,
            Self::ParameterProblem(_) => ScmpMessageType::ParameterProblem,
            Self::ExternalInterfaceDown(_) => ScmpMessageType::ExternalInterfaceDown,
            Self::InternalConnectivityDown(_) => ScmpMessageType::InternalConnectivityDown,
            Self::EchoRequest(_) => ScmpMessageType::EchoRequest,
            Self::EchoReply(_) => ScmpMessageType::EchoReply,
            Self::TracerouteRequest(_) => ScmpMessageType::TracerouteRequest,
            Self::TracerouteReply(_) => ScmpMessageType::TracerouteReply,
            Self::Unknown(msg) => ScmpMessageType::Unknown(msg.message_type),
        }
    }

    /// Convert the SCMP message to an informational message.
    pub fn try_into_informational_message(self) -> Result<ScmpInformationalMessage, ScmpMessage> {
        match self {
            Self::EchoRequest(x) => Ok(ScmpInformationalMessage::EchoRequest(x)),
            Self::EchoReply(x) => Ok(ScmpInformationalMessage::EchoReply(x)),
            Self::TracerouteRequest(x) => Ok(ScmpInformationalMessage::TracerouteRequest(x)),
            Self::TracerouteReply(x) => Ok(ScmpInformationalMessage::TracerouteReply(x)),
            _ => Err(self),
        }
    }

    /// Convert the SCMP message to an error message.
    pub fn try_into_error_message(self) -> Result<ScmpErrorMessage, ScmpMessage> {
        match self {
            Self::DestinationUnreachable(x) => Ok(ScmpErrorMessage::DestinationUnreachable(x)),
            Self::PacketTooBig(x) => Ok(ScmpErrorMessage::PacketTooBig(x)),
            Self::ParameterProblem(x) => Ok(ScmpErrorMessage::ParameterProblem(x)),
            Self::ExternalInterfaceDown(x) => Ok(ScmpErrorMessage::ExternalInterfaceDown(x)),
            Self::InternalConnectivityDown(x) => Ok(ScmpErrorMessage::InternalConnectivityDown(x)),
            _ => Err(self),
        }
    }

    /// Create a new SCMP message from a view.
    pub fn from_view(view: ScmpMessageView) -> Self {
        match view {
            ScmpMessageView::DestinationUnreachable(view) => {
                Self::DestinationUnreachable(ScmpDestinationUnreachable::from_view(view))
            }
            ScmpMessageView::PacketTooBig(view) => {
                Self::PacketTooBig(ScmpPacketTooBig::from_view(view))
            }
            ScmpMessageView::ParameterProblem(view) => {
                Self::ParameterProblem(ScmpParameterProblem::from_view(view))
            }
            ScmpMessageView::ExternalInterfaceDown(view) => {
                Self::ExternalInterfaceDown(ScmpExternalInterfaceDown::from_view(view))
            }
            ScmpMessageView::InternalConnectivityDown(view) => {
                Self::InternalConnectivityDown(ScmpInternalConnectivityDown::from_view(view))
            }
            ScmpMessageView::EchoRequest(view) => {
                Self::EchoRequest(ScmpEchoRequest::from_view(view))
            }
            ScmpMessageView::EchoReply(view) => Self::EchoReply(ScmpEchoReply::from_view(view)),
            ScmpMessageView::TracerouteRequest(view) => {
                Self::TracerouteRequest(ScmpTracerouteRequest::from_view(view))
            }
            ScmpMessageView::TracerouteReply(view) => {
                Self::TracerouteReply(ScmpTracerouteReply::from_view(view))
            }
            ScmpMessageView::UnknownMessage(view) => {
                Self::Unknown(ScmpMessageUnknown::from_view(view))
            }
        }
    }
}
impl ScmpWireEncode for ScmpMessage {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        match self {
            Self::DestinationUnreachable(x) => x.required_size(header_and_extensions_size),
            Self::PacketTooBig(x) => x.required_size(header_and_extensions_size),
            Self::ParameterProblem(x) => x.required_size(header_and_extensions_size),
            Self::ExternalInterfaceDown(x) => x.required_size(header_and_extensions_size),
            Self::InternalConnectivityDown(x) => x.required_size(header_and_extensions_size),
            Self::EchoRequest(x) => x.required_size(),
            Self::EchoReply(x) => x.required_size(),
            Self::TracerouteRequest(x) => x.required_size(),
            Self::TracerouteReply(x) => x.required_size(),
            Self::Unknown(x) => x.required_size(),
        }
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        unsafe {
            match self {
                Self::DestinationUnreachable(x) => {
                    x.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::PacketTooBig(x) => {
                    x.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::ParameterProblem(x) => {
                    x.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::ExternalInterfaceDown(x) => {
                    x.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::InternalConnectivityDown(x) => {
                    x.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::EchoRequest(x) => x.encode_unchecked(buf, address_header),
                Self::EchoReply(x) => x.encode_unchecked(buf, address_header),
                Self::TracerouteRequest(x) => x.encode_unchecked(buf, address_header),
                Self::TracerouteReply(x) => x.encode_unchecked(buf, address_header),
                Self::Unknown(x) => x.encode_unchecked(buf, address_header),
            }
        }
    }
}
impl From<ScmpErrorMessage> for ScmpMessage {
    fn from(value: ScmpErrorMessage) -> Self {
        match value {
            ScmpErrorMessage::DestinationUnreachable(x) => Self::DestinationUnreachable(x),
            ScmpErrorMessage::PacketTooBig(x) => Self::PacketTooBig(x),
            ScmpErrorMessage::ParameterProblem(x) => Self::ParameterProblem(x),
            ScmpErrorMessage::ExternalInterfaceDown(x) => Self::ExternalInterfaceDown(x),
            ScmpErrorMessage::InternalConnectivityDown(x) => Self::InternalConnectivityDown(x),
        }
    }
}
impl From<ScmpInformationalMessage> for ScmpMessage {
    fn from(value: ScmpInformationalMessage) -> Self {
        match value {
            ScmpInformationalMessage::EchoRequest(x) => Self::EchoRequest(x),
            ScmpInformationalMessage::EchoReply(x) => Self::EchoReply(x),
            ScmpInformationalMessage::TracerouteRequest(x) => Self::TracerouteRequest(x),
            ScmpInformationalMessage::TracerouteReply(x) => Self::TracerouteReply(x),
        }
    }
}

/// Fully decoded SCMP error message with an appropriate format.
///
/// The different variants correspond to the SCMP error message type variants.
///
/// See [`ScmpInformationalMessage`] for informational messages and [`ScmpMessage`] for an enum that
/// includes both error and informational messages.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum ScmpErrorMessage {
    /// An SCMP DestinationUnreachable message.
    ///
    /// See [`ScmpDestinationUnreachable`] for further details.
    DestinationUnreachable(ScmpDestinationUnreachable),
    /// An SCMP PacketTooBig message.
    ///
    /// See [`ScmpPacketTooBig`] for further details.
    PacketTooBig(ScmpPacketTooBig),
    /// An SCMP ParameterProblem message.
    ///
    /// See [`ScmpParameterProblem`] for further details.
    ParameterProblem(ScmpParameterProblem),
    /// An SCMP ExternalInterfaceDown message.
    ///
    /// See [`ScmpExternalInterfaceDown`] for further details.
    ExternalInterfaceDown(ScmpExternalInterfaceDown),
    /// An SCMP InternalConnectivityDown message.
    ///
    /// See [`ScmpInternalConnectivityDown`] for further details.
    InternalConnectivityDown(ScmpInternalConnectivityDown),
}

impl ScmpErrorMessage {
    /// Get the type of the error SCMP message.
    pub fn message_type(&self) -> ScmpMessageType {
        match self {
            Self::DestinationUnreachable(_) => ScmpMessageType::DestinationUnreachable,
            Self::PacketTooBig(_) => ScmpMessageType::PacketTooBig,
            Self::ParameterProblem(_) => ScmpMessageType::ParameterProblem,
            Self::ExternalInterfaceDown(_) => ScmpMessageType::ExternalInterfaceDown,
            Self::InternalConnectivityDown(_) => ScmpMessageType::InternalConnectivityDown,
        }
    }
}

impl ScmpWireEncode for ScmpErrorMessage {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        match self {
            Self::DestinationUnreachable(m) => m.required_size(header_and_extensions_size),
            Self::PacketTooBig(m) => m.required_size(header_and_extensions_size),
            Self::ParameterProblem(m) => m.required_size(header_and_extensions_size),
            Self::ExternalInterfaceDown(m) => m.required_size(header_and_extensions_size),
            Self::InternalConnectivityDown(m) => m.required_size(header_and_extensions_size),
        }
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        unsafe {
            match self {
                Self::DestinationUnreachable(m) => {
                    m.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::PacketTooBig(m) => {
                    m.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::ParameterProblem(m) => {
                    m.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::ExternalInterfaceDown(m) => {
                    m.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
                Self::InternalConnectivityDown(m) => {
                    m.encode_unchecked(buf, address_header, header_and_extensions_size)
                }
            }
        }
    }
}

/// Fully decoded SCMP informational message with an appropriate format.
///
/// The different variants correspond to the SCMP informational message type variants.
///
/// There is no `Unknown` variant, because the specification states:
/// "If an SCMP informational message of unknown type is received, it MUST be silently dropped."
///
/// See [`ScmpErrorMessage`] for error messages and [`ScmpMessage`] for an enum that includes both
/// error and informational messages.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum ScmpInformationalMessage {
    /// An SCMP EchoRequest message.
    ///
    /// See [`ScmpEchoRequest`] for further details.
    EchoRequest(ScmpEchoRequest),
    /// An SCMP EchoReply message.
    ///
    /// See [`ScmpEchoReply`] for further details.
    EchoReply(ScmpEchoReply),
    /// An SCMP TracerouteRequest message.
    ///
    /// See [`ScmpTracerouteRequest`] for further details.
    TracerouteRequest(ScmpTracerouteRequest),
    /// An SCMP TracerouteReply message.
    ///
    /// See [`ScmpTracerouteReply`] for further details.
    TracerouteReply(ScmpTracerouteReply),
}
impl ScmpInformationalMessage {
    /// Get the type of the informational SCMP message.
    pub fn message_type(&self) -> ScmpMessageType {
        match self {
            Self::EchoRequest(_) => ScmpMessageType::EchoRequest,
            Self::EchoReply(_) => ScmpMessageType::EchoReply,
            Self::TracerouteRequest(_) => ScmpMessageType::TracerouteRequest,
            Self::TracerouteReply(_) => ScmpMessageType::TracerouteReply,
        }
    }
}
impl ScmpWireEncode for ScmpInformationalMessage {
    fn required_size(&self, _header_and_extensions_size: usize) -> usize {
        match self {
            Self::EchoRequest(m) => m.required_size(),
            Self::EchoReply(m) => m.required_size(),
            Self::TracerouteRequest(m) => m.required_size(),
            Self::TracerouteReply(m) => m.required_size(),
        }
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        _header_and_extensions_size: usize,
    ) -> usize {
        unsafe {
            match self {
                Self::EchoRequest(m) => m.encode_unchecked(buf, address_header),
                Self::EchoReply(m) => m.encode_unchecked(buf, address_header),
                Self::TracerouteRequest(m) => m.encode_unchecked(buf, address_header),
                Self::TracerouteReply(m) => m.encode_unchecked(buf, address_header),
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
//
// Error Messages
//
// ------------------------------------------------------------------------------------------------
macro_rules! error_message {
    (
        $(#[$outer:meta])*
        pub struct $name:ident : $message_type:ident {
            $($(#[$doc:meta])* $vis:vis $field:ident : $type:ty,)*
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $($(#[$doc])* $vis $field: $type,)*
            /// The (truncated) packet that triggered the error.
            /// If the offending packet makes the resulting message longer than 1232 bytes, it is truncated.
            offending_packet: Vec<u8>,
        }

        impl $name {
            /// Create a new message with the corresponding values and an unset checksum.
            pub fn new($($field: $type,)* offending_packet: Vec<u8>) -> Self {
                Self{
                    $($field,)*
                    offending_packet,
                }
            }

            /// Get the (truncated) packet that triggered the error.
            #[inline]
            pub fn get_offending_packet(&self) -> &[u8] {
                &self.offending_packet
            }

            /// Set the (truncated) packet that triggered the error.
            #[inline]
            pub fn set_offending_packet(&mut self, offending_packet: Vec<u8>) {
                self.offending_packet = offending_packet;
            }
        }

        impl From<$name> for ScmpErrorMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }
        impl From<$name> for ScmpMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }
    };
}

error_message!(
    /// Error generated by the destination AS in response to a packet that cannot be delivered to
    /// its destination address for reasons other than congestion.
    pub struct ScmpDestinationUnreachable: DestinationUnreachable {
        /// Encodes the reason why the destination is unreachable.
        pub code: ScmpDestinationUnreachableCode,
    }
);
impl ScmpDestinationUnreachable {
    /// Create a new SCMP DestinationUnreachable message from a view.
    pub fn from_view(view: &ScmpDestinationUnreachableMessageView) -> Self {
        Self {
            code: view.code(),
            offending_packet: view.offending_packet().to_vec(),
        }
    }
}
impl ScmpWireEncode for ScmpDestinationUnreachable {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        ScmpDestinationUnreachableLayout::from_offending_packet_length(
            self.offending_packet.len(),
            header_and_extensions_size,
        )
        .size_bytes()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use ScmpDestinationUnreachableLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::DestinationUnreachable.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, self.code.into());
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write(buf, L::RESERVED_RNG, 0u32);

            let l = L::from_offending_packet_length(
                self.offending_packet.len(),
                header_and_extensions_size,
            );
            let message_length = l.size_bytes();
            let range = l.offending_packet_rng().aligned_byte_range();

            let offending_packet_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.offending_packet[..offending_packet_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..message_length],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            message_length
        }
    }
}

error_message!(
    /// Error sent in response to a packet that cannot be forwarded because it is larger than the
    /// MTU of the outgoing link.
    pub struct ScmpPacketTooBig: PacketTooBig {
        /// The Maximum Transmission Unit of the next-hop link.
        pub mtu: u16,
    }
);
impl ScmpPacketTooBig {
    /// Create a new SCMP PacketTooBig message from a view.
    pub fn from_view(view: &ScmpPacketTooBigMessageView) -> Self {
        Self {
            mtu: view.mtu(),
            offending_packet: view.offending_packet().to_vec(),
        }
    }
}
impl ScmpWireEncode for ScmpPacketTooBig {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        ScmpPacketTooBigLayout::from_offending_packet_length(
            self.offending_packet.len(),
            header_and_extensions_size,
        )
        .size_bytes()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use ScmpPacketTooBigLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::PacketTooBig.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::RESERVED_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::MTU_RNG, self.mtu);

            let l = L::from_offending_packet_length(
                self.offending_packet.len(),
                header_and_extensions_size,
            );
            let message_length = l.size_bytes();
            let range = l.offending_packet_rng().aligned_byte_range();

            let offending_packet_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.offending_packet[..offending_packet_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..message_length],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            message_length
        }
    }
}

error_message!(
    /// Error sent by an on-path AS in response to a packet with problems in any of the SCION
    /// headers.
    pub struct ScmpParameterProblem: ParameterProblem {
        /// Encodes the specific parameter problem.
        pub code: ScmpParameterProblemCode,
        /// Byte offset in the offending packet where the error was detected.
        ///
        /// Can point beyond the end of the SCMP packet if the offending byte is in the part of the
        /// original packet that does not fit in the data block.
        pub pointer: u16,
    }
);
impl ScmpParameterProblem {
    /// Create a new SCMP ParameterProblem message from a view.
    pub fn from_view(view: &ScmpParameterProblemMessageView) -> Self {
        Self {
            code: view.code(),
            pointer: view.pointer(),
            offending_packet: view.offending_packet().to_vec(),
        }
    }
}
impl ScmpWireEncode for ScmpParameterProblem {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        ScmpParameterProblemLayout::from_offending_packet_length(
            self.offending_packet.len(),
            header_and_extensions_size,
        )
        .size_bytes()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use ScmpParameterProblemLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::ParameterProblem.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, self.code.into());
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::RESERVED_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::POINTER_RNG, self.pointer);

            let l = L::from_offending_packet_length(
                self.offending_packet.len(),
                header_and_extensions_size,
            );
            let message_length = l.size_bytes();
            let range = l.offending_packet_rng().aligned_byte_range();

            let offending_packet_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.offending_packet[..offending_packet_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..message_length],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            message_length
        }
    }
}

error_message!(
    /// Error sent by a router in response to a packet that cannot be forwarded because the link to
    /// an external AS broken.
    pub struct ScmpExternalInterfaceDown: ExternalInterfaceDown {
        /// The ISD-AS number of the originating router.
        pub isd_asn: IsdAsn,
        /// The interface ID of the external link with connectivity issue.
        pub interface_id: u16,
    }
);
impl ScmpExternalInterfaceDown {
    /// Create a new SCMP ExternalInterfaceDown message from a view.
    pub fn from_view(view: &ScmpExternalInterfaceDownMessageView) -> Self {
        Self {
            isd_asn: view.isd_asn(),
            interface_id: view.interface_id() as u16,
            offending_packet: view.offending_packet().to_vec(),
        }
    }
}
impl ScmpWireEncode for ScmpExternalInterfaceDown {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        ScmpExternalInterfaceDownLayout::from_offending_packet_length(
            self.offending_packet.len(),
            header_and_extensions_size,
        )
        .size_bytes()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use ScmpExternalInterfaceDownLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::ExternalInterfaceDown.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u64>(buf, L::ISD_AS_RNG, self.isd_asn.to_u64());
            unchecked_bit_range_be_write::<u64>(buf, L::INTERFACE_ID_RNG, self.interface_id as u64);

            let l = L::from_offending_packet_length(
                self.offending_packet.len(),
                header_and_extensions_size,
            );
            let message_length = l.size_bytes();
            let range = l.offending_packet_rng().aligned_byte_range();

            let offending_packet_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.offending_packet[..offending_packet_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..message_length],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            message_length
        }
    }
}

error_message!(
    /// Error sent by a router in response to a packet that cannot be forwarded because the link to
    /// an internal AS broken.
    pub struct ScmpInternalConnectivityDown: InternalConnectivityDown {
        /// The ISD-AS number of the originating router.
        pub isd_asn: IsdAsn,
        /// The interface ID of the ingress link.
        pub ingress_interface_id: u16,
        /// The interface ID of the egress link.
        pub egress_interface_id: u16,
    }
);
impl ScmpInternalConnectivityDown {
    /// Create a new SCMP InternalConnectivityDown message from a view.
    pub fn from_view(view: &ScmpInternalConnectivityDownMessageView) -> Self {
        Self {
            isd_asn: view.isd_asn(),
            ingress_interface_id: view.ingress_interface_id() as u16,
            egress_interface_id: view.egress_interface_id() as u16,
            offending_packet: view.offending_packet().to_vec(),
        }
    }
}
impl ScmpWireEncode for ScmpInternalConnectivityDown {
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        ScmpInternalConnectivityDownLayout::from_offending_packet_length(
            self.offending_packet.len(),
            header_and_extensions_size,
        )
        .size_bytes()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use ScmpInternalConnectivityDownLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::InternalConnectivityDown.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u64>(buf, L::ISD_AS_RNG, self.isd_asn.to_u64());
            unchecked_bit_range_be_write::<u64>(
                buf,
                L::INGRESS_INTERFACE_ID_RNG,
                self.ingress_interface_id as u64,
            );
            unchecked_bit_range_be_write::<u64>(
                buf,
                L::EGRESS_INTERFACE_ID_RNG,
                self.egress_interface_id as u64,
            );

            let l = L::from_offending_packet_length(
                self.offending_packet.len(),
                header_and_extensions_size,
            );
            let message_length = l.size_bytes();
            let range = l.offending_packet_rng().aligned_byte_range();

            let offending_packet_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.offending_packet[..offending_packet_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..message_length],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            message_length
        }
    }
}

// ------------------------------------------------------------------------------------------------
//
// Informational Messages
//
// ------------------------------------------------------------------------------------------------

macro_rules! informational_message {
    (
        $(#[$outer:meta])*
        $message_type:ident => pub struct $name:ident {$($(#[$doc:meta])* $vis:vis $field:ident : $type:ty,)*}
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            /// A 16-bit identifier to aid matching replies with requests.
            pub identifier: u16,
            /// A 16-bit sequence number to aid matching replies with requests.
            pub sequence_number: u16,
            $($(#[$doc])* $vis $field: $type,)*
        }

        impl $name {
            /// Create a new message with the corresponding values and an unset checksum.
            pub fn new(identifier: u16, sequence_number: u16, $($field: $type,)*) -> Self {
                Self {
                    identifier,
                    sequence_number,
                    $($field,)*
                }
            }
        }

        impl From<$name> for ScmpInformationalMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }
        impl From<$name> for ScmpMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }
    };
}

informational_message!(
    /// Echo request to the destination to support ping functionality, equivalent to the
    /// corresponding ICMP message.
    EchoRequest => pub struct ScmpEchoRequest {
        /// Arbitrary data to be echoed by the destination.
        pub data: Vec<u8>,
    }
);
impl ScmpEchoRequest {
    /// Create a new SCMP EchoRequest message from a view.
    pub fn from_view(view: &ScmpEchoRequestMessageView) -> Self {
        Self {
            identifier: view.identifier(),
            sequence_number: view.sequence_number(),
            data: view.data().to_vec(),
        }
    }
}
impl ScmpEchoRequest {
    /// Returns the required size of the SCMP EchoRequest message.
    pub fn required_size(&self) -> usize {
        ScmpEchoRequestLayout::from_data_length(self.data.len()).size_bytes()
    }

    /// Encodes the SCMP EchoRequest message into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long.
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], address_header: &AddressHeader) -> usize {
        use ScmpEchoRequestLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::EchoRequest.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::IDENTIFIER_RNG, self.identifier);
            unchecked_bit_range_be_write::<u16>(buf, L::SEQUENCE_NUMBER_RNG, self.sequence_number);
            let layout = L::from_data_length(self.data.len());
            let range = layout.data_rng().aligned_byte_range();
            let included_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.data[..included_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..self.required_size()],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            self.required_size()
        }
    }

    /// Encodes the SCMP EchoRequest message into the provided buffer.
    pub fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }
        Ok(unsafe { self.encode_unchecked(buf, address_header) })
    }
}

informational_message!(
    /// Echo reply to support ping functionality, equivalent to the corresponding ICMP message.
    EchoReply => pub struct ScmpEchoReply {
        /// The data of the corresponding [`ScmpEchoRequest`].
        pub data: Vec<u8>,
    }
);
impl ScmpEchoReply {
    /// Create a new SCMP EchoReply message from a view.
    pub fn from_view(view: &ScmpEchoReplyMessageView) -> Self {
        Self {
            identifier: view.identifier(),
            sequence_number: view.sequence_number(),
            data: view.data().to_vec(),
        }
    }
}
impl ScmpEchoReply {
    /// Returns the required size of the SCMP EchoReply message.
    pub fn required_size(&self) -> usize {
        ScmpEchoReplyLayout::from_data_length(self.data.len()).size_bytes()
    }

    /// Encodes the SCMP EchoReply message into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long.
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], address_header: &AddressHeader) -> usize {
        use ScmpEchoReplyLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(buf, L::TYPE_RNG, ScmpMessageType::EchoReply.into());
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::IDENTIFIER_RNG, self.identifier);
            unchecked_bit_range_be_write::<u16>(buf, L::SEQUENCE_NUMBER_RNG, self.sequence_number);
            let layout = L::from_data_length(self.data.len());
            let range = layout.data_rng().aligned_byte_range();
            let included_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.data[..included_len]);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..self.required_size()],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            self.required_size()
        }
    }

    /// Encodes the SCMP EchoReply message into the provided buffer.
    pub fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }
        Ok(unsafe { self.encode_unchecked(buf, address_header) })
    }
}

informational_message!(
    /// Request to an on-path router to support traceroute functionality.
    TracerouteRequest => pub struct ScmpTracerouteRequest {}
);
impl ScmpTracerouteRequest {
    /// Create a new SCMP TracerouteRequest message from a view.
    pub fn from_view(view: &ScmpTracerouteRequestMessageView) -> Self {
        Self {
            identifier: view.identifier(),
            sequence_number: view.sequence_number(),
        }
    }
}
impl ScmpTracerouteRequest {
    /// Returns the required size of the SCMP TracerouteRequest message.
    pub fn required_size(&self) -> usize {
        ScmpTracerouteRequestLayout.size_bytes()
    }

    /// Encodes the SCMP TracerouteRequest message into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long.
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], address_header: &AddressHeader) -> usize {
        use ScmpTracerouteRequestLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::TracerouteRequest.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::IDENTIFIER_RNG, self.identifier);
            unchecked_bit_range_be_write::<u16>(buf, L::SEQUENCE_NUMBER_RNG, self.sequence_number);
            // Placeholders set to 0 by the sender, see SCMP specification.
            unchecked_bit_range_be_write::<u64>(buf, L::ISD_AS_RNG, 0u64);
            unchecked_bit_range_be_write::<u64>(buf, L::INTERFACE_ID_RNG, 0u64);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..self.required_size()],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            self.required_size()
        }
    }

    /// Encodes the SCMP TracerouteRequest message into the provided buffer.
    pub fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }
        Ok(unsafe { self.encode_unchecked(buf, address_header) })
    }
}

informational_message!(
    /// Reply by an on-path router to support traceroute functionality.
    TracerouteReply => pub struct ScmpTracerouteReply {
        /// The ISD-AS number of the originating router.
        pub isd_asn: IsdAsn,
        /// The interface ID of the originating router.
        pub interface_id: u16,
    }
);
impl ScmpTracerouteReply {
    /// Create a new SCMP TracerouteReply message from a view.
    pub fn from_view(view: &ScmpTracerouteReplyMessageView) -> Self {
        Self {
            identifier: view.identifier(),
            sequence_number: view.sequence_number(),
            isd_asn: view.isd_asn(),
            interface_id: view.interface_id() as u16,
        }
    }
}
impl ScmpTracerouteReply {
    /// Returns the required size of the SCMP TracerouteReply message.
    pub fn required_size(&self) -> usize {
        ScmpTracerouteReplyLayout.size_bytes()
    }

    /// Encodes the SCMP TracerouteReply message into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long.
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], address_header: &AddressHeader) -> usize {
        use ScmpTracerouteReplyLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                buf,
                L::TYPE_RNG,
                ScmpMessageType::TracerouteReply.into(),
            );
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, 0u8);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);
            unchecked_bit_range_be_write::<u16>(buf, L::IDENTIFIER_RNG, self.identifier);
            unchecked_bit_range_be_write::<u16>(buf, L::SEQUENCE_NUMBER_RNG, self.sequence_number);
            unchecked_bit_range_be_write::<u64>(buf, L::ISD_AS_RNG, self.isd_asn.to_u64());
            unchecked_bit_range_be_write::<u64>(buf, L::INTERFACE_ID_RNG, self.interface_id as u64);

            // Calculate and set the checksum.
            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..self.required_size()],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
            self.required_size()
        }
    }

    /// Encodes the SCMP TracerouteReply message into the provided buffer.
    pub fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }
        Ok(unsafe { self.encode_unchecked(buf, address_header) })
    }
}

/// An unknown SCMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmpMessageUnknown {
    /// The type of the SCMP message.
    pub message_type: u8,
    /// The code of the SCMP message.
    pub code: u8,
    /// The message specific payload of the SCMP message.
    pub message_specific_data: Vec<u8>,
}
impl ScmpMessageUnknown {
    /// Create a new unknown SCMP message.
    pub fn new(message_type: u8, code: u8, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            code,
            message_specific_data: payload,
        }
    }

    /// Create a new unknown SCMP message from a view.
    pub fn from_view(view: &ScmpUnknownMessageView) -> Self {
        Self {
            message_type: view.message_type(),
            code: view.code(),
            message_specific_data: view.message_specific_data().to_vec(),
        }
    }
}
impl ScmpMessageUnknown {
    /// Returns the required size of the SCMP Unknown message.
    pub fn required_size(&self) -> usize {
        ScmpUnknownMessageLayout::from_message_specific_data_length(
            self.message_specific_data.len(),
        )
        .size_bytes()
    }

    /// Encodes the SCMP Unknown message into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long.
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], address_header: &AddressHeader) -> usize {
        use ScmpUnknownMessageLayout as L;

        unsafe {
            unchecked_bit_range_be_write::<u8>(buf, L::TYPE_RNG, self.message_type);
            unchecked_bit_range_be_write::<u8>(buf, L::CODE_RNG, self.code);
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);

            let layout = ScmpUnknownMessageLayout::from_message_specific_data_length(
                self.message_specific_data.len(),
            );

            let range = layout.message_specific_data_rng().aligned_byte_range();
            let data_len = range.end - range.start;
            buf.get_unchecked_mut(range)
                .copy_from_slice(&self.message_specific_data[..data_len]);

            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                SCMP_PROTOCOL_NUMBER,
                &buf[0..layout.size_bytes()],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);

            layout.size_bytes()
        }
    }

    /// Encodes the SCMP Unknown message into the provided buffer.
    pub fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }
        Ok(unsafe { self.encode_unchecked(buf, address_header) })
    }
}
impl From<ScmpMessageUnknown> for ScmpMessage {
    fn from(value: ScmpMessageUnknown) -> Self {
        Self::Unknown(value)
    }
}
