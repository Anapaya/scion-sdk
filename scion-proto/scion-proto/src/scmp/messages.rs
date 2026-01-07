// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
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

//! Specific individual SCMP messages and their types.

use std::fmt::{Display, Pointer};

use bytes::{Buf, BufMut, Bytes};

use super::{SCMP_PROTOCOL_NUMBER, ScmpDecodeError, ScmpMessageBase, ScmpMessageRaw};
use crate::{
    address::IsdAsn,
    packet::{AddressHeader, ChecksumDigest, InadequateBufferSize, MessageChecksum},
    utils::encoded_type,
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// Fully decoded SCMP message with an appropriate format.
///
/// The different variants correspond to the [`ScmpType`] variants.
///
/// There is an [`UnknownError`][Self::UnknownError] variant, but no `UnknownInformational`, because
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
    UnknownError(ScmpMessageRaw),
}

/// Fully decoded SCMP error message with an appropriate format.
///
/// The different variants correspond to the [`ScmpType`] variants.
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
    /// An SCMP error message whose type is unknown.
    ///
    /// This is needed because the specification states:
    /// "If an SCMP error message of unknown type is received at its destination, it MUST be passed
    /// to the upper-layer process that originated the packet that caused the error, if it can be
    /// identified."
    Unknown(ScmpMessageRaw),
}

impl From<ScmpErrorMessage> for ScmpMessage {
    fn from(value: ScmpErrorMessage) -> Self {
        match value {
            ScmpErrorMessage::DestinationUnreachable(x) => Self::DestinationUnreachable(x),
            ScmpErrorMessage::PacketTooBig(x) => Self::PacketTooBig(x),
            ScmpErrorMessage::ParameterProblem(x) => Self::ParameterProblem(x),
            ScmpErrorMessage::ExternalInterfaceDown(x) => Self::ExternalInterfaceDown(x),
            ScmpErrorMessage::InternalConnectivityDown(x) => Self::InternalConnectivityDown(x),
            ScmpErrorMessage::Unknown(x) => Self::UnknownError(x),
        }
    }
}

/// Fully decoded SCMP informational message with an appropriate format.
///
/// The different variants correspond to the [`ScmpType`] variants.
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

macro_rules! call_method_on_scmp_variants {
    ($self:ident.$name:ident($($param:ident),*)) => {
        match $self {
            Self::DestinationUnreachable(x) => x.$name($($param),*),
            Self::PacketTooBig(x) => x.$name($($param),*),
            Self::ParameterProblem(x) => x.$name($($param),*),
            Self::ExternalInterfaceDown(x) => x.$name($($param),*),
            Self::InternalConnectivityDown(x) => x.$name($($param),*),
            Self::EchoRequest(x) => x.$name($($param),*),
            Self::EchoReply(x) => x.$name($($param),*),
            Self::TracerouteRequest(x) => x.$name($($param),*),
            Self::TracerouteReply(x) => x.$name($($param),*),
            Self::UnknownError(x) => x.$name($($param),*),
        }
    };
}

macro_rules! call_method_on_scmp_error_variants {
    ($self:ident.$name:ident($($param:ident),*)) => {
        match $self {
            Self::DestinationUnreachable(x) => x.$name($($param),*),
            Self::PacketTooBig(x) => x.$name($($param),*),
            Self::ParameterProblem(x) => x.$name($($param),*),
            Self::ExternalInterfaceDown(x) => x.$name($($param),*),
            Self::InternalConnectivityDown(x) => x.$name($($param),*),
            Self::Unknown(x) => x.$name($($param),*),
        }
    };
}

macro_rules! call_method_on_scmp_info_variants {
    ($self:ident.$name:ident($($param:ident),*)) => {
        match $self {
            Self::EchoRequest(x) => x.$name($($param),*),
            Self::EchoReply(x) => x.$name($($param),*),
            Self::TracerouteRequest(x) => x.$name($($param),*),
            Self::TracerouteReply(x) => x.$name($($param),*),
        }
    };
}

macro_rules! lift_fn_from_scmp_variants {
    (all; $($x:tt)*) => {
        lift_fn_from_scmp_variants!(call_method_on_scmp_variants; $($x)*);
    };
    (error; $($x:tt)*) => {
        lift_fn_from_scmp_variants!(call_method_on_scmp_error_variants; $($x)*);
    };
    (info; $($x:tt)*) => {
        lift_fn_from_scmp_variants!(call_method_on_scmp_info_variants; $($x)*);
    };
    (
        $call_method:ident;
        $(#[$outer:meta])*
        $vis:vis fn $name:ident(self$(: $self_ty:ty)? $(,$param:ident : $param_type:ty)*) $(-> $ret_ty:ty)?
    ) => {
        $(#[$outer])*
        $vis fn $name(self$(: $self_ty)? $(,$param : $param_type)*) $(-> $ret_ty)? {
            $call_method!(self.$name($($param),*))
        }
    };
}

macro_rules! implement_methods_for_scmp_enum {
    (
        $name:ident, $call_method:ident
    ) => {
        impl ScmpMessageBase for $name {
            lift_fn_from_scmp_variants!(
                $call_method;
                fn get_type(self: &Self) -> ScmpType
            );

            lift_fn_from_scmp_variants!(
                $call_method;
                fn code(self: &Self) -> u8
            );
        }

        impl Display for $name {
            lift_fn_from_scmp_variants!(
                $call_method;
                fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
            );
        }

        impl<T: Buf> WireDecode<T> for $name {
            type Error = ScmpDecodeError;

            fn decode(data: &mut T) -> Result<Self, Self::Error> {
                ScmpMessageRaw::decode(data)?.try_into()
            }
        }

        impl WireEncodeVec<2> for $name {
            type Error = InadequateBufferSize;

            lift_fn_from_scmp_variants!(
                $call_method;
                fn encode_with_unchecked(self: &Self, buffer: &mut bytes::BytesMut) -> [Bytes; 2]
            );

            lift_fn_from_scmp_variants!(
                $call_method;
                fn total_length(self: &Self) -> usize
            );

            lift_fn_from_scmp_variants!(
                $call_method;
                fn required_capacity(self: &Self) -> usize
            );
        }

        impl MessageChecksum for $name {
            lift_fn_from_scmp_variants!(
                $call_method;
                fn checksum(self: &Self) -> u16
            );

            lift_fn_from_scmp_variants!(
                $call_method;
                fn set_checksum(self: &mut Self, address_header: &AddressHeader)
            );


            lift_fn_from_scmp_variants!(
                $call_method;
                fn calculate_checksum(self: &Self, address_header: &AddressHeader) -> u16
            );
        }
    };
}

implement_methods_for_scmp_enum!(ScmpMessage, all);
implement_methods_for_scmp_enum!(ScmpErrorMessage, error);
implement_methods_for_scmp_enum!(ScmpInformationalMessage, info);

impl ScmpMessage {
    /// Returns true for all supported SCMP messages and false otherwise.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::UnknownError(_))
    }
}

impl ScmpErrorMessage {
    /// Returns true for all supported SCMP error messages and false otherwise.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// Get the (truncated) packet that triggered the error.
    ///
    /// For [`ScmpErrorMessage::Unknown`] instances, the whole message payload is returned.
    pub fn get_offending_packet(&self) -> Bytes {
        match self {
            ScmpErrorMessage::DestinationUnreachable(x) => x.get_offending_packet(),
            ScmpErrorMessage::PacketTooBig(x) => x.get_offending_packet(),
            ScmpErrorMessage::ParameterProblem(x) => x.get_offending_packet(),
            ScmpErrorMessage::ExternalInterfaceDown(x) => x.get_offending_packet(),
            ScmpErrorMessage::InternalConnectivityDown(x) => x.get_offending_packet(),
            ScmpErrorMessage::Unknown(x) => x.payload.clone(),
        }
    }
}

impl ScmpInformationalMessage {
    lift_fn_from_scmp_variants!(
        info;

        /// Get the message's identifier.
        pub fn get_identifier(self: &Self) -> u16
    );

    lift_fn_from_scmp_variants!(
        info;
        /// Get the message's sequence number.
        pub fn get_sequence_number(self: &Self) -> u16
    );

    lift_fn_from_scmp_variants!(
        info;
        /// Get the combination of the message's identifier and sequence number.
        ///
        /// This can be used to match reply messages to their corresponding requests.
        pub fn get_message_id(self: &Self) -> u32
    );

    lift_fn_from_scmp_variants!(
        info;
        /// Encodes the identifier and sequence number to the provided buffer.
        pub fn encode_message_id_unchecked(self: &Self, buffer: &mut impl BufMut)
    );
}

impl TryFrom<ScmpMessageRaw> for ScmpMessage {
    type Error = ScmpDecodeError;

    fn try_from(value: ScmpMessageRaw) -> Result<Self, Self::Error> {
        Ok(match value.message_type {
            ScmpType::DestinationUnreachable => {
                Self::DestinationUnreachable(ScmpDestinationUnreachable::try_from(value)?)
            }
            ScmpType::PacketTooBig => Self::PacketTooBig(ScmpPacketTooBig::try_from(value)?),
            ScmpType::ParameterProblem => {
                Self::ParameterProblem(ScmpParameterProblem::try_from(value)?)
            }
            ScmpType::ExternalInterfaceDown => {
                Self::ExternalInterfaceDown(ScmpExternalInterfaceDown::try_from(value)?)
            }
            ScmpType::InternalConnectivityDown => {
                Self::InternalConnectivityDown(ScmpInternalConnectivityDown::try_from(value)?)
            }
            ScmpType::EchoRequest => Self::EchoRequest(ScmpEchoRequest::try_from(value)?),
            ScmpType::EchoReply => Self::EchoReply(ScmpEchoReply::try_from(value)?),
            ScmpType::TracerouteRequest => {
                Self::TracerouteRequest(ScmpTracerouteRequest::try_from(value)?)
            }
            ScmpType::TracerouteReply => {
                Self::TracerouteReply(ScmpTracerouteReply::try_from(value)?)
            }
            ScmpType::OtherError(_) => Self::UnknownError(value),
            ScmpType::OtherInfo(t) => return Err(ScmpDecodeError::UnknownInfoMessage(t)),
        })
    }
}

/// Error returned when attempting to convert a SCMP message to an SCMP error message but the
/// message is not an SCMP error message.
#[derive(Debug, thiserror::Error)]
#[error("not an SCMP error message")]
pub struct NotAnScmpErrorMessage;

impl TryFrom<ScmpMessage> for ScmpErrorMessage {
    type Error = NotAnScmpErrorMessage;

    fn try_from(value: ScmpMessage) -> Result<Self, Self::Error> {
        match value {
            ScmpMessage::DestinationUnreachable(x) => {
                Ok(ScmpErrorMessage::DestinationUnreachable(x))
            }
            ScmpMessage::PacketTooBig(x) => Ok(ScmpErrorMessage::PacketTooBig(x)),
            ScmpMessage::ParameterProblem(x) => Ok(ScmpErrorMessage::ParameterProblem(x)),
            ScmpMessage::ExternalInterfaceDown(x) => Ok(ScmpErrorMessage::ExternalInterfaceDown(x)),
            ScmpMessage::InternalConnectivityDown(x) => {
                Ok(ScmpErrorMessage::InternalConnectivityDown(x))
            }
            ScmpMessage::UnknownError(x) => Ok(ScmpErrorMessage::Unknown(x)),
            _ => Err(NotAnScmpErrorMessage),
        }
    }
}

impl TryFrom<ScmpMessageRaw> for ScmpErrorMessage {
    type Error = ScmpDecodeError;

    fn try_from(value: ScmpMessageRaw) -> Result<Self, Self::Error> {
        Ok(match value.message_type {
            ScmpType::DestinationUnreachable => {
                Self::DestinationUnreachable(ScmpDestinationUnreachable::try_from(value)?)
            }
            ScmpType::PacketTooBig => Self::PacketTooBig(ScmpPacketTooBig::try_from(value)?),
            ScmpType::ParameterProblem => {
                Self::ParameterProblem(ScmpParameterProblem::try_from(value)?)
            }
            ScmpType::ExternalInterfaceDown => {
                Self::ExternalInterfaceDown(ScmpExternalInterfaceDown::try_from(value)?)
            }
            ScmpType::InternalConnectivityDown => {
                Self::InternalConnectivityDown(ScmpInternalConnectivityDown::try_from(value)?)
            }
            ScmpType::OtherError(_) => Self::Unknown(value),
            _ => return Err(ScmpDecodeError::MessageTypeMismatch),
        })
    }
}

impl TryFrom<ScmpMessageRaw> for ScmpInformationalMessage {
    type Error = ScmpDecodeError;

    fn try_from(value: ScmpMessageRaw) -> Result<Self, Self::Error> {
        Ok(match value.message_type {
            ScmpType::EchoRequest => Self::EchoRequest(ScmpEchoRequest::try_from(value)?),
            ScmpType::EchoReply => Self::EchoReply(ScmpEchoReply::try_from(value)?),
            ScmpType::TracerouteRequest => {
                Self::TracerouteRequest(ScmpTracerouteRequest::try_from(value)?)
            }
            ScmpType::TracerouteReply => {
                Self::TracerouteReply(ScmpTracerouteReply::try_from(value)?)
            }
            ScmpType::OtherInfo(t) => return Err(ScmpDecodeError::UnknownInfoMessage(t)),
            _ => return Err(ScmpDecodeError::MessageTypeMismatch),
        })
    }
}

trait ScmpMessageEncodeDecode: ScmpMessageBase + MessageChecksum + Sized {
    const INFO_BLOCK_LENGTH: usize;

    #[allow(unused_variables)]
    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {}

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest
    }

    fn data_block(&self) -> Bytes {
        Bytes::new()
    }

    fn check_code(code: u8) -> Result<(), ScmpDecodeError> {
        if code != 0 {
            return Err(ScmpDecodeError::InvalidCode);
        }
        Ok(())
    }

    /// This assumes that the function argument has the correct type and checksum and a valid code
    /// for this message type.
    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self;
}

impl<T: ScmpMessageEncodeDecode> WireEncodeVec<2> for T {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 2] {
        buffer.put_u8(self.get_type().into());
        buffer.put_u8(self.code());
        buffer.put_u16(self.checksum());
        self.encode_info_block_unchecked(buffer);
        [buffer.split().freeze(), self.data_block()]
    }

    #[inline]
    fn total_length(&self) -> usize {
        self.required_capacity() + self.data_block().len()
    }

    #[inline]
    fn required_capacity(&self) -> usize {
        ScmpMessageRaw::FIELD_LENGTH + Self::INFO_BLOCK_LENGTH
    }
}

macro_rules! impl_conversion_and_type {
    (
        $name:ident : $message_type:ident
        $(;$code_field:ident)?

    ) => {
        impl $name {
            /// The SCMP type of this message type.
            pub const MESSAGE_TYPE: ScmpType = ScmpType::$message_type;

            fn try_from(value: ScmpMessageRaw) -> Result<Self, ScmpDecodeError> {
                if value.message_type != Self::MESSAGE_TYPE {
                    return Err(ScmpDecodeError::MessageTypeMismatch);
                }
                Self::check_code(value.code)?;
                if value.payload.len() < Self::INFO_BLOCK_LENGTH {
                    return Err(ScmpDecodeError::MessageEmptyOrTruncated);
                }
                Ok(Self::from_raw_unchecked(value))
            }
        }

        impl TryFrom<ScmpMessage> for $name {
            type Error = ScmpDecodeError;

            fn try_from(value: ScmpMessage) -> Result<Self, Self::Error> {
                if let ScmpMessage::$message_type(m) = value {
                    Ok(m)
                } else {
                    Err(ScmpDecodeError::MessageTypeMismatch)
                }
            }
        }

        impl From<$name> for ScmpMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }

        impl ScmpMessageBase for $name {
            fn get_type(&self) -> ScmpType {
                Self::MESSAGE_TYPE
            }

            $(
                fn code(&self) -> u8 {
                    self.$code_field.into()
                }
            )?
        }

        impl MessageChecksum for $name {
            fn checksum(&self) -> u16 {
                self.checksum
            }

            fn set_checksum(&mut self, address_header: &AddressHeader) {
                self.checksum = 0;
                self.checksum = self.calculate_checksum(address_header);
            }


            fn calculate_checksum(&self, address_header: &AddressHeader) -> u16 {
                self.info_block_checksum(
                    ChecksumDigest::with_pseudoheader(
                        address_header,
                        SCMP_PROTOCOL_NUMBER,
                        self.total_length()
                            .try_into()
                            .expect("this never returns anything above `u32::MAX`"),
                    )
                    .add_u16((u8::from(self.get_type()) as u16) << 8 | self.code() as u16)
                    .add_u16(self.checksum()),
                )
                .add_slice(self.data_block().as_ref())
                .checksum()
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

macro_rules! error_message {
    (
        $(#[$outer:meta])*
        pub struct $name:ident : $message_type:ident {
            $($(#[$doc:meta])* $vis:vis $field:ident : $type:ty,)*
        }
        $(;code = self.$code_field:ident)?
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $($(#[$doc])* $vis $field: $type,)*
            /// The (truncated) packet that triggered the error.
            offending_packet: Bytes,
            checksum: u16,
        }

        impl $name {
            /// Create a new message with the corresponding values and an unset checksum.
            pub fn new($($field: $type,)* offending_packet: Bytes) -> Self {
                Self{
                    $($field,)*
                    offending_packet,
                    checksum: 0,
                }
            }

            /// Get the (truncated) packet that triggered the error.
            #[inline]
            pub fn get_offending_packet(&self) -> Bytes {
                self.offending_packet.clone()
            }
        }

        impl From<$name> for ScmpErrorMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }

        impl_conversion_and_type!($name: $message_type $(;$code_field)?);
    };
}

encoded_type!(
    #[allow(missing_docs)]
    pub enum DestinationUnreachableCode(u8) {
        NoRouteToDestination = 0,
        CommunicationAdministrativelyDenied = 1,
        BeyondScopeOfSourceAddress = 2,
        AddressUnreachable = 3,
        PortUnreachable = 4,
        SourceAddressFailedIngressEgressPolicy = 5,
        RejectRouteToDestination = 6;
        Unassigned = 7..=u8::MAX,
    }
);
error_message!(
    /// Error generated by the destination AS in response to a packet that cannot be delivered to
    /// its destination address for reasons other than congestion.
    pub struct ScmpDestinationUnreachable: DestinationUnreachable {
        /// Encodes the reason why the destination is unreachable.
        pub code: DestinationUnreachableCode,
    };
    code = self.code
);
impl ScmpMessageEncodeDecode for ScmpDestinationUnreachable {
    const INFO_BLOCK_LENGTH: usize = 4;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        buffer.put_u32(0); // unused field
    }

    fn data_block(&self) -> Bytes {
        self.offending_packet.clone()
    }

    fn check_code(_code: u8) -> Result<(), ScmpDecodeError> {
        Ok(())
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut offending_packet = value.payload.clone();
        offending_packet.advance(Self::INFO_BLOCK_LENGTH); // unused field
        Self {
            code: DestinationUnreachableCode::from(value.code),
            offending_packet,
            checksum: value.checksum,
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
impl ScmpMessageEncodeDecode for ScmpPacketTooBig {
    const INFO_BLOCK_LENGTH: usize = 4;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        buffer.put_u16(0); // reserved field
        buffer.put_u16(self.mtu);
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest.add_u16(self.mtu)
    }

    fn data_block(&self) -> Bytes {
        self.offending_packet.clone()
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        payload.advance(2); // reserved field
        let mtu = payload.get_u16();
        Self {
            mtu,
            offending_packet: payload,
            checksum: value.checksum,
        }
    }
}

encoded_type!(
    #[allow(missing_docs)]
    pub enum ParameterProblemCode(u8) {
        ErroneousHeaderField = 0,
        UnknownNextHdrType = 1,
        InvalidCommonHeader = 16,
        UnknownScionVersion = 17,
        FlowIdRequired = 18,
        InvalidPacketSize = 19,
        UnknownPathType = 20,
        UnknownAddressFormat = 21,
        InvalidAddressHeader = 32,
        InvalidSourceAddress = 33,
        InvalidDestinationAddress = 34,
        NonLocalDelivery = 35,
        InvalidPath = 48,
        UnknownHopFieldConsIngressInterface = 49,
        UnknownHopFieldConsEgressInterface = 50,
        InvalidHopFieldMac = 51,
        PathExpired = 52,
        InvalidSegmentChange = 53,
        InvalidExtensionHeader = 64,
        UnknownHopByHopOption = 65,
        UnknownEndToEndOption = 66;
        Unassigned = _,
    }
);
error_message!(
    /// Error sent by an on-path AS in response to a packet with problems in any of the SCION
    /// headers.
    pub struct ScmpParameterProblem: ParameterProblem {
        /// Encodes the specific parameter problem.
        pub code: ParameterProblemCode,
        /// Byte offset in the offending packet where the error was detected.
        ///
        /// Can point beyond the end of the SCMP packet if the offending byte is in the part of the
        /// original packet that does not fit in the data block.
        pub pointer: u16,
    };
    code = self.code
);
impl ScmpMessageEncodeDecode for ScmpParameterProblem {
    const INFO_BLOCK_LENGTH: usize = 4;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        buffer.put_u16(0); // reserved field
        buffer.put_u16(self.pointer);
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest.add_u16(self.pointer)
    }

    fn data_block(&self) -> Bytes {
        self.offending_packet.clone()
    }

    fn check_code(_code: u8) -> Result<(), ScmpDecodeError> {
        Ok(())
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        payload.advance(2); // reserved field
        let pointer = payload.get_u16();
        Self {
            code: ParameterProblemCode::from(value.code),
            pointer,
            offending_packet: payload,
            checksum: value.checksum,
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
        ///
        /// If the actual ID is shorter than 64 bits, it is stored in the least-significant bits
        /// of this field.
        pub interface_id: u64,
    }
);
impl ScmpMessageEncodeDecode for ScmpExternalInterfaceDown {
    const INFO_BLOCK_LENGTH: usize = 16;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        buffer.put_u64(self.isd_asn.into());
        buffer.put_u64(self.interface_id);
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest
            .add_u64(self.isd_asn.into())
            .add_u64(self.interface_id)
    }

    fn data_block(&self) -> Bytes {
        self.offending_packet.clone()
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        Self {
            isd_asn: payload.get_u64().into(),
            interface_id: payload.get_u64(),
            offending_packet: payload,
            checksum: value.checksum,
        }
    }
}

error_message!(
    /// Error sent by a router in response to a packet that cannot be forwarded inside the AS
    /// because the connectivity between the ingress and egress routers is broken.
    pub struct ScmpInternalConnectivityDown: InternalConnectivityDown {
        /// The ISD-AS number of the originating router.
        pub isd_asn: IsdAsn,
        /// The interface ID of the ingress link.
        ///
        /// If the actual ID is shorter than 64 bits, it is stored in the least-significant bits
        /// of this field.
        pub ingress_interface_id: u64,
        /// The interface ID of the egress link.
        ///
        /// If the actual ID is shorter than 64 bits, it is stored in the least-significant bits
        /// of this field.
        pub egress_interface_id: u64,
    }
);
impl ScmpMessageEncodeDecode for ScmpInternalConnectivityDown {
    const INFO_BLOCK_LENGTH: usize = 24;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        buffer.put_u64(self.isd_asn.into());
        buffer.put_u64(self.ingress_interface_id);
        buffer.put_u64(self.egress_interface_id);
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest
            .add_u64(self.isd_asn.into())
            .add_u64(self.ingress_interface_id)
            .add_u64(self.egress_interface_id)
    }

    fn data_block(&self) -> Bytes {
        self.offending_packet.clone()
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        Self {
            isd_asn: payload.get_u64().into(),
            ingress_interface_id: payload.get_u64(),
            egress_interface_id: payload.get_u64(),
            offending_packet: payload,
            checksum: value.checksum,
        }
    }
}

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
            checksum: u16,
        }

        impl $name {
            /// Create a new message with the corresponding values and an unset checksum.
            pub fn new(identifier: u16, sequence_number: u16, $($field: $type,)*) -> Self {
                Self {
                    identifier,
                    sequence_number,
                    $($field,)*
                    checksum: 0,
                }
            }

            /// Get the message's identifier.
            #[inline]
            pub fn get_identifier(&self) -> u16 {
                self.identifier
            }

            /// Get the message's sequence number.
            #[inline]
            pub fn get_sequence_number(&self) -> u16 {
                self.sequence_number
            }


            /// Get the combination of the message's identifier and sequence number.
            ///
            /// This can be used to match reply messages to their corresponding requests.
            #[inline]
            pub fn get_message_id(&self) -> u32 {
                (self.get_identifier() as u32) << 16 | self.get_sequence_number() as u32
            }

            /// Encodes the identifier and sequence number to the provided buffer.
            #[inline]
            pub fn encode_message_id_unchecked(&self, buffer: &mut impl BufMut) {
                buffer.put_u32(self.get_message_id());
            }
        }

        impl From<$name> for ScmpInformationalMessage {
            fn from(value: $name) -> Self {
                Self::$message_type(value)
            }
        }

        impl $name {
        }

        impl_conversion_and_type!($name: $message_type);
    };
}

macro_rules! impl_echo_request_and_reply {
    ($name:ident) => {
        impl ScmpMessageEncodeDecode for $name {
            const INFO_BLOCK_LENGTH: usize = 4;

            fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
                self.encode_message_id_unchecked(buffer)
            }

            fn info_block_checksum<'a>(
                &self,
                base_digest: &'a mut ChecksumDigest,
            ) -> &'a mut ChecksumDigest {
                base_digest
                    .add_u16(self.get_identifier())
                    .add_u16(self.get_sequence_number())
            }

            fn data_block(&self) -> Bytes {
                self.data.clone()
            }

            fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
                let mut payload = value.payload;
                Self {
                    identifier: payload.get_u16(),
                    sequence_number: payload.get_u16(),
                    data: payload,
                    checksum: value.checksum,
                }
            }
        }
    };
}

informational_message!(
    /// Echo request to the destination to support ping functionality, equivalent to the
    /// corresponding ICMP message.
    EchoRequest => pub struct ScmpEchoRequest {
        /// Arbitrary data to be echoed by the destination.
        pub data: Bytes,
    }
);
impl_echo_request_and_reply!(ScmpEchoRequest);

informational_message!(
    /// Echo reply to support ping functionality, equivalent to the corresponding ICMP message.
    EchoReply => pub struct ScmpEchoReply {
        /// The data of the corresponding [`ScmpEchoRequest`].
        pub data: Bytes,
    }
);
impl_echo_request_and_reply!(ScmpEchoReply);

informational_message!(
    /// Request to an on-path router to support traceroute functionality.
    TracerouteRequest => pub struct ScmpTracerouteRequest {}
);
impl ScmpMessageEncodeDecode for ScmpTracerouteRequest {
    const INFO_BLOCK_LENGTH: usize = 20;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        self.encode_message_id_unchecked(buffer);
        buffer.put_bytes(0, Self::INFO_BLOCK_LENGTH - 4)
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest
            .add_u16(self.get_identifier())
            .add_u16(self.get_sequence_number())
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        Self {
            identifier: payload.get_u16(),
            sequence_number: payload.get_u16(),
            checksum: value.checksum,
        }
    }
}

informational_message!(
    /// Reply by an on-path router to support traceroute functionality.
    TracerouteReply => pub struct ScmpTracerouteReply {
        /// The ISD-AS number of the originating router.
        pub isd_asn: IsdAsn,
        /// The interface ID of the originating router.
        ///
        /// If the actual ID is shorter than 64 bits, it is stored in the least-significant bits
        /// of this field.
        pub interface_id: u64,
    }
);
impl ScmpMessageEncodeDecode for ScmpTracerouteReply {
    const INFO_BLOCK_LENGTH: usize = 20;

    fn encode_info_block_unchecked(&self, buffer: &mut impl BufMut) {
        self.encode_message_id_unchecked(buffer);
        buffer.put_u64(self.isd_asn.into());
        buffer.put_u64(self.interface_id);
    }

    fn info_block_checksum<'a>(
        &self,
        base_digest: &'a mut ChecksumDigest,
    ) -> &'a mut ChecksumDigest {
        base_digest
            .add_u16(self.get_identifier())
            .add_u16(self.get_sequence_number())
            .add_u64(self.isd_asn.into())
            .add_u64(self.interface_id)
    }

    fn from_raw_unchecked(value: ScmpMessageRaw) -> Self {
        let mut payload = value.payload;
        Self {
            identifier: payload.get_u16(),
            sequence_number: payload.get_u16(),
            isd_asn: payload.get_u64().into(),
            interface_id: payload.get_u64(),
            checksum: value.checksum,
        }
    }
}

encoded_type!(
    /// SCMP message types.
    ///
    /// For the supported types (all except [`Self::OtherError`] and [`Self::OtherInfo`]) further
    /// documentation is provided by the corresponding `Scmp*` structs.
    pub enum ScmpType(u8) {
        /// Type of an SCMP DestinationUnreachable message.
        ///
        /// See [`ScmpDestinationUnreachable`] for further details.
        DestinationUnreachable = 1,
        /// Type of an SCMP PacketTooBig message.
        ///
        /// See [`ScmpPacketTooBig`] for further details.
        PacketTooBig = 2,
        /// Type of an SCMP ParameterProblem message.
        ///
        /// See [`ScmpParameterProblem`] for further details.
        ParameterProblem = 4,
        /// Type of an SCMP ExternalInterfaceDown message.
        ///
        /// See [`ScmpExternalInterfaceDown`] for further details.
        ExternalInterfaceDown = 5,
        /// Type of an SCMP InternalConnectivityDown message.
        ///
        /// See [`ScmpInternalConnectivityDown`] for further details.
        InternalConnectivityDown = 6,
        /// Type of an SCMP EchoRequest message.
        ///
        /// See [`ScmpEchoRequest`] for further details.
        EchoRequest = 128,
        /// Type of an SCMP EchoReply message.
        ///
        /// See [`ScmpEchoReply`] for further details.
        EchoReply = 129,
        /// An SCMP TracerouteRequest message.
        ///
        /// See [`ScmpTracerouteRequest`] for further details.
        TracerouteRequest = 130,
        /// Type of an SCMP TracerouteReply message.
        ///
        /// See [`ScmpTracerouteReply`] for further details.
        TracerouteReply = 131;
        /// Unknown SCMP error types.
        OtherError = 0..=Self::MAX_VALUE_ERROR,
        /// Unknown SCMP informational types.
        OtherInfo = Self::MIN_VALUE_INFORMATIONAL..,
    }
);

impl ScmpType {
    const MAX_VALUE_ERROR: u8 = 127;
    const MIN_VALUE_INFORMATIONAL: u8 = Self::MAX_VALUE_ERROR + 1;

    /// Returns true iff the type represents an error.
    pub fn is_error(&self) -> bool {
        u8::from(*self) <= Self::MAX_VALUE_ERROR
    }

    /// Returns true iff the type represents an informational message.
    pub fn is_informational(&self) -> bool {
        u8::from(*self) >= Self::MIN_VALUE_INFORMATIONAL
    }

    /// Returns true for all supported SCMP types and false otherwise.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::OtherError(_) | Self::OtherInfo(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address::ScionAddr, packet::ByEndpoint};

    #[test]
    fn scmp_type_consistent() {
        for value in 0..u8::MAX {
            let scmp_type = ScmpType::from(value);
            assert_eq!(u8::from(scmp_type), value);
            assert!(scmp_type.is_error() ^ scmp_type.is_informational());
        }
    }

    static OFFENDING_PACKET: Bytes = Bytes::from_static(b"1234");

    macro_rules! test_scmp_message {
        (
            $name:ident, $variant:ident, $message_type:ty, $type:ty {$($new_param:expr,)*}
        ) => {
            mod $name {
                use bytes::BytesMut;

                use super::*;
                use crate::wire_encoding::WireDecode;

                #[test]
                fn convert_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
                    type ScmpSpecificMessage = $message_type;

                    let mut buffer = BytesMut::new();
                    let mut input = <$type>::new($($new_param,)*);
                    let address_header = AddressHeader::from(ByEndpoint::<ScionAddr> {
                        source: "1-ff00:0:100,10.0.0.1".parse()?,
                        destination: "2-ff00:0:200,10.0.0.2".parse()?,
                    });

                    input.set_checksum(&address_header);
                    assert!(input.verify_checksum(&address_header));

                    let message = ScmpMessage::from(input.clone());
                    match message {
                        ScmpMessage::$variant(..) => (),
                        _ => panic!("wrong ScmpMessage variant"),
                    }

                    let specific_message = ScmpSpecificMessage::from(input);
                    match specific_message {
                        ScmpSpecificMessage::$variant(..) => (),
                        _ => panic!("wrong ScmpMessage variant"),
                    }

                    let bytes = message.encode_with(&mut buffer)?;
                    let mut buffer2 = BytesMut::new();
                    for buf in bytes {
                        buffer2.put_slice(buf.as_ref());
                    }

                    let decoded_message_raw = ScmpMessageRaw::decode(&mut buffer2)?;
                    println!("{}", decoded_message_raw.calculate_checksum(&address_header));

                    let decoded_message = ScmpMessage::try_from(decoded_message_raw)?;
                    assert_eq!(decoded_message, message);
                    assert!(decoded_message.verify_checksum(&address_header));

                    Ok(())
                }
            }
        };
    }

    test_scmp_message!(
        destination_unreachable,
        DestinationUnreachable,
        ScmpErrorMessage,
        ScmpDestinationUnreachable {
            DestinationUnreachableCode::AddressUnreachable,
            OFFENDING_PACKET.clone(),
        }
    );

    test_scmp_message!(
        packet_too_big,
        PacketTooBig,
        ScmpErrorMessage,
        ScmpPacketTooBig {
            42,
            OFFENDING_PACKET.clone(),
        }
    );

    test_scmp_message!(
        parameter_problem,
        ParameterProblem,
        ScmpErrorMessage,
        ScmpParameterProblem {
            ParameterProblemCode::InvalidExtensionHeader,
            42,
            OFFENDING_PACKET.clone(),
        }
    );

    test_scmp_message!(
        external_interface_down,
        ExternalInterfaceDown,
        ScmpErrorMessage,
        ScmpExternalInterfaceDown {
            "1-ff00:0:1".parse()?,
            42,
            OFFENDING_PACKET.clone(),
        }
    );

    test_scmp_message!(
        internal_connectivity_down,
        InternalConnectivityDown,
        ScmpErrorMessage,
        ScmpInternalConnectivityDown {
            "1-ff00:0:1".parse()?,
            42,
            314,
            OFFENDING_PACKET.clone(),
        }
    );

    test_scmp_message!(
        echo_request,
        EchoRequest,
        ScmpInformationalMessage,
        ScmpEchoRequest {
            42,
            314,
            Bytes::from_static(b"abcd"),
        }
    );

    test_scmp_message!(
        echo_reply,
        EchoReply,
        ScmpInformationalMessage,
        ScmpEchoReply {
            42,
            314,
            Bytes::from_static(b"abcd"),
        }
    );

    test_scmp_message!(
        traceroute_request,
        TracerouteRequest,
        ScmpInformationalMessage,
        ScmpTracerouteRequest {
            42,
            314,
        }
    );

    test_scmp_message!(
        traceroute_reply,
        TracerouteReply,
        ScmpInformationalMessage,
        ScmpTracerouteReply {
            42,
            314,
            "1-ff00:0:1".parse()?,
            10,
        }
    );
}
