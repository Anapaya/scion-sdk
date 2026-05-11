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
        layout::{BitRange, Layout, macros::gen_bitrange_const},
        view::{View as _, ViewConversionError},
    },
    payload::scmp::{types::ScmpMessageType, view::ScmpUnknownMessageView},
};

/// Maximum length of an SCMP packet that contains an error message
/// including the SCION HEADER and extensions.
pub const SCMP_ERROR_MAX_PACKET_SIZE: usize = 1232;

/// Layout for all SCMP messages.
pub enum ScmpMessageLayout {
    /// Layout for a `DestinationUnreachable` SCMP message.
    DestinationUnreachable(ScmpDestinationUnreachableLayout),
    /// Layout for a `PacketTooBig` SCMP message.
    PacketTooBig(ScmpPacketTooBigLayout),
    /// Layout for a `ParameterProblem` SCMP message.
    ParameterProblem(ScmpParameterProblemLayout),
    /// Layout for an `ExternalInterfaceDown` SCMP message.
    ExternalInterfaceDown(ScmpExternalInterfaceDownLayout),
    /// Layout for an `InternalConnectivityDown` SCMP message.
    InternalConnectivityDown(ScmpInternalConnectivityDownLayout),
    /// Layout for an `EchoRequest` SCMP message.
    EchoRequest(ScmpEchoRequestLayout),
    /// Layout for an `EchoReply` SCMP message.
    EchoReply(ScmpEchoReplyLayout),
    /// Layout for a `TracerouteRequest` SCMP message.
    TracerouteRequest(ScmpTracerouteRequestLayout),
    /// Layout for a `TracerouteReply` SCMP message.
    TracerouteReply(ScmpTracerouteReplyLayout),
    /// Layout for an unknown SCMP message.
    UnknownMessage(ScmpUnknownMessageLayout),
}

impl ScmpMessageLayout {
    /// Create a message layout from the given buffer, selecting the concrete
    /// layout based on the SCMP type field.
    ///
    /// If the contained message contains an variably sized data part e.g. offending packet or echo
    /// data, it assumes that the messages takes up the whole buffer and there are no trailing
    /// bytes.
    ///
    /// Note, that this functions does not validate the total size of the SCION SCMP packet
    /// which for SCMP error messages is required to be at most `MAX_OFFENDING_PACKET_LENGTH`
    /// bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        let (view, _) = ScmpUnknownMessageView::from_slice(buf).map_err(|e| {
            match e {
                ViewConversionError::BufferTooSmall {
                    required, actual, ..
                } => {
                    ViewConversionError::BufferTooSmall {
                        at: "ScmpMessageHeader",
                        required,
                        actual,
                    }
                }
                ViewConversionError::Other(e) => ViewConversionError::Other(e),
            }
        })?;

        // Safety: Only fields in the header part of the SCMP Message are accessed below.
        // Fields past the common part are not accessed until after size checks.
        use ScmpMessageLayout as L;
        use ScmpMessageType as T;
        let msg = match view.message_type().into() {
            T::DestinationUnreachable => L::DestinationUnreachable(buf.try_into()?),
            T::PacketTooBig => L::PacketTooBig(buf.try_into()?),
            T::ParameterProblem => L::ParameterProblem(buf.try_into()?),
            T::ExternalInterfaceDown => L::ExternalInterfaceDown(buf.try_into()?),
            T::InternalConnectivityDown => L::InternalConnectivityDown(buf.try_into()?),
            T::EchoRequest => L::EchoRequest(buf.try_into()?),
            T::EchoReply => L::EchoReply(buf.try_into()?),
            T::TracerouteRequest => L::TracerouteRequest(buf.try_into()?),
            T::TracerouteReply => L::TracerouteReply(buf.try_into()?),
            T::Unknown(_) => L::UnknownMessage(buf.try_into()?),
        };
        Ok(msg)
    }
}
impl TryFrom<&[u8]> for ScmpMessageLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}
impl ScmpMessageLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |           Checksum            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);
}

impl Layout for ScmpMessageLayout {
    fn size_bytes(&self) -> usize {
        match self {
            Self::DestinationUnreachable(inner) => inner.size_bytes(),
            Self::PacketTooBig(inner) => inner.size_bytes(),
            Self::ParameterProblem(inner) => inner.size_bytes(),
            Self::ExternalInterfaceDown(inner) => inner.size_bytes(),
            Self::InternalConnectivityDown(inner) => inner.size_bytes(),
            Self::EchoRequest(inner) => inner.size_bytes(),
            Self::EchoReply(inner) => inner.size_bytes(),
            Self::TracerouteRequest(inner) => inner.size_bytes(),
            Self::TracerouteReply(inner) => inner.size_bytes(),
            Self::UnknownMessage(inner) => inner.size_bytes(),
        }
    }
}

/// Layout for an SCMP `DestinationUnreachable` message.
pub struct ScmpDestinationUnreachableLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields).
    payload_length: usize,
}
impl ScmpDestinationUnreachableLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 8;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the byte length of the offending packet.
    pub fn from_offending_packet_length(
        offending_packet_length: usize,
        header_and_extensions_size: usize,
    ) -> Self {
        let max_payload = SCMP_ERROR_MAX_PACKET_SIZE.saturating_sub(header_and_extensions_size);
        let max_offending_len = max_payload.saturating_sub(Self::HEADER_SIZE_BYTES);
        let included_offending = offending_packet_length.min(max_offending_len);
        Self {
            payload_length: Self::HEADER_SIZE_BYTES + included_offending,
        }
    }
}
impl ScmpDestinationUnreachableLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                            Reserved                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                As much of the offending packet                |
    // |              as possible without the SCMP packet              +
    // |                    exceeding 1232 bytes.                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(RESERVED_RNG, 32, 32);

    /// Returns the bit range of the offending packet in the SCMP message.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn offending_packet_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpDestinationUnreachableLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpDestinationUnreachableLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpDestinationUnreachable",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpDestinationUnreachableLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `PacketTooBig` message.
pub struct ScmpPacketTooBigLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}

impl ScmpPacketTooBigLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 8;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the length of the offending packet.
    pub fn from_offending_packet_length(
        offending_packet_length: usize,
        header_and_extensions_size: usize,
    ) -> Self {
        let max_payload = SCMP_ERROR_MAX_PACKET_SIZE.saturating_sub(header_and_extensions_size);
        let max_offending_len = max_payload.saturating_sub(Self::HEADER_SIZE_BYTES);
        let included_offending = offending_packet_length.min(max_offending_len);
        Self {
            payload_length: Self::HEADER_SIZE_BYTES + included_offending,
        }
    }
}

impl ScmpPacketTooBigLayout {
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //|     Type      |     Code      |          Checksum             |
    //+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //|            reserved           |             MTU               |
    //+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //|                As much of the offending packet                |
    //+              as possible without the SCMP packet              +
    //|                    exceeding 1232 bytes.                      |
    //+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(RESERVED_RNG, 32, 16);
    gen_bitrange_const!(MTU_RNG, 48, 16);

    /// Returns the bit range of the offending packet in the SCMP message.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn offending_packet_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpPacketTooBigLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpPacketTooBigLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpPacketTooBig",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpPacketTooBigLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `ParameterProblem` message.
pub struct ScmpParameterProblemLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpParameterProblemLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 8;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the byte length of the offending packet.
    pub fn from_offending_packet_length(
        offending_packet_length: usize,
        header_and_extensions_size: usize,
    ) -> Self {
        let max_payload = SCMP_ERROR_MAX_PACKET_SIZE.saturating_sub(header_and_extensions_size);
        let max_offending_len = max_payload.saturating_sub(Self::HEADER_SIZE_BYTES);
        let included_offending = offending_packet_length.min(max_offending_len);
        Self {
            payload_length: Self::HEADER_SIZE_BYTES + included_offending,
        }
    }
}
impl ScmpParameterProblemLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            reserved           |           Pointer             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                As much of the offending packet                |
    // |              as possible without the SCMP packet              |
    // |                    exceeding 1232 bytes.                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(RESERVED_RNG, 32, 16);
    gen_bitrange_const!(POINTER_RNG, 48, 16);

    /// Returns the bit range of the offending packet in the SCMP message.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn offending_packet_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpParameterProblemLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpParameterProblemLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpParameterProblem",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpParameterProblemLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `ExternalInterfaceDown` message.
pub struct ScmpExternalInterfaceDownLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpExternalInterfaceDownLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 20;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the byte length of the offending packet.
    pub fn from_offending_packet_length(
        offending_packet_length: usize,
        header_and_extensions_size: usize,
    ) -> Self {
        let max_payload = SCMP_ERROR_MAX_PACKET_SIZE.saturating_sub(header_and_extensions_size);
        let max_offending_len = max_payload.saturating_sub(Self::HEADER_SIZE_BYTES);
        let included_offending = offending_packet_length.min(max_offending_len);
        Self {
            payload_length: Self::HEADER_SIZE_BYTES + included_offending,
        }
    }
}
impl ScmpExternalInterfaceDownLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ISD              |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // + Interface ID                           +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                As much of the offending packet                |
    // + as possible without the SCMP packet              +
    // |                    exceeding 1232 bytes.                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(ISD_AS_RNG, 32, 64);

    gen_bitrange_const!(INTERFACE_ID_RNG, 96, 64);

    /// Returns the bit range of the offending packet in the SCMP message.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn offending_packet_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}

impl Layout for ScmpExternalInterfaceDownLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpExternalInterfaceDownLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpExternalInterfaceDown",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpExternalInterfaceDownLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `InternalConnectivityDown` message.
pub struct ScmpInternalConnectivityDownLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpInternalConnectivityDownLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 28;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the byte length of the offending packet.
    pub fn from_offending_packet_length(
        offending_packet_length: usize,
        header_and_extensions_size: usize,
    ) -> Self {
        let max_payload = SCMP_ERROR_MAX_PACKET_SIZE.saturating_sub(header_and_extensions_size);
        let max_offending_len = max_payload.saturating_sub(Self::HEADER_SIZE_BYTES);
        let included_offending = offending_packet_length.min(max_offending_len);
        Self {
            payload_length: Self::HEADER_SIZE_BYTES + included_offending,
        }
    }
}
impl ScmpInternalConnectivityDownLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ISD              |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // + Ingress Interface ID                        +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // + Egress Interface ID                         +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                As much of the offending packet                |
    // + as possible without the SCMP packet              +
    // |                    exceeding 1232 bytes.                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(ISD_AS_RNG, 32, 64);

    gen_bitrange_const!(INGRESS_INTERFACE_ID_RNG, 96, 64);
    gen_bitrange_const!(EGRESS_INTERFACE_ID_RNG, 160, 64);

    /// Returns the bit range of the offending packet in the SCMP message.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn offending_packet_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpInternalConnectivityDownLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpInternalConnectivityDownLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpInternalConnectivityDown",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpInternalConnectivityDownLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `EchoRequest` message.
pub struct ScmpEchoRequestLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpEchoRequestLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 8;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the byte length of the echo data.
    pub fn from_data_length(data_length: usize) -> Self {
        Self {
            payload_length: data_length + Self::HEADER_SIZE_BYTES,
        }
    }
}
impl ScmpEchoRequestLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Identifier          |        Sequence Number        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Data...
    // +-+-+-+-+-

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(IDENTIFIER_RNG, 32, 16);
    gen_bitrange_const!(SEQUENCE_NUMBER_RNG, 48, 16);

    /// Returns the bit range of the echo data.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn data_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpEchoRequestLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpEchoRequestLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpEchoRequest",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpEchoRequestLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `EchoReply` message.
pub struct ScmpEchoReplyLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpEchoReplyLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 8;

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Create a layout based on the length of the echo data.
    pub fn from_data_length(data_length: usize) -> Self {
        Self {
            payload_length: data_length + Self::HEADER_SIZE_BYTES,
        }
    }
}
impl ScmpEchoReplyLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Identifier          |        Sequence Number        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Data...
    // +-+-+-+-+-

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(IDENTIFIER_RNG, 32, 16);
    gen_bitrange_const!(SEQUENCE_NUMBER_RNG, 48, 16);

    /// Returns the range of the echo data in bits.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn data_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpEchoReplyLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpEchoReplyLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpEchoReply",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpEchoReplyLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `TracerouteRequest` message.
pub struct ScmpTracerouteRequestLayout;
impl ScmpTracerouteRequestLayout {
    /// The size of the header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 24;
}
impl ScmpTracerouteRequestLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Identifier          |        Sequence Number        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ISD              |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // + Interface ID                         +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(IDENTIFIER_RNG, 32, 16);
    gen_bitrange_const!(SEQUENCE_NUMBER_RNG, 48, 16);

    // Placeholder for ISD-AS number. Set to 0 by the sender.
    gen_bitrange_const!(ISD_AS_RNG, 64, 64);
    // Placeholder for interface ID. Set to 0 by the sender.
    gen_bitrange_const!(INTERFACE_ID_RNG, 128, 64);
}
impl Layout for ScmpTracerouteRequestLayout {
    fn size_bytes(&self) -> usize {
        Self::HEADER_SIZE_BYTES
    }
}
impl ScmpTracerouteRequestLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpTracerouteRequest",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {})
    }
}
impl TryFrom<&[u8]> for ScmpTracerouteRequestLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP `TracerouteReply` message.
pub struct ScmpTracerouteReplyLayout;
impl ScmpTracerouteReplyLayout {
    /// Size of the fixed SCMP traceroute reply header in bytes.
    pub const HEADER_SIZE_BYTES: usize = 24;
}
impl ScmpTracerouteReplyLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Identifier          |        Sequence Number        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ISD              |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // + Interface ID                         +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    gen_bitrange_const!(IDENTIFIER_RNG, 32, 16);
    gen_bitrange_const!(SEQUENCE_NUMBER_RNG, 48, 16);

    gen_bitrange_const!(ISD_AS_RNG, 64, 64);

    gen_bitrange_const!(INTERFACE_ID_RNG, 128, 64);
}
impl Layout for ScmpTracerouteReplyLayout {
    fn size_bytes(&self) -> usize {
        Self::HEADER_SIZE_BYTES
    }
}
impl ScmpTracerouteReplyLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpTracerouteReply",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {})
    }
}
impl TryFrom<&[u8]> for ScmpTracerouteReplyLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

/// Layout for an SCMP unknown message.
pub struct ScmpUnknownMessageLayout {
    /// Total size of the SCMP message in bytes (including type, code and checksum fields)..
    payload_length: usize,
}
impl ScmpUnknownMessageLayout {
    const HEADER_SIZE_BYTES: usize = 8;

    /// Create a layout based on the byte length of the message specific data.
    pub fn from_message_specific_data_length(message_specific_data_length: usize) -> Self {
        Self {
            payload_length: message_specific_data_length + Self::HEADER_SIZE_BYTES,
        }
    }
}
impl ScmpUnknownMessageLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Data...
    // +-+-+-+-+-

    gen_bitrange_const!(TYPE_RNG, 0, 8);
    gen_bitrange_const!(CODE_RNG, 8, 8);
    gen_bitrange_const!(CHECKSUM_RNG, 16, 16);

    /// Create a new layout with the given payload length.
    pub fn new(payload_length: usize) -> Self {
        Self { payload_length }
    }

    /// Returns the bit range of the message specific data.
    /// The returned bit range is guaranteed to be aligned to the byte boundary.
    pub fn message_specific_data_rng(&self) -> BitRange {
        BitRange::new(
            Self::HEADER_SIZE_BYTES * 8,
            self.payload_length.saturating_sub(Self::HEADER_SIZE_BYTES) * 8,
        )
    }
}
impl Layout for ScmpUnknownMessageLayout {
    fn size_bytes(&self) -> usize {
        self.payload_length
    }
}
impl ScmpUnknownMessageLayout {
    /// Create a layout from a raw buffer, validating minimum size.
    /// This assumes that the buffer contains exactly the scmp message without trailing bytes.
    pub fn from_slice(buf: &[u8]) -> Result<Self, ViewConversionError> {
        if buf.len() < Self::HEADER_SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "ScmpUnknownMessage",
                required: Self::HEADER_SIZE_BYTES,
                actual: buf.len(),
            });
        }
        Ok(Self {
            payload_length: buf.len(),
        })
    }
}
impl TryFrom<&[u8]> for ScmpUnknownMessageLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}
