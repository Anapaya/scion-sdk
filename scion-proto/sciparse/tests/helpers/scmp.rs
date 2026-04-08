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

//! Shared helpers for SCION SCMP property tests.

// Suppress warnings for items/imports not used in every test binary that includes this module.
#![allow(dead_code, unused_imports)]

use std::cmp::min;

use proptest::{
    collection::vec,
    prelude::{Strategy, TestCaseError, any},
    prop_assert_eq, prop_oneof,
};
use proptest_derive::Arbitrary;
use sciparse::{
    address::host_addr::WireHostAddr,
    header::model::AddressHeader,
    identifier::isd_asn::IsdAsn,
    payload::{
        encode::PayloadEncode,
        scmp::{
            layout::{
                SCMP_ERROR_MAX_PACKET_SIZE, ScmpDestinationUnreachableLayout,
                ScmpExternalInterfaceDownLayout, ScmpInternalConnectivityDownLayout,
                ScmpPacketTooBigLayout, ScmpParameterProblemLayout,
            },
            model::{
                ScmpDestinationUnreachable, ScmpEchoReply, ScmpEchoRequest,
                ScmpExternalInterfaceDown, ScmpInternalConnectivityDown, ScmpMessage,
                ScmpPacketTooBig, ScmpParameterProblem, ScmpTracerouteReply, ScmpTracerouteRequest,
            },
            types::{ScmpDestinationUnreachableCode, ScmpParameterProblemCode},
            view::{ScmpMessageView, ScmpMessageViewMut, ScmpPayloadView},
        },
    },
};

/// Minimum SCION header size with IPv4 addresses (common + address header).
pub const HEADER_AND_EXTENSIONS_SIZE: usize = 36;

/// Returns a fixed `AddressHeader` for checksum computation during encoding.
/// The checksum value itself is not verified in this test — it just needs to be
/// consistent between encode and decode.
pub fn test_address_header() -> AddressHeader {
    AddressHeader {
        dst_ia: "1-ff00:0:110".parse().unwrap(),
        src_ia: "1-ff00:0:111".parse().unwrap(),
        dst_host_addr: WireHostAddr::V4("127.0.0.1".parse().unwrap()),
        src_host_addr: WireHostAddr::V4("10.0.0.1".parse().unwrap()),
    }
}

/// Strategy that favors known DestinationUnreachable codes (0..=6)
/// with a small probability of generating unknown codes (7..=255).
fn destination_unreachable_code() -> impl Strategy<Value = ScmpDestinationUnreachableCode> {
    prop_oneof![
        9 => 0u8..=6u8,
        1 => 7u8..=255u8,
    ]
    .prop_map(ScmpDestinationUnreachableCode::from)
}

/// Strategy that favors known ParameterProblem codes
/// with a small probability of generating unknown codes.
fn parameter_problem_code() -> impl Strategy<Value = ScmpParameterProblemCode> {
    prop_oneof![
        9 => proptest::strategy::Union::new(vec![
            (0u8..=1u8).boxed(),
            (16u8..=21u8).boxed(),
            (32u8..=35u8).boxed(),
            (48u8..=53u8).boxed(),
            (64u8..=66u8).boxed(),
        ]),
        1 => 0u8..=255u8,
    ]
    .prop_map(ScmpParameterProblemCode::from)
}

/// Options for constructing a valid SCMP message for testing.
#[derive(Debug, Clone, Arbitrary)]
pub enum ValidScmpMessageOptions {
    DestinationUnreachable {
        #[proptest(strategy = "destination_unreachable_code()")]
        code: ScmpDestinationUnreachableCode,
        offending_packet: Vec<u8>,
    },
    PacketTooBig {
        mtu: u16,
        offending_packet: Vec<u8>,
    },
    ParameterProblem {
        #[proptest(strategy = "parameter_problem_code()")]
        code: ScmpParameterProblemCode,
        pointer: u16,
        offending_packet: Vec<u8>,
    },
    ExternalInterfaceDown {
        isd_asn: u64,
        interface_id: u16,
        offending_packet: Vec<u8>,
    },
    InternalConnectivityDown {
        isd_asn: u64,
        ingress_interface_id: u16,
        egress_interface_id: u16,
        offending_packet: Vec<u8>,
    },
    EchoRequest {
        identifier: u16,
        sequence_number: u16,
        data: Vec<u8>,
    },
    EchoReply {
        identifier: u16,
        sequence_number: u16,
        data: Vec<u8>,
    },
    TracerouteRequest {
        identifier: u16,
        sequence_number: u16,
    },
    TracerouteReply {
        identifier: u16,
        sequence_number: u16,
        isd_asn: u64,
        interface_id: u16,
    },
}

impl ValidScmpMessageOptions {
    /// Encodes the SCMP message into a buffer and returns the expected model
    /// (with truncated offending packet) and the encoded bytes.
    ///
    /// `address_header` and `header_and_extensions_size` must match the values
    /// that will be used when encoding the enclosing SCION packet, so that the
    /// SCMP checksum is computed consistently.
    pub fn encode(
        &self,
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> Result<(ScmpMessage, Vec<u8>), TestCaseError> {
        match self {
            ValidScmpMessageOptions::DestinationUnreachable {
                code,
                offending_packet,
            } => {
                let mut model = ScmpDestinationUnreachable::new(*code, offending_packet.clone());
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;

                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - header_and_extensions_size
                    - ScmpDestinationUnreachableLayout::HEADER_SIZE_BYTES;
                let actual_len = min(offending_packet.len(), max_offending_len);
                model.set_offending_packet(offending_packet[..actual_len].to_vec());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::PacketTooBig {
                mtu,
                offending_packet,
            } => {
                let mut model = ScmpPacketTooBig::new(*mtu, offending_packet.clone());
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;

                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - header_and_extensions_size
                    - ScmpPacketTooBigLayout::HEADER_SIZE_BYTES;
                let actual_len = min(offending_packet.len(), max_offending_len);
                model.set_offending_packet(offending_packet[..actual_len].to_vec());

                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::ParameterProblem {
                code,
                pointer,
                offending_packet,
            } => {
                let mut model =
                    ScmpParameterProblem::new(*code, *pointer, offending_packet.clone());
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - header_and_extensions_size
                    - ScmpParameterProblemLayout::HEADER_SIZE_BYTES;
                let actual_len = min(offending_packet.len(), max_offending_len);
                model.set_offending_packet(offending_packet[..actual_len].to_vec());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::ExternalInterfaceDown {
                isd_asn,
                interface_id,
                offending_packet,
            } => {
                let mut model = ScmpExternalInterfaceDown::new(
                    IsdAsn::from_u64(*isd_asn),
                    *interface_id,
                    offending_packet.clone(),
                );
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - header_and_extensions_size
                    - ScmpExternalInterfaceDownLayout::HEADER_SIZE_BYTES;
                let actual_len = min(offending_packet.len(), max_offending_len);
                model.set_offending_packet(offending_packet[..actual_len].to_vec());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::InternalConnectivityDown {
                isd_asn,
                ingress_interface_id,
                egress_interface_id,
                offending_packet,
            } => {
                let mut model = ScmpInternalConnectivityDown::new(
                    IsdAsn::from_u64(*isd_asn),
                    *ingress_interface_id,
                    *egress_interface_id,
                    offending_packet.clone(),
                );
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - header_and_extensions_size
                    - ScmpInternalConnectivityDownLayout::HEADER_SIZE_BYTES;
                let actual_len = min(offending_packet.len(), max_offending_len);
                model.set_offending_packet(offending_packet[..actual_len].to_vec());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::EchoRequest {
                identifier,
                sequence_number,
                data,
            } => {
                let model = ScmpEchoRequest::new(*identifier, *sequence_number, data.clone());
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::EchoReply {
                identifier,
                sequence_number,
                data,
            } => {
                let model = ScmpEchoReply::new(*identifier, *sequence_number, data.clone());
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::TracerouteRequest {
                identifier,
                sequence_number,
            } => {
                let model = ScmpTracerouteRequest::new(*identifier, *sequence_number);
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                buf.truncate(encoded_len);
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::TracerouteReply {
                identifier,
                sequence_number,
                isd_asn,
                interface_id,
            } => {
                let model = ScmpTracerouteReply::new(
                    *identifier,
                    *sequence_number,
                    IsdAsn::from_u64(*isd_asn),
                    *interface_id,
                );
                let required = model.required_size(header_and_extensions_size);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, address_header, header_and_extensions_size)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
        }
    }
}

/// Execute every function on the SCMP view to ensure none of them panic.
///
/// Mutable functions are called with the current value to avoid changing the message.
pub fn exec_every_view_function(view: &mut ScmpPayloadView) {
    let _ = view.message_type();
    let _ = view.code();
    let _ = view.checksum();
    let _ = view.dst_port();

    match view.message() {
        ScmpMessageView::DestinationUnreachable(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            let _ = v.offending_packet();
        }
        ScmpMessageView::PacketTooBig(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            let _ = v.mtu();
            let _ = v.offending_packet();
        }
        ScmpMessageView::ParameterProblem(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.reserved();
            let _ = v.pointer();
            let _ = v.offending_packet();
        }
        ScmpMessageView::ExternalInterfaceDown(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.isd_asn();
            let _ = v.interface_id();
            let _ = v.offending_packet();
        }
        ScmpMessageView::InternalConnectivityDown(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.isd_asn();
            let _ = v.ingress_interface_id();
            let _ = v.egress_interface_id();
            let _ = v.offending_packet();
        }
        ScmpMessageView::EchoRequest(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.data();
        }
        ScmpMessageView::EchoReply(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.data();
        }
        ScmpMessageView::TracerouteRequest(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.isd_asn();
            let _ = v.interface_id();
        }
        ScmpMessageView::TracerouteReply(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.identifier();
            let _ = v.sequence_number();
            let _ = v.isd_asn();
            let _ = v.interface_id();
        }
        ScmpMessageView::UnknownMessage(v) => {
            let _ = v.message_type();
            let _ = v.code();
            let _ = v.checksum();
            let _ = v.message_specific_data();
        }
    }

    match view.message_mut() {
        ScmpMessageViewMut::DestinationUnreachable(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            let _ = v.offending_packet_mut();
        }
        ScmpMessageViewMut::PacketTooBig(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            v.set_mtu(v.mtu());
            let _ = v.offending_packet_mut();
        }
        ScmpMessageViewMut::ParameterProblem(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_reserved(v.reserved());
            v.set_pointer(v.pointer());
            let _ = v.offending_packet_mut();
        }
        ScmpMessageViewMut::ExternalInterfaceDown(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
            let _ = v.offending_packet_mut();
        }
        ScmpMessageViewMut::InternalConnectivityDown(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_isd_asn(v.isd_asn());
            v.set_ingress_interface_id(v.ingress_interface_id());
            v.set_egress_interface_id(v.egress_interface_id());
            let _ = v.offending_packet_mut();
        }
        ScmpMessageViewMut::EchoRequest(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            let _ = v.data_mut();
        }
        ScmpMessageViewMut::EchoReply(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            let _ = v.data_mut();
        }
        ScmpMessageViewMut::TracerouteRequest(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
        }
        ScmpMessageViewMut::TracerouteReply(v) => {
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            v.set_identifier(v.identifier());
            v.set_sequence_number(v.sequence_number());
            v.set_isd_asn(v.isd_asn());
            v.set_interface_id(v.interface_id());
        }
        ScmpMessageViewMut::UnknownMessage(v) => {
            v.set_message_type(v.message_type());
            v.set_code(v.code());
            v.set_checksum(v.checksum());
            let _ = v.message_specific_data_mut();
        }
    }
}
