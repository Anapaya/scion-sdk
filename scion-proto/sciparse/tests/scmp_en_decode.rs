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

//! Contains tests for SCION SCMP message parsing and encoding/decoding
//!
//! 1. All valid SCMP messages should roundtrip through encode/decode preserving all information and
//!    not causing any panics. One exception is that quoted offending packets may be truncated to
//!    fit within the maximum SCMP packet allowed size.
//! 2. Decoding a random buffer into an SCMP message view must not panic.
//! 3. Decoding a truncated SCMP message must not panic.

use std::{cmp::min, panic::catch_unwind};

use proptest::{
    collection::vec,
    prelude::{ProptestConfig, Strategy, TestCaseError, any},
    prop_assert, prop_assert_eq, prop_oneof, proptest,
};
use proptest_derive::Arbitrary;
use sciparse::{
    address::host_addr::WireHostAddr,
    core::view::{View, ViewConversionError},
    header::model::AddressHeader,
    identifier::isd_asn::IsdAsn,
    payload::scmp::{
        encode::ScmpWireEncode,
        layout::{
            SCMP_ERROR_MAX_PACKET_SIZE, ScmpDestinationUnreachableLayout,
            ScmpExternalInterfaceDownLayout, ScmpInternalConnectivityDownLayout,
            ScmpPacketTooBigLayout, ScmpParameterProblemLayout,
        },
        model::{
            ScmpDestinationUnreachable, ScmpEchoReply, ScmpEchoRequest, ScmpExternalInterfaceDown,
            ScmpInternalConnectivityDown, ScmpMessage, ScmpPacketTooBig, ScmpParameterProblem,
            ScmpTracerouteReply, ScmpTracerouteRequest,
        },
        types::{ScmpDestinationUnreachableCode, ScmpParameterProblemCode},
        view::{ScmpMessageView, ScmpMessageViewMut, ScmpPayloadView},
    },
};

/// Minimum SCION header size with IPv4 addresses (common + address header).
const HEADER_AND_EXTENSIONS_SIZE: usize = 36;

/// Returns a fixed `AddressHeader` for checksum computation during encoding.
/// The checksum value itself is not verified in this test — it just needs to be
/// consistent between encode and decode.
fn test_address_header() -> AddressHeader {
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
// Strategy that favors known ParameterProblem codes
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
enum ValidScmpMessageOptions {
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
    fn encode(&self) -> Result<(ScmpMessage, Vec<u8>), TestCaseError> {
        let address_header = test_address_header();

        match self {
            ValidScmpMessageOptions::DestinationUnreachable {
                code,
                offending_packet,
            } => {
                let mut model = ScmpDestinationUnreachable::new(*code, offending_packet.clone());
                let required = model.required_size(HEADER_AND_EXTENSIONS_SIZE);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, &address_header, HEADER_AND_EXTENSIONS_SIZE)?;

                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - HEADER_AND_EXTENSIONS_SIZE
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
                let required = model.required_size(HEADER_AND_EXTENSIONS_SIZE);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, &address_header, HEADER_AND_EXTENSIONS_SIZE)?;

                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - HEADER_AND_EXTENSIONS_SIZE
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
                let required = model.required_size(HEADER_AND_EXTENSIONS_SIZE);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, &address_header, HEADER_AND_EXTENSIONS_SIZE)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - HEADER_AND_EXTENSIONS_SIZE
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
                let required = model.required_size(HEADER_AND_EXTENSIONS_SIZE);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, &address_header, HEADER_AND_EXTENSIONS_SIZE)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - HEADER_AND_EXTENSIONS_SIZE
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
                let required = model.required_size(HEADER_AND_EXTENSIONS_SIZE);
                let mut buf = vec![0u8; required];
                let encoded_len =
                    model.encode(&mut buf, &address_header, HEADER_AND_EXTENSIONS_SIZE)?;
                prop_assert_eq!(encoded_len, buf.len());

                let max_offending_len = SCMP_ERROR_MAX_PACKET_SIZE
                    - HEADER_AND_EXTENSIONS_SIZE
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
                let required = model.required_size();
                let mut buf = vec![0u8; required];
                let encoded_len = model.encode(&mut buf, &address_header)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::EchoReply {
                identifier,
                sequence_number,
                data,
            } => {
                let model = ScmpEchoReply::new(*identifier, *sequence_number, data.clone());
                let required = model.required_size();
                let mut buf = vec![0u8; required];
                let encoded_len = model.encode(&mut buf, &address_header)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
            ValidScmpMessageOptions::TracerouteRequest {
                identifier,
                sequence_number,
            } => {
                let model = ScmpTracerouteRequest::new(*identifier, *sequence_number);
                let required = model.required_size();
                let mut buf = vec![0u8; required];
                let encoded_len = model.encode(&mut buf, &address_header)?;
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
                let required = model.required_size();
                let mut buf = vec![0u8; required];
                let encoded_len = model.encode(&mut buf, &address_header)?;
                prop_assert_eq!(encoded_len, buf.len());
                Ok((model.into(), buf))
            }
        }
    }
}

/// Execute every function on the SCMP view to ensure none of them panic.
///
/// Mutable functions are called with the current value to avoid changing the message.
fn exec_every_view_function(view: &mut ScmpPayloadView) {
    let _ = view.message_type();
    let _ = view.code();
    let _ = view.checksum();

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

#[test]
fn valid_scmp_messages_should_roundtrip_correctly() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(opts: ValidScmpMessageOptions)| {
            test_impl(opts)?;
        }
    );

    fn test_impl(opts: ValidScmpMessageOptions) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let (expected, mut buf) = opts.encode()?;

            let (view, rest) =
                ScmpPayloadView::from_mut_slice(&mut buf).expect("Creating ScmpPayloadView failed");
            prop_assert_eq!(rest.len(), 0);

            exec_every_view_function(view);

            let message_view = view.message();
            let reconstructed = ScmpMessage::from_view(message_view);

            prop_assert_eq!(expected, reconstructed);

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("Panic during SCMP roundtrip with options: {:#?}", opts);
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>());

                prop_assert_eq!(true, false, "Panic during SCMP roundtrip");
                Ok(())
            }
        }
    }
}

#[test]
fn parsing_random_data_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(mut data in vec(any::<u8>(), 0..=512))| {
            let unwind = catch_unwind(move || {
                match ScmpPayloadView::from_mut_slice(&mut data) {

                    Ok((view, _rest)) => {
                        exec_every_view_function(view);
                    }
                    Err(ViewConversionError::BufferTooSmall { .. })
                    | Err(ViewConversionError::Other(_)) => {}
                }

                Ok::<(), proptest::prelude::TestCaseError>(())
            });

            match unwind {
                Ok(res) => res?,
                Err(panic) => {
                    println!("{:?}", panic.downcast_ref::<&str>());
                    prop_assert!(false, "Panic during SCMP random data parsing");
                }
            }
        }
    );
}

#[test]
fn truncated_scmp_messages_must_not_panic() {
    let strategy = any::<ValidScmpMessageOptions>()
        .prop_filter_map("Encoding failed", |opts| {
            let buf = opts.encode();
            let buf = if let Ok((_, buf)) = buf {
                buf
            } else {
                // This should never happen, but we cannot panic inside a strategy.
                // This behavior is covered by the other tests.
                return None;
            };
            Some(buf)
        })
        .prop_flat_map(|buf| {
            (1..=buf.len()).prop_map(move |remove_bytes| (buf.clone(), remove_bytes))
        });

    proptest!(
        ProptestConfig::with_cases(5_000),
        |((mut buf, remove_bytes) in strategy)| {
            let unwind = catch_unwind(move || {
                buf.truncate(buf.len() - remove_bytes);

                match ScmpPayloadView::from_mut_slice(&mut buf) {
                    Ok((view, rest)) => {
                        prop_assert_eq!(rest.len(), 0);
                        exec_every_view_function(view);
                    }
                    Err(ViewConversionError::BufferTooSmall { .. })
                    | Err(ViewConversionError::Other(_)) => {}
                }

                Ok::<(), proptest::prelude::TestCaseError>(())
            });

            match unwind {
                Ok(res) => res?,
                Err(panic) => {
                    println!("{:?}", panic.downcast_ref::<&str>());
                    prop_assert!(false, "Panic during truncated SCMP message parsing");
                }
            }
        }
    );
}
