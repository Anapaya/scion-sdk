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

//! Contains tests for full SCION packet encoding/decoding roundtrips.
//!
//! Generates valid SCION packets with three payload types (raw, UDP, SCMP),
//! encodes them, decodes them, and verifies all fields match.

mod helpers;

use std::panic::catch_unwind;

use helpers::{header::valid::ValidHeaderOptions, scmp::ValidScmpMessageOptions};
use proptest::{
    collection::vec,
    prelude::{ProptestConfig, Strategy, TestCaseError, any},
    prop_assert, prop_assert_eq, prop_oneof, proptest,
    sample::select,
};
use proptest_derive::Arbitrary;
use sciparse::{
    core::{
        encode::WireEncode,
        view::{View, ViewConversionError},
    },
    header::{model::ScionPacketHeader, view::ScionHeaderView},
    packet::{
        classify::ClassifiedPacketView,
        model::{ScionPacket, ScionPacketRawRef},
        view::{ScionPacketView, ScionRawPacketView},
    },
    payload::{
        ProtocolNumber,
        scmp::{model::ScmpMessage, view::ScmpPayloadView},
        udp::{model::UdpDatagram, view::UdpDatagramView},
    },
};

/// Payload options for generating valid SCION packets.
#[derive(Debug, Clone)]
enum ValidPayloadOptions {
    /// Raw bytes payload with an arbitrary next_header value.
    Raw { next_header: u8, data: Vec<u8> },
    /// UDP payload.
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    /// SCMP payload, reusing the existing SCMP test options.
    Scmp(ValidScmpMessageOptions),
}

impl proptest::arbitrary::Arbitrary for ValidPayloadOptions {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        use proptest::prelude::Strategy;
        prop_oneof![
            // Raw: arbitrary next_header (avoiding UDP=17 and SCMP=202 to not conflict),
            // with up to 1000 bytes of random data
            2 => (
                select((0u8..=255).filter(|&nh| nh != u8::from(ProtocolNumber::Udp) && nh != u8::from(ProtocolNumber::Scmp)).collect::<Vec<_>>()),
                vec(any::<u8>(), 0..=1000)
            ).prop_map(|(next_header, data)| ValidPayloadOptions::Raw { next_header, data }),
            // UDP: random ports + up to 1000 bytes payload
            3 => (any::<u16>(), any::<u16>(), vec(any::<u8>(), 0..=1000))
                .prop_map(|(src_port, dst_port, payload)| ValidPayloadOptions::Udp {
                    src_port,
                    dst_port,
                    payload,
                }),
            // SCMP: reuse the existing ValidScmpMessageOptions
            3 => any::<ValidScmpMessageOptions>()
                .prop_map(ValidPayloadOptions::Scmp),
        ]
        .boxed()
    }
}

impl ValidPayloadOptions {
    /// Returns the `next_header` value for this payload type.
    fn next_header(&self) -> u8 {
        match self {
            ValidPayloadOptions::Raw { next_header, .. } => *next_header,
            ValidPayloadOptions::Udp { .. } => ProtocolNumber::Udp.into(),
            ValidPayloadOptions::Scmp(_) => ProtocolNumber::Scmp.into(),
        }
    }
}

/// Options for constructing a valid full SCION packet.
#[derive(Debug, Clone, Arbitrary)]
struct ValidPacketOptions {
    header: ValidHeaderOptions,
    #[proptest(strategy = "any::<ValidPayloadOptions>()")]
    payload: ValidPayloadOptions,
}

/// Result of encoding a packet: the expected models and the encoded bytes.
struct EncodedPacket {
    expected_header: ScionPacketHeader,
    expected_payload: ExpectedPayload,
    buf: Vec<u8>,
}

/// Expected payload for comparison after decoding.
enum ExpectedPayload {
    Raw(Vec<u8>),
    Udp(UdpDatagram),
    Scmp(ScmpMessage),
}

impl ValidPacketOptions {
    /// Builds and encodes the full SCION packet, returning the expected models and wire bytes.
    fn encode(&self) -> Result<EncodedPacket, TestCaseError> {
        let mut header = self.header.to_header();

        // Override next_header based on payload type
        header.common.next_header = self.payload.next_header();

        match &self.payload {
            ValidPayloadOptions::Raw { data, .. } => {
                let packet = ScionPacket::new(header.clone(), data.as_slice());
                let mut buf = vec![0u8; packet.required_size()];
                packet.encode(&mut buf).expect("Encoding raw packet failed");

                Ok(EncodedPacket {
                    expected_header: header,
                    expected_payload: ExpectedPayload::Raw(data.clone()),
                    buf,
                })
            }
            ValidPayloadOptions::Udp {
                src_port,
                dst_port,
                payload,
            } => {
                let udp = UdpDatagram::new(*src_port, *dst_port, payload.clone());
                let packet = ScionPacket::new(header.clone(), udp.clone());
                let mut buf = vec![0u8; packet.required_size()];
                packet.encode(&mut buf).expect("Encoding UDP packet failed");

                Ok(EncodedPacket {
                    expected_header: header,
                    expected_payload: ExpectedPayload::Udp(udp),
                    buf,
                })
            }
            ValidPayloadOptions::Scmp(scmp_opts) => {
                // Encode the SCMP message using the actual packet address header and header
                // size, so the SCMP checksum matches what ScionPacket::encode will compute.
                let (expected_scmp, _) =
                    scmp_opts.encode(&header.address, header.required_size())?;

                // Now encode the full packet using the SCMP message model.
                let packet = ScionPacket::new(header.clone(), expected_scmp.clone());
                let mut buf = vec![0u8; packet.required_size()];
                packet
                    .encode(&mut buf)
                    .expect("Encoding SCMP packet failed");

                Ok(EncodedPacket {
                    expected_header: header,
                    expected_payload: ExpectedPayload::Scmp(expected_scmp),
                    buf,
                })
            }
        }
    }
}

/// Exercise all `ScionPacketView` functions to ensure none panic on valid packets.
///
/// Calls the header view exerciser, dispatches to the payload view exerciser based on
/// `next_header`, then exercises the remaining packet-level accessors.
fn exec_every_packet_view_function(
    view: &mut ScionPacketView,
) -> Result<(), proptest::prelude::TestCaseError> {
    use proptest::prelude::TestCaseError;

    // Exercise payload view functions based on next_header
    let next_header: ProtocolNumber = view.header().next_header().into();
    match next_header {
        ProtocolNumber::Udp => {
            let (udp_view, _) = UdpDatagramView::from_mut_slice(view.payload_mut())
                .map_err(|e| TestCaseError::fail(format!("Parsing UDP payload failed: {e}")))?;
            helpers::udp::exec_every_view_function(udp_view);
        }
        ProtocolNumber::Scmp => {
            let (scmp_view, _) = ScmpPayloadView::from_mut_slice(view.payload_mut())
                .map_err(|e| TestCaseError::fail(format!("Parsing SCMP payload failed: {e}")))?;
            helpers::scmp::exec_every_view_function(scmp_view);
        }
        _ => {
            // Raw payload — no typed view to exercise
        }
    }

    // Exercise all header view functions
    helpers::header::exec_every_view_function(view.header_mut())?;

    // Exercise remaining packet-level accessors
    let _ = view.payload();
    let _ = view.payload_mut();
    let _ = view.classify();

    Ok(())
}

#[test]
fn valid_packets_should_roundtrip_correctly() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(opts: ValidPacketOptions)| {
            test_impl(opts)?;
        }
    );

    fn test_impl(opts: ValidPacketOptions) -> Result<(), TestCaseError> {
        let unwind = catch_unwind(|| {
            let encoded = opts.encode()?;
            let buf = &encoded.buf;

            // Decode via ScionPacketRawRef::from_slice
            let (decoded, rest) =
                ScionPacketRawRef::from_slice(buf).expect("Decoding ScionPacket failed");
            prop_assert_eq!(rest.len(), 0);

            // Compare header
            prop_assert_eq!(encoded.expected_header, decoded.header);

            // Classify the decoded packet view.
            let (packet_view, _) = ScionRawPacketView::from_slice(buf)
                .expect("Creating ScionPacketView for classify failed");
            let classified = packet_view
                .classify()
                .expect("classify() failed on valid packet");

            // Compare payload based on type and verify the classification variant and
            // extracted port match the expected payload.
            match encoded.expected_payload {
                ExpectedPayload::Raw(expected_data) => {
                    prop_assert_eq!(expected_data.as_slice(), decoded.payload);
                    prop_assert!(
                        matches!(classified, ClassifiedPacketView::Other(_)),
                        "expected Other classification for raw payload, got a different variant"
                    );
                }
                ExpectedPayload::Udp(expected_udp) => {
                    let udp_view = packet_view
                        .try_into_udp()
                        .expect("Decoding UDP packet failed")
                        .udp();
                    let reconstructed = UdpDatagram::from_view(udp_view);
                    prop_assert_eq!(expected_udp.clone(), reconstructed);

                    match classified {
                        ClassifiedPacketView::Udp(classified_udp) => {
                            prop_assert_eq!(
                                classified_udp.udp().dst_port(),
                                expected_udp.dst_port,
                                "classified dst_port does not match encoded UDP dst_port"
                            );
                        }
                        _ => {
                            prop_assert_eq!(
                                true,
                                false,
                                "expected Udp classification for UDP payload"
                            )
                        }
                    }
                }
                ExpectedPayload::Scmp(expected_scmp) => {
                    let payload = decoded.payload;
                    let mut payload_buf = payload.to_vec();
                    let (scmp_view, rest) = ScmpPayloadView::from_mut_slice(&mut payload_buf)
                        .expect("Parsing SCMP payload failed");
                    prop_assert_eq!(rest.len(), 0);

                    helpers::scmp::exec_every_view_function(scmp_view);

                    let message_view = scmp_view.message();
                    let reconstructed = ScmpMessage::from_view(message_view);
                    prop_assert_eq!(expected_scmp, reconstructed);

                    prop_assert!(
                        matches!(classified, ClassifiedPacketView::Scmp(_)),
                        "expected Scmp classification for SCMP payload, got a different variant"
                    );
                }
            }

            // Exercise all view functions on the full packet
            {
                let mut view_buf = buf.to_vec();
                let view = ScionPacketView::from_mut_slice(&mut view_buf)
                    .expect("Creating ScionPacketView failed")
                    .0;
                exec_every_packet_view_function(view)?;
            }

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("Panic during packet roundtrip with options: {:#?}", opts);
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>());

                prop_assert_eq!(true, false, "Panic during packet roundtrip");
                Ok(())
            }
        }
    }
}

/// Brute-force checks over random byte buffers to ensure that no panics occur during
/// `ScionRawPacketView` construction or any subsequent view-function calls.
///
/// If the buffer is too small or otherwise invalid the parse fails gracefully; if the
/// parse succeeds every public accessor (header fields, payload, classify, …) is called.
#[test]
fn parsing_random_data_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(data in rand_packet_data())| {
            random_data_must_not_panic_impl(data)?;
        }
    );

    fn random_data_must_not_panic_impl(data: Vec<u8>) -> Result<(), TestCaseError> {
        let unwind = catch_unwind(|| {
            let mut data = data;
            match ScionRawPacketView::from_mut_slice(&mut data) {
                Ok((view, _rest)) => {
                    // exec_every_packet_view_function may return Err for random data
                    // (e.g. next_header=UDP but the payload bytes are not a valid UDP
                    // datagram).  That is expected and not a bug; the test only checks
                    // that no panic occurs, which catch_unwind handles.
                    let _ = exec_every_packet_view_function(view);
                }
                Err(ViewConversionError::BufferTooSmall { .. })
                | Err(ViewConversionError::Other(_)) => {}
            }

            Ok::<(), TestCaseError>(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("{:?}", panic.downcast_ref::<&str>());
                prop_assert!(false, "Panic during random packet data parsing");
                Ok(())
            }
        }
    }

    /// Strategy for generating random packet data.
    ///
    /// The biased variants nudge the header fields toward values that pass the
    /// SCION layout checks (version = 0, consistent header/payload lengths),
    /// so a meaningful fraction of inputs actually exercises the view accessors.
    fn rand_packet_data() -> impl Strategy<Value = Vec<u8>> {
        fn bias_to_packet_shape(mut data: Vec<u8>) -> Vec<u8> {
            // Need at least 12 bytes to manipulate the SCION common-header fields.
            if data.len() < 12 {
                return data;
            }
            let len = data.len();
            let rand_byte = len % data[5].max(1) as usize;

            // SAFETY: buf is at least 12 bytes (the SCION common-header size).
            let view = unsafe { ScionHeaderView::from_mut_slice_unchecked(&mut data) };
            view.set_version(0);

            // Occasionally set consistent header_len / payload_len so that more
            // inputs pass the ScionHeaderLayout size checks.
            if rand_byte.is_multiple_of(3) {
                let header_len = ((len.min(1000) / 4) * 4).max(12) as u16;
                unsafe { view.set_header_len(header_len) };
                let payload_len = len.saturating_sub(header_len as usize) as u16;
                unsafe { view.set_payload_len(payload_len) };
            }

            data
        }

        prop_oneof![
            // Biased toward plausible packet sizes with header shaping applied.
            6 => vec(any::<u8>(), 30..=256).prop_map(bias_to_packet_shape),
            3 => vec(any::<u8>(), 30..=1500).prop_map(bias_to_packet_shape),
            // Completely random — exercises the early-exit error paths.
            1 => vec(any::<u8>(), 0..=1500),
        ]
    }
}
