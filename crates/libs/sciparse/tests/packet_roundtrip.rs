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

//! Valid packets roundtrip through encode → view → reconstruct without data loss or panics.

use std::panic::catch_unwind;

use proptest::{
    prelude::{ProptestConfig, TestCaseError},
    prop_assert, prop_assert_eq, proptest,
};
use sciparse::{
    core::{convert::TryFromView, encode::WireEncode, view::View},
    dataplane_path::view::ScionDpPathViewExt,
    packet::{
        classify::ClassifiedPacket,
        model::{
            ScionPacketExt, ScionRawPacket, ScionRawPacketRef, ScionScmpPacket, ScionScmpPacketRef,
            ScionUdpPacket, ScionUdpPacketExt, ScionUdpPacketRef,
        },
        view::ScionRawPacketView,
    },
};

/// Creates valid headers with various options and ensures they roundtrip through encoding and
/// decoding Validates all functions in the ScionHeaderView do not panic
#[test]
fn valid_packets_should_roundtrip_correctly() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(pkt: ClassifiedPacket)| {
            test_impl(pkt)?;
        }
    );

    fn test_impl(packet: ClassifiedPacket) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            if let Err(e) = packet.wire_valid() {
                println!("Generated packet is not valid: {:?}", e);
                return Err(proptest::prelude::TestCaseError::reject(
                    "Generated packet is not valid",
                ));
            }

            let mut buf = vec![0u8; packet.required_size()];
            packet
                .try_encode(&mut buf)
                .expect("Writing to buffer failed");

            // A buffer filled with `0xAA` shows each byte that the encoder does not write.
            let mut stale = vec![0xAAu8; packet.required_size()];
            packet
                .try_encode(&mut stale)
                .expect("Writing to buffer failed");
            prop_assert_eq!(&stale, &buf);

            assert_ref_eq(&packet)?;

            let (view, rst) =
                ScionRawPacketView::try_from_mut_slice(&mut buf).expect("Creating view failed");

            prop_assert_eq!(rst.len(), 0);

            assert_packet_eq(&packet, view)?;

            // Exercise every getter/setter on the view hierarchy to validate
            // that no access causes UB on validly-constructed packets.
            sciparse::util::fuzz::view_function_checks::packet::exec_every_view_function(view);

            // Packets should still match after exercising the views
            assert_packet_eq(&packet, view)?;

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                let panic_info = panic.downcast_ref::<&str>().unwrap();
                prop_assert!(false, "Panic during roundtrip test: {:?}", panic_info);
                Ok(())
            }
        }
    }
}

fn assert_packet_eq(
    packet: &ClassifiedPacket,
    view: &mut sciparse::packet::view::ScionPacketView,
) -> Result<(), proptest::prelude::TestCaseError> {
    let reconstructed =
        ScionRawPacket::try_from_view(view).expect("Converting view to packet failed");

    match packet {
        ClassifiedPacket::Scmp(input) => {
            let scmp = ScionScmpPacket::try_from_raw(reconstructed)
                .expect("Converting to SCMP packet failed");
            prop_assert_eq!(
                input,
                &scmp,
                "Original and reconstructed SCMP packets do not match"
            );
        }
        ClassifiedPacket::Udp(input) => {
            let udp = ScionUdpPacket::try_from_raw(reconstructed)
                .expect("Converting to UDP packet failed");
            prop_assert_eq!(
                input,
                &udp,
                "Original and reconstructed UDP packets do not match"
            );
        }
        ClassifiedPacket::Other(input) => {
            prop_assert_eq!(
                input,
                &reconstructed,
                "Original and reconstructed Other packets do not match"
            );
        }
        other => panic!("unknown packet class: {other:?}"),
    }
    Ok(())
}

/// Checks that a ref packet with the same parts as `packet` encodes to the same bytes as the owned
/// packet, also into a buffer with old data.
///
/// Skips a packet with a host address of unknown type, because the ref constructors take SCION
/// addresses. Also skips a packet kind without a ref type.
fn assert_ref_eq(packet: &ClassifiedPacket) -> Result<(), TestCaseError> {
    // Owned encoding with traffic class and flow ID 0, as the ref constructors set them
    let mut normalized = packet.clone();
    let common = match &mut normalized {
        ClassifiedPacket::Udp(p) => &mut p.header.common,
        ClassifiedPacket::Scmp(p) => &mut p.header.common,
        ClassifiedPacket::Other(p) => &mut p.header.common,
        _ => return Ok(()),
    };
    common.traffic_class = 0;
    common.flow_id = 0;
    let expected = normalized
        .try_encode_to_vec()
        .expect("Writing to buffer failed");
    let (view, _) = ScionRawPacketView::try_from_slice(&expected).expect("Creating view failed");
    let path = view.header().path();

    // Ref encoding into a zeroed buffer and into a buffer with old data
    let encoded = match &normalized {
        ClassifiedPacket::Udp(p) => {
            let (Ok(src), Ok(dst)) = (p.src_socket_addr(), p.dst_socket_addr()) else {
                return Ok(());
            };
            encode_twice(&ScionUdpPacketRef::new(
                src,
                dst,
                path.as_ref(),
                &p.payload.payload,
            ))
        }
        ClassifiedPacket::Scmp(p) => {
            let (Ok(src), Ok(dst)) = (p.src_scion_addr(), p.dst_scion_addr()) else {
                return Ok(());
            };
            encode_twice(&ScionScmpPacketRef::new(
                src,
                dst,
                path.as_ref(),
                &p.payload,
            ))
        }
        ClassifiedPacket::Other(p) => {
            let (Ok(src), Ok(dst)) = (p.src_scion_addr(), p.dst_scion_addr()) else {
                return Ok(());
            };
            let next_header = p.header.common.next_header;
            encode_twice(&ScionRawPacketRef::new(
                src,
                dst,
                path.as_ref(),
                next_header,
                &p.payload,
            ))
        }
        _ => return Ok(()),
    };

    let (zeroed, stale) = encoded;
    prop_assert_eq!(
        &zeroed,
        &expected,
        "Ref and owned packets encode differently"
    );
    prop_assert_eq!(&stale, &expected, "Ref leaves bytes of an old buffer");
    Ok(())
}

fn encode_twice(packet: &impl WireEncode) -> (Vec<u8>, Vec<u8>) {
    let mut zeroed = vec![0u8; packet.required_size()];
    let mut stale = vec![0xAAu8; packet.required_size()];
    packet
        .try_encode(&mut zeroed)
        .expect("Writing to buffer failed");
    packet
        .try_encode(&mut stale)
        .expect("Writing to buffer failed");

    (zeroed, stale)
}
