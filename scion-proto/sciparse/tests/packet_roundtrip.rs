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

mod helpers;

use std::panic::catch_unwind;

use proptest::{prelude::ProptestConfig, prop_assert, prop_assert_eq, proptest};
use sciparse::{
    core::{encode::WireEncode, view::View},
    packet::{
        classify::ClassifiedPacket,
        model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
        view::ScionRawPacketView,
    },
};

use crate::helpers::view_function_checks;

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
            packet.encode(&mut buf).expect("Writing to buffer failed");

            let (view, rst) =
                ScionRawPacketView::from_mut_slice(&mut buf).expect("Creating view failed");

            prop_assert_eq!(rst.len(), 0);

            assert_packet_eq(&packet, view)?;

            // Exercise every getter/setter on the view hierarchy to validate
            // that no access causes UB on validly-constructed packets.
            view_function_checks::packet::exec_every_view_function(view);

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
    let reconstructed = ScionRawPacket::from_view(view).expect("Converting view to packet failed");

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
    }
    Ok(())
}
