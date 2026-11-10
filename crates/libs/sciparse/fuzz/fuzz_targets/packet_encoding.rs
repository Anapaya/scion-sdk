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

//! Fuzzing of SCION packet encoding, for owned packets and for packets that borrow their parts.
//!
//! Each input that parses as a packet goes through three encodings:
//!
//! 1. The owned packet, built from the parsed view.
//! 2. A ref packet with the path of the input. The parser accepts paths that the proptest
//!    generators never produce, and the ref writes them with unchecked operations.
//! 3. A ref packet with the path of the owned encoding. It must give the same bytes as the owned
//!    packet.
//!
//! The proptests in `tests/packet_roundtrip.rs` check encoding into a buffer with old data.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use sciparse::{
    core::{convert::TryFromView, encode::WireEncode, view::View},
    packet::{
        model::{ScionPacketExt, ScionRawPacket, ScionRawPacketRef},
        view::ScionRawPacketView,
    },
    util::fuzz::packet_shape::bias_to_packet_shape,
};

fuzz_target!(|data: &[u8]| {
    let Ok((view, _rest)) = ScionRawPacketView::try_from_slice(data) else {
        return;
    };

    // Owned packet. The ref constructors set traffic class and flow ID to 0.
    let Ok(mut owned) = ScionRawPacket::try_from_view(view) else {
        return;
    };
    owned.header.common.traffic_class = 0;
    owned.header.common.flow_id = 0;
    let Ok(owned_bytes) = owned.try_encode_to_vec() else {
        return;
    };

    // The ref constructors take SCION addresses, which have no unknown host type.
    let (Ok(src), Ok(dst)) = (owned.src_scion_addr(), owned.dst_scion_addr()) else {
        return;
    };
    let next_header = owned.header.common.next_header;

    // Ref with the path of the input
    let input_ref =
        ScionRawPacketRef::new(src, dst, view.header().path(), next_header, view.payload());
    assert_eq!(encode(&input_ref).len(), owned_bytes.len());

    // Ref with the path of the owned encoding
    let (canonical, _) =
        ScionRawPacketView::try_from_slice(&owned_bytes).expect("an encoded packet parses");
    let canonical_ref = ScionRawPacketRef::new(
        src,
        dst,
        canonical.header().path(),
        next_header,
        canonical.payload(),
    );
    assert_eq!(encode(&canonical_ref), owned_bytes);
});

fn encode(packet: &impl WireEncode) -> Vec<u8> {
    let mut buf = vec![0u8; packet.required_size()];
    let written = packet
        .try_encode(&mut buf)
        .expect("a packet from a parsed view encodes");
    assert_eq!(written, buf.len());

    buf
}

// Same structure-aware mutator as in `packet_parsing`, so the corpus holds packet-shaped inputs.
fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        let new_size = fuzzer_mutate(data, size, max_size);
        bias_to_packet_shape(&mut data[..new_size]);

        new_size
    }
);
