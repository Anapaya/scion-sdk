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

//! Invalid Model-level packet must not panic during encoding.

mod helpers;

use std::panic::catch_unwind;

use proptest::{
    collection::vec,
    prelude::{BoxedStrategy, ProptestConfig, Strategy, any, prop},
    prop_assert, prop_oneof, proptest,
};
use sciparse::{
    core::{
        encode::{EncodeError, WireEncode},
        view::View,
    },
    packet::{
        model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
        view::ScionRawPacketView,
    },
};

use crate::helpers::view_function_checks::packet::exec_every_view_function;

/// Breaks packets at the model level and ensures no panics occur during encoding
#[test]
fn encoding_invalid_packets_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(invalid_opts: packet_manipulation::InvalidPacketOptions)| {
            encoding_invalid_packets_impl(invalid_opts)?;
        }
    );

    fn encoding_invalid_packets_impl(
        invalid_opts: packet_manipulation::InvalidPacketOptions,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let packet = invalid_opts.into_packet();

            let required_size = packet.required_size();
            let mut buf = vec![0u8; required_size];

            match packet.encode(&mut buf) {
                Ok(_) => {
                    let (view, _rest) = ScionRawPacketView::from_mut_slice(&mut buf)
                        .expect("Anything that encodes must be decodable");
                    exec_every_view_function(view);
                }
                Err(EncodeError::InvalidStructure(_)) => {
                    return Ok(());
                }
                Err(e) => {
                    prop_assert!(
                        false,
                        "Unexpected error during invalid packet encoding {:?}",
                        e
                    );
                }
            }

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("{:?}", panic.downcast_ref::<&str>());
                prop_assert!(false, "Panic during invalid packet encoding");
                Ok(())
            }
        }
    }
}

/// Model-level manipulation of packets to create invalid packets for encoding tests.
///
/// Includes all header-level modifications that affect offset calculations (segment lengths,
/// hop/info field indices, path bytes, address sizes) plus packet-level modifications that affect
/// payload interpretation (wrong next_header, mismatched raw payload).
mod packet_manipulation {
    use proptest::prelude::Arbitrary;
    use sciparse::{
        address::host_addr::WireHostAddr,
        packet::classify::ClassifiedPacket,
        path::{
            model::Path,
            standard::{
                layout::StdPathMetaLayout,
                model::HopField,
                types::{HopFieldFlags, HopFieldMac},
            },
            types::PathType,
        },
    };
    use tinyvec::ArrayVec;

    use super::*;

    /// Options for creating an invalid packet at the model level
    #[derive(Debug, Clone)]
    pub struct InvalidPacketOptions {
        /// Base valid packet to modify
        base: ClassifiedPacket,
        /// Modifications to apply
        modifications: Vec<PacketModification>,
    }

    /// Ways to break a packet at the model level.
    ///
    /// Only includes fields that participate in offset or size calculations —
    /// semantic-only fields (ports, traffic class, flow ID) are excluded because
    /// they cannot cause out-of-bounds access.
    #[derive(Debug, Clone)]
    pub enum PacketModification {
        // ── Header-level (offset-affecting) ──────────────────────────
        /// Set segment with no hop fields
        EmptySegment(u8),
        /// Set current hop field beyond valid range
        InvalidCurrentHop(u8),
        /// Set current info field beyond valid range
        InvalidCurrentInfo(u8),
        /// Create segment with more than 63 hop fields
        TooManyHopFields(u8, u8),
        /// Create path with invalid unknown path length (not multiple of 4)
        InvalidUnknownPathBytes(Vec<u8>),
        /// Make source address invalid length
        InvalidSrcAddrBytes(ArrayVec<[u8; 16]>),
        /// Make destination address invalid length
        InvalidDstAddrBytes(ArrayVec<[u8; 16]>),

        // ── Packet-level (payload interpretation) ────────────────────
        /// Set `next_header` to a protocol that doesn't match the payload.
        /// Affects which typed view (`classify`, `try_into_udp`, `try_into_scmp`)
        /// is constructed over the payload bytes.
        WrongNextHeader(u8),
    }

    impl InvalidPacketOptions {
        pub fn into_packet(self) -> ClassifiedPacket {
            let InvalidPacketOptions {
                base,
                modifications,
            } = self;

            // Decompose into header + raw payload
            let (mut header, payload) = match base {
                ClassifiedPacket::Udp(pkt) => {
                    // Encode the UDP payload to raw bytes so header modifications
                    // apply uniformly
                    (
                        pkt.header,
                        PayloadState::Typed(ClassifiedPayload::Udp(pkt.payload)),
                    )
                }
                ClassifiedPacket::Scmp(pkt) => {
                    (
                        pkt.header,
                        PayloadState::Typed(ClassifiedPayload::Scmp(pkt.payload)),
                    )
                }
                ClassifiedPacket::Other(pkt) => (pkt.header, PayloadState::Raw(pkt.payload)),
            };

            for modification in modifications {
                match modification {
                    // ── Header-level modifications ────────────────────
                    PacketModification::EmptySegment(seg_idx) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            if std_path.segments.is_empty() {
                                continue;
                            }
                            let target =
                                (seg_idx as usize).min(std_path.segments.len().saturating_sub(1));
                            if let Some(segment) = std_path.segments.get_mut(target) {
                                segment.hop_fields.clear();
                            }
                        }
                    }
                    PacketModification::InvalidCurrentHop(exceed_by) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let count = std_path.hop_field_count();
                            let max_valid = if count == 0 { 0 } else { count - 1 };
                            let invalid = max_valid + exceed_by as usize;
                            let clamped = invalid.min(StdPathMetaLayout::MAX_SEGMENT_HOPS);
                            std_path.curr_hop_field = clamped as u8;
                        }
                    }
                    PacketModification::InvalidCurrentInfo(exceed_by) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let count = std_path.info_field_count();
                            let max_valid = if count == 0 { 0 } else { count - 1 };
                            let invalid = max_valid + exceed_by as usize;
                            let clamped =
                                invalid.min(StdPathMetaLayout::CURR_INFO_FIELD_RNG.max_uint());
                            std_path.current_info_field = clamped as u8;
                        }
                    }
                    PacketModification::TooManyHopFields(seg_idx, extra) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let seg_len = std_path.segments.len();
                            if seg_len == 0 {
                                continue;
                            }
                            let seg_idx = (seg_idx as usize).min(seg_len - 1);
                            let segment = &mut std_path.segments[seg_idx];
                            let target_hops = 63usize.saturating_add(extra as usize);
                            if segment.hop_fields.len() < target_hops {
                                segment.hop_fields.resize(
                                    target_hops,
                                    HopField {
                                        flags: HopFieldFlags::empty(),
                                        expiration_units: 0,
                                        cons_ingress: 0,
                                        cons_egress: 0,
                                        mac: HopFieldMac::from([0; 6]),
                                    },
                                );
                            }
                        }
                    }
                    PacketModification::InvalidUnknownPathBytes(raw_bytes) => {
                        header.path = Path::Unsupported {
                            path_type: PathType::Other(6),
                            data: raw_bytes,
                        };
                    }
                    PacketModification::InvalidSrcAddrBytes(raw_bytes) => {
                        header.address.src_host_addr = WireHostAddr::Unknown {
                            id: 7,
                            bytes: raw_bytes,
                        };
                    }
                    PacketModification::InvalidDstAddrBytes(raw_bytes) => {
                        header.address.dst_host_addr = WireHostAddr::Unknown {
                            id: 7,
                            bytes: raw_bytes,
                        };
                    }

                    // ── Packet-level modifications ────────────────────
                    PacketModification::WrongNextHeader(nh) => {
                        header.common.next_header = nh;
                    }
                }
            }

            // Reassemble into ClassifiedPacket
            match payload {
                PayloadState::Typed(ClassifiedPayload::Udp(udp)) => {
                    ClassifiedPacket::Udp(ScionUdpPacket {
                        header,
                        payload: udp,
                    })
                }
                PayloadState::Typed(ClassifiedPayload::Scmp(scmp)) => {
                    ClassifiedPacket::Scmp(ScionScmpPacket {
                        header,
                        payload: scmp,
                    })
                }
                PayloadState::Raw(raw) => {
                    ClassifiedPacket::Other(ScionRawPacket {
                        header,
                        payload: raw,
                    })
                }
            }
        }
    }

    /// Internal helpers for payload decomposition
    #[derive(Debug, Clone)]
    enum PayloadState {
        Typed(ClassifiedPayload),
        Raw(Vec<u8>),
    }

    #[derive(Debug, Clone)]
    enum ClassifiedPayload {
        Udp(sciparse::payload::udp::model::UdpDatagram),
        Scmp(sciparse::payload::scmp::model::ScmpMessage),
    }

    impl Arbitrary for InvalidPacketOptions {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            any::<ClassifiedPacket>()
                .prop_flat_map(|base| {
                    let has_scion_path = match &base {
                        ClassifiedPacket::Udp(p) => {
                            matches!(p.header.path, Path::Standard(_))
                        }
                        ClassifiedPacket::Scmp(p) => {
                            matches!(p.header.path, Path::Standard(_))
                        }
                        ClassifiedPacket::Other(p) => {
                            matches!(p.header.path, Path::Standard(_))
                        }
                    };

                    prop::collection::vec(packet_modification_strategy(has_scion_path), 1..=5)
                        .prop_map(move |modifications| {
                            InvalidPacketOptions {
                                base: base.clone(),
                                modifications,
                            }
                        })
                })
                .boxed()
        }
    }

    fn packet_modification_strategy(has_scion_path: bool) -> BoxedStrategy<PacketModification> {
        if has_scion_path {
            prop_oneof![
                // Header-level: all path modifications valid for SCION paths
                (0u8..=2).prop_map(PacketModification::EmptySegment),
                (1u8..=255).prop_map(PacketModification::InvalidCurrentHop),
                (1u8..=4).prop_map(PacketModification::InvalidCurrentInfo),
                (0u8..=2, 1u8..=255)
                    .prop_map(|(seg, extra)| PacketModification::TooManyHopFields(seg, extra)),
                vec(prop::num::u8::ANY, 0..=15).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    PacketModification::InvalidSrcAddrBytes(ArrayVec::from_iter(bytes))
                }),
                vec(prop::num::u8::ANY, 0..=15).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    PacketModification::InvalidDstAddrBytes(ArrayVec::from_iter(bytes))
                }),
                // Packet-level
                any::<u8>().prop_map(PacketModification::WrongNextHeader),
            ]
            .boxed()
        } else {
            prop_oneof![
                // Header-level: only non-path modifications for Empty/Unknown paths
                vec(prop::num::u8::ANY, 1..=100).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    PacketModification::InvalidUnknownPathBytes(bytes)
                }),
                vec(prop::num::u8::ANY, 0..=15).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    PacketModification::InvalidSrcAddrBytes(ArrayVec::from_iter(bytes))
                }),
                vec(prop::num::u8::ANY, 0..=15).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    PacketModification::InvalidDstAddrBytes(ArrayVec::from_iter(bytes))
                }),
                // Packet-level
                any::<u8>().prop_map(PacketModification::WrongNextHeader),
            ]
            .boxed()
        }
    }
}
