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

//! Shared helpers for SCION header property tests.

// Suppress warnings for items/imports not used in every test binary that includes this module.
#![allow(dead_code, unused_imports)]

use proptest::{
    collection::vec,
    prelude::{BoxedStrategy, Strategy, any, prop},
    prop_assert, prop_assert_eq, prop_oneof,
};
use proptest_derive::Arbitrary;
use sciparse::{
    core::view::View,
    header::view::{ScionHeaderView, ScionPathViewMut},
    identifier::isd_asn::IsdAsn,
    path::standard::view::{HopFieldView, InfoFieldView},
};
use tinyvec::ArrayVec;

/// Execute every function in the ScionHeaderView to ensure they do not panic
///
/// Will execute all functions, both mutable and immutable.
/// Mutable functions are called with the current value to avoid changing the header.
pub fn exec_every_view_function(
    view: &mut ScionHeaderView,
) -> Result<(), proptest::prelude::TestCaseError> {
    // Common header - immutable functions
    let _ = view.version();
    let _ = view.traffic_class();
    let _ = view.flow_id();
    let _ = view.next_header();
    let _ = view.payload_len();
    let _ = view.header_len();
    let _ = view.path_type();
    let _ = view.dst_addr_type();
    let _ = view.src_addr_type();

    // Common header - mutable functions
    view.set_version(view.version());
    view.set_traffic_class(view.traffic_class());
    view.set_flow_id(view.flow_id());
    view.set_next_header(view.next_header());
    unsafe {
        view.set_payload_len(view.payload_len());
        view.set_header_len(view.header_len());
        view.set_path_type(view.path_type());
        view.set_dst_addr_type(view.dst_addr_type());
        view.set_src_addr_type(view.src_addr_type());
    }

    // Address header - immutable functions
    let dst_isd = view.dst_isd();
    let dst_as = view.dst_as();
    let dst_ia = view.dst_ia();
    prop_assert_eq!(dst_ia, IsdAsn::new(dst_isd, dst_as));
    let src_isd = view.src_isd();
    let src_as = view.src_as();
    let src_ia = view.src_ia();
    prop_assert_eq!(src_ia, IsdAsn::new(src_isd, src_as));
    let _ = view.dst_host_addr();
    let _ = view.src_host_addr();

    // Address header - mutable functions
    view.set_src_isd(view.src_isd());
    view.set_src_as(view.src_as());
    view.set_dst_isd(view.dst_isd());
    view.set_dst_as(view.dst_as());

    if let ScionPathViewMut::Standard(path_view) = view.path_mut() {
        // Standard path - immutable functions
        let _ = path_view.curr_info_field();
        let _ = path_view.curr_hop_field();
        let _ = path_view.seg0_len();
        let _ = path_view.seg1_len();
        let _ = path_view.seg2_len();

        check_slice_is_in_bounds(path_view.as_bytes());
        // Standard path - mutable functions
        path_view.set_curr_info_field(path_view.curr_info_field());
        path_view.set_curr_hop_field(path_view.curr_hop_field());
        unsafe {
            path_view.set_seg0_len(path_view.seg0_len());
            path_view.set_seg1_len(path_view.seg1_len());
            path_view.set_seg2_len(path_view.seg2_len());
        }

        for info_field in path_view.info_fields_mut() {
            exec_info_field_functions(info_field);
            check_slice_is_in_bounds(info_field.as_bytes());
        }

        for hop_field in path_view.hop_fields_mut() {
            exec_hop_field_functions(hop_field);
            check_slice_is_in_bounds(hop_field.as_bytes());
        }

        // Access every field
        for info_idx in 0..path_view.info_field_count() {
            let fld = path_view.info_field_mut(info_idx as usize);
            prop_assert!(
                fld.is_some(),
                "Info field index {} should be in bounds",
                info_idx
            );

            let fld = fld.unwrap();
            check_slice_is_in_bounds(fld.as_bytes());
            exec_info_field_functions(fld);
        }
        // Access every field
        for hop_idx in 0..path_view.hop_field_count() {
            let fld = path_view.hop_field_mut(hop_idx as usize);
            prop_assert!(
                fld.is_some(),
                "Hop field index {} should be in bounds",
                hop_idx
            );

            let fld = fld.unwrap();
            check_slice_is_in_bounds(fld.as_bytes());
            exec_hop_field_functions(fld);
        }
        // access out of bounds should not return valid fields
        let out_of_bounds_info = path_view.info_field(path_view.info_field_count() as usize);
        let out_of_bounds_hop = path_view.hop_field(path_view.hop_field_count() as usize);
        prop_assert!(
            out_of_bounds_info.is_none(),
            "Out of bounds info field should return None"
        );
        prop_assert!(
            out_of_bounds_hop.is_none(),
            "Out of bounds hop field should return None"
        );
    }

    if let ScionPathViewMut::OneHop(path_view) = view.path_mut() {
        let _ = path_view.info_field();
        let _ = path_view.hop_fields();

        let info_field = path_view.info_field_mut();
        check_slice_is_in_bounds(info_field.as_bytes());
        exec_info_field_functions(info_field);
        let hop_fields = path_view.mut_hop_fields();
        for hop_field in hop_fields {
            check_slice_is_in_bounds(hop_field.as_bytes());
            exec_hop_field_functions(hop_field);
        }
    }

    return Ok(());

    fn exec_info_field_functions(info_field: &mut InfoFieldView) {
        let _ = info_field.flags();
        let _ = info_field.segment_id();
        let _ = info_field.timestamp();

        info_field.set_flags(info_field.flags());
        info_field.set_segment_id(info_field.segment_id());
        info_field.set_timestamp(info_field.timestamp());
    }

    fn exec_hop_field_functions(hop_field: &mut HopFieldView) {
        let _ = hop_field.flags();
        let _ = hop_field.exp_time();
        let _ = hop_field.cons_ingress();
        let _ = hop_field.cons_egress();
        let _ = hop_field.mac();

        hop_field.set_flags(hop_field.flags());
        hop_field.set_exp_time(hop_field.exp_time());
        hop_field.set_cons_ingress(hop_field.cons_ingress());
        hop_field.set_cons_egress(hop_field.cons_egress());
        hop_field.set_mac(hop_field.mac());
    }
}

fn check_slice_is_in_bounds(slice: &[u8]) {
    let _a = slice[0];
    let _b = slice[slice.len() - 1];
}

/// Strategies for generating valid SCION headers
pub mod valid {
    use sciparse::{
        address::host_addr::{ServiceAddr, WireHostAddr},
        header::model::{AddressHeader, CommonHeader, Path, ScionPacketHeader},
        identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
        path::{
            onehop::model::OneHopPath,
            standard::{
                model::{HopField, InfoField, Segment, StandardPath},
                types::{HopFieldFlags, HopFieldMac, InfoFieldFlags, PathType},
            },
        },
    };

    use super::*;

    /// Options for constructing a valid SCION header for testing
    #[derive(Debug, Clone, Arbitrary)]
    pub struct ValidHeaderOptions {
        // Common
        pub traffic_class: u8,
        #[proptest(strategy = "0u32..=0xF_FFFFu32")]
        pub flow_id: u32,
        pub next_header: u8,
        pub payload_len: u16,

        // Address
        #[proptest(strategy = "isd()")]
        pub dst_isd: Isd,
        #[proptest(strategy = "asn()")]
        pub dst_as: Asn,
        #[proptest(strategy = "isd()")]
        pub src_isd: Isd,
        #[proptest(strategy = "asn()")]
        pub src_as: Asn,
        #[proptest(strategy = "scion_host_addr()")]
        pub dst_addr: WireHostAddr,
        #[proptest(strategy = "scion_host_addr()")]
        pub src_addr: WireHostAddr,

        // Path
        #[proptest(strategy = "header_path_options()")]
        pub path: HeaderPathOptions,
    }

    impl ValidHeaderOptions {
        pub fn to_header(&self) -> ScionPacketHeader {
            let common = CommonHeader {
                traffic_class: self.traffic_class,
                flow_id: self.flow_id,
                next_header: self.next_header,
            };

            let address = AddressHeader {
                dst_ia: IsdAsn::new(self.dst_isd, self.dst_as),
                src_ia: IsdAsn::new(self.src_isd, self.src_as),
                dst_host_addr: self.dst_addr.clone(),
                src_host_addr: self.src_addr.clone(),
            };

            let path = match &self.path {
                HeaderPathOptions::Empty => Path::Empty,
                HeaderPathOptions::OneHop { info, hops } => {
                    Path::OneHop(OneHopPath {
                        info: InfoField {
                            flags: info.flags,
                            segment_id: info.seg_id,
                            timestamp: info.timestamp,
                        },
                        hops: [
                            HopField {
                                flags: hops[0].flags,
                                expiration_units: hops[0].exp_time,
                                cons_ingress: hops[0].cons_ingress,
                                cons_egress: hops[0].cons_egress,
                                mac: HopFieldMac::from(hops[0].mac),
                            },
                            HopField {
                                flags: hops[1].flags,
                                expiration_units: hops[1].exp_time,
                                cons_ingress: hops[1].cons_ingress,
                                cons_egress: hops[1].cons_egress,
                                mac: HopFieldMac::from(hops[1].mac),
                            },
                        ],
                    })
                }
                HeaderPathOptions::Unknown { path_id, raw_bytes } => {
                    Path::Unsupported {
                        path_type: PathType::Other(*path_id),
                        data: raw_bytes.clone(),
                    }
                }
                HeaderPathOptions::Scion {
                    meta,
                    segment: segment_generator,
                } => {
                    let segments: Vec<Segment> = segment_generator
                        .iter()
                        .map(|seg_opt| {
                            Segment {
                                info_field: InfoField {
                                    flags: seg_opt.info.flags,
                                    segment_id: seg_opt.info.seg_id,
                                    timestamp: seg_opt.info.timestamp,
                                },
                                hop_fields: seg_opt
                                    .hops
                                    .iter()
                                    .map(|hop| {
                                        HopField {
                                            flags: hop.flags,
                                            expiration_units: hop.exp_time,
                                            cons_ingress: hop.cons_ingress,
                                            cons_egress: hop.cons_egress,
                                            mac: HopFieldMac::from(hop.mac),
                                        }
                                    })
                                    .collect(),
                            }
                        })
                        .collect();

                    Path::Standard(StandardPath {
                        current_info_field: meta.current_info,
                        curr_hop_field: meta.current_hop,
                        segments,
                    })
                }
            };

            ScionPacketHeader {
                common,
                address,
                path,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum HeaderPathOptions {
        Scion {
            meta: MetaOptions,
            segment: ArrayVec<[SegmentOptions; 3]>,
        },
        OneHop {
            info: TestInfoField,
            hops: [TestHopField; 2],
        },
        Empty,
        Unknown {
            path_id: u8, // Must be > 4
            raw_bytes: Vec<u8>,
        },
    }

    #[derive(Debug, Clone)]
    pub struct MetaOptions {
        // Should be at most seg_len.filter(|&x| x > 0).count() - 1
        current_info: u8,
        // Should be at most hops.len() - 1
        current_hop: u8,
    }

    #[derive(Debug, Clone, Default)]
    pub struct SegmentOptions {
        info: TestInfoField,
        /// len must be < 63
        hops: Vec<TestHopField>,
    }

    #[derive(Debug, Clone, Arbitrary, Default)]
    pub struct TestInfoField {
        #[proptest(strategy = "info_flag()")]
        flags: InfoFieldFlags,
        seg_id: u16,
        timestamp: u32,
    }

    #[derive(Debug, Clone, Arbitrary, Default)]
    pub struct TestHopField {
        #[proptest(strategy = "hop_flag()")]
        flags: HopFieldFlags,
        exp_time: u8,
        cons_ingress: u16,
        cons_egress: u16,
        mac: [u8; 6],
    }

    /// Strategy for generating ISD values
    fn isd() -> impl Strategy<Value = Isd> {
        prop::num::u16::ANY.prop_map(Isd::new)
    }

    /// Strategy for generating ASN values (48-bit)
    fn asn() -> impl Strategy<Value = Asn> {
        (0u64..=0x0000_FFFF_FFFF_FFFFu64).prop_map(Asn::new)
    }

    /// Strategy for generating WireHostAddr
    fn scion_host_addr() -> impl Strategy<Value = WireHostAddr> {
        prop_oneof![
            2 => prop::array::uniform4(prop::num::u8::ANY).prop_map(|bytes| WireHostAddr::V4(bytes.into())),
            2 => prop::array::uniform16(prop::num::u8::ANY).prop_map(|bytes| WireHostAddr::V6(bytes.into())),
            1 => prop::num::u16::ANY.prop_map(|val| WireHostAddr::Svc(ServiceAddr(val))),
            1 => ((2u8..=3), vec(prop::num::u8::ANY, 4..=16))
                .prop_map(|(id, bytes_vec)| {
                    // Take chunks of 4 bytes to keep alignment
                    let chunks = bytes_vec.chunks_exact(4);
                    let mut bytes = ArrayVec::new();
                    for chunk in chunks {
                        for &b in chunk {
                            bytes.push(b);
                        }
                    }
                    WireHostAddr::Unknown { id, bytes }
                }),
        ]
    }

    /// Strategy for generating HeaderPathOptions
    fn header_path_options() -> impl Strategy<Value = HeaderPathOptions> {
        prop_oneof![
            // Empty path
            1 => prop::strategy::Just(HeaderPathOptions::Empty),
            // One-hop path with 2 hop fields
            1 => (any::<TestInfoField>(), vec(any::<TestHopField>(), 2))
                .prop_map(|(info, hops)| HeaderPathOptions::OneHop { info, hops: hops.try_into().unwrap() }),
            // Unknown path
            1 => (
                (5u8..=255u8),
                vec(prop::array::uniform4(prop::num::u8::ANY), 0..=25)
            ).prop_map(|(path_id, raw_bytes_chunks)| {
                let raw_bytes = raw_bytes_chunks
              .into_iter()
              .flatten()
              .collect::<Vec<u8>>();
                HeaderPathOptions::Unknown { path_id, raw_bytes }
            }),
            // Scion path - most common
            8 => (scion_path())
                .prop_map(|(meta, segment)| HeaderPathOptions::Scion { meta, segment }),
        ]
    }

    /// Strategy for generating a Vec of SegmentOptions (up to 3 segments)
    fn scion_path() -> impl Strategy<Value = (MetaOptions, ArrayVec<[SegmentOptions; 3]>)> {
        (any::<u8>(), vec(segment_options(), 1..=3)).prop_map(|(curr, segments)| {
            let mut arr = ArrayVec::new();
            let mut total_hop_fields = 0;
            for seg in segments {
                total_hop_fields += seg.hops.len();
                if arr.try_push(seg).is_none() {
                    break;
                }
            }

            let segment_count = arr.len() as u8;
            let hop_count = total_hop_fields as u8;

            let current_info = if segment_count == 0 {
                0
            } else {
                curr % segment_count
            };

            let current_hop = if hop_count == 0 { 0 } else { curr % hop_count };

            (
                MetaOptions {
                    current_info,
                    current_hop,
                },
                arr,
            )
        })
    }

    /// Strategy for generating SegmentOptions
    fn segment_options() -> impl Strategy<Value = SegmentOptions> {
        (any::<TestInfoField>(), vec(any::<TestHopField>(), 1..63))
            .prop_map(|(info, hops)| SegmentOptions { info, hops })
    }

    fn hop_flag() -> impl Strategy<Value = HopFieldFlags> {
        (0..=255u8).prop_map(HopFieldFlags::from_bits_truncate)
    }

    fn info_flag() -> impl Strategy<Value = InfoFieldFlags> {
        (0..=255u8).prop_map(InfoFieldFlags::from_bits_truncate)
    }
}
