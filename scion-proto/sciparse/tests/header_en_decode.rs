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

//! Contains tests for SCION header parsing and encoding/decoding
//!
//! 1. All valid headers should roundtrip through encode/decode without loss of information or
//!    panics
//! 2. Strategic fuzzing of important field must not cause panics during decoding or manipulation
//! 3. Brute force fuzzing must not panic during parsing or view manipulation
//! 4. No invalid header must panic during encoding

mod helpers;

use std::panic::catch_unwind;

use helpers::header::{valid, valid::ValidHeaderOptions};
use proptest::{
    collection::vec,
    prelude::{BoxedStrategy, ProptestConfig, Strategy, any, prop},
    prop_assert, prop_assert_eq, prop_oneof, proptest,
};
use sciparse::{
    core::{
        encode::EncodeError,
        view::{View, ViewConversionError},
    },
    header::{
        model::ScionPacketHeader,
        view::{ScionHeaderView, ScionPathViewMut},
    },
};
use tinyvec::ArrayVec;

/// Creates valid headers with various options and ensures they roundtrip through encoding and
/// decoding Validates all functions in the ScionHeaderView do not panic
#[test]
fn valid_headers_should_roudtrip_correctly() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(opts: ValidHeaderOptions)| {
            test_impl(opts)?;
        }
    );

    fn test_impl(header_opts: ValidHeaderOptions) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let initial = header_opts.to_header();

            match initial.wire_valid() {
                Ok(_) => {}
                Err(e) => {
                    println!("Generated header is not valid: {:?}", e);
                    return Err(proptest::prelude::TestCaseError::reject(
                        "Generated header is not valid",
                    ));
                }
            }

            let mut buf = vec![0u8; initial.required_size()];
            initial
                .encode(&mut buf, header_opts.payload_len)
                .expect("Writing to buffer failed");

            let (view, rst) =
                ScionHeaderView::from_mut_slice(&mut buf).expect("Creating view failed");

            prop_assert_eq!(rst.len(), 0);

            helpers::header::exec_every_view_function(view)?;

            // Reconstruct header from view
            let reconstructed = ScionPacketHeader::from_view(view);

            prop_assert_eq!(initial, reconstructed);

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("Panic during roundtrip with options: {:#?}", header_opts);
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>()); // Some("A wild panic appeared!")

                prop_assert!(false, "Panic during roundtrip");
                Ok(())
            }
        }
    }
}

/// Breaks headers in specific ways to create invalid headers and ensures no panics occur during
/// encoding
#[test]
fn encoding_invalid_headers_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(invalid_opts: header_manipulation::InvalidLoadedHeaderOptions)| {
            encoding_invalid_headers_must_not_panic_impl(invalid_opts)?;
        }
    );
    fn encoding_invalid_headers_must_not_panic_impl(
        invalid_opts: header_manipulation::InvalidLoadedHeaderOptions,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let payload_len = invalid_opts.payload_len();
            let header = invalid_opts.into_header();

            let required_size = header.required_size();
            let mut buf = vec![0u8; required_size];

            match header.encode(&mut buf, payload_len) {
                Ok(_) => {
                    prop_assert!(false, "Invalid header encoding succeeded unexpectedly",);
                }
                Err(EncodeError::InvalidStructure(_)) => {
                    return Ok(());
                }
                // Other errors are unexpected
                Err(e) => {
                    prop_assert!(
                        false,
                        "Unexpected error during invalid header encoding {:?}",
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

                prop_assert!(false, "Panic during invalid header encoding");
                Ok(())
            }
        }
    }
}

/// Strategically breaks important header fields and ensures no panics occur during parsing or
/// view manipulation
#[test]
fn parsing_invalid_headers_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        |(breaking_opts: wire_manipulation::HeaderBreakingOptions,
          valid_opts: valid::ValidHeaderOptions)| {
            no_invalid_header_must_panic_impl(breaking_opts, valid_opts)?;
        }
    );

    fn no_invalid_header_must_panic_impl(
        breaking_opts: wire_manipulation::HeaderBreakingOptions,
        valid_opts: valid::ValidHeaderOptions,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let mut broken_buf = breaking_opts.apply(valid_opts);

            match ScionHeaderView::from_mut_slice(&mut broken_buf) {
                // Expected that some invalid headers may still parse successfully
                Ok((view, _rest)) => {
                    helpers::header::exec_every_view_function(view)?;
                }
                Err(ViewConversionError::BufferTooSmall { .. })
                | Err(ViewConversionError::Other(_)) => {
                    return Ok(());
                }
            }

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!(
                    "Panic during invalid header parsing with breaking options: {:#?}",
                    breaking_opts
                );
                println!("---");
                println!("{:?}", panic.downcast_ref::<&str>()); // Some("A wild panic appeared!")

                prop_assert!(false, "Panic during invalid header parsing");
                Ok(())
            }
        }
    }
}

/// Brute force checks over random data to ensure no panics occur during parsing or view
/// manipulation
#[test]
fn parsing_random_data_must_not_panic() {
    proptest!(
        ProptestConfig::with_cases(5_000),
        | (data in rand_header_data()) | {
            random_data_must_not_panic_impl(data)?;
        }
    );

    fn random_data_must_not_panic_impl(
        data: Vec<u8>,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let unwind = catch_unwind(|| {
            let mut data = data;
            match ScionHeaderView::from_mut_slice(&mut data) {
                Ok((view, _rest)) => {
                    helpers::header::exec_every_view_function(view)?;
                }
                Err(ViewConversionError::BufferTooSmall { .. })
                | Err(ViewConversionError::Other(_)) => {
                    return Ok(());
                }
            }

            Ok(())
        });

        match unwind {
            Ok(res) => res,
            Err(panic) => {
                println!("{:?}", panic.downcast_ref::<&str>());
                prop_assert!(false, "Panic during invalid header parsing");
                Ok(())
            }
        }
    }

    /// Strategy for generating random header data
    fn rand_header_data() -> impl Strategy<Value = Vec<u8>> {
        // Bias random data to look like a SCION header to pass more static checks
        fn bias_to_header_shape(mut data: Vec<u8>) -> Vec<u8> {
            if data.len() < 30 {
                return data;
            }

            let rand_byte = data.len() % data[5].max(1) as usize; // Just a pseudo random byte
            let len: usize = data.len();

            // SAFETY: We know that data is 30 bytes at least which is enough to modify the common
            // header
            let view = unsafe { ScionHeaderView::from_mut_slice_unchecked(&mut data) };
            view.set_version(0);

            // Set some header lengths to a reasonable value so we pass more static checks
            if rand_byte.is_multiple_of(3) {
                let header_len = ((len.min(1000) / 4) * 4) as u16;
                unsafe {
                    view.set_header_len(header_len);
                }
            }

            data
        }

        prop_oneof![
            6 => vec(any::<u8>(), 30..=128).prop_map(bias_to_header_shape),
            3 => vec(any::<u8>(), 30..=512).prop_map(bias_to_header_shape),
            // Completely random data, likely caught by simple static checks
            1 => vec(any::<u8>(), 0..=512),
        ]
    }
}

/// Strategic manipulation of loaded headers to create invalid headers
mod header_manipulation {
    use helpers::header::valid::HeaderPathOptions;
    use proptest::prelude::Arbitrary;
    use sciparse::{
        address::host_addr::WireHostAddr,
        header::model::{Path, ScionPacketHeader},
        path::standard::{
            layout::StdPathMetaLayout,
            model::HopField,
            types::{HopFieldFlags, HopFieldMac, PathType},
        },
    };

    use super::*;

    /// Options for creating an invalid loaded header
    #[derive(Debug, Clone)]
    pub struct InvalidLoadedHeaderOptions {
        /// Base valid header to modify
        base: ValidHeaderOptions,
        /// Modifications to apply
        modifications: Vec<HeaderModification>,
    }

    #[derive(Debug, Clone)]
    pub enum HeaderModification {
        /// Set segment with no hop fields
        EmptySegment(u8), // segment index 0-2
        /// Set current hop field beyond valid range
        InvalidCurrentHop(u8),
        /// Set current info field beyond valid range
        InvalidCurrentInfo(u8),
        /// Create segment with more than 63 hop fields
        TooManyHopFields(u8, u8), // (segment_index, exceed_by)
        /// Create path with invalid unknown path length
        InvalidUnknownPathBytes(Vec<u8>),
        /// Make source address invalid length
        InvalidSrcAddrBytes(ArrayVec<[u8; 16]>),
        /// Make dst address invalid length
        InvalidDstAddrBytes(ArrayVec<[u8; 16]>),
    }

    impl InvalidLoadedHeaderOptions {
        pub fn payload_len(&self) -> u16 {
            self.base.payload_len
        }
        pub fn into_header(self) -> ScionPacketHeader {
            let mut header = self.base.to_header();

            for modification in self.modifications {
                match modification {
                    HeaderModification::EmptySegment(seg_idx) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            if std_path.segments.is_empty() {
                                continue;
                            }

                            // If segment index too high, go to lowest valid
                            let target_seg_idx =
                                (seg_idx as usize).min(std_path.segments.len().saturating_sub(1));

                            if let Some(segment) = std_path.segments.get_mut(target_seg_idx) {
                                segment.hop_fields.clear();
                            }
                        }
                    }
                    HeaderModification::InvalidCurrentHop(exceed_by) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let count = std_path.hop_field_count();
                            let max_valid = if count == 0 { 0 } else { count - 1 };
                            let invalid = max_valid + exceed_by as usize;
                            let clamped = invalid.min(StdPathMetaLayout::MAX_SEGMENT_LENGTH);

                            std_path.curr_hop_field = clamped as u8;
                        }
                    }

                    HeaderModification::InvalidCurrentInfo(exceed_by) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let count = std_path.info_field_count();
                            let max_valid = if count == 0 { 0 } else { count - 1 };
                            let invalid = max_valid + exceed_by as usize;
                            let clamped =
                                invalid.min(StdPathMetaLayout::CURR_INFO_FIELD_RNG.max_uint());

                            std_path.current_info_field = clamped as u8;
                        }
                    }

                    HeaderModification::TooManyHopFields(seg_idx, extra) => {
                        if let Path::Standard(ref mut std_path) = header.path {
                            let seg_len = std_path.segments.len();
                            if seg_len == 0 {
                                continue;
                            }

                            // Clamp segment index to last valid segment
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

                    HeaderModification::InvalidUnknownPathBytes(raw_bytes) => {
                        header.path = Path::Unsupported {
                            path_type: PathType::Other(6),
                            data: raw_bytes,
                        };
                    }
                    HeaderModification::InvalidSrcAddrBytes(raw_bytes) => {
                        header.address.src_host_addr = WireHostAddr::Unknown {
                            id: 7,
                            bytes: raw_bytes,
                        };
                    }
                    HeaderModification::InvalidDstAddrBytes(raw_bytes) => {
                        header.address.dst_host_addr = WireHostAddr::Unknown {
                            id: 7,
                            bytes: raw_bytes,
                        };
                    }
                }
            }
            header
        }
    }

    impl Arbitrary for InvalidLoadedHeaderOptions {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            use proptest::prelude::*;

            any::<ValidHeaderOptions>()
                .prop_flat_map(|base| {
                    let has_scion_path = matches!(base.path, HeaderPathOptions::Scion { .. });

                    prop::collection::vec(header_modification_strategy(has_scion_path), 1..=5)
                        .prop_map(move |modifications| {
                            InvalidLoadedHeaderOptions {
                                base: base.clone(),
                                modifications,
                            }
                        })
                })
                .boxed()
        }
    }

    fn header_modification_strategy(has_scion_path: bool) -> BoxedStrategy<HeaderModification> {
        if has_scion_path {
            // All modifications are allowed for SCION paths
            prop_oneof![
                (0u8..=2).prop_map(HeaderModification::EmptySegment),
                (1u8..=255).prop_map(HeaderModification::InvalidCurrentHop),
                (1u8..=4).prop_map(HeaderModification::InvalidCurrentInfo),
                (0u8..=2, 1u8..=255)
                    .prop_map(|(seg, extra)| HeaderModification::TooManyHopFields(seg, extra)),
                (vec(prop::num::u8::ANY, 0..=15)).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }

                    HeaderModification::InvalidSrcAddrBytes(ArrayVec::from_iter(bytes))
                }),
                (vec(prop::num::u8::ANY, 0..=15)).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }

                    HeaderModification::InvalidDstAddrBytes(ArrayVec::from_iter(bytes))
                }),
            ]
            .boxed()
        } else {
            // Only non-path modifications are allowed for Empty/Unknown paths
            prop_oneof![
                (vec(prop::num::u8::ANY, 1..=100)).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }
                    HeaderModification::InvalidUnknownPathBytes(bytes)
                }),
                (vec(prop::num::u8::ANY, 0..=15)).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }

                    HeaderModification::InvalidSrcAddrBytes(ArrayVec::from_iter(bytes))
                }),
                (vec(prop::num::u8::ANY, 0..=15)).prop_map(|mut bytes| {
                    if bytes.len().is_multiple_of(4) {
                        bytes.pop();
                    }

                    HeaderModification::InvalidDstAddrBytes(ArrayVec::from_iter(bytes))
                }),
            ]
            .boxed()
        }
    }
}

/// Strategic manipulation of important header fields on the wire format
mod wire_manipulation {
    use helpers::header::valid::ValidHeaderOptions;
    use proptest::prelude::{Arbitrary, BoxedStrategy};

    use super::*;

    /// Options for breaking a valid SCION header
    ///
    /// Ordered in the order they should be applied to ensure no UB during view manipulation
    #[derive(Debug)]
    pub struct HeaderBreakingOptions {
        /// Overflow current hop field by this amount
        hop_field_overflow: Option<u8>,
        /// Overflow current info field
        info_field_overflow: Option<u8>,
        /// Override segment length
        segment_len: Option<(u8, u8, u8)>,
        /// Override path type
        path_type: Option<u8>,
        /// Override header length
        header_len: Option<usize>,
        /// Override src_addr_info
        src_addr: Option<u8>,
        /// Override dst_addr_info
        dst_addr: Option<u8>,
        /// Number of bytes to remove from the end of the
        remove_trailing_bytes: usize,
        /// Number of bytes to remove at a random position
        /// (start, length)
        remove_random_bytes: (usize, usize),
    }

    impl HeaderBreakingOptions {
        pub fn apply(&self, options: ValidHeaderOptions) -> Vec<u8> {
            let header = options.to_header();

            // Encode header
            let mut buf = vec![0u8; header.required_size()];
            header
                .encode(&mut buf, options.payload_len)
                .expect("Writing to buffer failed");

            let (view, rest) =
                ScionHeaderView::from_mut_slice(&mut buf).expect("Creating view failed");

            if !rest.is_empty() {
                panic!("Rest len is not zero");
            }

            // Apply breaking options, needs to be applied in a specific order as they will break
            // the views capability to calculate sizes correctly.

            if let ScionPathViewMut::Standard(path_view) = view.path_mut() {
                if let Some(hf_overflow) = self.hop_field_overflow {
                    let max_hop = header.path.standard().unwrap().hop_field_count() as u8;
                    let max_hop = max_hop.saturating_sub(1);
                    let overflow_hop = max_hop.saturating_add(hf_overflow).min(255 >> 2);
                    path_view.set_curr_hop_field(overflow_hop);
                }

                if let Some(overflow) = self.info_field_overflow {
                    path_view.set_curr_info_field(overflow); // This will just select a random info field
                }

                if let Some((seg0_len, seg1_len, seg2_len)) = self.segment_len {
                    // SAFETY: We make sure that we break the packet in order to not cause UB
                    unsafe {
                        path_view.set_seg0_len(seg0_len);
                        path_view.set_seg1_len(seg1_len);
                        path_view.set_seg2_len(seg2_len);
                    }
                }
            }

            if let Some(pt) = self.path_type {
                // SAFETY: We make sure that we break the packet in order to not cause UB
                unsafe {
                    view.set_path_type(pt.into());
                }
            }

            if let Some(hl) = self.header_len {
                // SAFETY: We make sure that we break the packet in order to not cause UB
                unsafe {
                    view.set_header_len(((hl / 4) * 4) as u16); // Must be multiple of 4
                }
            }

            if let Some(sa) = self.src_addr {
                // SAFETY: We make sure that we break the packet in order to not cause UB
                unsafe {
                    view.set_src_addr_type(sa.into());
                }
            }
            if let Some(da) = self.dst_addr {
                // SAFETY: We make sure that we break the packet in order to not cause UB
                unsafe {
                    view.set_dst_addr_type(da.into());
                }
            }

            // Remove trailing bytes
            let final_len = buf.len().saturating_sub(self.remove_trailing_bytes);
            buf.truncate(final_len);

            // Slice off part of the buffer at a random position
            let (start, length) = self.remove_random_bytes;
            if buf.len() > length {
                let wrapped_start = start % (buf.len() - length);
                let end = wrapped_start + length;
                let mut new_buf = Vec::with_capacity(buf.len() - length);

                new_buf.extend_from_slice(&buf[..wrapped_start]);
                new_buf.extend_from_slice(&buf[end..]);
                buf = new_buf;
            }

            buf
        }
    }

    impl Arbitrary for HeaderBreakingOptions {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            header_breaking_options().boxed()
        }
    }

    /// Strategy for generating [`HeaderBreakingOptions`]
    fn header_breaking_options() -> impl Strategy<Value = HeaderBreakingOptions> {
        (
            prop::option::of(1u8..=16),
            prop::option::of(1u8..=16),
            prop::option::of((0u8..=63, 0u8..=63, 0u8..=63)),
            prop::option::of(0u8..=255),
            prop::option::of(1usize..=64),
            prop::option::of(0u8..=7),
            prop::option::of(0u8..=7),
            0usize..=64,
            (0usize..=256, 0usize..=64),
        )
            .prop_map(
                |(
                    hop_field_overflow,
                    info_field_overflow,
                    segment_len,
                    path_type,
                    header_len_words,
                    src_addr,
                    dst_addr,
                    remove_trailing_bytes,
                    remove_random_bytes,
                )| {
                    HeaderBreakingOptions {
                        hop_field_overflow,
                        info_field_overflow,
                        segment_len,
                        path_type,
                        header_len: header_len_words.map(|words| words * 4),
                        src_addr,
                        dst_addr,
                        remove_trailing_bytes,
                        remove_random_bytes,
                    }
                },
            )
    }
}
