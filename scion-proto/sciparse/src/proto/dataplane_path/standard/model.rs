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

//! SCION standard path models
use tinyvec::{ArrayVec, TinyVec};

use crate::{
    core::{
        convert::{FromView, TryFromModel},
        encode::{InvalidStructureError, WireEncode},
        layout::Layout,
        model::Model,
        write::unchecked_bit_range_be_write,
    },
    dataplane_path::{
        layout::ScionHeaderPathLayout,
        standard::{
            layout::{HopFieldLayout, InfoFieldLayout, StdPathDataLayout, StdPathMetaLayout},
            mac::{ForwardingKey, HopMacCalculate, HopMacInput, HopMacInputSource},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags, exp_time_to_duration},
            view::{HopFieldView, InfoFieldView, StandardPathView},
        },
        types::PathReverseError,
    },
};

/// Represents a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StandardPath {
    /// The current info field index
    pub current_info_field: u8,
    /// The current hop field index
    pub current_hop_field: u8,
    /// The segments of the path
    pub segments: ArrayVec<[Segment; 3]>,
}
impl StandardPath {
    /// Creates a new empty [StandardPath] with zeroed fields and no segments.
    pub fn new_empty() -> Self {
        StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: ArrayVec::new(),
        }
    }
}
// Utility
impl StandardPath {
    /// Returns the total number of hop fields in the path
    pub fn hop_field_count(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.hop_fields.len())
            .sum()
    }

    /// Returns the total number of info fields in the path
    pub fn info_field_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the lengths of each segment in the path as a tuple
    pub fn segment_lengths(&self) -> (u8, u8, u8) {
        let seg0 = self.segments.first().map_or(0, |s| s.hop_fields.len()) as u8;
        let seg1 = self.segments.get(1).map_or(0, |s| s.hop_fields.len()) as u8;
        let seg2 = self.segments.get(2).map_or(0, |s| s.hop_fields.len()) as u8;
        (seg0, seg1, seg2)
    }

    /// Returns an iterator over all hop fields in the path
    pub fn iter_hop_fields(&self) -> impl Iterator<Item = &HopField> {
        self.segments
            .iter()
            .flat_map(|segment| segment.hop_fields.iter())
    }

    /// Returns an iterator over all info fields in the path
    pub fn iter_info_fields(&self) -> impl Iterator<Item = &InfoField> {
        self.segments.iter().map(|segment| &segment.info_field)
    }

    /// Returns the sizes of each segment in the path
    pub fn segment_sizes(&self) -> [u8; 3] {
        let seg0 = self.segments.first().map_or(0, |s| s.hop_fields.len()) as u8;
        let seg1 = self.segments.get(1).map_or(0, |s| s.hop_fields.len()) as u8;
        let seg2 = self.segments.get(2).map_or(0, |s| s.hop_fields.len()) as u8;
        [seg0, seg1, seg2]
    }

    /// Calculates expiry time of the path as a Unix timestamp in seconds by scanning all segments.
    ///
    /// Returns 0 if any of the segments in the path has no hop fields
    pub fn expiration(&self) -> u32 {
        let mut min_expiry = u32::MAX;
        for segment in &self.segments {
            // find the minimum expiry time across all hop fields in the segment
            let Some(exp_units) = segment
                .hop_fields
                .iter()
                .map(|hop| hop.expiration_units)
                .min()
            else {
                // A segment has no hop fields
                return 0;
            };

            let exp_duration = exp_time_to_duration(exp_units)
                .as_secs()
                .try_into()
                .expect("exp_units can't exceed u32");

            let expiry = segment.info_field.timestamp.saturating_add(exp_duration);

            // update expiry
            min_expiry = min_expiry.min(expiry);
        }

        min_expiry
    }

    /// Reverses the path in place.
    pub fn try_reverse(&mut self) -> Result<(), PathReverseError> {
        let seg_count = self.segments.len();
        if seg_count == 0 {
            return Err(PathReverseError::new(
                "Cannot reverse a path with no segments",
            ));
        }

        if self.current_hop_field as usize >= self.hop_field_count() {
            return Err(PathReverseError::new(
                "Cannot reverse a path with invalid current hop field index",
            ));
        }

        if self.current_info_field as usize >= seg_count {
            return Err(PathReverseError::new(
                "Cannot reverse a path with invalid current info field index",
            ));
        }

        // Reverse order of segment lengths (by reversing the segments slice itself)
        // and toggle CONS_DIR on every info field
        for segment in self.segments.iter_mut() {
            segment.info_field.flags.toggle(InfoFieldFlags::CONS_DIR);
        }
        self.segments.reverse();

        // Reverse hop fields within each segment
        for segment in self.segments.iter_mut() {
            segment.hop_fields.reverse();
        }

        // Update current info and hop field indices
        let total_hops = self.hop_field_count();
        let new_hop_idx = (total_hops - self.current_hop_field as usize) - 1;
        let new_info_idx = (seg_count - self.current_info_field as usize) - 1;
        self.current_hop_field = new_hop_idx as u8;
        self.current_info_field = new_info_idx as u8;

        Ok(())
    }
}
impl WireEncode for StandardPath {
    fn required_size(&self) -> usize {
        let [seg0, seg1, seg2] = self.segment_sizes();
        StdPathMetaLayout::SIZE_BYTES + StdPathDataLayout::new(seg0, seg1, seg2).size_bytes()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        if self.required_size() > ScionHeaderPathLayout::MAX_SIZE_BYTES {
            return Err("Encoded path size exceeds maximum allowed".into());
        }

        // Should never be hit since we are using an ArrayVec with a max length of 3.
        // Compiler should optimize this check away.
        if self.segments.len() > StdPathMetaLayout::MAX_SEGMENTS {
            return Err("Number of segments exceeds maximum allowed".into());
        }

        if self.segments.is_empty() {
            return Err("Standard path must contain at least one segment".into());
        }

        if self.current_hop_field as usize >= self.hop_field_count() {
            return Err("curr_hop_field exceeds total number of hop fields".into());
        }

        if self.current_info_field as usize >= self.info_field_count() {
            return Err("current_info_field exceeds total number of info fields".into());
        }

        for segment in &self.segments {
            if segment.hop_fields.len() > StdPathMetaLayout::MAX_SEGMENT_HOPS {
                return Err("Number of hop fields in segment exceeds maximum allowed".into());
            }

            if segment.hop_fields.is_empty() {
                return Err("Segment must contain at least one hop field".into());
            }

            segment.info_field.wire_valid()?;

            for hop_field in &segment.hop_fields {
                hop_field.wire_valid()?;
            }
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        use StdPathMetaLayout as SL;

        let [seg0, seg1, seg2] = self.segment_sizes();

        // Encode standard path meta information
        unsafe {
            unchecked_bit_range_be_write(buf, SL::CURR_INFO_FIELD_RNG, self.current_info_field);
            unchecked_bit_range_be_write(buf, SL::CURR_HOP_FIELD_RNG, self.current_hop_field);
            unchecked_bit_range_be_write(buf, SL::SEG0_LEN_RNG, seg0);
            unchecked_bit_range_be_write(buf, SL::SEG1_LEN_RNG, seg1);
            unchecked_bit_range_be_write(buf, SL::SEG2_LEN_RNG, seg2);
        }

        // Advance offset to path data
        let data_buf = unsafe { buf.get_unchecked_mut(SL::SIZE_BYTES..) };
        let data_layout = StdPathDataLayout::new(seg0, seg1, seg2);

        // Encode standard path data
        // Encode info fields
        for (i, info_field) in self.iter_info_fields().enumerate() {
            let range = data_layout.info_field_range(i).aligned_byte_range();
            unsafe {
                let info_field_buf = data_buf.get_unchecked_mut(range);
                info_field.encode_unchecked(info_field_buf);
            }
        }

        // Encode hop fields
        for (i, hop_field) in self.iter_hop_fields().enumerate() {
            let range = data_layout.hop_field_range(i).aligned_byte_range();
            unsafe {
                let hop_field_buf = data_buf.get_unchecked_mut(range);
                hop_field.encode_unchecked(hop_field_buf);
            }
        }

        SL::SIZE_BYTES + data_layout.size_bytes()
    }
}
impl Model for StandardPath {
    type ViewType = StandardPathView;
}
impl TryFromModel for StandardPathView {
    type ModelType = StandardPath;
}
impl FromView for StandardPath {
    type ViewType = StandardPathView;

    fn from_view(view: &Self::ViewType) -> Self {
        let info_fields = view.info_fields();
        let hop_fields = view.hop_fields();
        let segment_sizes = [view.seg0_len(), view.seg1_len(), view.seg2_len()];

        let mut segments = ArrayVec::new();
        let mut hop_fields_iter = hop_fields.iter();

        for (info_field, segment_size) in info_fields.iter().zip(segment_sizes.iter()) {
            let segment = Segment {
                info_field: InfoField::from_view(info_field),
                hop_fields: hop_fields_iter
                    .by_ref()
                    .take(*segment_size as usize)
                    .map(HopField::from_view)
                    .collect(),
            };

            segments.push(segment);
        }

        StandardPath {
            current_info_field: view.curr_info_field_idx(),
            current_hop_field: view.curr_hop_field_idx(),
            segments,
        }
    }
}

/// Represents a segment in a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Segment {
    /// Info field containing metadata about the segment
    pub info_field: InfoField,
    /// Hop fields representing the hops in the segment
    // Note: As long as the total number of hops does not exceed the defined maximum, tinyvec will
    // store the hop fields inline without heap allocation.
    pub hop_fields: TinyVec<[HopField; 12]>,
}
impl Default for Segment {
    fn default() -> Self {
        Self {
            info_field: InfoField {
                flags: InfoFieldFlags::empty(),
                segment_id: 0,
                timestamp: 0,
            },
            hop_fields: TinyVec::new(),
        }
    }
}

/// Represents an info field in a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InfoField {
    /// Info field flags
    pub flags: InfoFieldFlags,
    /// Segment ID
    ///
    /// Segment IDs are part of the MAC computation for hop fields.
    ///
    /// Each position in the path, has a segment ID which is computed and modified while the
    /// path is being traversed.
    pub segment_id: u16,
    /// Timestamp when the segment was created
    ///
    /// Used to determine if this segment currently valid.
    pub timestamp: u32,
}
impl WireEncode for InfoField {
    fn required_size(&self) -> usize {
        InfoFieldLayout::SIZE_BYTES
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // All values are full range, so always valid
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use InfoFieldLayout as IFL;
            unchecked_bit_range_be_write(buf, IFL::FLAGS_RNG, self.flags.bits());
            unchecked_bit_range_be_write(buf, IFL::RSV_RNG, 0u8);
            unchecked_bit_range_be_write(buf, IFL::SEGMENT_ID_RNG, self.segment_id);
            unchecked_bit_range_be_write(buf, IFL::TIMESTAMP_RNG, self.timestamp);
        }
        self.required_size()
    }
}
impl Model for InfoField {
    type ViewType = InfoFieldView;
}
impl TryFromModel for InfoFieldView {
    type ModelType = InfoField;
}
impl FromView for InfoField {
    type ViewType = InfoFieldView;

    fn from_view(view: &Self::ViewType) -> Self {
        InfoField {
            flags: view.flags(),
            segment_id: view.segment_id(),
            timestamp: view.timestamp(),
        }
    }
}

/// Represents a hop field in a standard SCION path
///
/// Hop fields contain information about individual hops in a SCION path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HopField {
    /// Hop field flags
    pub flags: HopFieldFlags,
    /// Hop field expiration units
    ///
    /// The expiration time of a hop field is determined by multiplying the value in this field
    /// by [`EXP_TIME_UNIT`](crate::dataplane_path::standard::types::EXP_TIME_UNIT)
    ///
    /// After this duration has passed since the segment creation time (found in the info
    /// field), the hop field is considered expired and may not be used for forwarding.
    pub expiration_units: u8,
    /// Hop field construction ingress interface
    ///
    /// A value of 0 indicates that the hop is at the start of the path segment.
    /// The interface number corresponds to the ingress interface used when constructing the
    /// path.
    ///
    /// The construction always starts at a Core router and proceeds towards the Child.
    ///
    /// When traversing the path in the reverse direction from construction (e.g. in a UP
    /// segment to a Core router), this field indicates the egress interface instead.
    pub cons_ingress: u16,
    /// Hop field construction egress interface
    ///
    /// A value of 0 indicates that the hop is at the end of the path segment.
    /// The interface number corresponds to the egress interface used when constructing the
    /// path.
    ///
    /// The construction always starts at a Core router and proceeds towards the Child.
    ///
    /// When traversing the path in the reverse direction from construction (e.g. in a UP
    /// segment to a Core router), this field indicates the ingress interface instead.
    pub cons_egress: u16,
    /// Hop field message authentication code (MAC)
    ///
    /// The MAC is used to ensure the integrity and authenticity of the hop field.
    /// It is computed when a segment is created and verified at each hop.
    pub mac: HopFieldMac,
}
impl Default for HopField {
    fn default() -> Self {
        Self {
            flags: HopFieldFlags::empty(),
            expiration_units: 0,
            cons_ingress: 0,
            cons_egress: 0,
            mac: HopFieldMac([0; 6]),
        }
    }
}
impl HopField {
    /// Creates an empty `HopField` with zeroed fields.
    pub fn empty() -> Self {
        Self {
            flags: HopFieldFlags::empty(),
            expiration_units: 0,
            cons_ingress: 0,
            cons_egress: 0,
            mac: HopFieldMac([0; 6]),
        }
    }
}
// MAC methods
impl HopField {
    /// Recalculates the MAC for this hop field and updates the `mac` field with the new value.
    ///
    /// See [`HopMacCalculate::calculate_mac`](crate::dataplane_path::standard::mac::HopMacCalculate::calculate_mac) for details on how the MAC is calculated.
    pub fn with_calculated_mac(
        mut self,
        mac_chain_beta: u16,
        timestamp_epoch: u32,
        forwarding_key: &ForwardingKey,
    ) -> Self {
        self.mac = self.calculate_mac(mac_chain_beta, timestamp_epoch, forwarding_key);
        self
    }
}
/// Provides the necessary input for calculating the MAC of a hop field.
/// Automatically implements
/// [`HopMacCalculate`](crate::dataplane_path::standard::mac::HopMacCalculate)
impl HopMacInputSource for HopField {
    #[inline]
    fn get_mac_input(&self) -> HopMacInput {
        HopMacInput {
            exp_time: self.expiration_units,
            cons_ingress: self.cons_ingress,
            cons_egress: self.cons_egress,
        }
    }
}
impl WireEncode for HopField {
    fn required_size(&self) -> usize {
        HopFieldLayout::SIZE_BYTES
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // All values are full range, so always valid
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use HopFieldLayout as HFL;
            unchecked_bit_range_be_write(buf, HFL::FLAGS_RNG, self.flags.bits());
            unchecked_bit_range_be_write(buf, HFL::EXP_TIME_RNG, self.expiration_units);
            unchecked_bit_range_be_write(buf, HFL::CONS_INGRESS_RNG, self.cons_ingress);
            unchecked_bit_range_be_write(buf, HFL::CONS_EGRESS_RNG, self.cons_egress);
            buf.get_unchecked_mut(HFL::MAC_RNG.aligned_byte_range())
                .copy_from_slice(&self.mac.0);
        }
        self.required_size()
    }
}
impl Model for HopField {
    type ViewType = HopFieldView;
}
impl TryFromModel for HopFieldView {
    type ModelType = HopField;
}
impl FromView for HopField {
    type ViewType = HopFieldView;
    fn from_view(view: &Self::ViewType) -> Self {
        HopField {
            flags: view.flags(),
            expiration_units: view.exp_time(),
            cons_ingress: view.cons_ingress(),
            cons_egress: view.cons_egress(),
            mac: view.mac(),
        }
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use std::{fmt::Debug, sync::Arc};

    use ::proptest::prelude::*;

    use super::*;
    use crate::dataplane_path::standard::mac::algo::mac_beta_step;

    /// Trait for generating forwarding keys for hop fields when generating arbitrary paths with
    /// valid MACs.
    pub trait ArbitraryForwardingKeyGenerator {
        /// Generates a forwarding key for the given hop field.
        ///
        /// ### Parameters
        /// * `field` is the hop field for which the forwarding key is being generated.
        /// * `segment_index` is the index of the segment that the hop field belongs to.
        /// * `segment_hop_index` is the index of the hop field within its segment.
        /// * `segment_change` indicates whether this hop field is the first or last hop field in
        ///   its segment
        fn generate(
            &self,
            field: &HopField,
            segment_index: usize,
            segment_hop_index: usize,
            segment_change: bool,
        ) -> ForwardingKey;
    }
    /// Configuration for generating arbitrary [`StandardPath`] values.
    #[derive(Clone)]
    pub struct ArbitraryPathContext {
        /// Range of hop fields per segment. Defaults to `2..=63` (the protocol maximum).
        pub hops_per_segment: std::ops::RangeInclusive<usize>,
        /// Range of segments per path. Defaults to `1..=3` (the protocol maximum).
        pub segments: std::ops::RangeInclusive<usize>,
        /// Key generator for hop fields used in MAC calculation. If `None`, generated paths will
        /// not have valid MACs. Defaults to `None`.
        pub forwarding_key_generator: Option<Arc<dyn ArbitraryForwardingKeyGenerator>>,
    }

    impl Default for ArbitraryPathContext {
        fn default() -> Self {
            Self {
                hops_per_segment: 2..=63,
                segments: 1..=3,
                forwarding_key_generator: None,
            }
        }
    }
    impl Debug for ArbitraryPathContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ArbitraryPathContext")
                .field("hops_per_segment", &self.hops_per_segment)
                .field(
                    "forwarding_key_generator",
                    &self.forwarding_key_generator.as_ref().map(|_| "Generator"),
                )
                .finish()
        }
    }

    /// Generates a `Vec<usize>` of `n` hop counts, each in `min..=max_each`,
    /// with a total sum that does not exceed `total_cap`.
    fn gen_hop_counts(
        segment_count: usize,
        min: usize,
        max_each: usize,
        total_cap: usize,
    ) -> BoxedStrategy<Vec<usize>> {
        prop::collection::vec(min..=max_each, segment_count)
            .prop_map(move |mut counts| {
                let sum: usize = counts.iter().sum();
                if sum > total_cap {
                    // Each count is at least `min`. The room above that minimum is
                    // what we can trim. Scale everyone's room above `min` down
                    // proportionally so the total fits within `total_cap`.
                    let max_total: usize = counts.iter().map(|count| count - min).sum();
                    let min_total = total_cap.saturating_sub(segment_count * min);
                    if segment_count * min > total_cap {
                        // Impossible constraints: set all counts to min
                        counts.iter_mut().for_each(|c| *c = min);
                    } else {
                        let mut remaining_cap_room = min_total;
                        let mut remaining_total_room = max_total;
                        for c in &mut counts {
                            let room = *c - min;
                            let share = if remaining_total_room > 0 {
                                room * remaining_cap_room / remaining_total_room
                            } else {
                                0
                            };
                            *c = min + share;
                            remaining_cap_room = remaining_cap_room.saturating_sub(share);
                            remaining_total_room = remaining_total_room.saturating_sub(room);
                        }
                    }
                }
                counts
            })
            .boxed()
    }

    impl Arbitrary for StandardPath {
        type Parameters = ArbitraryPathContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(ctx: Self::Parameters) -> Self::Strategy {
            // A full path can only address up to 63 hops due to the 6-bit limit of the
            // curr_hop_field.
            let max_total_hops = StdPathMetaLayout::MAX_TOTAL_HOPS;
            let hops_per_segment = ctx.hops_per_segment.clone();
            let fkg = ctx.forwarding_key_generator.clone();

            // choose number of segments, then for each segment generate an exact hop
            // count drawn sequentially from the remaining budget.
            (ctx.segments)
                .prop_flat_map(move |num_segments| {
                    let fkg = fkg.clone();
                    let min = *hops_per_segment.start();
                    let max_each = *hops_per_segment.end();

                    gen_hop_counts(num_segments, min, max_each, max_total_hops).prop_flat_map(
                        move |hop_counts| {
                            let fkg = fkg.clone();

                            // Build one segment strategy per index with its exact hop count,
                            // then fold them into a single strategy producing a Vec<Segment>
                            // to ensure each segment gets its designated hop count.
                            let init: BoxedStrategy<Vec<Segment>> = Just(Vec::new()).boxed();
                            hop_counts.iter().enumerate().fold(
                                init,
                                move |acc, (seg_idx, &count)| {
                                    let seg_strat =
                                        Segment::arbitrary_with(ArbitrarySegmentContext {
                                            hop_count: count..=count,
                                            segment_index: seg_idx,
                                            forwarding_key_generator: fkg.clone(),
                                        });
                                    (acc, seg_strat)
                                        .prop_map(|(mut v, s)| {
                                            v.push(s);
                                            v
                                        })
                                        .boxed()
                                },
                            )
                        },
                    )
                })
                // now that the exact hop counts are known, generate curr_hop in range.
                .prop_flat_map(|segments| {
                    let total_hops: usize = segments.iter().map(|s| s.hop_fields.len()).sum();
                    let curr_hop_range = 0u8..total_hops as u8;
                    (Just(segments), curr_hop_range)
                })
                .prop_map(|(mut segments, curr_hop)| {
                    // current_info_field is defined by which segment the current_hop_field is in
                    let mut hop_count = 0;
                    let mut curr_info = 0;
                    for (i, seg) in segments.iter().enumerate() {
                        hop_count += seg.hop_fields.len();
                        if (curr_hop as usize) < hop_count {
                            curr_info = i as u8;
                            break;
                        }
                    }

                    // Advance each segment's seg_id to reflect the hops already traversed before
                    // the current hop field position.
                    let mut advanced_hops = 0;
                    'outer: for segment in segments.iter_mut() {
                        let is_cons_dir =
                            segment.info_field.flags.contains(InfoFieldFlags::CONS_DIR);

                        // We either need to skip the first or the last hop field depending on the
                        // direction
                        let hop_iter: Box<dyn Iterator<Item = &HopField>> = match is_cons_dir {
                            true => {
                                Box::new(
                                    segment
                                        .hop_fields
                                        .iter()
                                        .take(segment.hop_fields.len().saturating_sub(1)),
                                )
                            }
                            false => Box::new(segment.hop_fields.iter().skip(1)),
                        };

                        for hop in hop_iter {
                            if advanced_hops >= curr_hop as usize {
                                break 'outer;
                            }

                            segment.info_field.segment_id =
                                mac_beta_step(segment.info_field.segment_id, hop.mac.0);

                            advanced_hops += 1;
                        }

                        // Account for the skipped hop field
                        advanced_hops += 1;
                    }

                    StandardPath {
                        current_info_field: curr_info,
                        current_hop_field: curr_hop,
                        segments: segments.into_iter().collect(),
                    }
                })
                .boxed()
        }
    }

    /// Configuration for generating arbitrary [`Segment`] values.
    pub struct ArbitrarySegmentContext {
        /// Range of hop fields in the segment. Defaults to `2..=62`
        pub hop_count: std::ops::RangeInclusive<usize>,
        /// The index of the segment being generated, starting from 0. This is passed to the
        /// forwarding key generator.
        pub segment_index: usize,
        /// A forwarding key generator which will be used to generate keys for hop fields used in
        /// the MAC calculation.
        pub forwarding_key_generator: Option<Arc<dyn ArbitraryForwardingKeyGenerator>>,
    }
    impl Default for ArbitrarySegmentContext {
        fn default() -> Self {
            Self {
                hop_count: 2..=62,
                segment_index: 0,
                forwarding_key_generator: None,
            }
        }
    }

    impl Arbitrary for Segment {
        type Parameters = ArbitrarySegmentContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(ctx: Self::Parameters) -> Self::Strategy {
            let range = ctx.hop_count.clone();
            (
                any::<InfoField>(),
                prop::collection::vec(any::<HopField>(), range),
            )
                .prop_map(move |(mut info_field, mut hop_fields)| {
                    let total_count = hop_fields.len();
                    let const_dir = info_field.flags.contains(InfoFieldFlags::CONS_DIR);

                    // set first and last hop's cons_ingress/cons_egress to 0 to reflect segment
                    // boundaries
                    if let Some(first) = hop_fields.first_mut() {
                        match const_dir {
                            true => first.cons_ingress = 0,
                            false => first.cons_egress = 0,
                        }
                    }
                    if let Some(last) = hop_fields.last_mut() {
                        match const_dir {
                            true => last.cons_egress = 0,
                            false => last.cons_ingress = 0,
                        }
                    }

                    if let Some(key_gen) = ctx.forwarding_key_generator.as_ref() {
                        let mut beta = info_field.segment_id;
                        let mut prev_beta = beta;

                        // Normalize the direction of iteration based on CONS_DIR to simplify the
                        // logic of MAC calculation.
                        let hopiter: Box<dyn Iterator<Item = &mut HopField>> = match const_dir {
                            true => Box::new(hop_fields.iter_mut()),
                            false => Box::new(hop_fields.iter_mut().rev()),
                        };

                        for (hop_idx, hop_field) in hopiter.enumerate() {
                            let segment_change = hop_idx == 0 || hop_idx == total_count - 1;
                            let forwarding_key = key_gen.generate(
                                hop_field,
                                ctx.segment_index,
                                hop_idx,
                                segment_change,
                            );

                            hop_field.mac = hop_field.calculate_mac(
                                beta,
                                info_field.timestamp,
                                &forwarding_key,
                            );
                            prev_beta = beta;
                            beta = mac_beta_step(beta, hop_field.mac.0);
                        }

                        // If not in construction dir, our previous_beta is the final segment id
                        if !const_dir {
                            info_field.segment_id = prev_beta;
                        }
                    }

                    Segment {
                        info_field,
                        hop_fields: TinyVec::Heap(hop_fields),
                    }
                })
                .boxed()
        }
    }

    impl Arbitrary for InfoField {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            (any::<InfoFieldFlags>(), any::<u16>(), any::<u32>())
                .prop_map(|(flags, segment_id, timestamp)| {
                    InfoField {
                        flags,
                        segment_id,
                        timestamp,
                    }
                })
                .boxed()
        }
    }

    /// Configuration for generating arbitrary [`HopField`] values.
    #[derive(Clone, Default)]
    pub struct ArbitraryHopFieldContext {
        /// If true, the `cons_ingress` and `cons_egress` fields may be zero, indicating start or
        /// end of segment. If false, they will be in the range `1..=u16::MAX`, indicating valid
        /// interfaces.
        pub allow_zero_interfaces: bool,
    }

    impl Arbitrary for HopField {
        type Parameters = ArbitraryHopFieldContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            let interface_range = if params.allow_zero_interfaces {
                0..=u16::MAX
            } else {
                1..=u16::MAX
            };

            (
                any::<HopFieldFlags>(),
                any::<u8>(),
                interface_range.clone(),
                interface_range,
                any::<[u8; 6]>(),
            )
                .prop_map(
                    |(flags, expiration_units, cons_ingress, cons_egress, mac_bytes)| {
                        HopField {
                            flags,
                            expiration_units,
                            cons_ingress,
                            cons_egress,
                            mac: HopFieldMac(mac_bytes),
                        }
                    },
                )
                .boxed()
        }
    }
}
