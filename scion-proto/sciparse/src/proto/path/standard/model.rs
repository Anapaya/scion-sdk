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

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        layout::Layout,
        write::unchecked_bit_range_be_write,
    },
    path::standard::{
        layout::{HopFieldLayout, InfoFieldLayout, StdPathDataLayout, StdPathMetaLayout},
        types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
        view::{HopFieldView, InfoFieldView, StandardPathView},
    },
};

/// Represents a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardPath {
    /// The current info field index
    pub current_info_field: u8,
    /// The current hop field index
    pub curr_hop_field: u8,
    /// The segments of the path
    pub segments: Vec<Segment>,
}

impl StandardPath {
    /// Constructs a `StandardPath` from a `StandardPathView`
    pub fn from_view(view: &StandardPathView) -> Self {
        let info_fields = view.info_fields();
        let hop_fields = view.hop_fields();
        let segment_sizes = [view.seg0_len(), view.seg1_len(), view.seg2_len()];

        let mut segments = Vec::with_capacity(info_fields.len());
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
            current_info_field: view.curr_info_field(),
            curr_hop_field: view.curr_hop_field(),
            segments,
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
}

impl WireEncode for StandardPath {
    fn required_size(&self) -> usize {
        let [seg0, seg1, seg2] = self.segment_sizes();
        StdPathMetaLayout::SIZE_BYTES + StdPathDataLayout::new(seg0, seg1, seg2).size_bytes()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        if self.curr_hop_field != 0 && self.curr_hop_field as usize >= self.hop_field_count() {
            return Err("curr_hop_field exceeds total number of hop fields".into());
        }

        if self.current_info_field != 0
            && self.current_info_field as usize >= self.info_field_count()
        {
            return Err("current_info_field exceeds total number of info fields".into());
        }

        if self.segments.is_empty() {
            return Err("Standard path must contain at least one segment".into());
        }

        for segment in &self.segments {
            if segment.hop_fields.len() > StdPathMetaLayout::MAX_SEGMENT_LENGTH {
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
            unchecked_bit_range_be_write(buf, SL::CURR_HOP_FIELD_RNG, self.curr_hop_field);
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

/// Represents a segment in a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Info field containing metadata about the segment
    pub info_field: InfoField,
    /// Hop fields representing the hops in the segment
    pub hop_fields: Vec<HopField>,
}

/// Represents an info field in a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl InfoField {
    /// Constructs a `InfoField` from a `InfoFieldView`
    pub fn from_view(view: &InfoFieldView) -> Self {
        InfoField {
            flags: view.flags(),
            segment_id: view.segment_id(),
            timestamp: view.timestamp(),
        }
    }
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

/// Represents a hop field in a standard SCION path
///
/// Hop fields contain information about individual hops in a SCION path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopField {
    /// Hop field flags
    pub flags: HopFieldFlags,
    /// Hop field expiration units
    ///
    /// The expiration time of a hop field is determined by multiplying the value in this field
    /// by [`EXP_TIME_UNIT`](super::types::EXP_TIME_UNIT)
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

impl HopField {
    /// Constructs a `HopField` from a `HopFieldView`
    pub fn from_view(view: &HopFieldView) -> Self {
        HopField {
            flags: view.flags(),
            expiration_units: view.exp_time(),
            cons_ingress: view.cons_ingress(),
            cons_egress: view.cons_egress(),
            mac: view.mac(),
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
