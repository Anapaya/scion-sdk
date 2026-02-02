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

//! SCION protocol header layout calculations
//!
//! See [`Layout`](crate::core::layout) for more information about layouts in general.

use crate::{
    core::{
        debug::Annotations,
        layout::{BitRange, Layout, LayoutParseError, macros::gen_bitrange_const},
        view::View,
    },
    path::standard::view::StandardPathView,
};

/// Layout for the standard SCION path, composed of a meta header and data
pub struct StdPathLayout {
    /// Layout of the path meta header
    pub meta: StdPathMetaLayout,
    /// Layout of the path data
    pub data: StdPathDataLayout,
}
impl StdPathLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           PathMeta                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           PathData                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Attempts to parse the standard SCION path layout from the given buffer
    pub fn from_slice(buf: &[u8]) -> Result<Self, LayoutParseError> {
        // Check Meta header
        let (meta_buf, _rest) = StdPathMetaLayout.split_off_checked(buf).ok_or_else(|| {
            LayoutParseError::BufferTooSmall {
                at: "StdPathMeta",
                required: StdPathMetaLayout.size_bytes(),
                actual: buf.len(),
            }
        })?;

        let meta_view = unsafe { StandardPathView::from_slice_unchecked(meta_buf) };
        let seg0_len = meta_view.seg0_len();
        let seg1_len = meta_view.seg1_len();
        let seg2_len = meta_view.seg2_len();

        // Check data is contained
        let data_layout = StdPathDataLayout::new(seg0_len, seg1_len, seg2_len);
        let required_size = StdPathMetaLayout.size_bytes() + data_layout.size_bytes();

        if buf.len() < required_size {
            return Err(LayoutParseError::BufferTooSmall {
                at: "StdPathData",
                required: required_size,
                actual: buf.len(),
            });
        }

        Ok(Self {
            meta: StdPathMetaLayout,
            data: data_layout,
        })
    }
}
impl Layout for StdPathLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        self.meta.size_bytes() + self.data.size_bytes()
    }
}

/// Layout for the standard SCION path meta header
pub struct StdPathMetaLayout;
impl StdPathMetaLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | C |  CurrHF   |    RSV    |  Seg0Len  |  Seg1Len  |  Seg2Len  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(CURR_INFO_FIELD_RNG, 0, 2);
    gen_bitrange_const!(CURR_HOP_FIELD_RNG, 2, 6);
    gen_bitrange_const!(RSV_RNG, 8, 6);
    gen_bitrange_const!(SEG0_LEN_RNG, 14, 6);
    gen_bitrange_const!(SEG1_LEN_RNG, 20, 6);
    gen_bitrange_const!(SEG2_LEN_RNG, 26, 6);
    gen_bitrange_const!(TOTAL_RNG, 0, 32);

    /// Size of meta header in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;

    /// Maximum length of a path segment
    pub const MAX_SEGMENT_LENGTH: usize = 63;
}
impl StdPathMetaLayout {
    /// Returns annotations for the common header fields
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (StdPathMetaLayout::CURR_INFO_FIELD_RNG, "curr_info_field"),
            (StdPathMetaLayout::CURR_HOP_FIELD_RNG, "curr_hop_field"),
            (StdPathMetaLayout::RSV_RNG, "rsv"),
            (StdPathMetaLayout::SEG0_LEN_RNG, "seg0_len"),
            (StdPathMetaLayout::SEG1_LEN_RNG, "seg1_len"),
            (StdPathMetaLayout::SEG2_LEN_RNG, "seg2_len"),
        ];

        Annotations::new_with("StandardPathMetaHeader".to_string(), ann)
    }
}
impl Layout for StdPathMetaLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}

/// Layout for the standard SCION path data
pub struct StdPathDataLayout {
    /// Lengths of the three path segments
    pub segment_lengths: (u8, u8, u8),
}
impl StdPathDataLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Creates a new StdPathDataLayout with the given segment lengths
    #[inline]
    pub const fn new(seg0len: u8, seg1len: u8, seg2len: u8) -> Self {
        Self {
            segment_lengths: (seg0len, seg1len, seg2len),
        }
    }

    /// Returns the number of info fields
    #[inline]
    pub const fn info_field_count(&self) -> usize {
        (self.segment_lengths.0 > 0) as usize
            + (self.segment_lengths.1 > 0) as usize
            + (self.segment_lengths.2 > 0) as usize
    }

    /// Returns the number of hop fields
    #[inline]
    pub const fn hop_field_count(&self) -> usize {
        (self.segment_lengths.0 as usize)
            + (self.segment_lengths.1 as usize)
            + (self.segment_lengths.2 as usize)
    }

    /// Returns the bit range for the info field at the given index
    #[inline]
    pub fn info_field_range(&self, index: usize) -> BitRange {
        InfoFieldLayout::TOTAL_RNG.shift(index * InfoFieldLayout.size_bytes())
    }

    /// Returns the bit range for the hop field at the given index
    #[inline]
    pub fn hop_field_range(&self, index: usize) -> BitRange {
        let base = self.info_fields_range().size_bytes();
        HopFieldLayout::TOTAL_RNG.shift(base + index * HopFieldLayout.size_bytes())
    }

    /// Returns the bit range for all info fields
    #[inline]
    pub fn info_fields_range(&self) -> BitRange {
        let info_field_count = self.info_field_count();
        BitRange {
            start: 0,
            end: info_field_count * InfoFieldLayout.size_bits(),
        }
    }

    /// Returns the bit range for all hop fields
    #[inline]
    pub fn hop_fields_range(&self) -> BitRange {
        let info_fields_end = self.info_fields_range().end;
        let hop_field_count = self.hop_field_count();
        BitRange {
            start: info_fields_end,
            end: info_fields_end + hop_field_count * HopFieldLayout.size_bits(),
        }
    }
}
impl StdPathDataLayout {
    /// Returns annotations for all info and hop fields
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();

        for _ in 0..self.info_field_count() {
            annotations.extend(InfoFieldLayout.annotations());
        }

        for _ in 0..self.hop_field_count() {
            annotations.extend(HopFieldLayout.annotations());
        }

        annotations
    }
}
impl Layout for StdPathDataLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        let info_fields_size = self.info_field_count() * InfoFieldLayout.size_bytes();
        let hop_fields_size = self.hop_field_count() * HopFieldLayout.size_bytes();
        info_fields_size + hop_fields_size
    }
}

/// Layout for a SCION standard path info field
pub struct InfoFieldLayout;
impl InfoFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |r r r r r r P C|      RSV      |             SegID             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           Timestamp                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(FLAGS_RNG, 0, 8);
    gen_bitrange_const!(RSV_RNG, 8, 8);
    gen_bitrange_const!(SEGMENT_ID_RNG, 16, 16);
    gen_bitrange_const!(TIMESTAMP_RNG, 32, 32);
    gen_bitrange_const!(TOTAL_RNG, 0, 64);

    /// Size of info field in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;
}
impl InfoFieldLayout {
    /// Returns annotations for the info field
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (InfoFieldLayout::FLAGS_RNG, "flags"),
            (InfoFieldLayout::RSV_RNG, "rsv"),
            (InfoFieldLayout::SEGMENT_ID_RNG, "segment_id"),
            (InfoFieldLayout::TIMESTAMP_RNG, "timestamp"),
        ];

        Annotations::new_with("InfoField".to_string(), ann)
    }
}
impl Layout for InfoFieldLayout {
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}

/// Layout for a SCION standard path hop field
pub struct HopFieldLayout;
impl HopFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |r r r r r r I E|    ExpTime    |           ConsIngress         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ConsEgress             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                              MAC                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(FLAGS_RNG, 0, 8);
    gen_bitrange_const!(EXP_TIME_RNG, 8, 8);
    gen_bitrange_const!(CONS_INGRESS_RNG, 16, 16);
    gen_bitrange_const!(CONS_EGRESS_RNG, 32, 16);
    gen_bitrange_const!(MAC_RNG, 48, 48);
    gen_bitrange_const!(TOTAL_RNG, 0, 96);

    /// Size of hop field in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;
}
impl HopFieldLayout {
    /// Returns annotations for the hop field
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (HopFieldLayout::FLAGS_RNG, "flags"),
            (HopFieldLayout::EXP_TIME_RNG, "exp_time"),
            (HopFieldLayout::CONS_INGRESS_RNG, "cons_ingress"),
            (HopFieldLayout::CONS_EGRESS_RNG, "cons_egress"),
            (HopFieldLayout::MAC_RNG, "mac"),
        ];

        Annotations::new_with("HopField".to_string(), ann)
    }
}
impl Layout for HopFieldLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}
