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
//! These structs and traits define the layout of the SCION protocol headers
//! and provide methods to calculate sizes and offsets of various fields.
//!
//! The main struct is [ScionHeaderLayout], which represents the layout of a SCION
//! header, including the common header, address header, and path header.
//!
//! Each header layout struct provides methods to calculate the size in bytes,
//! as well as bit ranges for individual fields.

use crate::{
    helper::debug::Annotations,
    types::path::PathType,
    views::{ScionHeaderView, StandardPathView, View},
};

/// Helper macro to generate bit range constants
macro_rules! gen_bitrange_const {
    ($range_name:ident, $start:expr, $offset:expr) => {
        /// Bit range constant for the specified field
        pub const $range_name: BitRange = BitRange::new($start, $offset);
    };
}

/// Trait representing the layout of a protocol header or field
pub trait Layout {
    /// Returns the expected size of the layout in bytes
    fn size_bytes(&self) -> usize;

    /// Returns the expected size of the layout in bits
    #[inline(always)]
    fn size_bits(&self) -> usize {
        self.size_bytes() * 8
    }

    /// Attempts to Split the buffer into two at the size of the layout
    /// Returns None if the buffer is too small
    #[inline]
    fn split_off_checked<'a>(&self, buf: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        buf.split_at_checked(self.size_bytes())
    }
}

/// Errors that can occur when parsing a SCION header layout from a byte slice
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq, Hash)]
pub enum LayoutParseError {
    /// The SCION version is unsupported
    #[error("Unsupported version")]
    UnsupportedVersion,
    /// The buffer is too small to contain the expected layout
    #[error("Buffer too small at {at}: required {required}, actual {actual}")]
    BufferTooSmall {
        /// Location where the buffer was too small
        at: &'static str,
        /// Number of bytes required
        required: usize,
        /// Number of bytes actually available
        actual: usize,
    },
    /// The advertised header length does not match the actual calculated length
    #[error("Invalid header length: advertised {advertised}, actual {actual}")]
    InvalidHeaderLength {
        /// Advertised header length
        advertised: usize,
        /// Actual calculated header length
        actual: usize,
    },
}

/// Metadata about the SCION header layout
///
/// Includes information about the common header, address header, path header, and payload
///
/// The total header size and payload size are stored for convenience
pub struct ScionHeaderLayout {
    /// Layout of the common header
    pub common: CommonHeaderLayout,
    /// Layout of the address header
    pub address: AddressHeaderLayout,
    /// Layout of the path header
    pub path: ScionHeaderPathLayout,

    /// Total header length in bytes
    pub header_len: usize,
    /// Payload length in bytes
    pub payload_len: usize,
}
impl ScionHeaderLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          CommonHeader                         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          AddressHeader                        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              Path                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Reads minimal header information from the buffer to construct the layout
    ///
    /// Validates:
    /// - Common header version
    /// - Total header length matches sum of parts
    /// - Buffer is large enough to contain all header fields
    ///
    /// Does not validate:
    /// - Field values beyond version and size
    /// - That the given buffer contains the payload
    pub fn from_slice(buf: &[u8]) -> Result<Self, LayoutParseError> {
        // Impl Note: We perform size checks before accessing any fields beyond the common header.
        // Ensuring the entire buffer is large enough, happens at the end, after all size
        // calculations.

        let len = buf.len();
        let common = CommonHeaderLayout;
        let (common_buf, _rest) = common.split_off_checked(buf).ok_or_else(|| {
            LayoutParseError::BufferTooSmall {
                at: "CommonHeader",
                required: common.size_bytes(),
                actual: buf.len(),
            }
        })?;

        // Safety: Only fields in the common header are accessed below.
        // Fields past the common header are not accessed until after size checks.
        let common_view = unsafe { ScionHeaderView::from_slice_unchecked(common_buf) };
        if common_view.version() != 0 {
            return Err(LayoutParseError::UnsupportedVersion);
        }

        let path_type = common_view.path_type();

        let src_addr_len = common_view.src_addr_len();
        let dst_addr_len = common_view.dst_addr_len();

        let total_header_size = common_view.header_len();
        let payload_size = common_view.payload_len() as usize;

        let addr_header_end =
            common.size_bytes() + AddressHeaderLayout::new(src_addr_len, dst_addr_len).size_bytes();

        // Check that the buffer is large enough to contain the address header
        if buf.len() < addr_header_end {
            return Err(LayoutParseError::BufferTooSmall {
                at: "AddressHeader",
                required: addr_header_end,
                actual: len,
            });
        }

        let path = match path_type {
            PathType::Scion => {
                let (path_meta_buf, _rest) = StdPathMetaLayout
                    .split_off_checked(&buf[addr_header_end..])
                    .ok_or_else(|| {
                        LayoutParseError::BufferTooSmall {
                            at: "PathMeta",
                            required: StdPathMetaLayout.size_bytes(),
                            actual: buf.len() - addr_header_end,
                        }
                    })?;

                // Safety: path_meta_buf is guaranteed to be of sufficient length by
                // split_off_checked
                let path_meta_view =
                    unsafe { StandardPathView::from_slice_unchecked(path_meta_buf) };

                let seg0_len = path_meta_view.seg0_len();
                let seg1_len = path_meta_view.seg1_len();
                let seg2_len = path_meta_view.seg2_len();

                let path_data_layout = StdPathDataLayout::new(seg0_len, seg1_len, seg2_len);

                ScionHeaderPathLayout::Standard(StdPathMetaLayout, path_data_layout)
            }
            PathType::Empty => ScionHeaderPathLayout::Empty,
            path_type => {
                ScionHeaderPathLayout::Unknown {
                    path_type,
                    range: BitRange::from_range(addr_header_end * 8..(total_header_size * 8)),
                }
            }
        };

        // Important Checks:

        // Check that the calculated total header size matches the sum of the parts
        let calculated_size = common.size_bytes()
            + AddressHeaderLayout::new(src_addr_len, dst_addr_len).size_bytes()
            + path.size_bytes();

        // Critical: Check that the buffer is large enough to contain the entire header
        if calculated_size > buf.len() {
            return Err(LayoutParseError::BufferTooSmall {
                at: "TotalHeader",
                required: calculated_size,
                actual: buf.len(),
            });
        }

        // Check that the calculated size matches the advertised size
        if calculated_size != total_header_size {
            return Err(LayoutParseError::InvalidHeaderLength {
                advertised: total_header_size,
                actual: calculated_size,
            });
        }

        Ok(Self {
            common,
            address: AddressHeaderLayout {
                src_addr_len,
                dst_addr_len,
            },
            path,
            header_len: total_header_size,
            payload_len: payload_size,
        })
    }
}
impl ScionHeaderLayout {
    /// Returns annotations for all SCION header fields
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();

        annotations.extend(CommonHeaderLayout.annotations());
        annotations.extend(self.address.annotations());
        annotations.extend(self.path.annotations());

        annotations
    }
}
impl Layout for ScionHeaderLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        self.header_len
    }
}

/// Layout for the SCION common header
pub struct CommonHeaderLayout;
impl CommonHeaderLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Version| TrafficClass  |                FlowID                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    NextHdr    |    HdrLen     |          PayloadLen           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    PathType   |DT |DL |ST |SL |              RSV              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // Bit range constants
    gen_bitrange_const!(VERSION_RNG, 0, 4);
    gen_bitrange_const!(TRAFFIC_CLASS_RNG, 4, 8);
    gen_bitrange_const!(FLOW_ID_RNG, 12, 20);
    gen_bitrange_const!(NEXT_HEADER_RNG, 32, 8);
    gen_bitrange_const!(HEADER_LEN_RNG, 40, 8);
    gen_bitrange_const!(PAYLOAD_LEN_RNG, 48, 16);
    gen_bitrange_const!(PATH_TYPE_RNG, 64, 8);
    gen_bitrange_const!(DST_ADDR_TYPE_RNG, 72, 2);
    gen_bitrange_const!(DST_ADDR_LEN_RNG, 74, 2);
    gen_bitrange_const!(SRC_ADDR_TYPE_RNG, 76, 2);
    gen_bitrange_const!(SRC_ADDR_LEN_RNG, 78, 2);
    gen_bitrange_const!(RSV_RNG, 80, 16);
    gen_bitrange_const!(TOTAL_RNG, 0, 96);

    /// Total size in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;
}
impl CommonHeaderLayout {
    /// Returns annotations for the common header fields
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (CommonHeaderLayout::VERSION_RNG, "version"),
            (CommonHeaderLayout::TRAFFIC_CLASS_RNG, "traffic_class"),
            (CommonHeaderLayout::FLOW_ID_RNG, "flow_id"),
            (CommonHeaderLayout::NEXT_HEADER_RNG, "next_header"),
            (CommonHeaderLayout::HEADER_LEN_RNG, "header_length"),
            (CommonHeaderLayout::PAYLOAD_LEN_RNG, "payload_length"),
            (CommonHeaderLayout::PATH_TYPE_RNG, "path_type"),
            (CommonHeaderLayout::DST_ADDR_TYPE_RNG, "dst_addr_type"),
            (CommonHeaderLayout::DST_ADDR_LEN_RNG, "dst_addr_len"),
            (CommonHeaderLayout::SRC_ADDR_TYPE_RNG, "src_addr_type"),
            (CommonHeaderLayout::SRC_ADDR_LEN_RNG, "src_addr_len"),
            (CommonHeaderLayout::RSV_RNG, "rsv"),
        ];

        Annotations::new_with("CommonHeader".to_string(), ann)
    }
}
impl Layout for CommonHeaderLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::TOTAL_RNG.end / 8
    }
}

/// Layout for the SCION address header
pub struct AddressHeaderLayout {
    /// Length of the source host address in bytes
    pub src_addr_len: u8,
    /// Length of the destination host address in bytes
    pub dst_addr_len: u8,
}
impl AddressHeaderLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            DstISD             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                             DstAS                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            SrcISD             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                             SrcAS                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    DstHostAddr (variable Len)                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    SrcHostAddr (variable Len)                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Creates a new AddressHeaderLayout with the given source and destination address lengths
    #[inline]
    pub const fn new(src_addr_len: u8, dst_addr_len: u8) -> Self {
        Self {
            src_addr_len,
            dst_addr_len,
        }
    }

    gen_bitrange_const!(DST_ISD_RNG, 0, 16);
    gen_bitrange_const!(DST_AS_RNG, 16, 48);
    gen_bitrange_const!(SRC_ISD_RNG, 64, 16);
    gen_bitrange_const!(SRC_AS_RNG, 80, 48);

    const FIXED_SIZE_BITS: usize = 128;

    /// Returns the bit range for the destination host address
    #[inline]
    pub const fn dst_host_addr_range(&self) -> BitRange {
        let start = Self::FIXED_SIZE_BITS;
        let end = start + (self.dst_addr_len as usize) * 8;
        BitRange::from_range(start..end)
    }

    /// Returns the bit range for the source host address
    #[inline]
    pub const fn src_host_addr_range(&self) -> BitRange {
        let start = Self::FIXED_SIZE_BITS + (self.dst_addr_len as usize) * 8;
        let end = start + (self.src_addr_len as usize) * 8;
        BitRange::from_range(start..end)
    }

    /// Returns the total bit range for the address header
    #[inline]
    pub const fn total_range(&self) -> BitRange {
        let mut last_field = self.src_host_addr_range();
        last_field.start = 0;
        last_field
    }
}
impl AddressHeaderLayout {
    /// Returns annotations for the address header fields
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (AddressHeaderLayout::DST_ISD_RNG, "dst_isd"),
            (AddressHeaderLayout::DST_AS_RNG, "dst_as"),
            (AddressHeaderLayout::SRC_ISD_RNG, "src_isd"),
            (AddressHeaderLayout::SRC_AS_RNG, "src_as"),
            (self.dst_host_addr_range(), "dst_addr"),
            (self.src_host_addr_range(), "src_addr"),
        ];

        Annotations::new_with("AddressHeader".to_string(), ann)
    }
}
impl Layout for AddressHeaderLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        self.total_range().end / 8
    }
}

/// Layout for the SCION path header
pub enum ScionHeaderPathLayout {
    /// Layout for the standard SCION path
    Standard(StdPathMetaLayout, StdPathDataLayout),
    /// Layout for an empty path
    Empty,
    /// Layout for an unknown path type
    Unknown {
        /// The type of the unknown path
        path_type: PathType,
        /// The bit range of the unknown path
        range: BitRange,
    },
}
impl ScionHeaderPathLayout {
    /// Returns the path type of the layout
    #[inline]
    pub const fn path_type(&self) -> PathType {
        match self {
            ScionHeaderPathLayout::Standard(..) => PathType::Scion,
            ScionHeaderPathLayout::Empty => PathType::Empty,
            ScionHeaderPathLayout::Unknown { path_type, .. } => *path_type,
        }
    }

    /// Returns annotations for the path header fields
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();
        match self {
            ScionHeaderPathLayout::Standard(_, data_layout) => {
                annotations.extend(StdPathMetaLayout.annotations());
                annotations.extend(data_layout.annotations());
            }
            ScionHeaderPathLayout::Empty => {}
            ScionHeaderPathLayout::Unknown { range, .. } => {
                annotations.add("Unknown Path".to_string(), vec![(*range, "unknown")])
            }
        };

        annotations
    }
}
impl Layout for ScionHeaderPathLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        match self {
            ScionHeaderPathLayout::Standard(meta, data_layout) => {
                meta.size_bytes() + data_layout.size_bytes()
            }
            ScionHeaderPathLayout::Empty => 0,
            ScionHeaderPathLayout::Unknown { range, .. } => range.size_bytes(),
        }
    }
}

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

/// Represents a range of bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitRange {
    /// Start bit (inclusive)
    pub start: usize,
    /// End bit (exclusive)
    pub end: usize,
}
impl BitRange {
    /// Creates a new BitRange with the given start and width
    #[inline]
    pub const fn new(start: usize, width: usize) -> Self {
        Self {
            start,
            end: start + width,
        }
    }

    /// Creates a BitRange from a standard Range
    #[inline]
    pub const fn from_range(range: std::ops::Range<usize>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }

    /// Returns the standard Range representation of the BitRange
    #[inline]
    pub const fn bit_range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    /// Checks if the given bit is contained within the BitRange
    #[inline]
    pub const fn contains(&self, bit: usize) -> bool {
        bit >= self.start && bit < self.end
    }

    /// Returns the byte range, assuming the start and end are byte-aligned
    ///
    /// This function will panic in debug mode if the start or end are not byte-aligned
    /// Otherwise, the behavior is undefined.
    #[inline]
    pub const fn aligned_byte_range(&self) -> std::ops::Range<usize> {
        debug_assert!(
            self.start.is_multiple_of(8),
            "Start bit is not byte-aligned"
        );
        debug_assert!(self.end.is_multiple_of(8), "End bit is not byte-aligned");
        self.start / 8..self.end.div_ceil(8)
    }

    /// Returns the byte range containing the bit range
    ///
    /// Does not require byte alignment
    pub const fn containing_byte_range(&self) -> std::ops::Range<usize> {
        let start_byte = self.start / 8; // floor division
        let end_byte = self.end.div_ceil(8); // ceiling division
        start_byte..end_byte
    }

    /// Returns the size of the bit range in bytes
    #[inline]
    pub const fn size_bytes(&self) -> usize {
        let range = self.containing_byte_range();
        range.end - range.start
    }

    /// Returns the size of the bit range in bits
    #[inline]
    pub const fn size_bits(&self) -> usize {
        self.end - self.start
    }

    /// Shifts the bit range forward by the given number of bytes
    #[inline]
    pub const fn shift(mut self, bytes: usize) -> Self {
        self.start += bytes * 8;
        self.end += bytes * 8;
        self
    }

    /// Offsets the bit range by the given number of bits (can be negative)
    #[inline]
    pub fn offset_bits(&self, offset: isize) -> Self {
        BitRange {
            start: (self.start as isize + offset) as usize,
            end: (self.end as isize + offset) as usize,
        }
    }
}
