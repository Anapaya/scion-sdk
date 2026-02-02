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
        encode::WireEncode,
        layout::{BitRange, Layout, LayoutParseError, macros::gen_bitrange_const},
        view::View,
    },
    header::{
        model::{Path, ScionPacketHeader},
        view::ScionHeaderView,
    },
    path::standard::{
        layout::{StdPathDataLayout, StdPathMetaLayout},
        types::PathType,
        view::StandardPathView,
    },
};

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

    /// Constructs the layout from its individual parts
    pub fn from_parts(
        src_addr_len: u8,
        dst_addr_len: u8,
        path: ScionHeaderPathLayout,
        payload_len: usize,
    ) -> Self {
        let common = CommonHeaderLayout;
        let address = AddressHeaderLayout::new(src_addr_len, dst_addr_len);
        let header_len = common.size_bytes() + address.size_bytes() + path.size_bytes();

        ScionHeaderLayout {
            common,
            address,
            path,

            header_len,
            payload_len,
        }
    }

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

        let src_addr_len = common_view.src_addr_type().size();
        let dst_addr_len = common_view.dst_addr_type().size();

        let total_header_size = common_view.header_len() as usize;
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
                // For unknown path types, we assume the rest of the header is path data
                if total_header_size < addr_header_end {
                    return Err(LayoutParseError::BufferTooSmall {
                        at: "path",
                        required: addr_header_end * 8,
                        actual: total_header_size * 8,
                    });
                }

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

    /// Constructs the layout from a loaded SCION packet header
    pub fn from_loaded(packet: &ScionPacketHeader) -> Self {
        let common = CommonHeaderLayout;
        let address = AddressHeaderLayout::new(
            packet.address.src_host_addr.required_size() as u8,
            packet.address.dst_host_addr.required_size() as u8,
        );

        let path = match &packet.path {
            Path::Standard(std_path) => {
                let (seg0, seg1, seg2) = std_path.segment_lengths();

                ScionHeaderPathLayout::Standard(
                    StdPathMetaLayout,
                    StdPathDataLayout::new(seg0, seg1, seg2),
                )
            }
            Path::Empty => ScionHeaderPathLayout::Empty,
            Path::Unsupported { path_type, data } => {
                let addr_end = common.size_bytes() + address.size_bytes();
                ScionHeaderPathLayout::Unknown {
                    path_type: *path_type,
                    range: BitRange::from_range(addr_end * 8..(addr_end + data.len()) * 8), /* Placeholder, actual range unknown */
                }
            }
        };

        let header_len = common.size_bytes() + address.size_bytes() + path.size_bytes();

        Self {
            common,
            address,
            path,
            header_len,
            payload_len: 0,
        }
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
    gen_bitrange_const!(DST_ADDR_INFO_RNG, 72, 4);
    gen_bitrange_const!(SRC_ADDR_INFO_RNG, 76, 4);
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
            (CommonHeaderLayout::DST_ADDR_INFO_RNG, "dst_addr_info"),
            (CommonHeaderLayout::SRC_ADDR_INFO_RNG, "src_addr_info"),
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

    /// Creates a new AddressHeaderLayout with the given source and destination address lengths in
    /// bytes
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
impl From<StdPathDataLayout> for ScionHeaderPathLayout {
    fn from(data_layout: StdPathDataLayout) -> Self {
        ScionHeaderPathLayout::Standard(StdPathMetaLayout, data_layout)
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::*, prop_assert_eq};

    use super::*;

    /// Reimplements all size calculations in one place for cross-checking
    ///
    /// This purposefully does not reuse any static constants from the main code,
    /// to ensure that any changes to the main code are caught by tests.
    struct SimpleTestCalc;
    impl SimpleTestCalc {
        fn common_size() -> usize {
            12 // Fixed Size
        }
        fn address_size(dst_addr_len: u8, src_addr_len: u8) -> usize {
            16 // Fixed Size
             + (dst_addr_len as usize)
             + (src_addr_len as usize)
        }

        fn standard_path_size(seg0_len: u8, seg1_len: u8, seg2_len: u8) -> usize {
            Self::standard_path_meta_size()
                + Self::standard_path_data_size(seg0_len, seg1_len, seg2_len)
        }
        fn standard_path_meta_size() -> usize {
            4 // Fixed Size
        }
        fn standard_path_data_size(seg0_len: u8, seg1_len: u8, seg2_len: u8) -> usize {
            let info_fields =
                (seg0_len > 0) as usize + (seg1_len > 0) as usize + (seg2_len > 0) as usize;
            let hop_fields = (seg0_len as usize) + (seg1_len as usize) + (seg2_len as usize);

            info_fields * 8 // Info Field Size
            + hop_fields * 12 // Hop Field Size
        }
    }

    // Ensure test coverage of edge cases for segment lengths
    fn seg() -> impl Strategy<Value = u8> {
        prop_oneof![
        1 => Just(0),
        1 => Just(63),
        5 => 1u8..62,
        ]
    }

    #[test]
    fn should_calculate_correct_total_sizes() {
        proptest!(
            |(dst_addr_len_unit in 0u8..=4,
              src_addr_len_unit in 0u8..=4,
              seg0 in seg(),
              seg1 in seg(),
              seg2 in seg(),)| {
                println!(
                    "{}, {}, {}, {}, {}",
                    dst_addr_len_unit, src_addr_len_unit, seg0, seg1, seg2
                );
                test_impl(
                    dst_addr_len_unit,
                    src_addr_len_unit,
                    seg0,
                    seg1,
                    seg2,
                )?;
            }
        );

        fn test_impl(
            dst_addr_len_unit: u8,
            src_addr_len_unit: u8,
            seg0: u8,
            seg1: u8,
            seg2: u8,
        ) -> Result<(), proptest::prelude::TestCaseError> {
            let dst_addr_len = (dst_addr_len_unit + 1) * 4; // 4, 8, 12, 16
            let src_addr_len = (src_addr_len_unit + 1) * 4; // 4, 8, 12, 16

            let common = CommonHeaderLayout;
            let address = AddressHeaderLayout::new(src_addr_len, dst_addr_len);
            let meta = StdPathMetaLayout;
            let data = StdPathDataLayout::new(seg0, seg1, seg2);

            prop_assert_eq!(
                common.size_bytes(),
                SimpleTestCalc::common_size(),
                "Common header size does not match"
            );

            prop_assert_eq!(
                address.size_bytes(),
                SimpleTestCalc::address_size(dst_addr_len, src_addr_len),
                "Address header size does not match"
            );
            prop_assert_eq!(
                meta.size_bytes(),
                SimpleTestCalc::standard_path_meta_size(),
                "Standard path meta size does not match"
            );
            prop_assert_eq!(
                data.size_bytes(),
                SimpleTestCalc::standard_path_data_size(seg0, seg1, seg2),
                "Standard path data size does not match"
            );

            let path_layout = ScionHeaderPathLayout::Standard(meta, data);
            prop_assert_eq!(
                path_layout.size_bytes(),
                SimpleTestCalc::standard_path_size(seg0, seg1, seg2),
                "Path layout size does not match"
            );

            Ok(())
        }
    }
}
