// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
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

use std::mem;

use bytes::{Buf, BufMut};

use super::DataPlanePathErrorKind;
use crate::{
    packet::{DecodeError, InadequateBufferSize},
    wire_encoding::{self, WireDecode, WireEncode},
};

wire_encoding::bounded_uint! {
    /// A 2-bit index into the info fields.
    #[derive(Default)]
    pub struct InfoFieldIndex(u8 : 2);
}

wire_encoding::bounded_uint! {
    /// A 6-bit index into the hop fields.
    #[derive(Default)]
    pub struct HopFieldIndex(u8 : 6);
}

wire_encoding::bounded_uint! {
    /// A 6-bit count of the number of hop fields in a path segment.
    #[derive(Default)]
    pub struct SegmentLength(u8 : 6);
}

impl SegmentLength {
    /// Gets the indicated length of the segment as a usize.
    pub const fn length(&self) -> usize {
        self.0 as usize
    }
}

wire_encoding::bounded_uint! {
    /// A 6-bit reserved field within the [`MetaHeader`].
    #[derive(Default)]
    pub struct MetaReserved(u8 : 6);
}

/// Meta information about the SCION path contained in a [`StandardPath`][super::StandardPath].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MetaHeader {
    /// An index to the current info field for the packet on its way through the network.
    ///
    /// This must be smaller than [`Self::info_fields_count`].
    pub current_info_field: InfoFieldIndex,

    /// An index to the current hop field within the segment pointed to by the info field.
    ///
    /// For valid SCION packets, this should point at a hop field associated with the
    /// current info field.
    ///
    /// This must be smaller than [`Self::hop_fields_count`].
    pub current_hop_field: HopFieldIndex,

    /// Unused bits in the path path meta header.
    pub reserved: MetaReserved,

    /// The number of hop fields in a given segment.
    ///
    /// For valid SCION packets, the SegmentLengths at indices 1 and 2 should be non-zero
    /// only if all the preceding SegmentLengths are non-zero.
    pub segment_lengths: [SegmentLength; 3],
}

impl MetaHeader {
    /// The length of a path meta header in bytes.
    pub const LENGTH: usize = 4;
    /// The length of an info field in bytes.
    pub const INFO_FIELD_LENGTH: usize = 8;
    /// The length of a hop field in bytes.
    pub const HOP_FIELD_LENGTH: usize = 12;

    /// The number of info fields.
    pub const fn info_fields_count(&self) -> usize {
        match &self.segment_lengths {
            [SegmentLength(0), ..] => 0,
            [_, SegmentLength(0), _] => 1,
            [.., SegmentLength(0)] => 2,
            _ => 3,
        }
    }

    /// Returns the index of the current info field.
    pub fn info_field_index(&self) -> usize {
        self.current_info_field.get().into()
    }

    /// The number of hop fields.
    pub const fn hop_fields_count(&self) -> usize {
        self.segment_lengths[0].length()
            + self.segment_lengths[1].length()
            + self.segment_lengths[2].length()
    }

    /// Returns the index of the current hop field.
    pub fn hop_field_index(&self) -> usize {
        self.current_hop_field.get().into()
    }

    /// Returns index of segment that contains the current hop field.
    ///
    /// If hop is out of range, this returns None.
    pub fn segment_index(&self) -> Option<usize> {
        let hop_index = self.hop_field_index();
        let seg0 = self.segment_lengths[0].length();
        let seg1 = self.segment_lengths[1].length();
        let seg2 = self.segment_lengths[2].length();

        if hop_index < seg0 {
            Some(0)
        } else if hop_index < seg0 + seg1 {
            Some(1)
        } else if hop_index < seg0 + seg1 + seg2 {
            Some(2)
        } else {
            // Hop index is out of range
            None
        }
    }

    /// The number of interfaces on the path.
    ///
    /// This starts counting at 0 with the egress interface of the first AS and only counts actually
    /// traversed interfaces. In particular, crossover ASes are only counted as 2 interfaces even
    /// though they are represented by two hop fields.
    pub fn interfaces_count(&self) -> usize {
        2 * (self.hop_fields_count() - self.info_fields_count())
    }

    /// Returns the index of the hop field including the given interface.
    ///
    /// This does *not* check that the `interface_index` is in range and provides meaningless
    /// results if the [`Self::segment_lengths`] are invalid but does not panic in those cases.
    pub fn hop_field_index_for_interface(&self, interface_index: usize) -> usize {
        let actual_hop_index = interface_index.div_ceil(2);
        match interface_index / 2 + 1 {
            // The interface is in the first segment
            x if x < self.segment_lengths[0].length() => actual_hop_index,
            // The interface is in the second segment; add 1 for the additional crossover hop field
            x if x + 1 < self.segment_lengths[0].length() + self.segment_lengths[1].length() => {
                actual_hop_index + 1
            }
            // The interface is in the third segment; add 2 for the additional crossover hop fields
            _ => actual_hop_index + 2,
        }
    }

    /// Returns the offset in bytes of the given info field.
    pub fn info_field_offset(info_field_index: usize) -> usize {
        Self::LENGTH + Self::INFO_FIELD_LENGTH * info_field_index
    }

    /// Returns the offset in bytes of the given hop field.
    pub fn hop_field_offset(&self, hop_field_index: usize) -> usize {
        Self::LENGTH
            + Self::INFO_FIELD_LENGTH * self.info_fields_count()
            + Self::HOP_FIELD_LENGTH * hop_field_index
    }

    /// Encodes the header as a `u32`.
    pub fn as_u32(&self) -> u32 {
        (u32::from(self.current_info_field.get()) << 30)
            | (u32::from(self.current_hop_field.get()) << 24)
            | (u32::from(self.reserved.get()) << 18)
            | (u32::from(self.segment_lengths[0].get()) << 12)
            | (u32::from(self.segment_lengths[1].get()) << 6)
            | (u32::from(self.segment_lengths[2].get()))
    }

    pub(super) const fn encoded_path_length(&self) -> usize {
        Self::LENGTH
            + self.info_fields_count() * Self::INFO_FIELD_LENGTH
            + self.hop_fields_count() * Self::HOP_FIELD_LENGTH
    }

    /// Creates a new, reversed [MetaHeader]
    ///
    /// Rotates the Segment Lengths and Indices are set to their reversed position
    pub(super) fn to_reversed(&self) -> Self {
        let final_info_idx = self.info_fields_count().saturating_sub(1) as u8;
        let reversed_info_idx = final_info_idx.saturating_sub(self.current_info_field.get());

        let final_hop_idx = self.hop_fields_count().saturating_sub(1) as u8;
        let reversed_hop_idx = final_hop_idx.saturating_sub(self.current_hop_field.get());

        Self {
            current_info_field: InfoFieldIndex(reversed_info_idx),
            current_hop_field: HopFieldIndex(reversed_hop_idx),
            reserved: MetaReserved::default(),
            segment_lengths: match self.segment_lengths {
                [SegmentLength(0), ..] => [SegmentLength(0); 3],
                [s1, SegmentLength(0), ..] => [s1, SegmentLength(0), SegmentLength(0)],
                [s1, s2, SegmentLength(0)] => [s2, s1, SegmentLength(0)],
                [s1, s2, s3] => [s3, s2, s1],
            },
        }
    }
}

impl WireEncode for MetaHeader {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        Self::LENGTH
    }

    #[inline]
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u32(self.as_u32());
    }
}

impl<T: Buf> WireDecode<T> for MetaHeader {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < mem::size_of::<u32>() {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }
        let fields = data.get_u32();

        let meta = Self {
            current_info_field: InfoFieldIndex(nth_field::<0>(fields)),
            current_hop_field: HopFieldIndex(nth_field::<1>(fields)),
            reserved: MetaReserved(nth_field::<2>(fields)),
            segment_lengths: [
                SegmentLength(nth_field::<3>(fields)),
                SegmentLength(nth_field::<4>(fields)),
                SegmentLength(nth_field::<5>(fields)),
            ],
        };

        if meta.segment_lengths[2].get() > 0 && meta.segment_lengths[1].get() == 0
            || meta.segment_lengths[1].get() > 0 && meta.segment_lengths[0].get() == 0
            || meta.segment_lengths[0].get() == 0
        {
            return Err(DataPlanePathErrorKind::InvalidSegmentLengths.into());
        }

        if meta.info_field_index() >= meta.info_fields_count() {
            return Err(DataPlanePathErrorKind::InfoFieldOutOfRange.into());
        }
        // Above errs also when info_fields_index() is 4, since info_fields_count() is at most 3
        debug_assert!(meta.info_field_index() <= 3);

        let fallback_seg_index = 255; // Will never match and thus always return OutOfRange
        if meta.hop_field_index() >= meta.hop_fields_count()
            || meta.segment_index().unwrap_or(fallback_seg_index) != meta.info_field_index()
        {
            return Err(DataPlanePathErrorKind::HopFieldOutOfRange.into());
        }

        Ok(meta)
    }
}

/// Return the n-th 2 or 6-bit field from a u32 value, as indexed below.
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | 0 |     1     |     2     |     3     |     4     |     5     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[inline]
const fn nth_field<const N: usize>(fields: u32) -> u8 {
    const FIELD_BITS: usize = 6;
    const MASK: u32 = 0b11_1111;

    ((fields >> ((5 - N) * FIELD_BITS)) & MASK) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! new_path_meta_header {
        [$seg1:expr, $seg2:expr, $seg3:expr] => {
            MetaHeader {
                current_info_field: InfoFieldIndex(0),
                current_hop_field: HopFieldIndex(0),
                reserved: MetaReserved(0),
                segment_lengths: [
                    SegmentLength($seg1),
                    SegmentLength($seg2),
                    SegmentLength($seg3),
                ],
            }
        };
    }

    #[test]
    fn segment_index_calculated_correctly() {
        test_case(0, [2, 0, 0], Some(0)).unwrap();
        test_case(1, [2, 2, 2], Some(0)).unwrap();
        test_case(2, [2, 1, 0], Some(1)).unwrap();
        test_case(3, [2, 1, 0], None).unwrap();

        test_case(255, [2, 1, 0], None).unwrap();
        test_case(255, [255, 1, 0], Some(1)).unwrap();
        test_case(255, [1, 255, 0], Some(1)).unwrap();

        test_case(0, [0, 0, 0], None).unwrap();
        test_case(1, [0, 0, 0], None).unwrap();

        fn test_case(
            hop_index: u8,
            segments: [u8; 3],
            expected_segment: Option<usize>,
        ) -> Result<(), String> {
            let mut meta = new_path_meta_header![segments[0], segments[1], segments[2]];
            meta.current_hop_field = HopFieldIndex(hop_index);

            if meta.segment_index() != expected_segment {
                return Err(format!(
                    "Expected segment index {:?} for hop index {}, got {:?}",
                    expected_segment,
                    hop_index,
                    meta.segment_index()
                ));
            }

            Ok(())
        }
    }

    #[test]
    fn reverse_at_hop_index_updates_correctly() {
        struct HeaderState {
            hop: u8,
            info: u8,
            segs: [u8; 3],
        }
        impl HeaderState {
            fn new(hop: u8, info: u8, segs: [u8; 3]) -> Self {
                HeaderState { hop, info, segs }
            }
        }

        // Reversing at the first hop
        test_case(
            HeaderState::new(0, 0, [2, 0, 0]),
            HeaderState::new(1, 0, [2, 0, 0]),
        )
        .unwrap();
        test_case(
            HeaderState::new(0, 0, [1, 2, 0]),
            HeaderState::new(2, 1, [2, 1, 0]),
        )
        .unwrap();
        test_case(
            HeaderState::new(0, 0, [1, 2, 3]),
            HeaderState::new(5, 2, [3, 2, 1]),
        )
        .unwrap();

        // Reversing in between
        test_case(
            HeaderState::new(3, 2, [1, 2, 3]),
            HeaderState::new(2, 0, [3, 2, 1]),
        )
        .unwrap();
        test_case(
            HeaderState::new(2, 1, [1, 2, 3]),
            HeaderState::new(3, 1, [3, 2, 1]),
        )
        .unwrap();

        // Bounds checks
        test_case(
            HeaderState::new(0, 0, [0, 0, 0]),
            HeaderState::new(0, 0, [0, 0, 0]),
        )
        .unwrap();
        test_case(
            HeaderState::new(255, 0, [255, 0, 0]),
            HeaderState::new(0, 0, [255, 0, 0]),
        )
        .unwrap();

        // Invalid input - should just not panic
        test_case(
            HeaderState::new(255, 25, [255, 254, 0]),
            HeaderState::new(0, 0, [254, 255, 0]),
        )
        .unwrap();
        test_case(
            HeaderState::new(20, 1, [0, 0, 0]),
            HeaderState::new(0, 0, [0, 0, 0]),
        )
        .unwrap();

        fn test_case(in_state: HeaderState, expected: HeaderState) -> Result<(), String> {
            let mut header =
                new_path_meta_header![in_state.segs[0], in_state.segs[1], in_state.segs[2]];

            header.current_hop_field = HopFieldIndex(in_state.hop);
            header.current_info_field = InfoFieldIndex(in_state.info);

            let reversed = header.to_reversed();
            let result = [
                reversed.segment_lengths[0].get(),
                reversed.segment_lengths[1].get(),
                reversed.segment_lengths[2].get(),
            ];

            if reversed.current_hop_field.get() != expected.hop {
                return Err(format!(
                    "Expected hop index {}, got {}",
                    expected.hop,
                    reversed.current_hop_field.get()
                ));
            }
            if reversed.current_info_field.get() != expected.info {
                return Err(format!(
                    "Expected info index {}, got {}",
                    expected.info,
                    reversed.current_info_field.get()
                ));
            }

            if result != expected.segs {
                return Err(format!(
                    "Expected segment lengths {:?}, got {:?}",
                    expected.segs, result
                ));
            }

            Ok(())
        }
    }
    mod interfaces_count {
        use super::*;

        macro_rules! test_interfaces_count {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr], $count:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        new_path_meta_header![$seg1, $seg2, $seg3].interfaces_count(),
                        $count
                    )
                }
            };
        }

        test_interfaces_count!(no_segment, [0, 0, 0], 0);
        test_interfaces_count!(single_segment1, [2, 0, 0], 2);
        test_interfaces_count!(single_segment2, [4, 0, 0], 6);
        test_interfaces_count!(two_segments, [4, 3, 0], 10);
        test_interfaces_count!(three_segments, [4, 3, 2], 12);
    }

    mod hop_index_for_interface {
        use super::*;

        macro_rules! test_hop_index_for_interface {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr], $interface_index:expr, $hop_index:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        new_path_meta_header![$seg1, $seg2, $seg3]
                            .hop_field_index_for_interface($interface_index),
                        $hop_index
                    )
                }
            };
        }
        test_hop_index_for_interface!(single_segment1, [4, 0, 0], 0, 0);
        test_hop_index_for_interface!(single_segment2, [4, 0, 0], 1, 1);
        test_hop_index_for_interface!(single_segment3, [4, 0, 0], 4, 2);
        test_hop_index_for_interface!(single_segment4, [4, 0, 0], 5, 3);
        test_hop_index_for_interface!(two_segments1, [4, 3, 0], 5, 3);
        test_hop_index_for_interface!(two_segments2, [4, 3, 0], 6, 4);
        test_hop_index_for_interface!(two_segments3, [4, 3, 0], 9, 6);
        test_hop_index_for_interface!(three_segments1, [4, 3, 2], 9, 6);
        test_hop_index_for_interface!(three_segments2, [4, 3, 2], 10, 7);
        test_hop_index_for_interface!(three_segments3, [4, 3, 2], 11, 8);

        macro_rules! test_no_panic {
            ($name:ident, [$seg1:expr, $seg2:expr, $seg3:expr]) => {
                #[test]
                fn $name() {
                    let header = new_path_meta_header![$seg1, $seg2, $seg3];
                    header.hop_field_index_for_interface(0);
                    header.hop_field_index_for_interface(4);
                }
            };
        }

        test_no_panic!(no_segment, [0, 0, 0]);
        test_no_panic!(invalid_segments1, [0, 0, 4]);
        test_no_panic!(invalid_segments2, [2, 0, 4]);
        test_no_panic!(invalid_segments3, [0, 3, 0]);
    }
}
