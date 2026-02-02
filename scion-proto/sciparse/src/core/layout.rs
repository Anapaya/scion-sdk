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

//! Utilities for creating layout representations of bit-level data
//!
//! Layouts are the source of truth for the structure of protocol headers and fields.
//!
//! They define the size and position of fields within a header or data structure, where the views
//! and models use the layout definitions to read/write data from/to byte buffers.
//!
//! Layouts are on the hot path for view construction and parsing, so they should be efficient and
//! avoid unnecessary computations.
//!
//! Layouts should also offer annotations for debugging purposes, which can be used to visualize the
//! structure of binary data.

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

    /// Returns the maximum unsigned integer that can be represented by the BitRange
    #[inline]
    pub const fn max_uint(&self) -> usize {
        (1 << self.size_bits()) - 1
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
        debug_assert!(self.end >= self.start, "BitRange end must be >= start");
        self.end - self.start
    }

    /// Shifts the bit range forward by the given number of bytes
    #[inline]
    pub const fn shift(mut self, bytes: usize) -> Self {
        self.start += bytes * 8;
        self.end += bytes * 8;
        self
    }

    /// Offsets the bit range by the given number of bits
    #[inline]
    pub fn shift_bits(&self, offset: usize) -> Self {
        // Check no overflow occurs
        debug_assert!(self.start + offset >= self.start);
        debug_assert!(self.end + offset >= self.end);

        BitRange {
            start: self.start + offset,
            end: self.end + offset,
        }
    }
}

/// Macros for layout definitions
pub mod macros {
    /// Helper macro to generate bit range constants
    macro_rules! gen_bitrange_const {
        ($range_name:ident, $start:expr, $offset:expr) => {
            /// Bit range constant for the specified field
            pub const $range_name: BitRange = BitRange::new($start, $offset);
        };
    }

    pub(crate) use gen_bitrange_const;
}
