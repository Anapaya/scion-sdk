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

use crate::core::layout::BitRange;

/// Trait for types that can be constructed from an unaligned read value
/// Required to use the `unchecked_unaligned_be_read` function.
pub trait FromUnalignedRead {
    fn from_unaligned_read(v: u128) -> Self;
}

macro_rules! impl_from_u128 {
    ($($t:ty),*) => {
        $(
            impl FromUnalignedRead for $t {
                #[inline(always)]
                fn from_unaligned_read(v: u128) -> Self {
                    v as $t
                }
            }
        )*
    };
}
impl_from_u128!(u8, u16, u32, u64, u128);

/// Reads an unaligned value from the buffer at the specified bit offset and width.
///
/// The returned value will be interpreted in big-endian bit order.
///
/// SAFETY:
/// The caller must ensure that the buffer contains enough bits to satisfy the read.
///
/// Parameters:
/// - buf: The buffer to read from.
/// - range: The bit range to read. (generally <=120 bits)
///
/// Performance, assuming range is known at compile time:
/// - An aligned read is as fast as a normal read. e.g.`*buf.get_unchecked()`
/// - An unaligned read generates extra bitshift and mask operations.
#[inline(always)]
pub unsafe fn unchecked_bit_range_be_read<T>(buf: &[u8], range: BitRange) -> T
where
    T: FromUnalignedRead,
{
    const LANE_BITS: usize = 128;
    const LANE_BYTES: usize = LANE_BITS / 8;

    let bit_count = range.size_bits();
    let bit_range = range.bit_range();
    let byte_count = range.size_bytes();
    let byte_range = range.containing_byte_range();

    debug_assert!(
        range.size_bytes() <= LANE_BYTES,
        "BitRange too large for write"
    );
    debug_assert!(byte_range.end <= buf.len(), "write exceeds buffer");

    let mut lane = [0u8; 16];

    unsafe {
        // Copy relevant bytes into lane, aligned to the right
        core::ptr::copy_nonoverlapping(
            buf.get_unchecked(byte_range).as_ptr(),
            lane[LANE_BYTES - byte_count..].as_mut_ptr(),
            byte_count,
        );
    };

    let lane_val = u128::from_be_bytes(lane);
    // Lane Val now contains the relevant bytes like:
    // xxxx xx11 111x xxx
    // 1 = Relevant bits
    // x = Irrelevant bits

    // Bitshift value to align relevant bits to the right
    let next_full_byte = bit_range.end.div_ceil(8) * 8;
    let right_shift = next_full_byte - bit_range.end;
    let aligned_val = lane_val >> right_shift;

    // Remove irrelevant bits from the left
    let value_mask = (1u128 << bit_count) - 1;
    let cleaned_val = aligned_val & value_mask;

    T::from_unaligned_read(cleaned_val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_aligned_u8() {
        let buf = [0b10101010u8, 0];
        let val: u8 = unsafe { unchecked_bit_range_be_read(&buf, BitRange::new(0, 8)) };
        println!("val = {:08b}", val);
        assert_eq!(val, 0b10101010);
    }

    #[test]
    fn should_read_aligned_u16() {
        let buf = [0b10101010, 0b01010101];
        let val: u16 = unsafe { unchecked_bit_range_be_read(&buf, BitRange::new(0, 16)) };
        println!("val = {:016b}", val);
        assert_eq!(val, 0b1010101001010101);
    }

    #[test]
    fn should_read_unaligned_single_byte() {
        // buffer = 00011100
        let buf = [0b00011100];
        let val: u8 = unsafe { unchecked_bit_range_be_read(&buf, BitRange::new(3, 3)) };
        println!("val = {:03b}", val);
        assert_eq!(val, 0b111);
    }

    #[test]
    fn should_read_cross_byte() {
        let buf = [0b00000011, 0b01000000, 0];
        let val: u16 = unsafe { unchecked_bit_range_be_read(&buf, BitRange::new(6, 4)) };
        println!("val = {:010b}", val);
        assert_eq!(val, 0b1101);
    }

    #[test]
    fn should_read_large_cross_byte() {
        let buf = [0b00000011, 0b01111111, 0b11111111, 0b01000000, 0];
        let val: u32 = unsafe { unchecked_bit_range_be_read(&buf, BitRange::new(6, 20)) };
        println!("val = {:020b}", val);
        assert_eq!(val, 0b1101_1111_1111_1111_1101);
    }

    #[test]
    fn should_read_bits_at_long_offset() {
        let mut buf = [0u8; 20];
        buf[10] = 0b00111100;
        let range = BitRange::new(10 * 8 + 2, 4); // bits 82..86
        let val: u8 = unsafe { unchecked_bit_range_be_read(&buf, range) };
        println!("val = {:04b}", val);
        assert_eq!(val, 0b1111);
    }
}
