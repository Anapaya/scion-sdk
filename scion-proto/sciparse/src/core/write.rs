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

/// Trait for types that can be converted into an unaligned write value
/// Required to use the `unchecked_unaligned_be_write` function.
pub trait IntoUnalignedWrite {
    fn into_write_value(v: Self) -> u128;
}

macro_rules! impl_into_u128 {
    ($($t:ty),*) => {
        $(
            impl IntoUnalignedWrite for $t {

                #[inline(always)]
                fn into_write_value(v: Self) -> u128 {
                    v as u128
                }
            }
        )*
    };
}
impl_into_u128!(u8, u16, u32, u64);

/// Writes an unaligned value into the buffer at the specified bit offset and width.
///
/// If a value exceeds the specified bit_width, it will be truncated to fit.
///
/// SAFETY:
/// The caller must ensure that the buffer is large enough to hold the written value.
///
/// Parameters:
/// - buf: The buffer to write into.
/// - range: The bit range to write. (generally <=120 bits)
/// - val: The value to write.
///
/// Performance, assuming range is known at compile time:
/// - A aligned write is as fast as a normal write. e.g.`*buf.get_unchecked_mut() = val`
/// - An unaligned write must read-modify-write the affected bytes.
#[inline(always)]
pub unsafe fn unchecked_bit_range_be_write<T>(buf: &mut [u8], range: BitRange, val: T)
where
    T: IntoUnalignedWrite,
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

    // Copy relevant bytes into lane, aligned to the right
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.get_unchecked(byte_range.clone()).as_ptr(),
            lane[LANE_BYTES - byte_count..].as_mut_ptr(),
            byte_count,
        );
    };

    let mut lane_val = u128::from_be_bytes(lane);

    // Lane Val now contains the relevant bytes like:
    // xxxx xx00 000x xxx
    // 0 = Bits to be written to
    // x = Existing bits which should be preserved

    // Truncate our value to ensure no bits outside bit_width are set
    let value_mask = (1u128 << bit_count) - 1;
    let truncated_val = T::into_write_value(val) & value_mask;

    // Bitshift our value to align to target bits to the left
    let next_full_byte = bit_range.end.div_ceil(8) * 8;
    let left_shift = next_full_byte - bit_range.end;
    let aligned_val = truncated_val << left_shift;

    // Clean target bits in lane
    let aligned_write_mask = value_mask << left_shift;
    lane_val &= !aligned_write_mask;

    // Insert new value
    lane_val |= aligned_val;

    // Write back modified bytes
    let new_bytes = lane_val.to_be_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(
            new_bytes[LANE_BYTES - byte_count..].as_ptr(),
            buf.get_unchecked_mut(byte_range).as_mut_ptr(),
            byte_count,
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(buf: &[u8]) -> String {
        buf.iter()
            .map(|b| format!("{:08b}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn should_write_aligned_u8() {
        let mut buf = [0u8; 2];
        unsafe {
            unchecked_bit_range_be_write(&mut buf, BitRange::new(0, 8), 0b10101010u8);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf, [0b10101010, 0]);
    }

    #[test]
    fn should_write_aligned_u16() {
        let mut buf = [0u8; 2];
        unsafe {
            unchecked_bit_range_be_write(&mut buf, BitRange::new(0, 16), 0b1010101001010101u16);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf, [0b10101010, 0b01010101]);
    }

    #[test]
    fn should_write_unaligned_single_byte() {
        let mut buf = [0u8; 1];
        unsafe {
            unchecked_bit_range_be_write(&mut buf, BitRange::new(3, 3), 0b111u8);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf, [0b00011100]);
    }

    #[test]
    fn should_write_cross_byte() {
        let mut buf = [0u8; 3];
        unsafe {
            // writes 0000 0011 1111 1111
            unchecked_bit_range_be_write(&mut buf, BitRange::new(5, 10), 0x3F1u16);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf, [0b111, 0b11100010, 0]);
    }

    #[test]
    fn should_preserve_non_written_bits() {
        // Preload buffer with pattern 10101010_01010101
        // Write 0b1111 into bits 2..6 (big-endian numbering)
        let mut buf = [0b10101010, 0b01010101];
        unsafe {
            unchecked_bit_range_be_write(&mut buf, BitRange::new(2, 4), 0b0101u8);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf[0], 0b10010110);
        assert_eq!(buf[1], 0b01010101);
    }

    #[test]
    fn should_truncate_value() {
        let mut buf = [0u8; 2];
        unsafe {
            unchecked_bit_range_be_write(&mut buf, BitRange::new(2, 4), 0xFFu8);
        }

        println!("buf = {}", bits(&buf));
        assert_eq!(buf, [0b00111100, 0]);
    }
}
