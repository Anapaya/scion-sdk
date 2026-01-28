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

//! Utilities for working with bit-level data in byte buffers

/// Utilities for reading unaligned values from byte buffers
pub(crate) mod read {
    use crate::layout::BitRange;

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
}

/// Utilities for writing unaligned values into byte buffers
pub(crate) mod write {
    use crate::layout::BitRange;

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
}

/// Utilities for formatting bit-level annotations for debugging purposes
pub mod debug {
    use std::fmt::Write as FmtWrite;

    use crate::{helper::read::unchecked_bit_range_be_read, layout::BitRange};

    /// Annotations for bit-level fields in a buffer
    pub struct Annotations {
        buckets: Vec<AnnotationBucket>,
        current_offset: isize,
    }
    impl Default for Annotations {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Annotations {
        /// Create a new, empty Annotations instance
        pub fn new() -> Self {
            Self {
                buckets: Vec::new(),
                current_offset: 0,
            }
        }

        /// Create a new Annotations instance containing the given title and annotations
        pub fn new_with(title: String, annotations: Vec<(BitRange, &'static str)>) -> Self {
            let mut ann = Self::new();
            ann.add(title, annotations);
            ann
        }

        /// Extend the annotations with another Annotations instance
        pub fn extend(&mut self, other: Annotations) {
            for bucket in other.buckets {
                let ann = offset_annotations(bucket.annotations, self.current_offset);
                self.buckets.push(AnnotationBucket {
                    title: bucket.title,
                    annotations: ann,
                });
            }

            self.current_offset = self
                .buckets
                .last()
                .unwrap()
                .annotations
                .last()
                .unwrap()
                .0
                .end as isize;
        }

        /// Add a new annotation bucket with the given title and annotations
        pub fn add(&mut self, title: String, annotations: Vec<(BitRange, &'static str)>) {
            let annotations = offset_annotations(annotations, self.current_offset);
            self.buckets.push(AnnotationBucket { title, annotations });

            self.current_offset = self
                .buckets
                .last()
                .unwrap()
                .annotations
                .last()
                .unwrap()
                .0
                .end as isize;
        }
    }
    impl Annotations {
        /// Format the given buffer and annotations into a human-readable, colored string.
        ///
        /// The output will display the bits in the buffer, with annotations indicating the meaning
        /// of different bit ranges. Bits that are not part of the buffer but are annotated
        /// will be displayed as 'X'. Each annotation label will be assigned a unique color
        /// for better visibility.
        /// # Parameters
        /// - `out`: The output buffer to write the formatted string to.
        /// - `buffer`: The byte buffer containing the bits to be formatted.
        /// - `ann`: The annotations describing the meaning of different bit ranges in the buffer.
        /// - `bytes_per_line`: The number of bytes to display per line in the output
        pub fn fmt_on_buffer(
            &self,
            out: &mut impl FmtWrite,
            buffer: &[u8],
            bytes_per_line: usize,
        ) -> std::fmt::Result {
            const COLORS: [u8; 6] = [31, 32, 33, 34, 35, 36];
            const COLOR_PLAIN: u8 = 90;

            let total_bits = buffer.len() * 8;
            let bits_per_line = bytes_per_line * 8;

            use std::collections::HashMap;
            let mut label_colors: HashMap<&str, u8> = HashMap::new();
            let mut color_idx = 0;

            for bucket in &self.buckets {
                for (_, label) in &bucket.annotations {
                    label_colors.entry(*label).or_insert_with(|| {
                        let c = COLORS[color_idx % COLORS.len()];
                        color_idx += 1;
                        c
                    });
                }
            }

            let write_colored = |buf: &mut String,
                                 i: usize,
                                 ch: char,
                                 annotations: &[(BitRange, &str)]|
             -> std::fmt::Result {
                let color = annotations
                    .iter()
                    .find(|(r, _)| r.contains(i))
                    .and_then(|(_, l)| label_colors.get(l))
                    .copied()
                    .unwrap_or(COLOR_PLAIN);
                write!(buf, "\x1b[{}m{}\x1b[0m", color, ch)
            };

            let mut global_start = 0usize;

            for (idx, bucket) in self.buckets.iter().enumerate() {
                let annotations = &bucket.annotations;

                let bucket_start = annotations
                    .iter()
                    .map(|(r, _)| r.start)
                    .min()
                    .unwrap_or(global_start);

                let bucket_end = annotations
                    .iter()
                    .map(|(r, _)| r.end)
                    .max()
                    .unwrap_or(bucket_start);

                if idx == 0 || bucket_start >= global_start {
                    writeln!(out, "                | {}", bucket.title)?;
                }

                let span_start = global_start.min(bucket_start);
                let span_end = bucket_end.max(span_start);

                for chunk_start in (span_start..span_end).step_by(bits_per_line) {
                    let chunk_end = (chunk_start + bits_per_line).saturating_sub(1);
                    let byte_offset = chunk_start / 8;

                    let mut line = String::new();
                    for i in chunk_start..=chunk_end {
                        if i % 4 == 0 && i != chunk_start {
                            write!(line, " ")?;
                        }

                        if i < total_bits {
                            let bit = (buffer[i / 8] >> (7 - (i % 8))) & 1;
                            write_colored(
                                &mut line,
                                i,
                                if bit == 1 { '1' } else { '0' },
                                annotations,
                            )?;
                        } else if annotations.iter().any(|(r, _)| r.contains(i)) {
                            write_colored(&mut line, i, 'X', annotations)?;
                        } else {
                            write!(line, " ")?;
                        }
                    }

                    let mut label_str = String::new();
                    let active: Vec<_> = annotations
                        .iter()
                        .filter(|(r, _)| r.start <= chunk_end && r.end > chunk_start)
                        .collect();

                    if active.is_empty() {
                        write!(label_str, "-")?;
                    } else {
                        for (range, label) in active {
                            let color = label_colors[label];
                            let bit_width = range.end - range.start;

                            if bit_width > 64 {
                                write!(label_str, "\x1b[{}m{}\x1b[0m ", color, label)?;
                                continue;
                            }

                            let value_str = if range.end > total_bits {
                                "n/a".to_string()
                            } else {
                                let v =
                                    unsafe { unchecked_bit_range_be_read::<u64>(buffer, *range) };
                                v.to_string()
                            };

                            write!(label_str, "\x1b[{}m{}={}\x1b[0m ", color, label, value_str)?;
                        }
                        label_str.pop();
                    }

                    writeln!(
                        out,
                        "0x{:04X}  {:03}–{:03} | {:<width$} | {}",
                        byte_offset,
                        chunk_start,
                        chunk_end,
                        line,
                        label_str,
                        width = bits_per_line + (bits_per_line / 4 - 1)
                    )?;
                }

                global_start = span_end;
            }

            Ok(())
        }
    }

    struct AnnotationBucket {
        title: String,
        annotations: Vec<(BitRange, &'static str)>,
    }

    /// Offset all annotations by the given bit offset
    fn offset_annotations(
        annotations: Vec<(BitRange, &str)>,
        bit_offset: isize,
    ) -> Vec<(BitRange, &str)> {
        annotations
            .iter()
            .map(|(r, label)| (r.offset_bits(bit_offset), *label))
            .collect()
    }
}
