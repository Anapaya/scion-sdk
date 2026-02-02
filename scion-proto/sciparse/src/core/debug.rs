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

//! Utility for formatting bit-level annotations for debugging purposes
//!
//! This module provides functionality to create human-readable, colored
//! representations of bit-level data in byte buffers, along with annotations
//! that describe the meaning of different bit ranges.
//!
//! These Annotations can be used to visualize the structure of binary data,
//! making it easier to understand and debug complex protocols or data formats.
//!
//! All Layouts in this crate provide associated Annotations for their field.

use std::fmt::Write as FmtWrite;

use crate::core::{layout::BitRange, read::unchecked_bit_range_be_read};

/// Annotations for bit-level fields in a buffer
pub struct Annotations {
    buckets: Vec<AnnotationBucket>,
    current_offset: usize,
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
            .map_or_else(|| 0, |b| b.annotations.last().map_or(0, |a| a.0.end));
    }

    /// Add a new annotation bucket with the given title and annotations
    pub fn add(&mut self, title: String, annotations: Vec<(BitRange, &'static str)>) {
        let annotations = offset_annotations(annotations, self.current_offset);
        self.buckets.push(AnnotationBucket { title, annotations });

        self.current_offset = self
            .buckets
            .last()
            .map_or_else(|| 0, |b| b.annotations.last().map_or(0, |a| a.0.end));
    }
}
impl Annotations {
    /// Format the given buffer and annotations into a human-readable, colored string.
    ///
    /// The output will display the bits in the buffer, with annotations indicating the meaning
    /// of different bit ranges. Bits that are not part of the buffer but are annotated
    /// will be displayed as 'X'. Each annotation label will be assigned a unique color
    /// for better visibility.
    ///
    /// # Parameters
    /// - `out`: The output to write the formatted string to.
    /// - `buffer`: The byte buffer containing the bits to be formatted.
    /// - `ann`: The annotations describing the meaning of different bit ranges in the buffer.
    /// - `bytes_per_line`: The number of bytes to display per line in the output, annotation
    ///   buckets should be aligned.
    pub fn fmt_on_buffer(
        &self,
        out: &mut impl FmtWrite,
        buffer: &[u8],
        bytes_per_line: usize,
    ) -> std::fmt::Result {
        const PALETTE: [u8; 24] = [
            // High-contrast shuffle across hue families
            160, 34, 27, 130, 161, 35, 33, 136, 162, 36, 69, 142, 163, 37, 75, 148, 164, 38, 81,
            154, 165, 39, 87, 190,
        ];
        // Neutral gray for unannotated bits
        const COLOR_PLAIN: u8 = 244;

        let total_bits = buffer.len() * 8;
        let bits_per_line = bytes_per_line * 8;

        use std::collections::HashMap;
        let mut label_colors: HashMap<&str, u8> = HashMap::new();
        let mut color_idx = 0usize;

        // Assign colors to labels
        for bucket in &self.buckets {
            for (_, label) in &bucket.annotations {
                label_colors.entry(*label).or_insert_with(|| {
                    let c = PALETTE[color_idx % PALETTE.len()];
                    color_idx += 1;
                    c
                });
            }
        }

        // Helper to write a colored character based on annotations
        let write_colored = |buf: &mut String,
                             i: usize,
                             ch: char,
                             annotations: &[(BitRange, &str)]|
         -> std::fmt::Result {
            let color = annotations
                .iter()
                // Find the first annotation range that contains the bit index
                .find(|(r, _)| r.contains(i))
                // Get the colour for the associated label
                .and_then(|(_, l)| label_colors.get(l))
                .copied()
                .unwrap_or(COLOR_PLAIN);

            // 256-color foreground escape sequence
            write!(buf, "\x1b[38;5;{}m{}\x1b[0m", color, ch)
        };

        let mut global_offset = 0usize;
        // Iterate per bucket, printing its title and annotated bits
        for (idx, bucket) in self.buckets.iter().enumerate() {
            let annotations = &bucket.annotations;

            // Determine the start of the bucket
            let bucket_start = annotations
                .iter()
                .map(|(r, _)| r.start)
                .min()
                .unwrap_or(global_offset);

            // Determine the end of the bucket
            let bucket_end = annotations
                .iter()
                .map(|(r, _)| r.end)
                .max()
                .unwrap_or(bucket_start);

            // Print bucket title
            if idx == 0 || bucket_start >= global_offset {
                writeln!(out, "                | {}", bucket.title)?;
            }

            let span_start = global_offset.min(bucket_start);
            let span_end = bucket_end.max(span_start);

            // Print bits in chunks of `bits_per_line`
            for chunk_start in (span_start..span_end).step_by(bits_per_line) {
                let chunk_end = (chunk_start + bits_per_line).saturating_sub(1);
                let byte_offset = chunk_start / 8;

                let mut line = String::new();
                for bit_idx in chunk_start..=chunk_end {
                    // Add space every 4 bits for readability
                    if bit_idx % 4 == 0 && bit_idx != chunk_start {
                        write!(line, " ")?;
                    }

                    // Determine if the bit is within the buffer
                    if bit_idx < total_bits {
                        // If it is, read the bit value and write it colored
                        let bit = (buffer[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1;
                        write_colored(
                            &mut line,
                            bit_idx,
                            if bit == 1 { '1' } else { '0' },
                            annotations,
                        )?;
                    } else if annotations.iter().any(|(r, _)| r.contains(bit_idx)) {
                        // If the bit is outside the buffer but annotated, mark it as 'X'
                        write_colored(&mut line, bit_idx, 'X', annotations)?;
                    } else {
                        // Otherwise, just write a plain space
                        write!(line, " ")?;
                    }
                }

                // Collect active annotations for this chunk
                let mut label_str = String::new();
                let active_annotations: Vec<_> = annotations
                    .iter()
                    .filter(|(r, _)| r.start <= chunk_end && r.end > chunk_start)
                    .collect();

                if active_annotations.is_empty() {
                    // No active annotations for this chunk
                    write!(label_str, "-")?;
                } else {
                    // Print active annotations with their values
                    for (range, label) in active_annotations {
                        let color = label_colors[label];
                        let bit_width = range.end - range.start;

                        // Skip values of more than 64 bits
                        if bit_width > 64 {
                            write!(label_str, "\x1b[38;5;{}m{}\x1b[0m ", color, label)?;
                            continue;
                        }

                        let value_str = if range.end > total_bits {
                            // Annotated bits exceed buffer size, cannot read value
                            "n/a".to_string()
                        } else {
                            // SAFETY: range was checked to be within buffer
                            let v = unsafe { unchecked_bit_range_be_read::<u128>(buffer, *range) };
                            v.to_string()
                        };

                        // Write label and value with color
                        write!(
                            label_str,
                            "\x1b[38;5;{}m{}={}\x1b[0m ",
                            color, label, value_str
                        )?;
                    }

                    // Remove trailing space
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

            // Update global offset for next bucket
            global_offset = span_end;
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
    bit_offset: usize,
) -> Vec<(BitRange, &str)> {
    annotations
        .iter()
        .map(|(r, label)| (r.shift_bits(bit_offset), *label))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::{
        core::layout::Layout, header::layout::ScionHeaderLayout,
        path::standard::layout::StdPathDataLayout,
    };

    #[test]
    #[ignore = "can only be inspected manually"]
    fn it_works() {
        let layout = ScionHeaderLayout::from_parts(4, 8, StdPathDataLayout::new(1, 2, 2).into(), 0);
        let annotations = layout.annotations();
        let mut buf = vec![0u8; layout.size_bytes() - 3]; // smaller buffer to test out-of-bounds

        // fill buf with data
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i * 37 + 13) as u8;
        }

        let mut out = String::new();
        annotations.fmt_on_buffer(&mut out, &buf, 4).unwrap();
        println!("{}", out);
    }
}
