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

//! SCION standard path views
//!
//! See [`View`](crate::core::view) for more information about views in general.

use std::{fmt::Debug, mem::transmute, ops::Range};

use crate::{
    core::{
        read::unchecked_bit_range_be_read,
        view::{
            View, ViewConversionError,
            macros::{gen_field_read, gen_field_write, gen_unsafe_field_write, gen_view_impl},
        },
        write::unchecked_bit_range_be_write,
    },
    dataplane_path::{
        standard::{
            layout::{
                HopFieldLayout, InfoFieldLayout, StdPathDataLayout, StdPathLayout,
                StdPathMetaLayout,
            },
            mac::{HopMacInput, HopMacInputSource},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags, exp_time_to_duration},
        },
        types::PathReverseError,
    },
};

/// A view over a standard SCION path, including meta header and data
#[repr(transparent)]
pub struct StandardPathView([u8]);
gen_view_impl!(StandardPathView, StdPathLayout);

// Meta header
impl StandardPathView {
    gen_field_read!(
        curr_info_field_idx,
        StdPathMetaLayout::CURR_INFO_FIELD_RNG,
        u8
    );
    gen_field_read!(
        curr_hop_field_idx,
        StdPathMetaLayout::CURR_HOP_FIELD_RNG,
        u8
    );
    gen_field_read!(seg0_len, StdPathMetaLayout::SEG0_LEN_RNG, u8);
    gen_field_read!(seg1_len, StdPathMetaLayout::SEG1_LEN_RNG, u8);
    gen_field_read!(seg2_len, StdPathMetaLayout::SEG2_LEN_RNG, u8);

    /// Returns the number of info fields present in the path
    #[inline]
    pub fn info_field_count(&self) -> u8 {
        (self.seg0_len() > 0) as u8 + (self.seg1_len() > 0) as u8 + (self.seg2_len() > 0) as u8
    }

    /// Returns the number of hop fields present in the path
    #[inline]
    pub fn hop_field_count(&self) -> u8 {
        self.seg0_len() + self.seg1_len() + self.seg2_len()
    }
}

// Meta header mut
impl StandardPathView {
    gen_field_write!(
        set_curr_info_field,
        StdPathMetaLayout::CURR_INFO_FIELD_RNG,
        u8
    );
    gen_field_write!(
        set_curr_hop_field,
        StdPathMetaLayout::CURR_HOP_FIELD_RNG,
        u8
    );
    gen_unsafe_field_write!(set_seg0_len, StdPathMetaLayout::SEG0_LEN_RNG, u8);
    gen_unsafe_field_write!(set_seg1_len, StdPathMetaLayout::SEG1_LEN_RNG, u8);
    gen_unsafe_field_write!(set_seg2_len, StdPathMetaLayout::SEG2_LEN_RNG, u8);
}
// Data Helpers
impl StandardPathView {
    /// Returns the byte range for the info field at the given index, or None if the index is out of
    /// bounds
    #[inline]
    fn checked_info_field_range(&self, index: usize) -> Option<Range<usize>> {
        let info_field_count = self.info_field_count() as usize;
        if index >= info_field_count {
            return None;
        }

        Some(
            StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len())
                .info_field_range(index)
                .shift(StdPathMetaLayout::SIZE_BYTES)
                .aligned_byte_range(),
        )
    }

    /// Returns the byte range for the hop field at the given index, or None if the index is out of
    /// bounds
    #[inline]
    pub fn checked_hop_field_range(&self, index: usize) -> Option<Range<usize>> {
        let hop_field_count = self.hop_field_count() as usize;
        if index >= hop_field_count {
            return None;
        }

        Some(
            StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len())
                .hop_field_range(index)
                .shift(StdPathMetaLayout::SIZE_BYTES)
                .aligned_byte_range(),
        )
    }
}
// Data
impl StandardPathView {
    /// Returns a view over the current info field, or None if the current info field index is out
    /// of bounds
    #[inline]
    pub fn curr_info_field(&self) -> Option<&InfoFieldView> {
        let index = self.curr_info_field_idx() as usize;
        self.info_field(index)
    }

    /// Returns a view over the info field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn info_field(&self, index: usize) -> Option<&InfoFieldView> {
        let field_range = self.checked_info_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field =
            unsafe { InfoFieldView::from_slice_unchecked(self.0.get_unchecked(field_range)) };

        Some(field)
    }

    /// Returns a view over the current hop field, or None if the current hop field index is out of
    /// bounds
    #[inline]
    pub fn curr_hop_field(&self) -> Option<&HopFieldView> {
        let index = self.curr_hop_field_idx() as usize;
        self.hop_field(index)
    }

    /// Returns a view over the hop field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn hop_field(&self, index: usize) -> Option<&HopFieldView> {
        let field_range = self.checked_hop_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field =
            unsafe { HopFieldView::from_slice_unchecked(self.0.get_unchecked(field_range)) };

        Some(field)
    }

    /// Returns a view over all info fields
    #[inline]
    pub fn info_fields(&self) -> &[InfoFieldView] {
        let layout = StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len());

        let info_fields_range = layout
            .info_fields_range()
            .shift(StdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked(info_fields_range) };

        debug_assert!(slice.len() == layout.info_field_count() * InfoFieldLayout::SIZE_BYTES);

        // SAFETY: InfoFieldView is #[repr(transparent)] over [u8; SIZE_BYTES], as such the cast is
        // safe
        unsafe {
            std::slice::from_raw_parts(
                slice.as_ptr() as *const InfoFieldView,
                layout.info_field_count(),
            )
        }
    }

    /// Returns a view over all hop fields
    #[inline]
    pub fn hop_fields(&self) -> &[HopFieldView] {
        let layout = StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len());

        let hop_fields_range = layout
            .hop_fields_range()
            .shift(StdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked(hop_fields_range) };

        // SAFETY: View is #[repr(transparent)] over [u8; SIZE_BYTES], as such raw byte slices can
        // be safely interpreted
        debug_assert!(slice.len() == layout.hop_field_count() * HopFieldLayout::SIZE_BYTES);
        unsafe {
            std::slice::from_raw_parts(
                slice.as_ptr() as *const HopFieldView,
                layout.hop_field_count(),
            )
        }
    }
}
// Data mut
impl StandardPathView {
    /// Returns a view over the current info field, or None if the current info field index is out
    /// of bounds
    #[inline]
    pub fn curr_info_field_mut(&mut self) -> Option<&mut InfoFieldView> {
        let index = self.curr_info_field_idx() as usize;
        self.info_field_mut(index)
    }

    /// Returns a view over the info field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn info_field_mut(&mut self, index: usize) -> Option<&mut InfoFieldView> {
        let field_range = self.checked_info_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field = unsafe {
            InfoFieldView::from_mut_slice_unchecked(self.0.get_unchecked_mut(field_range))
        };

        Some(field)
    }

    /// Returns a view over the current hop field, or None if the current hop field index is out of
    /// bounds
    #[inline]
    pub fn curr_hop_field_mut(&mut self) -> Option<&mut HopFieldView> {
        let index = self.curr_hop_field_idx() as usize;
        self.hop_field_mut(index)
    }

    /// Returns a view over the hop field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn hop_field_mut(&mut self, index: usize) -> Option<&mut HopFieldView> {
        let field_range = self.checked_hop_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field = unsafe {
            HopFieldView::from_mut_slice_unchecked(self.0.get_unchecked_mut(field_range))
        };

        Some(field)
    }

    /// Returns a view over all info fields
    #[inline]
    pub fn info_fields_mut(&mut self) -> &mut [InfoFieldView] {
        let layout = StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len());

        let info_fields_range = layout
            .info_fields_range()
            .shift(StdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked_mut(info_fields_range) };

        debug_assert!(slice.len() == layout.info_field_count() * InfoFieldLayout::SIZE_BYTES);

        // SAFETY: InfoFieldView is #[repr(transparent)] over [u8; SIZE_BYTES], as such the cast is
        // safe
        unsafe {
            std::slice::from_raw_parts_mut(
                slice.as_mut_ptr() as *mut InfoFieldView,
                layout.info_field_count(),
            )
        }
    }

    /// Returns a view over all hop fields
    #[inline]
    pub fn hop_fields_mut(&mut self) -> &mut [HopFieldView] {
        let layout = StdPathDataLayout::new(self.seg0_len(), self.seg1_len(), self.seg2_len());

        let hop_fields_range = layout
            .hop_fields_range()
            .shift(StdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked_mut(hop_fields_range) };
        // SAFETY: View is #[repr(transparent)] over [u8; SIZE_BYTES], as such raw byte slices can
        // be safely interpreted

        debug_assert!(slice.len() == layout.hop_field_count() * HopFieldLayout::SIZE_BYTES);
        unsafe {
            std::slice::from_raw_parts_mut(
                slice.as_mut_ptr() as *mut HopFieldView,
                layout.hop_field_count(),
            )
        }
    }

    /// Reverses the path in-place
    ///
    /// This function preserves the current logical position in the path.
    pub fn try_reverse(&mut self) -> Result<(), PathReverseError> {
        let seg0 = self.seg0_len();
        let seg1 = self.seg1_len();
        let seg2 = self.seg2_len();

        let seg_count;

        // Update current info and hop field indices
        let curr_hop_idx = self.curr_hop_field_idx() as usize;
        let curr_info_idx = self.curr_info_field_idx() as usize;

        // Reverse order of segment lengths
        {
            match (seg0, seg1, seg2) {
                (0, ..) => {
                    // Invalid path, no segments present, nothing to do
                    return Err(PathReverseError::new(
                        "Cannot reverse a path with no segments",
                    ));
                }
                (_, 0, _) => {
                    seg_count = 1;
                    // Only seg0 is present, nothing to do
                }
                (_, _, 0) => {
                    seg_count = 2;
                    // Swap seg0 and seg1
                    // SAFETY: Total number of hop fields is unchanged
                    unsafe {
                        self.set_seg0_len(seg1);
                        self.set_seg1_len(seg0);
                    }
                }
                (..) => {
                    seg_count = 3;
                    // All segments are present, swap seg0 with seg2, and keep seg1 in the middle
                    // SAFETY: Total number of hop fields is unchanged
                    unsafe {
                        self.set_seg0_len(seg2);
                        self.set_seg1_len(seg1);
                        self.set_seg2_len(seg0);
                    }
                }
            }
        }

        // Check if path is valid
        let total_hops = seg0 as usize + seg1 as usize + seg2 as usize;
        if curr_hop_idx >= total_hops {
            return Err(PathReverseError::new(
                "Current hop field index is out of bounds",
            ));
        }
        if curr_info_idx >= seg_count {
            return Err(PathReverseError::new(
                "Current info field index is out of bounds",
            ));
        }

        debug_assert!(
            total_hops > 0,
            "0 hops should have been caught by the check at the beginning of the function"
        );
        debug_assert!(
            seg_count > 0,
            "0 segments should have been caught by the check at the beginning of the function"
        );

        // Swap Construction dir and reverse order of info fields
        {
            let info_fields = self.info_fields_mut();

            for info_field in info_fields.iter_mut() {
                let mut flags = info_field.flags();
                flags.toggle(InfoFieldFlags::CONS_DIR);
                info_field.set_flags(flags);
            }

            info_fields.reverse();
        }

        // Reverse order of hop fields
        self.hop_fields_mut().reverse();

        let new_hop_idx = (total_hops - curr_hop_idx) - 1;
        let new_info_idx = (seg_count - curr_info_idx) - 1;
        self.set_curr_hop_field(new_hop_idx as u8);
        self.set_curr_info_field(new_info_idx as u8);

        Ok(())
    }
}

// Utility
impl StandardPathView {
    /// Returns a iterator over the segments of the path, where each segment is represented as a
    /// tuple of an info field and a slice of hop fields.
    ///
    /// The iterator gurantees that each info field has at least one hop field, and that the number
    /// of info fields and hop fields matches the segment lengths in the meta header.
    #[inline]
    pub fn segments(&self) -> SegmentIterator<'_> {
        SegmentIterator::new(self)
    }

    /// Calculates the expiry time of the path by scanning info and hop fields
    ///
    /// Returns the absolute expiry time as a UNIX timestamp in seconds, or 0 if the path has no hop
    /// fields.
    pub fn expiration(&self) -> u32 {
        let segment_iter = self.segments();
        if segment_iter.is_empty() {
            return 0;
        }

        let mut expiry_time = u32::MAX;

        for (info_field, hop_fields) in self.segments() {
            // get the lowest exp_time of the hop fields in the segment
            let exp_time = hop_fields
                .iter()
                .map(|hop_field| hop_field.exp_time())
                .min()
                .expect("segment iterator ensures at least one hop field per segment");

            let info_expiry = info_field.timestamp();

            // calculate the absolute expiry time of the segment
            let exp_time: u32 = exp_time_to_duration(exp_time)
                .as_secs()
                .try_into()
                .expect("maximum expiry time fits in u32");

            let segment_expiry = info_expiry.saturating_add(exp_time);

            // Update the path expiry time to be the minimum of the current expiry time and the
            // segment expiry
            expiry_time = expiry_time.min(segment_expiry);
        }

        expiry_time
    }
}
impl Debug for StandardPathView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hop_fields = self.hop_fields();
        let info_fields = self.info_fields();
        f.debug_struct("StandardPathMetaHeaderView")
            .field("current_info_field", &self.curr_info_field_idx())
            .field("curr_hop_field", &self.curr_hop_field_idx())
            .field("seg0_len", &self.seg0_len())
            .field("seg1_len", &self.seg1_len())
            .field("seg2_len", &self.seg2_len())
            .field("info_fields", &info_fields)
            .field("hop_fields", &hop_fields)
            .finish()
    }
}

/// Iterator over the segments of a standard path, where each segment is represented as a tuple of
/// an info field and a slice of hop fields.
pub struct SegmentIterator<'a> {
    segment_lengths: [u8; 3],
    hop_fields: &'a [HopFieldView],
    info_fields: &'a [InfoFieldView],
    seg_idx: usize,
    total_segments: usize,
    hop_idx: usize,
}
impl SegmentIterator<'_> {
    fn new(path_view: &StandardPathView) -> SegmentIterator<'_> {
        let segment_lengths = [
            path_view.seg0_len(),
            path_view.seg1_len(),
            path_view.seg2_len(),
        ];

        let mut total_segments = 0;
        for &len in &segment_lengths {
            if len == 0 {
                break;
            }
            total_segments += 1;
        }

        SegmentIterator {
            total_segments: total_segments as usize,
            hop_fields: path_view.hop_fields(),
            info_fields: path_view.info_fields(),
            segment_lengths,
            seg_idx: 0,
            hop_idx: 0,
        }
    }

    /// Returns true if the path has no segments, i.e. no info fields and no hop fields.
    pub fn is_empty(&self) -> bool {
        self.total_segments == 0
    }

    /// Returns the total number of segments in the path, which is determined by the number of info
    pub fn segment_count(&self) -> usize {
        self.total_segments
    }

    /// Returns the total number of hop fields in the path.
    pub fn hop_field_count(&self) -> usize {
        self.hop_fields.len()
    }
}
impl<'a> Iterator for SegmentIterator<'a> {
    type Item = (&'a InfoFieldView, &'a [HopFieldView]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.seg_idx >= self.total_segments {
            return None;
        }

        let info_field = self.info_fields.get(self.seg_idx)?;
        let hop_fields = &self.hop_fields
            [self.hop_idx..(self.hop_idx + self.segment_lengths[self.seg_idx] as usize)];

        self.seg_idx += 1;
        self.hop_idx += hop_fields.len();

        Some((info_field, hop_fields))
    }
}

/// A view over a standard SCION path info field
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct InfoFieldView([u8; InfoFieldLayout::SIZE_BYTES]);
impl View for InfoFieldView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        if buf.len() < InfoFieldLayout::SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "InfoFieldView",
                required: InfoFieldLayout::SIZE_BYTES,
                actual: buf.len(),
            });
        }

        Ok(InfoFieldLayout::SIZE_BYTES)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        let sized: &[u8; InfoFieldLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        let sized: &mut [u8; InfoFieldLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        let sized: Box<[u8; InfoFieldLayout::SIZE_BYTES]> =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8; N]
        let sized: Box<[u8; InfoFieldLayout::SIZE_BYTES]> = unsafe { transmute(self) };
        sized
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
// Immutable
impl InfoFieldView {
    /// Returns the flags of the info field
    #[inline]
    pub fn flags(&self) -> InfoFieldFlags {
        // SAFETY: buffer size is checked on construction
        let val = unsafe { unchecked_bit_range_be_read::<u8>(&self.0, InfoFieldLayout::FLAGS_RNG) };
        InfoFieldFlags::from_bits_retain(val)
    }

    gen_field_read!(segment_id, InfoFieldLayout::SEGMENT_ID_RNG, u16);

    #[inline]
    #[allow(unused)]
    /// Returns the timestamp of the info field, which is used for path expiry calculations
    ///
    /// The timestamp is the number of seconds since the UNIX epoch, and is used in combination with
    /// the `exp_time` field of the hop fields to calculate the absolute expiry time of the path.
    pub fn timestamp(&self) -> u32 {
        use crate::core::read::unchecked_bit_range_be_read;
        unsafe { unchecked_bit_range_be_read::<u32>(&self.0, (InfoFieldLayout::TIMESTAMP_RNG)) }
    }
}
// Mutable
impl InfoFieldView {
    /// Sets the flags of the info field
    #[inline]
    pub fn set_flags(&mut self, flags: InfoFieldFlags) {
        // SAFETY: buffer size is checked on construction
        let val = flags.bits();
        unsafe { unchecked_bit_range_be_write::<u8>(&mut self.0, InfoFieldLayout::FLAGS_RNG, val) }
    }

    gen_field_write!(set_segment_id, InfoFieldLayout::SEGMENT_ID_RNG, u16);
    gen_field_write!(set_timestamp, InfoFieldLayout::TIMESTAMP_RNG, u32);
}
impl Debug for InfoFieldView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardPathInfoFieldView")
            .field("flags", &self.flags())
            .field("segment_id", &self.segment_id())
            .field("timestamp", &self.timestamp())
            .finish()
    }
}

/// A view over a standard SCION path hop field
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct HopFieldView([u8; HopFieldLayout::SIZE_BYTES]);
impl View for HopFieldView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        if buf.len() < HopFieldLayout::SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "HopFieldView",
                required: HopFieldLayout::SIZE_BYTES,
                actual: buf.len(),
            });
        }

        Ok(HopFieldLayout::SIZE_BYTES)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        let sized: &[u8; HopFieldLayout::SIZE_BYTES] = unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        let sized: &mut [u8; HopFieldLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        let sized: Box<[u8; HopFieldLayout::SIZE_BYTES]> =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8; N]
        let sized: Box<[u8; HopFieldLayout::SIZE_BYTES]> = unsafe { transmute(self) };
        sized
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
// Immutable
impl HopFieldView {
    /// Returns the flags of the hop field
    #[inline]
    pub fn flags(&self) -> HopFieldFlags {
        // SAFETY: buffer size is checked on construction
        let value =
            unsafe { unchecked_bit_range_be_read::<u8>(&self.0, HopFieldLayout::FLAGS_RNG) };
        HopFieldFlags::from_bits_retain(value)
    }

    gen_field_read!(exp_time, HopFieldLayout::EXP_TIME_RNG, u8);
    gen_field_read!(cons_ingress, HopFieldLayout::CONS_INGRESS_RNG, u16);
    gen_field_read!(cons_egress, HopFieldLayout::CONS_EGRESS_RNG, u16);

    /// Returns the MAC of the hop field
    #[inline]
    pub fn mac(&self) -> HopFieldMac {
        // SAFETY: buffer size is checked on construction
        let mac: [u8; 6] = unsafe {
            self.0
                .get_unchecked(HopFieldLayout::MAC_RNG.aligned_byte_range())
                .try_into()
                .unwrap_unchecked()
        };

        HopFieldMac(mac)
    }

    /// Returns the ingress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_ingress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_egress` otherwise (reversed segment).
    #[inline]
    pub fn ingress_interface(&self, info_field: &InfoFieldView) -> u16 {
        if info_field.flags().contains(InfoFieldFlags::CONS_DIR) {
            self.cons_ingress()
        } else {
            self.cons_egress()
        }
    }

    /// Returns the egress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_egress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_ingress` otherwise (reversed segment).
    #[inline]
    pub fn egress_interface(&self, info_field: &InfoFieldView) -> u16 {
        if info_field.flags().contains(InfoFieldFlags::CONS_DIR) {
            self.cons_egress()
        } else {
            self.cons_ingress()
        }
    }
}
// Mutable
impl HopFieldView {
    /// Sets the flags of the hop field
    #[inline]
    pub fn set_flags(&mut self, flags: HopFieldFlags) {
        // SAFETY: buffer size is checked on construction
        let value = flags.bits();
        unsafe { unchecked_bit_range_be_write::<u8>(&mut self.0, HopFieldLayout::FLAGS_RNG, value) }
    }

    gen_field_write!(set_exp_time, HopFieldLayout::EXP_TIME_RNG, u8);
    gen_field_write!(set_cons_ingress, HopFieldLayout::CONS_INGRESS_RNG, u16);
    gen_field_write!(set_cons_egress, HopFieldLayout::CONS_EGRESS_RNG, u16);

    /// Sets the MAC of the hop field
    #[inline]
    pub fn set_mac(&mut self, mac: HopFieldMac) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            self.0
                .get_unchecked_mut(HopFieldLayout::MAC_RNG.aligned_byte_range())
                .copy_from_slice(&mac.0);
        }
    }
}
impl Debug for HopFieldView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardPathHopFieldView")
            .field("flags", &self.flags())
            .field("exp_time", &self.exp_time())
            .field("cons_ingress", &self.cons_ingress())
            .field("cons_egress", &self.cons_egress())
            .field("mac", &self.mac())
            .finish()
    }
}
/// Provides the necessary input for calculating the MAC of a hop field.
/// Automatically implements [`HopMacCalculate`](crate::path::standard::mac::HopMacCalculate)
impl HopMacInputSource for HopFieldView {
    #[inline]
    fn get_mac_input(&self) -> HopMacInput {
        HopMacInput {
            exp_time: self.exp_time(),
            cons_ingress: self.cons_ingress(),
            cons_egress: self.cons_egress(),
        }
    }
}
