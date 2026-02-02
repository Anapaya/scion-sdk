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
        layout::Layout,
        read::unchecked_bit_range_be_read,
        view::{
            View, ViewConversionError,
            macros::{gen_field_read, gen_field_write, gen_unsafe_field_write},
        },
        write::unchecked_bit_range_be_write,
    },
    path::standard::{
        layout::{
            HopFieldLayout, InfoFieldLayout, StdPathDataLayout, StdPathLayout, StdPathMetaLayout,
        },
        types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
    },
};

/// A view over a standard SCION path, including meta header and data
#[repr(transparent)]
pub struct StandardPathView([u8]);
impl View for StandardPathView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let layout = StdPathLayout::from_slice(buf).map_err(ViewConversionError::from)?;

        // Layout validation should already ensure that the buffer is large enough
        // this is just a sanity check
        debug_assert!(buf.len() >= layout.size_bytes());

        Ok(layout.size_bytes())
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
// Meta header
impl StandardPathView {
    gen_field_read!(curr_info_field, StdPathMetaLayout::CURR_INFO_FIELD_RNG, u8);
    gen_field_read!(curr_hop_field, StdPathMetaLayout::CURR_HOP_FIELD_RNG, u8);
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
}
impl Debug for StandardPathView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hop_fields = self.hop_fields();
        let info_fields = self.info_fields();
        f.debug_struct("StandardPathMetaHeaderView")
            .field("current_info_field", &self.curr_info_field())
            .field("curr_hop_field", &self.curr_hop_field())
            .field("seg0_len", &self.seg0_len())
            .field("seg1_len", &self.seg1_len())
            .field("seg2_len", &self.seg2_len())
            .field("info_fields", &info_fields)
            .field("hop_fields", &hop_fields)
            .finish()
    }
}

/// A view over a standard SCION path info field
#[repr(transparent)]
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
    gen_field_read!(timestamp, InfoFieldLayout::TIMESTAMP_RNG, u32);
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
