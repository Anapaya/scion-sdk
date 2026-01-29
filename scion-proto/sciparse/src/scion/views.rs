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

//! Views are zero-copy representations of SCION packet headers over byte buffers.
//!
//! Fields can be read directly from given byte buffers without copying data.
//!
//! Minimal modifications are possible via mutable views. However, more complex modifications on
//! dynamic fields (e.g., addresses, path segments) are not supported.
//!
//! For creating or manipulating SCION packet headers programmatically, prefer using the loaded
//! structures.

// TODO: Max header lenght is 1020 bytes (255 * 4), so we should be able to use [u8; 1020] as a safe
// construction buffer without checks. Need to check that no view would ever try to go beyond
// that size first.

/// Implementation Note:
///
/// All views are #[repr(transparent)] wrappers around [u8] (or [u8; fixed_size]).
///
/// This allows interpreting byte slices as views via transmutations:
///  - &[u8] == &View
///  - &mut [u8] == &mut View
///  - Box<[u8]> == Box<View>
///
/// Mutability and ownership is fully handled by Rust's built-in types.
///
/// Safety:
/// - The transmutations are safe since the target types are #[repr(transparent)] over [u8] or
///   [u8; fixed_size].
/// - When using the safe from_x functions to create a view from a buffer, it is checked that
///   the buffer is at least as large as required by the view.
///
/// Limitations:
/// - We can not have any data inside the view structs, since that would break the
///   #[repr(transparent)] attribute.
/// - Therefore we need to combine Header which depend on each other into a single view. E.g.
///   CommonHeader + AddressHeader
use std::{fmt::Debug, mem::transmute, ops::Range};

use crate::{
    helper::{read::unchecked_bit_range_be_read, write::unchecked_bit_range_be_write},
    layout::{
        AddressHeaderLayout, CommonHeaderLayout, HopFieldLayout, InfoFieldLayout, Layout,
        LayoutParseError, ScionHeaderLayout, StdPathDataLayout, StdPathLayout, StdPathMetaLayout,
    },
    types::{
        address::{Asn, HostAddressSizeError, Isd, ScionHostAddr, ScionHostAddrType},
        path::{HopFieldFlags, HopFieldMac, InfoFieldFlags, PathType},
    },
    views::macros::{gen_field_read, gen_field_write, gen_unsafe_field_write},
};

/// A view over a complete SCION packet
#[repr(transparent)]
pub struct ScionPacketView([u8]);
impl View for ScionPacketView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let layout = ScionHeaderLayout::from_slice(buf)?;

        let packet_len = layout.header_len + layout.payload_len;

        if buf.len() < packet_len {
            return Err(ViewConversionError::BufferTooSmall {
                at: "Payload",
                required: packet_len,
                actual: buf.len(),
            });
        }

        Ok(packet_len)
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
impl ScionPacketView {
    /// Returns a view over the SCION headers
    #[inline]
    pub fn header(&self) -> &ScionHeaderView {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.0).header_len() as usize;
            ScionHeaderView::from_slice_unchecked(self.0.get_unchecked(..header_len))
        }
    }

    /// Returns a mutable view over the SCION headers
    #[inline]
    pub fn header_mut(&mut self) -> &mut ScionHeaderView {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.0).header_len() as usize;
            ScionHeaderView::from_mut_slice_unchecked(self.0.get_unchecked_mut(..header_len))
        }
    }

    /// Returns a slice of the payload
    #[inline]
    pub fn payload(&self) -> &[u8] {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.0).header_len() as usize;
            self.0.get_unchecked(header_len..)
        }
    }

    /// Returns a mutable slice of the payload
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.0).header_len() as usize;
            self.0.get_unchecked_mut(header_len..)
        }
    }
}

/// A view over the SCION headers
///
/// Combines CommonHeader, AddressHeader and PathHeader
#[repr(transparent)]
pub struct ScionHeaderView([u8]);
impl View for ScionHeaderView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let layout = ScionHeaderLayout::from_slice(buf)?;

        // Layout validation already ensures that the buffer is large enough
        // this is just a sanity check
        debug_assert!(buf.len() >= layout.size_bytes());

        Ok(layout.size_bytes())
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: See View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: See View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: See View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
// Common header
impl ScionHeaderView {
    // Field readers
    gen_field_read!(version, CommonHeaderLayout::VERSION_RNG, u8);
    gen_field_read!(traffic_class, CommonHeaderLayout::TRAFFIC_CLASS_RNG, u8);
    gen_field_read!(flow_id, CommonHeaderLayout::FLOW_ID_RNG, u32);
    gen_field_read!(next_header, CommonHeaderLayout::NEXT_HEADER_RNG, u8);
    gen_field_read!(payload_len, CommonHeaderLayout::PAYLOAD_LEN_RNG, u16);

    /// Returns the header length in bytes
    #[inline]
    pub fn header_len(&self) -> u16 {
        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_read::<u8>(&self.0, CommonHeaderLayout::HEADER_LEN_RNG) as u16
                * 4
        }
    }

    /// Returns the path type
    #[inline]
    pub fn path_type(&self) -> PathType {
        // SAFETY: buffer size is checked on construction
        unsafe { unchecked_bit_range_be_read::<u8>(&self.0, CommonHeaderLayout::PATH_TYPE_RNG) }
            .into()
    }

    /// Returns the destination address type
    #[inline]
    pub fn dst_addr_type(&self) -> ScionHostAddrType {
        // SAFETY: buffer size is checked on construction
        unsafe { unchecked_bit_range_be_read::<u8>(&self.0, CommonHeaderLayout::DST_ADDR_INFO_RNG) }
            .into()
    }

    /// Returns the source address type
    #[inline]
    pub fn src_addr_type(&self) -> ScionHostAddrType {
        // SAFETY: buffer size is checked on construction
        unsafe { unchecked_bit_range_be_read::<u8>(&self.0, CommonHeaderLayout::SRC_ADDR_INFO_RNG) }
            .into()
    }
}
// Mut Common header
impl ScionHeaderView {
    // Field writers
    gen_field_write!(set_version, CommonHeaderLayout::VERSION_RNG, u8);
    gen_field_write!(set_traffic_class, CommonHeaderLayout::TRAFFIC_CLASS_RNG, u8);
    gen_field_write!(set_flow_id, CommonHeaderLayout::FLOW_ID_RNG, u32);
    gen_field_write!(set_next_header, CommonHeaderLayout::NEXT_HEADER_RNG, u8);
    gen_unsafe_field_write!(set_payload_len, CommonHeaderLayout::PAYLOAD_LEN_RNG, u16);

    /// Sets the header length in bytes.
    ///
    /// The length must be a multiple of 4, and at most 255 * 4 = 1020 bytes.
    ///
    /// # Safety
    /// Modifying the header length can lead to undefined behavior on subsequent accesses to the
    /// View. If the new length surpasses the actual buffer size, out-of-bounds accesses can occur.
    #[inline]
    pub unsafe fn set_header_len(&mut self, len: u16) {
        debug_assert!(
            len.is_multiple_of(4),
            "Header length must be a multiple of 4"
        );
        debug_assert!(len <= 255 * 4, "Header length must be at most 1020 bytes");

        let raw_len = (len / 4) as u8;

        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                &mut self.0,
                CommonHeaderLayout::HEADER_LEN_RNG,
                raw_len,
            )
        }
    }

    /// Sets the path type
    ///
    /// # Safety
    /// Modifying the path type can lead to undefined behavior on subsequent accesses to the
    /// View. If the required size for the new path type surpasses the actual buffer size,
    /// out-of-bounds accesses can occur.
    #[inline]
    pub unsafe fn set_path_type(&mut self, path_type: PathType) {
        let raw_path_type: u8 = path_type.into();

        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                &mut self.0,
                CommonHeaderLayout::PATH_TYPE_RNG,
                raw_path_type,
            )
        }
    }

    /// Sets the destination address type
    ///
    /// This function does not modify the actual address data.
    /// If a different address type should be used, prefer using a loaded packet instead of a view.
    ///
    /// # Safety
    /// This field is changes the size requirements of the header. The caller has to ensure
    /// that the buffer is large enough to accommodate the new address size. If the new size
    /// surpasses the actual buffer size, out-of-bounds accesses can occur on subsequent accesses to
    /// the View.
    #[inline]
    pub unsafe fn set_dst_addr_type(&mut self, addr_type: ScionHostAddrType) {
        let addr_info: u8 = addr_type.into();

        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                &mut self.0,
                CommonHeaderLayout::DST_ADDR_INFO_RNG,
                addr_info,
            )
        }
    }

    /// Sets the source address type
    ///
    /// This function does not modify the actual address data.
    /// If a different address type should be used, prefer using a loaded packet instead of a view.
    ///
    /// # Safety
    /// This field is changes the size requirements of the header. The caller has to ensure
    /// that the buffer is large enough to accommodate the new address size. If the new size
    /// surpasses the actual buffer size, out-of-bounds accesses can occur on subsequent accesses to
    /// the View.
    #[inline]
    pub unsafe fn set_src_addr_type(&mut self, addr_type: ScionHostAddrType) {
        let addr_info: u8 = addr_type.into();

        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write::<u8>(
                &mut self.0,
                CommonHeaderLayout::SRC_ADDR_INFO_RNG,
                addr_info,
            )
        }
    }
}
// Address header
impl ScionHeaderView {
    /// Returns the destination ISD
    pub fn dst_isd(&self) -> Isd {
        // SAFETY: buffer size is checked on construction
        let val = unsafe {
            unchecked_bit_range_be_read::<u16>(
                &self.0,
                AddressHeaderLayout::DST_ISD_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
            )
        };

        Isd(val)
    }

    /// Returns the destination ASN
    pub fn dst_as(&self) -> Asn {
        // SAFETY: buffer size is checked on construction
        let val = unsafe {
            unchecked_bit_range_be_read::<u64>(
                &self.0,
                AddressHeaderLayout::DST_AS_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
            )
        };

        Asn(val)
    }

    /// Returns the source ISD
    pub fn src_isd(&self) -> Isd {
        // SAFETY: buffer size is checked on construction
        let val = unsafe {
            unchecked_bit_range_be_read::<u16>(
                &self.0,
                AddressHeaderLayout::SRC_ISD_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
            )
        };

        Isd(val)
    }

    /// Returns the source ASN
    pub fn src_as(&self) -> Asn {
        // SAFETY: buffer size is checked on construction
        let val = unsafe {
            unchecked_bit_range_be_read::<u64>(
                &self.0,
                AddressHeaderLayout::SRC_AS_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
            )
        };

        Asn(val)
    }

    /// Attempts to return the destination host address
    ///
    /// If the address type and length do not match, an error is returned.
    #[inline]
    pub fn dst_host_addr(&self) -> Result<ScionHostAddr, HostAddressSizeError> {
        let src_len = self.src_addr_type().size();
        let dst_len = self.dst_addr_type().size();
        let range = AddressHeaderLayout::new(src_len, dst_len)
            .dst_host_addr_range()
            .shift(CommonHeaderLayout::SIZE_BYTES);

        // SAFETY: buffer size is checked on construction
        let raw = unsafe { self.0.get_unchecked(range.aligned_byte_range()) };

        ScionHostAddr::from_parts(self.dst_addr_type(), raw)
    }

    /// Attempts to return the destination host address
    ///
    /// If the address type and length do not match, an error is returned.
    #[inline]
    pub fn src_host_addr(&self) -> Result<ScionHostAddr, HostAddressSizeError> {
        let src_len = self.src_addr_type().size();
        let dst_len = self.dst_addr_type().size();
        let range = AddressHeaderLayout::new(src_len, dst_len)
            .src_host_addr_range()
            .shift(CommonHeaderLayout::SIZE_BYTES);

        // SAFETY: buffer size is checked on construction
        let raw = unsafe { self.0.get_unchecked(range.aligned_byte_range()) };

        ScionHostAddr::from_parts(self.src_addr_type(), raw)
    }
}
// Address header mut
impl ScionHeaderView {
    /// Sets the source ISD
    pub fn set_src_isd(&mut self, isd: Isd) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write(
                &mut self.0,
                AddressHeaderLayout::SRC_ISD_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
                isd.0,
            )
        }
    }

    /// Sets the source ASN
    pub fn set_src_as(&mut self, asn: Asn) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write(
                &mut self.0,
                AddressHeaderLayout::SRC_AS_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
                asn.0,
            )
        }
    }

    /// Sets the destination ISD
    pub fn set_dst_isd(&mut self, isd: Isd) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write(
                &mut self.0,
                AddressHeaderLayout::DST_ISD_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
                isd.0,
            )
        }
    }

    /// Sets the destination ASN
    pub fn set_dst_as(&mut self, asn: Asn) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            unchecked_bit_range_be_write(
                &mut self.0,
                AddressHeaderLayout::DST_AS_RNG.shift(CommonHeaderLayout::SIZE_BYTES),
                asn.0,
            )
        }
    }

    // Impl Note: no functions to set dst_host_addr and src_host_addr, as both are variable-length
    // and would require shifting the rest of the buffer.
}
// Path header
impl ScionHeaderView {
    /// Returns a view over the path
    #[inline]
    pub fn path(&self) -> ScionPathView<'_> {
        let path_offset = CommonHeaderLayout::SIZE_BYTES
            + AddressHeaderLayout::new(self.dst_addr_type().size(), self.src_addr_type().size())
                .size_bytes();

        let len = self.header_len() as usize;

        match self.path_type() {
            PathType::Empty => ScionPathView::Empty,
            PathType::Scion => {
                // SAFETY: buffer size is checked on construction
                let path_buf = unsafe { self.0.get_unchecked(path_offset..len) };
                let path = unsafe { StandardPathView::from_slice_unchecked(path_buf) };

                ScionPathView::Standard(path)
            }
            pt => {
                // SAFETY: buffer size is checked on construction
                let path_buf = unsafe { self.0.get_unchecked(path_offset..len) };
                ScionPathView::Unsupported {
                    path_type: pt,
                    data: path_buf,
                }
            }
        }
    }

    /// Returns a mutable view over the path
    #[inline]
    pub fn path_mut(&mut self) -> ScionPathViewMut<'_> {
        let path_offset = CommonHeaderLayout::SIZE_BYTES
            + AddressHeaderLayout::new(self.dst_addr_type().size(), self.src_addr_type().size())
                .size_bytes();

        let len = self.header_len() as usize;

        match self.path_type() {
            PathType::Empty => ScionPathViewMut::Empty,
            PathType::Scion => {
                // SAFETY: size is checked on construction of ScionHeaderView
                let path_buf = unsafe { self.0.get_unchecked_mut(path_offset..len) };
                let path = unsafe { StandardPathView::from_mut_slice_unchecked(path_buf) };

                ScionPathViewMut::Standard(path)
            }
            pt => {
                // SAFETY: size is checked on construction of ScionHeaderView
                let path_buf = unsafe { self.0.get_unchecked_mut(path_offset..len) };
                ScionPathViewMut::Unsupported {
                    path_type: pt,
                    buf: path_buf,
                }
            }
        }
    }
}
impl Debug for ScionHeaderView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path();
        f.debug_struct("ScionHeaderView")
            .field("version", &self.version())
            .field("traffic_class", &self.traffic_class())
            .field("flow_id", &self.flow_id())
            .field("next_header", &self.next_header())
            .field("payload_len", &self.payload_len())
            .field("header_len", &self.header_len())
            .field("path_type", &self.path_type())
            .field("dst_addr_type", &self.dst_addr_type())
            .field("src_addr_type", &self.src_addr_type())
            .field("dst_isd", &self.dst_isd())
            .field("dst_as", &self.dst_as())
            .field("src_isd", &self.src_isd())
            .field("src_as", &self.src_as())
            .field("dst_host_addr", &self.dst_host_addr())
            .field("src_host_addr", &self.src_host_addr())
            .field("path", &path)
            .finish()
    }
}

/// View over different path types
#[derive(Debug)]
pub enum ScionPathView<'a> {
    /// View over a standard SCION path
    Standard(&'a StandardPathView),
    /// View over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        data: &'a [u8],
    },
    /// Empty path type
    Empty,
}

/// Mutable view over different path types
#[derive(Debug)]
pub enum ScionPathViewMut<'a> {
    /// Mutable view over a standard SCION path
    Standard(&'a mut StandardPathView),
    /// Mutable view over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        buf: &'a mut [u8],
    },
    /// Empty path type
    Empty,
}

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

/// Errors that can occur during view conversion
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq, Hash)]
pub enum ViewConversionError {
    /// Buffer is too small for the view
    #[error("Buffer too small at {at}: required {required}, got {actual}")]
    BufferTooSmall {
        /// Location where the error occurred
        at: &'static str,
        /// Required size in bytes
        required: usize,
        /// Actual size in bytes
        actual: usize,
    },
    /// Other errors
    #[error("Could not convert view: {0}")]
    Other(&'static str),
}
impl From<LayoutParseError> for ViewConversionError {
    fn from(value: LayoutParseError) -> Self {
        match value {
            LayoutParseError::BufferTooSmall {
                at,
                required,
                actual,
            } => {
                ViewConversionError::BufferTooSmall {
                    at,
                    required,
                    actual,
                }
            }
            LayoutParseError::InvalidHeaderLength { .. } => {
                ViewConversionError::Other("InvalidHeaderLength")
            }
            LayoutParseError::UnsupportedVersion => {
                ViewConversionError::Other("UnsupportedVersion")
            }
        }
    }
}

/// Trait for views over byte buffers
///
/// Views are zero-copy representations of data structures over byte buffers.
/// They provide methods to read fields directly from the buffer without copying data.
///
/// A view must implement methods to check the required size of the buffer
pub trait View {
    /// Asserts that the buffer has the required size for the view.
    /// Returns the range of bytes used by the view in the buffer.
    ///
    /// If the buffer is too small, returns a ViewConversionError.
    ///
    /// # Important
    ///
    /// This function ensures that all view functions are safe to call after it returns Ok.
    /// If this function is incorrectly implemented, it will lead to undefined behavior.
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError>;

    /// Converts a slice into the view
    ///
    /// This function checks that the buffer is at least as large as required by the view.
    #[inline]
    fn from_slice(buf: &[u8]) -> Result<(&Self, &[u8]), ViewConversionError> {
        let size = Self::has_required_size(buf)?;

        debug_assert!(buf.len() >= size);

        // SAFETY: size is checked to be at least the required size
        let (view_buf, rest) = unsafe { buf.split_at_unchecked(size) };
        let view = unsafe { Self::from_slice_unchecked(view_buf) };

        Ok((view, rest))
    }

    /// Converts a mutable slice into the view
    ///
    /// This function checks that the buffer is at least as large as required by the view.
    #[inline]
    fn from_mut_slice(buf: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ViewConversionError> {
        let size = Self::has_required_size(buf)?;

        debug_assert!(buf.len() >= size);

        // SAFETY: size is checked to be at least the required size
        let (view_buf, rest) = unsafe { buf.split_at_mut_unchecked(size) };
        let view = unsafe { Self::from_mut_slice_unchecked(view_buf) };

        Ok((view, rest))
    }

    /// Converts a boxed slice into the view
    ///
    /// This function checks that the buffer is exactly as large as required by the view.
    #[inline]
    fn from_boxed(buf: Box<[u8]>) -> Result<Box<Self>, ViewConversionError> {
        let size = Self::has_required_size(&buf)?;

        if buf.len() != size {
            return Err(ViewConversionError::Other(
                "Boxed buffer size does not match view size",
            ));
        }

        Ok(unsafe { Self::from_boxed_unchecked(buf) })
    }

    /// Returns the underlying byte representation of the view
    fn as_bytes(&self) -> &[u8];

    /// Converts the view into an owned boxed slice
    #[inline]
    fn to_owned(&self) -> Box<Self> {
        unsafe { Self::from_boxed_unchecked(self.as_bytes().to_vec().into_boxed_slice()) }
    }

    /// Converts the slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self;

    /// Converts the mutable slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self;

    /// Converts the boxed slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self>;
}

mod macros {
    /// Macro to generate unaligned field readers - expects self to be a wrapper around [u8]
    ///
    /// - $name: name of the generated function
    /// - $bit_range: bit range of the field
    /// - $repr: representation type of the field
    ///
    /// Repr can be any integer from u8 to u64, u128 can only be read if it is aligned.
    macro_rules! gen_field_read {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Reads the field
            pub fn $name(&self) -> $repr {
                use $crate::helper::read::unchecked_bit_range_be_read;
                unsafe { unchecked_bit_range_be_read::<$repr>(&self.0, $bit_range) }
            }
        };
    }
    pub(super) use gen_field_read;

    /// Macro to generate unaligned field writers - expects self to be a wrapper around [u8]
    ///
    /// - $name: name of the generated function
    /// - $bit_range: bit range of the field
    /// - $repr: representation type of the field
    ///
    /// Repr can be any integer from u8 to u64, u128 can only be written if it is aligned.
    macro_rules! gen_field_write {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Writes the field
            pub fn $name(&mut self, value: $repr) {
                use $crate::helper::write::unchecked_bit_range_be_write;
                unsafe { unchecked_bit_range_be_write::<$repr>(&mut self.0, $bit_range, value) }
            }
        };
    }
    pub(super) use gen_field_write;

    macro_rules! gen_unsafe_field_write {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Writes the field
            ///
            /// Writing to this field is considered unsafe, as editing this field changes the
            /// required size for the view. Accesses after writing to this field may lead to
            /// undefined behavior.
            ///
            /// ## Safety
            ///
            /// The caller must ensure that subsequent accesses to the view are valid, i.e. the
            /// underlying buffer is large enough to hold the view with the new field value.
            pub unsafe fn $name(&mut self, value: $repr) {
                use $crate::helper::write::unchecked_bit_range_be_write;
                unsafe { unchecked_bit_range_be_write::<$repr>(&mut self.0, $bit_range, value) }
            }
        };
    }
    pub(super) use gen_unsafe_field_write;
}
