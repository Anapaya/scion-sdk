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

//! SCION header views
//!
//! See [`View`](crate::core::view) for more information about views in general.

// TODO: Max header lenght is 1020 bytes (255 * 4), so we should be able to use [u8; 1020] as a safe
// construction buffer without checks. Need to check that no view would ever try to go beyond
// that size first.

use std::{fmt::Debug, mem::transmute};

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
    header::layout::{AddressHeaderLayout, CommonHeaderLayout, ScionHeaderLayout},
    path::standard::{types::PathType, view::StandardPathView},
    types::address::{Asn, HostAddressSizeError, Isd, ScionHostAddr, ScionHostAddrType},
};

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
