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

use std::mem::transmute;

use crate::{
    core::view::{View, ViewConversionError},
    header::{layout::ScionHeaderLayout, view::ScionHeaderView},
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
