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

//! View for one-hop paths between neighboring border routers in SCION.

use std::{fmt::Debug, mem::transmute};

use crate::{
    core::view::{View, ViewConversionError},
    path::{
        onehop::layout::OneHopPathLayout,
        standard::view::{HopFieldView, InfoFieldView},
    },
};

/// View for a one-hop path between neighboring border routers in SCION.
#[repr(transparent)]
pub struct OneHopPathView([u8; OneHopPathLayout::SIZE_BYTES]);
impl OneHopPathView {
    /// Returns a reference to the info field
    #[inline]
    pub fn info_field(&self) -> &InfoFieldView {
        unsafe {
            InfoFieldView::from_slice_unchecked(
                &self.0[OneHopPathLayout::INFO_FIELD.aligned_byte_range()],
            )
        }
    }

    /// Returns a mutable reference to the info field
    #[inline]
    pub fn info_field_mut(&mut self) -> &mut InfoFieldView {
        unsafe {
            InfoFieldView::from_mut_slice_unchecked(
                &mut self.0[OneHopPathLayout::INFO_FIELD.aligned_byte_range()],
            )
        }
    }

    /// Returns a reference to the hop fields
    #[inline]
    pub fn hop_fields(&self) -> [&HopFieldView; 2] {
        unsafe {
            [
                HopFieldView::from_slice_unchecked(
                    &self.0[OneHopPathLayout::HOP_FIELD_1.aligned_byte_range()],
                ),
                HopFieldView::from_slice_unchecked(
                    &self.0[OneHopPathLayout::HOP_FIELD_2.aligned_byte_range()],
                ),
            ]
        }
    }

    /// Returns a mutable reference to the hop fields
    #[inline]
    pub fn mut_hop_fields(&mut self) -> [&mut HopFieldView; 2] {
        unsafe {
            let [hop1, hop2] = self.0.get_disjoint_unchecked_mut([
                OneHopPathLayout::HOP_FIELD_1.aligned_byte_range(),
                OneHopPathLayout::HOP_FIELD_2.aligned_byte_range(),
            ]);

            [
                HopFieldView::from_mut_slice_unchecked(hop1),
                HopFieldView::from_mut_slice_unchecked(hop2),
            ]
        }
    }
}
impl Debug for OneHopPathView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneHopPathView")
            .field("info_field", &self.info_field())
            .field("hop_fields", &self.hop_fields())
            .finish()
    }
}
impl View for OneHopPathView {
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        use crate::core::layout::Layout;
        let layout = OneHopPathLayout::try_from(buf)?;
        Ok(layout.size_bytes())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        let sized: &[u8; OneHopPathLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        let sized: &mut [u8; OneHopPathLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        let sized: Box<[u8; OneHopPathLayout::SIZE_BYTES]> =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }
}
