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

//! Layout for one-hop paths between neighboring border routers in SCION.

use crate::{
    core::{
        debug::Annotations,
        layout::{Layout, macros::gen_bitrange_const},
        view::ViewConversionError,
    },
    path::standard::layout::{HopFieldLayout, InfoFieldLayout},
};

/// Layout for a one-hop path between neighboring border routers in SCION.
pub struct OneHopPathLayout;
impl OneHopPathLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Total size of a one-hop path in bytes
    pub const SIZE_BYTES: usize = InfoFieldLayout::SIZE_BYTES + 2 * HopFieldLayout::SIZE_BYTES;

    gen_bitrange_const!(INFO_FIELD, 0, InfoFieldLayout::SIZE_BYTES * 8);
    gen_bitrange_const!(
        HOP_FIELD_1,
        Self::INFO_FIELD.end,
        HopFieldLayout::SIZE_BYTES * 8
    );
    gen_bitrange_const!(
        HOP_FIELD_2,
        Self::HOP_FIELD_1.end,
        HopFieldLayout::SIZE_BYTES * 8
    );
    gen_bitrange_const!(TOTAL, 0, Self::SIZE_BYTES * 8);
}
impl OneHopPathLayout {
    /// Returns an array of all field layouts in the one-hop path layout.
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();
        annotations.extend(InfoFieldLayout.annotations());
        annotations.extend(HopFieldLayout.annotations());
        annotations.extend(HopFieldLayout.annotations());
        annotations
    }
}
impl Layout for OneHopPathLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}
impl TryFrom<&[u8]> for OneHopPathLayout {
    type Error = ViewConversionError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < Self::SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "OneHopPath",
                required: Self::SIZE_BYTES,
                actual: buf.len(),
            });
        }

        Ok(Self)
    }
}
