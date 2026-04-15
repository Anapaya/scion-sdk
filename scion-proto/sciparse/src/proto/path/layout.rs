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

//! SCION protocol header layout calculations
//!
//! See [`Layout`](crate::core::layout) for more information about layouts in general.

use crate::{
    core::{
        debug::Annotations,
        layout::{BitRange, Layout},
    },
    header::layout::{AddressHeaderLayout, CommonHeaderLayout, ScionHeaderLayout},
    path::{
        onehop::layout::OneHopPathLayout,
        standard::layout::{StdPathDataLayout, StdPathMetaLayout},
        types::PathType,
    },
};

/// Layout for the SCION path header
pub enum ScionHeaderPathLayout {
    /// Layout for the standard SCION path
    Standard(StdPathMetaLayout, StdPathDataLayout),
    /// Layout for a one-hop path
    OneHop(OneHopPathLayout),
    /// Layout for an empty path
    Empty,
    /// Layout for an unknown path type
    Unknown {
        /// The type of the unknown path
        path_type: PathType,
        /// The bit range of the unknown path
        range: BitRange,
    },
}
impl ScionHeaderPathLayout {
    /// Maximum size of a encodeable SCION path in bytes.
    pub const MAX_SIZE_BYTES: usize = ScionHeaderLayout::MAX_SIZE_BYTES
        - CommonHeaderLayout::SIZE_BYTES
        - AddressHeaderLayout::MIN_SIZE_BYTES;

    /// Returns the path type of the layout
    #[inline]
    pub const fn path_type(&self) -> PathType {
        match self {
            ScionHeaderPathLayout::Standard(..) => PathType::Scion,
            ScionHeaderPathLayout::OneHop(_) => PathType::OneHop,
            ScionHeaderPathLayout::Empty => PathType::Empty,
            ScionHeaderPathLayout::Unknown { path_type, .. } => *path_type,
        }
    }

    /// Returns annotations for the path header fields
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();
        match self {
            ScionHeaderPathLayout::Standard(meta_layout, data_layout) => {
                annotations.extend(meta_layout.annotations());
                annotations.extend(data_layout.annotations());
            }
            ScionHeaderPathLayout::OneHop(layout) => {
                annotations.extend(layout.annotations());
            }
            ScionHeaderPathLayout::Empty => {}
            ScionHeaderPathLayout::Unknown { range, .. } => {
                annotations.add("Unknown Path".to_string(), vec![(*range, "unknown")])
            }
        };

        annotations
    }
}
impl Layout for ScionHeaderPathLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        match self {
            ScionHeaderPathLayout::Standard(meta, data_layout) => {
                meta.size_bytes() + data_layout.size_bytes()
            }
            ScionHeaderPathLayout::OneHop(onehop_layout) => onehop_layout.size_bytes(),
            ScionHeaderPathLayout::Empty => 0,
            ScionHeaderPathLayout::Unknown { range, .. } => range.size_bytes(),
        }
    }
}
impl From<StdPathDataLayout> for ScionHeaderPathLayout {
    fn from(data_layout: StdPathDataLayout) -> Self {
        ScionHeaderPathLayout::Standard(StdPathMetaLayout, data_layout)
    }
}
