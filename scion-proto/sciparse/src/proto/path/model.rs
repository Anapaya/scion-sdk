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

//! SCION path header model and encoding

use crate::{
    core::encode::{InvalidStructureError, WireEncode},
    path::{
        layout::ScionHeaderPathLayout, onehop::model::OneHopPath, standard::model::StandardPath,
        types::PathType, view::ScionPathView,
    },
};

/// Represents a SCION path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum Path {
    /// Standard SCION path
    Standard(StandardPath),
    /// One-hop SCION path
    OneHop(OneHopPath),
    /// Empty path
    Empty,
    /// Unsupported path type with raw data
    Unsupported {
        /// The type of the unsupported path
        path_type: PathType,
        /// Raw path data
        data: Vec<u8>,
    },
}
impl Path {
    /// Constructs a `Path` from a `ScionPathView`
    pub fn from_view(view: &ScionPathView) -> Self {
        match *view {
            ScionPathView::Standard(standard_view) => {
                Path::Standard(StandardPath::from_view(standard_view))
            }
            ScionPathView::OneHop(onehop_view) => Path::OneHop(OneHopPath::from_view(onehop_view)),
            ScionPathView::Empty => Path::Empty,
            ScionPathView::Unsupported {
                path_type,
                data: buf,
            } => {
                Path::Unsupported {
                    path_type,
                    data: buf.to_vec(),
                }
            }
        }
    }
}
impl Path {
    /// Returns the type of the path
    pub fn path_type(&self) -> PathType {
        match self {
            Path::Standard(_) => PathType::Scion,
            Path::OneHop(_) => PathType::OneHop,
            Path::Empty => PathType::Empty,
            Path::Unsupported { path_type, .. } => PathType::Other((*path_type).into()),
        }
    }

    /// Returns a reference to the standard path if it is of that type
    pub fn standard(&self) -> Option<&StandardPath> {
        match self {
            Path::Standard(path) => Some(path),
            _ => None,
        }
    }
}

impl WireEncode for Path {
    fn required_size(&self) -> usize {
        match self {
            Path::Standard(path) => path.required_size(),
            Path::OneHop(path) => path.required_size(),
            Path::Unsupported { data, .. } => data.len(),
            Path::Empty => 0,
        }
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        if self.required_size() > ScionHeaderPathLayout::MAX_SIZE_BYTES {
            return Err("Path size exceeds maximum encodable size (984 bytes)".into());
        }

        match self {
            Self::Standard(standard_path) => standard_path.wire_valid()?,
            Self::OneHop(onehop_path) => onehop_path.wire_valid()?,
            Self::Empty => {}
            Self::Unsupported { path_type: _, data } => {
                if !data.len().is_multiple_of(4) {
                    return Err("Path data must be a multiple of 4 bytes".into());
                }
            }
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        match self {
            Path::Standard(path) => unsafe { path.encode_unchecked(buf) },
            Path::OneHop(path) => unsafe { path.encode_unchecked(buf) },
            Path::Empty => 0,
            Path::Unsupported { data, .. } => {
                let len = data.len();

                unsafe {
                    buf.get_unchecked_mut(..len).copy_from_slice(data);
                }

                len
            }
        }
    }
}

#[cfg(feature = "proptest")]
mod ptest {
    use ::proptest::prelude::*;

    use super::*;
    use crate::path::{model::Path, types::PathType};

    impl Arbitrary for Path {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            let standard_path = any::<StandardPath>();
            let onehop_path = any::<OneHopPath>();

            prop_oneof![
                8 => standard_path.prop_map(Path::Standard),
                2 => onehop_path.prop_map(Path::OneHop),
                1 => Just(Path::Empty),
                // Unrecognized path type
                1 => (
                    any::<PathType>(),
                    ::proptest::collection::vec(any::<u8>(), 0..512)
                )
                    .prop_map(|(path_type, data)| {
                        // Should not be a compatible path type
                        let path_type = match path_type {
                            PathType::Scion|PathType::OneHop|PathType::Empty => {PathType::Other(123)}
                            PathType::Epic | PathType::Colibri | PathType::Other(_) => path_type,
                        };

                        let data_len = data.len() / 4 * 4; // Truncate to multiple of 4 bytes
                        let data_truncated = &data[..data_len];
                        Path::Unsupported { path_type, data: data_truncated.to_vec() }
                    }),
            ]
            .boxed()
        }
    }
}
