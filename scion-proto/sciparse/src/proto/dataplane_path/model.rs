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

//! SCION dataplane path model and encoding.

use crate::{
    core::encode::{InvalidStructureError, WireEncode},
    dataplane_path::{
        layout::ScionHeaderPathLayout, onehop::model::OneHopPath, standard::model::StandardPath,
        types::PathType, view::ScionDpPathViewRef,
    },
};

/// Represents a SCION dataplane path.
///
/// The dataplane path is usually supplied by the SCION control plane, contained in a
/// [ScionPath](crate::path::ScionPath) together with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum DpPath {
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
impl DpPath {
    /// Constructs a `DpPath` from a `ScionDpPathView`
    pub fn from_view(view: &ScionDpPathViewRef) -> Self {
        match *view {
            ScionDpPathViewRef::Standard(standard_view) => {
                DpPath::Standard(StandardPath::from_view(standard_view))
            }
            ScionDpPathViewRef::OneHop(onehop_view) => {
                DpPath::OneHop(OneHopPath::from_view(onehop_view))
            }
            ScionDpPathViewRef::Empty => DpPath::Empty,
            ScionDpPathViewRef::Unsupported {
                path_type,
                data: buf,
            } => {
                DpPath::Unsupported {
                    path_type,
                    data: buf.to_vec(),
                }
            }
        }
    }
}
impl DpPath {
    /// Returns the type of the path
    pub fn path_type(&self) -> PathType {
        match self {
            DpPath::Standard(_) => PathType::Scion,
            DpPath::OneHop(_) => PathType::OneHop,
            DpPath::Empty => PathType::Empty,
            DpPath::Unsupported { path_type, .. } => PathType::Other((*path_type).into()),
        }
    }

    /// Returns a reference to the standard path if it is of that type
    pub fn standard(&self) -> Option<&StandardPath> {
        match self {
            DpPath::Standard(path) => Some(path),
            _ => None,
        }
    }
}

impl WireEncode for DpPath {
    fn required_size(&self) -> usize {
        match self {
            DpPath::Standard(path) => path.required_size(),
            DpPath::OneHop(path) => path.required_size(),
            DpPath::Unsupported { data, .. } => data.len(),
            DpPath::Empty => 0,
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
            DpPath::Standard(path) => unsafe { path.encode_unchecked(buf) },
            DpPath::OneHop(path) => unsafe { path.encode_unchecked(buf) },
            DpPath::Empty => 0,
            DpPath::Unsupported { data, .. } => {
                let len = data.len();

                unsafe {
                    buf.get_unchecked_mut(..len).copy_from_slice(data);
                }

                len
            }
        }
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;
    use crate::dataplane_path::{model::DpPath, types::PathType};

    /// Configuration for generating arbitrary [`DpPath`] values.
    ///
    /// Controls the relative probability of each path variant being generated,
    /// and allows passing sub-parameters to the generators for specific path types.
    ///
    /// Default weights: `standard = 8, one_hop = 2, empty = 1, unsupported = 1`.
    #[derive(Debug, Clone)]
    pub struct ArbitraryPathParams {
        /// Weight for generating standard SCION paths.
        pub standard: u32,
        /// Weight for generating one-hop paths.
        pub one_hop: u32,
        /// Weight for generating empty paths.
        pub empty: u32,
        /// Weight for generating unsupported path types.
        pub unsupported: u32,
        /// Parameters for generating standard paths.
        pub standard_params: <StandardPath as Arbitrary>::Parameters,
        /// Parameters for generating one-hop paths.
        pub one_hop_params: <OneHopPath as Arbitrary>::Parameters,
    }
    impl Default for ArbitraryPathParams {
        fn default() -> Self {
            Self {
                standard: 8,
                one_hop: 2,
                empty: 1,
                unsupported: 1,
                standard_params: Default::default(),
                one_hop_params: Default::default(),
            }
        }
    }

    impl Arbitrary for DpPath {
        type Parameters = ArbitraryPathParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                params.standard => StandardPath::arbitrary_with(params.standard_params)
                    .prop_map(DpPath::Standard),
                params.one_hop => OneHopPath::arbitrary_with(params.one_hop_params)
                    .prop_map(DpPath::OneHop),
                params.empty => Just(DpPath::Empty),
                params.unsupported => (
                    any::<PathType>(),
                    ::proptest::collection::vec(any::<u8>(), 0..512),
                )
                    .prop_map(|(path_type, data)| {
                        // Should not be a compatible path type
                        let path_type = match path_type {
                            PathType::Scion|PathType::OneHop|PathType::Empty => {PathType::Other(123)}
                            PathType::Epic | PathType::Colibri | PathType::Other(_) => path_type,
                        };

                        let data_len = data.len() / 4 * 4; // Truncate to multiple of 4 bytes
                        let data_truncated = &data[..data_len];
                        DpPath::Unsupported {
                            path_type,
                            data: data_truncated.to_vec(),
                        }
                    }),
            ]
            .boxed()
        }
    }
}
