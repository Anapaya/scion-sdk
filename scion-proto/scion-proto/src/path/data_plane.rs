// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
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

//! Types and functions for SCION data plane paths.

use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes};

use super::encoded::EncodedStandardPath;
use crate::{
    packet::{DecodeError, InadequateBufferSize},
    utils::encoded_type,
    wire_encoding::{WireDecode, WireDecodeWithContext, WireEncode},
};

encoded_type!(
    /// SCION path types that may be encountered in a packet.
    pub enum PathType(u8){
        /// The empty path type.
        Empty = 0,
        /// The standard SCION path type.
        Scion = 1,
        /// One-hop paths between neighboring border routers.
        OneHop = 2,
        /// Experimental Epic path type.
        Epic = 3,
        /// Experimental Colibri path type.
        Colibri = 4;
        /// Other, unrecognized path types.
        Other = _,
    }
);

/// Error returned when performing operations on a path of currently unsupported [`PathType`].
#[derive(Debug, thiserror::Error)]
#[error("unsupported path type {0}")]
pub struct UnsupportedPathType(pub u8);

/// Data plane path found in a SCION packet.
#[derive(Debug, Clone)]
pub enum DataPlanePath<T = Bytes> {
    /// The empty path type, used for intra-AS hops.
    EmptyPath,
    /// The standard SCION path header.
    Standard(EncodedStandardPath<T>),
    /// The raw bytes of an unsupported path header type.
    Unsupported {
        /// The path's type.
        path_type: PathType,
        /// The raw encoded path.
        bytes: T,
    },
}

impl<T> DataPlanePath<T> {
    /// The maximum length of a SCION data plane path.
    ///
    /// Computed from the max header length (1020) minus the common header length (12)
    /// and the minimum SCION address header length (24).
    pub const MAX_LEN: usize = 984;

    /// Returns the path's type.
    pub fn path_type(&self) -> PathType {
        match self {
            Self::EmptyPath => PathType::Empty,
            Self::Standard(_) => PathType::Scion,
            Self::Unsupported { path_type, .. } => *path_type,
        }
    }

    /// Returns true iff the path is a [`DataPlanePath::EmptyPath`].
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::EmptyPath)
    }
}

impl<T> DataPlanePath<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns the raw binary of the path.
    pub fn raw(&self) -> &[u8] {
        match self {
            DataPlanePath::EmptyPath => &[],
            DataPlanePath::Standard(path) => path.raw(),
            DataPlanePath::Unsupported { bytes, .. } => bytes.deref(),
        }
    }

    /// Creates a new [DataPlanePath] by copying this one into the provided backing buffer.
    ///
    /// # Panics
    ///
    /// For non-empty paths, this panics if the provided buffer does not have the same
    /// length as self.raw().
    pub fn copy_to_slice<'b>(&self, buffer: &'b mut [u8]) -> DataPlanePath<&'b mut [u8]> {
        match self {
            DataPlanePath::EmptyPath => DataPlanePath::EmptyPath,
            DataPlanePath::Standard(path) => DataPlanePath::Standard(path.copy_to_slice(buffer)),
            DataPlanePath::Unsupported { path_type, bytes } => {
                buffer.copy_from_slice(bytes);
                DataPlanePath::Unsupported {
                    path_type: *path_type,
                    bytes: buffer,
                }
            }
        }
    }

    /// Reverse the path to the provided slice.
    ///
    /// Unsupported path types are copied to the slice, as is.
    pub fn reverse_to_slice<'b>(&self, buffer: &'b mut [u8]) -> DataPlanePath<&'b mut [u8]> {
        match self {
            DataPlanePath::EmptyPath => DataPlanePath::EmptyPath,
            DataPlanePath::Standard(path) => DataPlanePath::Standard(path.reverse_to_slice(buffer)),
            DataPlanePath::Unsupported { .. } => self.copy_to_slice(buffer),
        }
    }

    /// Reverses the path.
    pub fn to_reversed(&self) -> Result<DataPlanePath, UnsupportedPathType> {
        match self {
            Self::EmptyPath => Ok(DataPlanePath::EmptyPath),
            Self::Standard(standard_path) => {
                Ok(DataPlanePath::Standard(standard_path.to_reversed()))
            }
            Self::Unsupported { path_type, .. } => Err(UnsupportedPathType(u8::from(*path_type))),
        }
    }
}

impl DataPlanePath<Bytes> {
    /// Returns a deep copy of the object.
    pub fn deep_copy(&self) -> Self {
        match self {
            Self::EmptyPath => Self::EmptyPath,
            Self::Standard(path) => Self::Standard(path.deep_copy()),
            Self::Unsupported { path_type, bytes } => {
                Self::Unsupported {
                    path_type: *path_type,
                    bytes: Bytes::copy_from_slice(bytes),
                }
            }
        }
    }

    /// Reverses the path in place.
    pub fn reverse(&mut self) -> Result<&mut Self, UnsupportedPathType> {
        match self {
            Self::EmptyPath => (),
            Self::Standard(standard_path) => *standard_path = standard_path.to_reversed(),
            Self::Unsupported { path_type, .. } => {
                return Err(UnsupportedPathType(u8::from(*path_type)));
            }
        }
        Ok(self)
    }

    /// Creates a new Path, using the Bytes of the given path as backing storage
    pub fn to_slice_path(&self) -> DataPlanePath<&[u8]> {
        match self {
            DataPlanePath::EmptyPath => DataPlanePath::EmptyPath,
            DataPlanePath::Standard(path) => DataPlanePath::Standard(path.to_slice_path()),
            DataPlanePath::Unsupported { path_type, bytes } => {
                DataPlanePath::Unsupported {
                    path_type: *path_type,
                    bytes: bytes.deref(),
                }
            }
        }
    }
}

impl<T: AsRef<[u8]>> DataPlanePath<T> {
    /// Transforms the data plane path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> DataPlanePath<Bytes> {
        match self {
            DataPlanePath::EmptyPath => DataPlanePath::EmptyPath,
            DataPlanePath::Standard(path) => DataPlanePath::Standard(path.to_bytes_path()),
            DataPlanePath::Unsupported { path_type, bytes } => {
                DataPlanePath::Unsupported {
                    path_type: *path_type,
                    bytes: Bytes::copy_from_slice(bytes.as_ref()),
                }
            }
        }
    }
}

impl From<EncodedStandardPath> for DataPlanePath {
    fn from(value: EncodedStandardPath) -> Self {
        Self::Standard(value)
    }
}

impl<T, U> PartialEq<DataPlanePath<U>> for DataPlanePath<T>
where
    T: Deref<Target = [u8]>,
    U: Deref<Target = [u8]>,
{
    fn eq(&self, other: &DataPlanePath<U>) -> bool {
        match (self, other) {
            (Self::Standard(lhs), DataPlanePath::Standard(rhs)) => lhs.raw() == rhs.raw(),
            (
                Self::Unsupported {
                    path_type: l_path_type,
                    bytes: l_bytes,
                },
                DataPlanePath::Unsupported {
                    path_type: r_path_type,
                    bytes: r_bytes,
                },
            ) => l_path_type == r_path_type && l_bytes.deref() == r_bytes.deref(),
            (Self::EmptyPath, DataPlanePath::EmptyPath) => true,
            _ => false,
        }
    }
}

impl WireEncode for DataPlanePath {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        match self {
            Self::Standard(path) => path.raw().len(),
            Self::EmptyPath => 0,
            Self::Unsupported { bytes, .. } => bytes.len(),
        }
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        match self {
            Self::Standard(path) => buffer.put(path.raw()),
            Self::EmptyPath => (),
            Self::Unsupported { bytes, .. } => buffer.put_slice(bytes),
        }
    }
}

impl WireDecodeWithContext<Bytes> for DataPlanePath {
    type Error = DecodeError;
    type Context = (PathType, usize);

    fn decode_with_context(
        data: &mut Bytes,
        (path_type, length_hint): Self::Context,
    ) -> Result<Self, Self::Error> {
        match path_type {
            PathType::Empty => Ok(DataPlanePath::EmptyPath),
            PathType::Scion => Ok(EncodedStandardPath::decode(data)?.into()),
            other => {
                if data.remaining() < length_hint {
                    Err(Self::Error::PacketEmptyOrTruncated)
                } else {
                    Ok(DataPlanePath::Unsupported {
                        path_type: other,
                        bytes: data.split_to(length_hint),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn path_type_consistent() {
        for value in 0..u8::MAX {
            assert_eq!(u8::from(PathType::from(value)), value);
        }
    }

    macro_rules! test_path_create_encode_decode {
        ($name:ident, $data_plane_path:expr, $expected_length:expr) => {
            #[test]
            fn $name() -> Result<(), Box<dyn std::error::Error>> {
                let data_plane_path: DataPlanePath = $data_plane_path;
                let mut encoded_path = data_plane_path.encode_to_bytes();

                assert_eq!(data_plane_path.encoded_length(), $expected_length);
                assert_eq!(encoded_path.len(), $expected_length);

                assert_eq!(data_plane_path.deep_copy(), data_plane_path);

                assert_eq!(
                    DataPlanePath::decode_with_context(
                        &mut encoded_path,
                        (data_plane_path.path_type(), $expected_length)
                    )?,
                    data_plane_path
                );
                Ok(())
            }
        };
    }

    test_path_create_encode_decode!(empty, DataPlanePath::EmptyPath, 0);

    #[test]
    fn reverse_empty() {
        let dp_path = DataPlanePath::<Bytes>::EmptyPath;
        let reverse_path = dp_path.to_reversed().unwrap();
        assert_eq!(dp_path, reverse_path);
        assert_eq!(reverse_path.to_reversed().unwrap(), dp_path);
    }

    test_path_create_encode_decode!(
        other,
        DataPlanePath::Unsupported {
            path_type: PathType::Colibri,
            bytes: Bytes::from_static(&[1, 2, 3, 4])
        },
        4
    );

    fn standard_path() -> DataPlanePath {
        let mut path_raw = BytesMut::with_capacity(36);
        path_raw.put_u32(0x0000_2000);
        path_raw.put_slice(&[0_u8; 32]);
        DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap())
    }

    test_path_create_encode_decode!(standard, standard_path(), 36);

    #[test]
    fn reverse_standard() {
        let dp_path = standard_path();
        let reverse_path = dp_path.to_reversed().unwrap();
        assert!(
            dp_path != reverse_path,
            "reversed path should differ from original path"
        );
        assert_eq!(
            reverse_path.to_reversed().unwrap(),
            dp_path,
            "double reversal should return original path"
        );
    }
}
