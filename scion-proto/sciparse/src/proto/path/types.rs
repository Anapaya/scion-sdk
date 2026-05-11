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

//! Standard SCION path types and related structures.

use std::fmt::Debug;

/// Path types used in SCION packets.
///
/// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
///
///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#name-common-header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PathType {
    /// The empty path type.
    Empty = 0,
    /// The standard SCION path type.
    Scion = 1,
    /// One-hop paths between neighboring border routers.
    OneHop = 2,
    /// Experimental Epic path type.
    Epic = 3,
    /// Experimental Colibri path type.
    Colibri = 4,
    /// Other, unrecognized path types.
    Other(u8),
}
impl From<u8> for PathType {
    fn from(value: u8) -> Self {
        match value {
            0 => PathType::Empty,
            1 => PathType::Scion,
            2 => PathType::OneHop,
            3 => PathType::Epic,
            4 => PathType::Colibri,
            other => PathType::Other(other),
        }
    }
}
impl From<PathType> for u8 {
    fn from(val: PathType) -> Self {
        match val {
            PathType::Empty => 0,
            PathType::Scion => 1,
            PathType::OneHop => 2,
            PathType::Epic => 3,
            PathType::Colibri => 4,
            PathType::Other(other) => other,
        }
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;

    /// Configuration for generating arbitrary [`PathType`] values.
    ///
    /// Controls the relative probability of each variant being generated.
    ///
    /// Default weights: `empty = 1, scion = 4, one_hop = 2, epic = 1, colibri = 1, other = 1`.
    #[derive(Debug, Clone)]
    pub struct ArbitraryPathTypeParams {
        /// Weight for generating Empty path type.
        pub empty: u32,
        /// Weight for generating Scion (standard) path type.
        pub scion: u32,
        /// Weight for generating OneHop path type.
        pub one_hop: u32,
        /// Weight for generating Epic path type.
        pub epic: u32,
        /// Weight for generating Colibri path type.
        pub colibri: u32,
        /// Weight for generating Other (unknown) path types.
        pub other: u32,
    }
    impl Default for ArbitraryPathTypeParams {
        fn default() -> Self {
            Self {
                empty: 1,
                scion: 4,
                one_hop: 2,
                epic: 1,
                colibri: 1,
                other: 1,
            }
        }
    }

    impl Arbitrary for PathType {
        type Parameters = ArbitraryPathTypeParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                params.empty => Just(PathType::Empty),
                params.scion => Just(PathType::Scion),
                params.one_hop => Just(PathType::OneHop),
                params.epic => Just(PathType::Epic),
                params.colibri => Just(PathType::Colibri),
                params.other => (5u8..=255).prop_map(PathType::Other),
            ]
            .boxed()
        }
    }
}
