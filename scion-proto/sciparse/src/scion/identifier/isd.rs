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

//! SCION Isolation Domain (ISD) identifier

use std::{
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};
use utoipa::ToSchema;

use crate::{
    core::{macros::impl_from, read::FromUnalignedRead},
    scion::address::AddressParseError,
};

/// A 16-bit identifier of a SCION Isolation Domain.
///
/// See [this table][anapaya-assignments] for current ISD network assignments.
///
/// [anapaya-assignments]: https://docs.anapaya.net/en/latest/resources/isd-as-assignments/
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    SerializeDisplay,
    DeserializeFromStr,
    ToSchema,
)]
#[repr(transparent)]
pub struct Isd(pub u16);
impl Isd {
    /// Wildcard ISD identifier, represented by zero.
    pub const WILDCARD: Self = Self(0);

    /// Maximum valid ISD identifier.
    pub const MAX: Self = Self::new(u16::MAX);

    /// The number of bits in a SCION ISD number.
    pub const BITS: u32 = u16::BITS;

    /// Creates a new ISD from a 16-bit value.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Return the identifier as a 16-bit value.
    pub const fn to_u16(&self) -> u16 {
        self.0
    }

    /// Return true if this Isd is a wildcard.
    pub const fn is_wildcard(&self) -> bool {
        self.0 == Self::WILDCARD.0
    }

    /// Returns true if this Isd matches another Isd, taking wildcards into account.
    pub const fn matches(&self, other: Isd) -> bool {
        self.is_wildcard() || other.is_wildcard() || self.0 == other.0
    }

    /// Returns true if this Isd matches any entry in the given collection, taking wildcards into
    /// account.
    pub fn matches_any_in<'a>(&self, collection: impl IntoIterator<Item = &'a Isd>) -> bool {
        collection.into_iter().any(|other| self.matches(*other))
    }
}
impl Debug for Isd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}
impl Display for Isd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl FromStr for Isd {
    type Err = AddressParseError;

    /// Parses an ISD from a decimal string.
    ///
    /// ISD 0 is parsed without any errors.
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        u16::from_str(string)
            .map(Isd::new)
            .or(Err(AddressParseError::Isd))
    }
}
impl_from!(u16, Isd, |v| Isd::new(v));
impl_from!(Isd, u16, |v| v.to_u16());
impl FromUnalignedRead for Isd {
    fn from_unaligned_read(v: u128) -> Self {
        Isd::new(u16::from_unaligned_read(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod display {
        use super::*;

        #[test]
        fn wildcard() {
            assert_eq!(Isd::WILDCARD.to_string(), "0");
        }
    }
}
