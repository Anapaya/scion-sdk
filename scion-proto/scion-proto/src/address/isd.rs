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

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use sciparse::identifier::isd::Isd as SciparseIsd;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{AddressParseError, error::AddressKind};

/// A 16-bit identifier of a SCION Isolation Domain.
///
/// See [this table][anapaya-assignments] for current ISD network assignments.
///
/// [anapaya-assignments]: https://docs.anapaya.net/en/latest/resources/isd-as-assignments/
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, ToSchema,
)]
#[repr(transparent)]
pub struct Isd(pub u16);

impl Isd {
    /// The SCION ISD number representing the wildcard ISD.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert_eq!(Isd::WILDCARD, Isd::new(0));
    /// ```
    pub const WILDCARD: Self = Self(0);

    /// Maximum valid ISD identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert_eq!(Isd::MAX, Isd::new(u16::MAX));
    /// ```
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

    /// Return true for the special 'wildcard' AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::Isd;
    /// assert!(Isd::WILDCARD.is_wildcard());
    /// assert!(Isd::new(0).is_wildcard());
    /// assert!(!Isd::new(1).is_wildcard());
    /// ```
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
            .or(Err(AddressKind::Isd.into()))
    }
}

impl From<SciparseIsd> for Isd {
    fn from(value: SciparseIsd) -> Self {
        Isd::new(value.to_u16())
    }
}

impl From<Isd> for SciparseIsd {
    fn from(value: Isd) -> Self {
        SciparseIsd::new(value.to_u16())
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
