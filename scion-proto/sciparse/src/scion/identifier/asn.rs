// Copyright 2025 Mysten Labs
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

//! SCION Autonomous System (AS) identifier

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use crate::{
    core::{macros::impl_from, read::FromUnalignedRead},
    scion::address::AddressParseError,
};

/// A 48-bit SCION autonomous system (AS) number.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Asn(pub u64);
impl Asn {
    /// Wildcard AS number, represented by zero.
    pub const WILDCARD: Self = Asn::new(0);
    /// Maximum valid AS number
    pub const MAX: Self = Self((1 << Self::BITS) - 1);
    /// The number of bits in a SCION AS number.
    pub const BITS: u32 = 48;
    /// The number of bits per part when representing ASNs in the "xxxx:xxxx:xxxx" format.
    const BITS_PER_PART: u32 = 16;
    /// The number of parts when representing ASNs in the "xxxx:xxxx:xxxx" format.
    const NUMBER_PARTS: u32 = 3;

    /// Creates a new AS from a u64 value.
    ///
    /// This function will truncate the input value to fit within 48 bits.
    pub const fn new(id: u64) -> Self {
        Self(id & Self::MAX.0)
    }

    /// Creates a new AS from a u64 value, returning none if the value is out of range.
    pub const fn new_checked(id: u64) -> Option<Self> {
        if id > Self::MAX.0 {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Returns the AS number as a u64 integer.
    pub const fn to_u64(&self) -> u64 {
        self.0
    }

    /// Returns true if this Asn is a wildcard.
    pub const fn is_wildcard(&self) -> bool {
        self.0 == Self::WILDCARD.0
    }

    /// Returns true if this Asn matches another Asn, taking wildcards into account.
    pub const fn matches(&self, other: Asn) -> bool {
        self.is_wildcard() || other.is_wildcard() || self.0 == other.0
    }

    /// Returns true if this Asn matches any entry in the given collection, taking wildcards into
    /// account.
    pub fn matches_any_in<'a>(&self, collection: impl IntoIterator<Item = &'a Asn>) -> bool {
        collection.into_iter().any(|other| self.matches(*other))
    }
}
impl Display for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        const BGP_ASN_FORMAT_BOUNDARY: u64 = u32::MAX as u64;

        if self.to_u64() <= BGP_ASN_FORMAT_BOUNDARY {
            return write!(f, "{}", self.to_u64());
        }

        for i in (0..Asn::NUMBER_PARTS).rev() {
            let asn_part = (self.to_u64() >> (Asn::BITS_PER_PART * i)) & u64::from(u16::MAX);
            let separator = if i != 0 { ":" } else { "" };

            write!(f, "{asn_part:x}{separator}")?;
        }

        Ok(())
    }
}
impl FromStr for Asn {
    type Err = AddressParseError;

    fn from_str(asn_string: &str) -> Result<Self, Self::Err> {
        // AS numbers less than 2^32 can be provided as decimal
        if let Ok(bgp_asn) = u64::from_str(asn_string) {
            return if bgp_asn <= u32::MAX.into() {
                Ok(Self(bgp_asn))
            } else {
                Err(AddressParseError::Asn)
            };
        }

        let result = asn_string.splitn(Asn::NUMBER_PARTS as usize, ':').try_fold(
            (0u64, 0u32),
            |(asn_value, n_parts), asn_part| {
                u16::from_str_radix(asn_part, 16).map(|value| {
                    (
                        (asn_value << Asn::BITS_PER_PART) | u64::from(value),
                        n_parts + 1,
                    )
                })
            },
        );

        match result {
            Ok((val, Asn::NUMBER_PARTS)) => {
                match Asn::new_checked(val) {
                    Some(asn) => Ok(asn),
                    None => Err(AddressParseError::Asn),
                }
            }
            _ => Err(AddressParseError::Asn),
        }
    }
}
impl TryFrom<u64> for Asn {
    type Error = AddressParseError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match Asn::new_checked(value) {
            Some(asn) => Ok(asn),
            None => Err(AddressParseError::Asn),
        }
    }
}
impl_from!(Asn, u64, |v| v.to_u64());
impl FromUnalignedRead for Asn {
    fn from_unaligned_read(v: u128) -> Self {
        Asn::new(u64::from_unaligned_read(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::test::param_test, scion::address::AddressParseError};

    param_test! {
        converts_from_number: [
            wildcard: (0, Ok(Asn::WILDCARD)),
            max_value: (0xffff_ffff_ffff, Ok(Asn::MAX)),
            out_of_range: (0xffff_ffff_ffff + 1, Err(AddressParseError::Asn))
        ]
    }
    fn converts_from_number(numeric_value: u64, expected: Result<Asn, AddressParseError>) {
        assert_eq!(Asn::try_from(numeric_value), expected);
    }

    param_test! {
        successfully_parses_valid_strings: [
            zero: ("0", Asn::WILDCARD),
            zero_with_colon: ("0:0:0", Asn::WILDCARD),
            low_bit: ("0:0:1", Asn(1)),
            high_bit: ("1:0:0", Asn(0x000100000000)),
            max: ("ffff:ffff:ffff", Asn::MAX),
            bgp_asn: ("65535", Asn(65535))
        ]
    }
    fn successfully_parses_valid_strings(asn_str: &str, expected: Asn) {
        assert_eq!(Ok(expected), asn_str.parse());
    }

    param_test! {
        parse_rejects_invalid_strings: [
            large_decimal_format: ("4294967296"),
            only_colon: (":"),
            extra_colon: ("0:0:0:"),
            too_few: ("0:0"),
            invalid_part: (":0:0"),
            out_of_range: ("10000:0:0"),
            out_of_range2: ("0:0:10000"),
            invalid_format: ("0:0x0:0"),
        ]
    }
    fn parse_rejects_invalid_strings(asn_str: &str) {
        assert_eq!(Asn::from_str(asn_str), Err(AddressParseError::Asn));
    }

    param_test! {
        correctly_displays_asn: [
            large: (Asn(0xff00000000ab), "ff00:0:ab"),
            large_symmetric: (Asn(0x0001fcd10001), "1:fcd1:1"),
            max: (Asn::MAX, "ffff:ffff:ffff"),
            wildcard: (Asn(0), "0"),
            bgp_asn: (Asn(1), "1"),
            bgp_asn_max: (Asn(u32::MAX.into()), "4294967295"),
            outside_bgp_asn: (Asn(u32::MAX as u64 + 1), "1:0:0"),
        ]
    }
    fn correctly_displays_asn(asn: Asn, expected: &str) {
        assert_eq!(asn.to_string(), expected);
    }
}
