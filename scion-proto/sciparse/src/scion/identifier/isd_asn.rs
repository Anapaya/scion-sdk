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

//! SCION ISD-AS identifier

use std::{
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    core::{macros::impl_from, read::FromUnalignedRead, write::IntoUnalignedWrite},
    scion::{
        address::AddressParseError,
        identifier::{asn::Asn, isd::Isd},
    },
};

/// The combined ISD and AS identifier of a SCION AS (sometimes abbreviated as IA).
#[derive(
    Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
#[repr(transparent)]
pub struct IsdAsn(pub u64);
impl IsdAsn {
    /// Wildcard ISD-AS number, represented by zero.
    pub const WILDCARD: Self = Self(0);
    /// Maximum valid ISD-AS number.
    pub const MAX: Self = Self(u64::MAX);
    /// The number of bits in a SCION ISD-AS number.
    pub const BITS: u32 = u64::BITS;

    /// Construct a new identifier from ISD and AS identifiers.
    pub const fn new(isd: Isd, asn: Asn) -> Self {
        Self(((isd.to_u16() as u64) << Asn::BITS) | asn.to_u64())
    }

    /// Return the ISD.
    pub const fn isd(&self) -> Isd {
        Isd::new((self.0 >> Asn::BITS) as u16)
    }

    /// Set the ISD number.
    pub fn set_isd(&mut self, isd: Isd) {
        self.0 = ((isd.to_u16() as u64) << Asn::BITS) | (self.0 & 0xffff_ffff_ffff);
    }

    /// Return the AS number.
    pub const fn asn(&self) -> Asn {
        Asn::new(self.0 & 0xffff_ffff_ffff)
    }

    /// Set the AS number.
    pub fn set_asn(&mut self, asn: Asn) {
        self.0 = (self.0 & 0xffff_0000_0000_0000) | asn.to_u64();
    }

    /// Create an ISD-AS from a 64-bit integer.
    /// First 16 bits are the ISD, last 48 bits are the AS.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Return the IA as a 64-bit integer.
    /// First 16 bits are the ISD, last 48 bits are the AS.
    pub const fn to_u64(&self) -> u64 {
        self.0
    }

    /// Return the IA as a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns true if either the ISD or AS numbers are wildcards.
    pub const fn is_wildcard(&self) -> bool {
        self.isd().is_wildcard() || self.asn().is_wildcard()
    }

    /// Returns true if this IsdAsn matches another IsdAsn, taking wildcards into account.
    pub const fn matches(&self, other: IsdAsn) -> bool {
        self.isd().matches(other.isd()) && self.asn().matches(other.asn())
    }

    /// Returns true if this IsdAsn is contained in the given collection, taking wildcards into
    /// account.
    pub fn matches_any_in<'a>(&self, collection: impl IntoIterator<Item = &'a IsdAsn>) -> bool {
        collection.into_iter().any(|other| self.matches(*other))
    }
}
impl Debug for IsdAsn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}
impl Display for IsdAsn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.isd(), self.asn())
    }
}
impl FromStr for IsdAsn {
    type Err = AddressParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let n_separators = string.chars().filter(|c| *c == '-').take(2).count();
        if n_separators != 1 {
            return Err(AddressParseError::IsdAsn);
        }

        let (isd_str, asn_str) = string
            .split_once('-')
            .expect("already checked that the string contains exactly one '-'");

        if let (Ok(isd), Ok(asn)) = (Isd::from_str(isd_str), Asn::from_str(asn_str)) {
            Ok(IsdAsn::new(isd, asn))
        } else {
            Err(AddressParseError::IsdAsn)
        }
    }
}
impl TryFrom<String> for IsdAsn {
    type Error = AddressParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        IsdAsn::from_str(&value)
    }
}
impl_from!(IsdAsn, String, |v| v.to_string());
impl_from!(IsdAsn, u64, |v| v.to_u64());
impl_from!(u64, IsdAsn, |v| IsdAsn::from_u64(v));
impl FromUnalignedRead for IsdAsn {
    fn from_unaligned_read(v: u128) -> Self {
        IsdAsn::from_u64(u64::from_unaligned_read(v))
    }
}
impl IntoUnalignedWrite for IsdAsn {
    fn into_write_value(v: IsdAsn) -> u128 {
        v.to_u64() as u128
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test::param_test;

    param_test! {
        constructs_from_parts: [
            arbitrary: (Isd::new(1), Asn::new(0xff00_0000_00ab), IsdAsn(0x1_ff00_0000_00ab)),
            wildcard: (Isd::WILDCARD, Asn::WILDCARD, IsdAsn::WILDCARD),
        ]
    }
    fn constructs_from_parts(isd: Isd, asn: Asn, expected: IsdAsn) {
        assert_eq!(IsdAsn::new(isd, asn), expected);
    }

    #[test]
    fn isd_extracts_correctly() {
        assert_eq!(IsdAsn(0x2_ff00_0000_1101).isd(), Isd::new(2));
    }

    #[test]
    fn asn_extracts_correctly() {
        assert_eq!(IsdAsn(0x2_ff00_0000_1101).asn(), Asn::new(0xff00_0000_1101));
    }

    #[test]
    fn to_u64_converts_correctly() {
        assert_eq!(
            IsdAsn::new(Isd::new(0x0123), Asn::new(0x4567_89ab_cdef)).to_u64(),
            0x0123_4567_89ab_cdef
        )
    }

    #[test]
    fn debug_format_displays_hyphenated_string() {
        assert_eq!(
            format!("{:?}", IsdAsn(0x0001_ff00_0000_00ab)),
            "1-ff00:0:ab"
        );
    }

    param_test! {
        correctly_displays_ia: [
            simple: (IsdAsn(0x0001_ff00_0000_00ab), "1-ff00:0:ab"),
            wildcard: (IsdAsn::WILDCARD, "0-0"),
            max_ia: (IsdAsn::MAX, "65535-ffff:ffff:ffff"),
        ]
    }
    fn correctly_displays_ia(ia: IsdAsn, expected: &str) {
        assert_eq!(ia.to_string(), expected);
    }

    param_test! {
        from_str_parses_valid_strings: [
            wildcard: ("0-0", IsdAsn::WILDCARD),
            max_ia: ("65535-ffff:ffff:ffff", IsdAsn::MAX),
            min_non_wildcard: ("1-0:0:1", IsdAsn(0x0001_0000_0000_0001)),
        ]
    }
    fn from_str_parses_valid_strings(ia_str: &str, expected: IsdAsn) {
        assert_eq!(IsdAsn::from_str(ia_str), Ok(expected));
    }

    param_test! {
        try_from_str_parses_valid_strings: [
            wildcard: ("0-0", IsdAsn::WILDCARD),
            max_ia: ("65535-ffff:ffff:ffff", IsdAsn::MAX),
            min_non_wildcard: ("1-0:0:1", IsdAsn(0x0001_0000_0000_0001)),
        ]
    }
    fn try_from_str_parses_valid_strings(ia_str: &str, expected: IsdAsn) {
        assert_eq!(IsdAsn::try_from(ia_str.to_string()), Ok(expected));
    }

    #[test]
    fn from_str_invalid_isd_returns_error() {
        assert_eq!(
            IsdAsn::from_str("a-0:0:1").unwrap_err(),
            AddressParseError::IsdAsn
        );
    }

    #[test]
    fn from_str_invalid_format_returns_error() {
        assert_eq!(
            IsdAsn::from_str("1-1-0:0:1").unwrap_err(),
            AddressParseError::IsdAsn
        );
    }
}
