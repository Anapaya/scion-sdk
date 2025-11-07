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
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use utoipa::ToSchema;

use super::{AddressParseError, Asn, Isd, error::AddressKind};

/// The combined ISD and AS identifier of a SCION AS (sometimes abbreviated as IA).
///
/// # Examples
///
/// ```
/// # use scion_proto::address::IsdAsn;
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(IsdAsn(0x1_ff00_0000_0110), "1-ff00:0:110".parse()?);
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord, ToSchema)]
#[schema(examples("1-ff00:0:110"), value_type = String, pattern = r"^\d+-([a-f0-9]{1,4}:){2}([a-f0-9]{1,4})|\d+$" )]
#[repr(transparent)]
pub struct IsdAsn(pub u64);

impl IsdAsn {
    /// A SCION IA of the special wildcard IA, 0-0.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{Isd, Asn, IsdAsn};
    /// #
    /// assert_eq!(IsdAsn::WILDCARD, IsdAsn(0));
    /// assert_eq!(IsdAsn::WILDCARD, IsdAsn::new(Isd::WILDCARD, Asn::WILDCARD));
    /// ```
    pub const WILDCARD: Self = Self(0);

    /// Maximum valid ISD-AS number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{Isd, Asn, IsdAsn};
    /// #
    /// assert_eq!(IsdAsn::MAX, IsdAsn(u64::MAX));
    /// assert_eq!(IsdAsn::MAX, IsdAsn::new(Isd::MAX, Asn::MAX));
    /// ```
    pub const MAX: Self = Self(u64::MAX);

    /// The number of bits in a SCION ISD-AS number.
    pub const BITS: u32 = u64::BITS;

    /// Construct a new identifier from ISD and AS identifiers.
    pub const fn new(isd: Isd, asn: Asn) -> Self {
        Self(((isd.to_u16() as u64) << Asn::BITS) | asn.to_u64())
    }

    /// Return the ISD associated with this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{IsdAsn, Isd, Asn};
    /// #
    /// let ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
    /// assert_eq!(ia.isd(), Isd(1));
    /// ```
    pub const fn isd(&self) -> Isd {
        Isd::new((self.0 >> Asn::BITS) as u16)
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

    /// Set the ISD number associated with this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{IsdAsn, Isd, Asn};
    /// #
    /// let mut ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
    /// ia.set_isd(Isd::new(2));
    /// assert_eq!(ia.isd(), Isd(2));
    /// ```
    pub fn set_isd(&mut self, isd: Isd) {
        self.0 = ((isd.to_u16() as u64) << Asn::BITS) | (self.0 & 0xffff_ffff_ffff);
    }

    /// Return the AS number associated with this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{Asn, IsdAsn, Isd};
    /// #
    /// let ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
    /// assert_eq!(ia.asn(), Asn::new(0xff00_0000_0110));
    /// ```
    pub const fn asn(&self) -> Asn {
        Asn::new(self.0 & 0xffff_ffff_ffff)
    }

    /// Set the AS number associated with this identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{Asn, IsdAsn, Isd};
    /// #
    /// let mut ia = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));
    /// ia.set_asn(Asn::new(0xff00_0000_0111));
    /// assert_eq!(ia.asn(), Asn::new(0xff00_0000_0111));
    /// ```
    pub fn set_asn(&mut self, asn: Asn) {
        self.0 = (self.0 & 0xffff_0000_0000_0000) | asn.to_u64();
    }

    /// Returns true if either the ISD or AS numbers are wildcards.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::{Asn, IsdAsn, Isd};
    /// assert!(IsdAsn::new(Isd::WILDCARD, Asn::new(1)).is_wildcard());
    /// assert!(IsdAsn::new(Isd::new(1), Asn::WILDCARD).is_wildcard());
    /// assert!(!IsdAsn::new(Isd::new(1), Asn::new(1)).is_wildcard());
    /// ```
    pub const fn is_wildcard(&self) -> bool {
        self.isd().is_wildcard() || self.asn().is_wildcard()
    }

    /// Return the IA as a 64-bit integer.
    ///
    /// The highest 16 bits constitute the ISD number, and the lower 48 bits form the AS number.
    pub const fn to_u64(&self) -> u64 {
        self.0
    }

    /// Return the IA as a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl Debug for IsdAsn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.isd(), self.asn())
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
            return Err(AddressKind::IsdAsn.into());
        }

        let (isd_str, asn_str) = string
            .split_once('-')
            .expect("already checked that the string contains exactly one '-'");

        if let (Ok(isd), Ok(asn)) = (Isd::from_str(isd_str), Asn::from_str(asn_str)) {
            Ok(IsdAsn::new(isd, asn))
        } else {
            Err(AddressKind::IsdAsn.into())
        }
    }
}

impl TryFrom<String> for IsdAsn {
    type Error = AddressParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl From<IsdAsn> for u64 {
    fn from(value: IsdAsn) -> Self {
        value.to_u64()
    }
}

impl From<u64> for IsdAsn {
    fn from(value: u64) -> Self {
        IsdAsn(value)
    }
}

// Serde
mod serde {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::address::IsdAsn;

    impl Serialize for IsdAsn {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.to_string().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for IsdAsn {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            IsdAsn::from_str(&s).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{Asn, Isd},
        test_utils::param_test,
    };

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
            AddressParseError(AddressKind::IsdAsn)
        );
    }

    #[test]
    fn from_str_invalid_format_returns_error() {
        assert_eq!(
            IsdAsn::from_str("1-1-0:0:1").unwrap_err(),
            AddressParseError(AddressKind::IsdAsn)
        );
    }

    mod serde {

        use super::*;
        use crate::address::{Asn, IsdAsn};

        #[test]
        fn isd_asn_serializes_and_deserializes() {
            let tests = [
                (IsdAsn::new(Isd::WILDCARD, Asn::WILDCARD), "0-0"),
                (IsdAsn::new(Isd::WILDCARD, Asn::new(1)), "0-1"),
                (IsdAsn::new(Isd::new(1), Asn::WILDCARD), "1-0"),
                (IsdAsn::new(Isd::new(1), Asn::new(1)), "1-1"),
                (
                    IsdAsn::new(Isd::new(1), Asn::new(0xff00_0000_0110)),
                    "1-ff00:0:110",
                ),
                (
                    IsdAsn::new(Isd::new(65535), Asn::new(0xffff_ffff_ffff)),
                    "65535-ffff:ffff:ffff",
                ),
            ];

            for (ia, expected) in tests {
                let serialized = match serde_yaml_ng::to_string(&ia) {
                    Ok(s) => s,
                    Err(e) => panic!("Failed to serialize {ia:?}: {e}"),
                };

                assert_eq!(
                    serialized.trim(),
                    expected,
                    "Unexpected serialization of {ia:?}"
                );

                let deserialized: IsdAsn = match serde_yaml_ng::from_str(&serialized) {
                    Ok(d) => d,
                    Err(e) => {
                        panic!(
                            "Failed to deserialize serialized IsdAsn {ia:?} (serialized: {serialized}): {e}"
                        )
                    }
                };
                assert_eq!(ia, deserialized);
            }
        }
    }
}
