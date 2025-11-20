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

use std::fmt;

use sha2::{Digest, Sha256};

use super::Path;
use crate::address::IsdAsn;

/// Error returned on failure to determine the fingerprint for a [`Path`].
///
/// This indicates that the interfaces over which the fingerprint is computed
/// are wholly or partially missing from the provided path.
#[derive(Debug, thiserror::Error)]
#[error("interface metadata is required to compute path fingerprints")]
pub struct FingerprintError;

/// A fingerprint for a SCION path.
///
/// A `PathFingerprint` uniquely identifies a SCION [`Path`] based on the sequence of
/// SCION ASes router interfaces traversed. Other metadata, such as the path MTU or
/// the next hop on the network underlay have no effect on the fingerprint.
///
/// With the exception of local paths, creating a fingerprint requires the traversed ASes
/// and interfaces of the path. Therefore, attempting to fingerprint a non-local path which
/// lacks metadata or some of interfaces fails with a [`FingerprintError`].
///
/// Fingerprints can be created with the [`fingerprint`][Path::<T>::fingerprint] method
/// on [`Path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathFingerprint([u8; PathFingerprint::LENGTH]);

impl PathFingerprint {
    const LENGTH: usize = 32;
    const DISPLAYED_BYTES: usize = 8;

    /// Returns the fingerprint for the provided path.
    pub(crate) fn new<T>(path: &Path<T>) -> Result<PathFingerprint, FingerprintError> {
        if path.isd_asn.are_equal() {
            Ok(PathFingerprint::local(path.isd_asn.source))
        } else {
            Self::digest_interfaces(path)
        }
    }

    /// Returns the fingerprint that always corresponds to the local SCION path for the
    /// specified AS.
    ///
    /// # Example
    /// ```
    /// # use scion_proto::path::{Path, PathFingerprint};
    /// # use scion_proto::address::IsdAsn;
    /// # use bytes::Bytes;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let local_ia: IsdAsn = "1-ff00:0:110".parse()?;
    /// assert_eq!(
    ///     Path::<Bytes>::local(local_ia).fingerprint()?,
    ///     PathFingerprint::local(local_ia)
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn local(local_ia: IsdAsn) -> Self {
        Self(
            Sha256::new_with_prefix(local_ia.to_u64().to_be_bytes())
                .finalize()
                .into(),
        )
    }

    fn digest_interfaces<T>(path: &Path<T>) -> Result<Self, FingerprintError> {
        debug_assert!(!path.isd_asn.are_equal());

        let interfaces = path
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.interfaces.as_ref())
            .ok_or(FingerprintError)?;

        let mut hasher = Sha256::new();

        for interface in interfaces {
            hasher.update(interface.isd_asn.to_u64().to_be_bytes());
            hasher.update(u64::from(interface.id).to_be_bytes());
        }

        Ok(Self(hasher.finalize().into()))
    }

    /// Writes the fingerprint as lower or upper case hex, without the leading 0x.
    ///
    /// The argument n_displayed controls how many characters are written.
    fn format(&self, f: &mut fmt::Formatter<'_>, n_displayed: usize, lower: bool) -> fmt::Result {
        for byte in &self.0[..n_displayed] {
            if lower {
                write!(f, "{byte:02x}")?;
            } else {
                write!(f, "{byte:02X}")?;
            }
        }

        Ok(())
    }
}

impl<T> TryFrom<&Path<T>> for PathFingerprint {
    type Error = FingerprintError;

    fn try_from(value: &Path<T>) -> Result<Self, Self::Error> {
        PathFingerprint::new(value)
    }
}

impl AsRef<[u8]> for PathFingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PathFingerprint {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<[u8; 32]> for PathFingerprint {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for PathFingerprint {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl fmt::Display for PathFingerprint {
    /// Formats the first 8 bytes of the fingerprint as a lower-case hex.
    ///
    /// The alternate flag formats the entire 32-bytes of the fingerprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.format(f, Self::LENGTH, true)
        } else {
            self.format(f, Self::DISPLAYED_BYTES, true)
        }
    }
}

impl fmt::LowerHex for PathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, true)
    }
}

impl fmt::UpperHex for PathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, false)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use chrono::DateTime;

    use super::*;
    use crate::{
        address::IsdAsn,
        packet::ByEndpoint,
        path::{DataPlanePath, Metadata, Path, PathInterface, PathType},
    };

    macro_rules! test_format {
        ($name:ident, $fingerprint:expr, $fmt_str:tt, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(format!($fmt_str, $fingerprint), $expected);
            }
        };
    }

    const FINGERPRINT: PathFingerprint = PathFingerprint([
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
        0xf9, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d,
        0x8e, 0x9f,
    ]);

    test_format!(display, FINGERPRINT, "{}", "0a1b2c3d4e5f6071");
    test_format!(
        display_alt,
        FINGERPRINT,
        "{:#}",
        "0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f"
    );
    test_format!(lower_hex, FINGERPRINT, "{:x}", "0a1b2c3d4e5f6071");
    test_format!(lower_hex_alt, FINGERPRINT, "{:#x}", "0x0a1b2c3d4e5f6071");
    test_format!(upper_hex, FINGERPRINT, "{:X}", "0A1B2C3D4E5F6071");
    test_format!(upper_hex_alt, FINGERPRINT, "{:#X}", "0x0A1B2C3D4E5F6071");

    macro_rules! test_case {
        ($name:ident: $func:expr) => {
            #[test]
            fn $name() {
                $func
            }
        };
    }

    fn get_path_for(interfaces: &[(u16, &str)]) -> Path {
        assert_ne!(interfaces.len(), 0);
        let isd_asn = ByEndpoint::<IsdAsn> {
            source: interfaces.first().unwrap().1.parse().unwrap(),
            destination: interfaces.last().unwrap().1.parse().unwrap(),
        };
        let interfaces: Vec<_> = interfaces
            .iter()
            .map(|(id, ia_string)| {
                PathInterface {
                    isd_asn: ia_string.parse().unwrap(),
                    id: *id,
                }
            })
            .collect();
        let dp_path = DataPlanePath::Unsupported {
            path_type: PathType::Other(255),
            bytes: Bytes::new(),
        };

        Path {
            data_plane_path: dp_path,
            isd_asn,
            underlay_next_hop: None,
            metadata: Some(Metadata {
                expiration: DateTime::from_timestamp(0, 0).unwrap(),
                mtu: 1500,
                interfaces: Some(interfaces),
                latency: None,
                bandwidth_kbps: None,
                geo: None,
                link_type: None,
                internal_hops: None,
                notes: None,
                epic_auths: None,
            }),
        }
    }

    fn test_fingerprint(interfaces: &[(u16, &str)], expected_short_fingerprint: &str) {
        let fingerprint = get_path_for(interfaces).fingerprint().unwrap();
        assert_eq!(fingerprint.to_string(), expected_short_fingerprint);
    }

    test_case! {
        showpaths_fingerprint1:
            test_fingerprint(&[(1, "65-2:0:42"), (3, "65-2:0:24")], "f416fe092e6cbd4c")
    }

    test_case! {
        showpaths_fingerprint2:
            test_fingerprint(
                &[
                    (1, "65-2:0:42"),
                    (3, "65-2:0:24"),
                    (2, "65-2:0:24"),
                    (1, "64-2:0:23"),
                    (2, "64-2:0:23"),
                    (19, "64-2:0:13"),
                    (2, "64-2:0:13"),
                    (2, "66-2:0:10")
                ],
                "d75e7ac9b6cd510c"
            )
    }
}
