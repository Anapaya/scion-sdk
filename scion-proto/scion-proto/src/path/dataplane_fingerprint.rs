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

use std::{fmt, ops::Deref};

use sha2::{Digest, Sha256};

use super::Path;

/// A fingerprint for a SCION path, derived from the dataplane path.
///
/// Different from [`PathFingerprint`](super::PathFingerprint), this fingerprint is computed solely
/// based on data available on the dataplane path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataPlanePathFingerprint([u8; DataPlanePathFingerprint::LENGTH]);

impl DataPlanePathFingerprint {
    const LENGTH: usize = 32;
    const DISPLAYED_BYTES: usize = 8;

    /// Returns the unique fingerprint for the provided path.
    ///
    /// Because Interface IDs are locally unique, the sequence of interfaces anchored
    /// at a known Source AS deterministically maps to exactly one specific sequence of
    /// traversed ASes. Therefore, hashing (Src, Dst, Interfaces) is topologically
    /// equivalent to hashing the full control plane path segment.
    pub fn new<T: Deref<Target = [u8]>>(path: &Path<T>) -> DataPlanePathFingerprint {
        let mut hasher = Sha256::new();
        match &path.data_plane_path {
            crate::path::DataPlanePath::EmptyPath => {
                hasher.update(path.isd_asn.source.to_be_bytes());
                hasher.update(path.isd_asn.destination.to_be_bytes());
            }
            crate::path::DataPlanePath::Standard(encoded_standard_path) => {
                hasher.update(path.isd_asn.source.to_be_bytes());
                hasher.update(path.isd_asn.destination.to_be_bytes());
                encoded_standard_path.hop_fields().for_each(|hf| {
                    hasher.update(
                        hf.cons_ingress_interface()
                            .map(|i| i.get())
                            .unwrap_or(0)
                            .to_be_bytes(),
                    );
                    hasher.update(
                        hf.cons_egress_interface()
                            .map(|i| i.get())
                            .unwrap_or(0)
                            .to_be_bytes(),
                    );
                });
            }
            crate::path::DataPlanePath::Unsupported { path_type, bytes } => {
                // Not really a valid fingerprint, but it's not worth special-casing.
                hasher.update(path.isd_asn.source.to_be_bytes());
                hasher.update(path.isd_asn.destination.to_be_bytes());
                let path_type_val: u8 = (*path_type).into();
                hasher.update([path_type_val]);
                hasher.update(bytes.as_ref());
            }
        }

        DataPlanePathFingerprint(hasher.finalize().into())
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

impl AsRef<[u8]> for DataPlanePathFingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for DataPlanePathFingerprint {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<[u8; 32]> for DataPlanePathFingerprint {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for DataPlanePathFingerprint {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl fmt::Display for DataPlanePathFingerprint {
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

impl fmt::LowerHex for DataPlanePathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, true)
    }
}

impl fmt::UpperHex for DataPlanePathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, false)
    }
}
