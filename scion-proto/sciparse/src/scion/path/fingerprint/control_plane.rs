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

//! SCION path fingerprinting based on the control plane path.
//!
//! This module provides the [PathFingerprint] type, which uniquely identifies a SCION path based on
//! the sequence of ASes and interfaces traversed. The fingerprint is computed by hashing the
//! sequence of interfaces (identified by their ISD-AS and interface ID) with SHA-256
//!
//! If path metadata might be missing, for example because the path was obtained from a source that
//! does not provide full path metadata, the
//! [DpPathFingerprint](super::data_plane::DpPathFingerprint) should be used instead.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::{identifier::isd_asn::IsdAsn, path::ScionPath};

/// Error returned on failure to determine the fingerprint for a [`ScionPath`].
///
/// This indicates that the interfaces over which the fingerprint is computed
/// are wholly or partially missing from the provided path.
#[derive(Debug, thiserror::Error)]
#[error("interface metadata is required to compute path fingerprints")]
pub struct FingerprintError;

/// A fingerprint for a SCION path including the sequence of ASes and interfaces traversed.
///
/// A `PathFingerprint` uniquely identifies a [`ScionPath`] based on the sequence of
/// SCION ASes router interfaces traversed. Other metadata, such as the path MTU or
/// the next hop on the network underlay have no effect on the fingerprint.
///
/// With the exception of local paths, creating a fingerprint requires the traversed ASes
/// and interfaces of the path. Therefore, attempting to fingerprint a non-local path which
/// lacks metadata or some of interfaces fails with a [`FingerprintError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathFingerprint([u8; PathFingerprint::LENGTH]);

impl PathFingerprint {
    const LENGTH: usize = 32;
    const DISPLAYED_BYTES: usize = 8;

    /// Returns the fingerprint for the provided path.
    pub(crate) fn from_scion_path(path: &ScionPath) -> Result<PathFingerprint, FingerprintError> {
        if path.src_ia == path.dst_ia {
            Ok(PathFingerprint::local(path.src_ia))
        } else {
            // Ensure we have metadata
            let if_metadata = path
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.interfaces.as_ref())
                .ok_or(FingerprintError)?;

            let mut hasher = Sha256::new();

            for metadata in if_metadata {
                hasher.update(metadata.interface.isd_asn.to_u64().to_be_bytes());
                hasher.update(u64::from(metadata.interface.id).to_be_bytes());
            }

            Ok(Self(hasher.finalize().into()))
        }
    }

    /// Returns a fingerprint for a path that starts and ends in the same AS.
    pub fn local(local_ia: IsdAsn) -> Self {
        Self(
            Sha256::new_with_prefix(local_ia.to_u64().to_be_bytes())
                .finalize()
                .into(),
        )
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
