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
//! This module provides the [DpPathFingerprint] type, which uniquely identifies a SCION path based
//! on the sequence interfaces traversed.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    dataplane_path::{
        types::PathType,
        view::{ScionDpPathViewExt, ScionDpPathViewRef},
    },
    identifier::isd_asn::IsdAsn,
    path::ScionPath,
};

/// A fingerprint for a SCION path, derived from the dataplane path.
///
/// Different from [`PathFingerprint`](super::control_plane::PathFingerprint), this fingerprint is
/// computed solely based on data available on the dataplane path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DpPathFingerprint([u8; DpPathFingerprint::LENGTH]);
impl DpPathFingerprint {
    const LENGTH: usize = 32;
    const DISPLAYED_BYTES: usize = 8;

    /// Returns a unique fingerprint for the provided path.
    ///
    /// Fields like expiration time, or MACs are not included in the fingerprint. Allowing these
    /// fields to differ without affecting the fingerprint.
    ///
    /// The fingerprint is computed by hashing the path type, src and dst AS and the sequence of hop
    /// field interfaces. As the sequence of interfaces is unique for each path, the resulting
    /// fingerprint is also unique for each path.
    ///
    /// For unsupported path types, the fingerprint is computed by hashing the path type, src and
    /// dst AS and the raw path data.
    pub fn from_scion_path(path: &ScionPath) -> DpPathFingerprint {
        Self::from_dp_path(path.dp_path.as_ref(), path.src_ia, path.dst_ia)
    }

    /// Returns a unique fingerprint for the provided path.
    ///
    /// Fields like expiration time, or MACs are not included in the fingerprint. Allowing these
    /// fields to differ without affecting the fingerprint.
    ///
    /// The fingerprint is computed by hashing the path type, src and dst AS and the sequence of hop
    /// field interfaces. As the sequence of interfaces is unique for each path, the resulting
    /// fingerprint is also unique for each path.
    ///
    /// For unsupported path types, the fingerprint is computed by hashing the path type, src and
    /// dst AS and the raw path data.
    pub fn from_dp_path(
        dp_path: ScionDpPathViewRef<'_>,
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
    ) -> DpPathFingerprint {
        let mut hasher = Sha256::new();
        match dp_path {
            ScionDpPathViewRef::Empty => {
                hasher.update([u8::from(PathType::Empty)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
            }
            ScionDpPathViewRef::Standard(standard_path) => {
                hasher.update([u8::from(PathType::Scion)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                standard_path.hop_fields().iter().for_each(|hf| {
                    hasher.update(hf.cons_ingress().to_be_bytes());
                    hasher.update(hf.cons_egress().to_be_bytes());
                });
            }
            ScionDpPathViewRef::Unsupported { path_type, data } => {
                hasher.update([u8::from(path_type)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                hasher.update(data.as_ref());
            }
            ScionDpPathViewRef::OneHop(onehop) => {
                hasher.update([u8::from(PathType::OneHop)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                onehop.hop_fields().iter().for_each(|hf| {
                    hasher.update(hf.cons_ingress().to_be_bytes());
                    hasher.update(hf.cons_egress().to_be_bytes());
                });
            }
        }

        DpPathFingerprint(hasher.finalize().into())
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
impl AsRef<[u8]> for DpPathFingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl TryFrom<&[u8]> for DpPathFingerprint {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}
impl From<[u8; 32]> for DpPathFingerprint {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}
impl fmt::Display for DpPathFingerprint {
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
impl fmt::LowerHex for DpPathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, true)
    }
}
impl fmt::UpperHex for DpPathFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, false)
    }
}
