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
//! SNAP token library.

pub mod v0;
pub mod v1;

use std::time::SystemTime;

use scion_sdk_token_validator::validator::Token;
use serde::{Deserialize, Serialize};

/// A wrapper that can handle any version of SNAP token claims.
///
/// It uses a custom deserializer to inspect the `ver` field:
/// - `ver` matches a known version (e.g., 1): Deserializes into that version.
/// - `ver` is missing: Falls back to V0 (legacy).
/// - `ver` is unknown: Returns an error.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum AnyClaims {
    /// Version 1 SNAP token claims.
    V1(v1::SnapTokenClaims),
    /// Legacy Version 0 SNAP token claims.
    V0(v0::SnapTokenClaims),
}

impl<'de> Deserialize<'de> for AnyClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        // Inspect for "ver" to determine version explicitly.
        // This ensures forward compatibility (we won't accidentally parse V2 as V1).
        if let Some(ver) = value.get("ver") {
            match ver.as_u64() {
                Some(1) => {
                    let claims: v1::SnapTokenClaims =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    Ok(AnyClaims::V1(claims))
                }
                Some(n) => {
                    Err(serde::de::Error::custom(format!(
                        "unsupported SNAP token version: {}",
                        n
                    )))
                }
                None => {
                    Err(serde::de::Error::custom(
                        "invalid SNAP token: 'ver' claim must be a number",
                    ))
                }
            }
        } else {
            // No version claim -> Legacy V0
            let claims: v0::SnapTokenClaims =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(AnyClaims::V0(claims))
        }
    }
}

impl Token for AnyClaims {
    fn id(&self) -> String {
        match self {
            Self::V1(c) => c.id(),
            Self::V0(c) => c.id(),
        }
    }

    fn exp_time(&self) -> SystemTime {
        match self {
            Self::V1(c) => c.exp_time(),
            Self::V0(c) => c.exp_time(),
        }
    }

    fn required_claims() -> Vec<&'static str> {
        // We only enforce the intersection of claims required by *all* versions
        // at the generic JWT validation layer.
        vec!["exp", "pssid"]
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_any_claims_dispatch() {
        // Legacy V0 (No ver)
        let v0_json = json!({
            "jti": "jti_v0",
            "exp": 2000000000,
            "pssid": "ef16640f-0fa9-4360-be74-dbeec7ab4f9a"
        });
        let c: AnyClaims = serde_json::from_value(v0_json).expect("should parse as V0");
        assert!(matches!(c, AnyClaims::V0(_)));

        // V1 (ver = 1)
        let v1_json = json!({
            "ver": 1,
            "jti": "jti_v1",
            "iss": "ssr",
            "aud": "snap",
            "exp": 2000000000,
            "nbf": 1000,
            "iat": 1000,
            "pssid": "AAAAAAAAAAAAAAAAAAAAAAA",
            "aa_acc_subject_id": "subj",
            "aa_acc_allowed_dst": "[]"
        });
        let c: AnyClaims = serde_json::from_value(v1_json).expect("should parse as V1");
        assert!(matches!(c, AnyClaims::V1(_)));

        // V2 (Future/Unsupported)
        let v2_json = json!({
            "ver": 2,
            "exp": 2000000000
        });
        let err = serde_json::from_value::<AnyClaims>(v2_json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported SNAP token version: 2")
        );
    }
}
