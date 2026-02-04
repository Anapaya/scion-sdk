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
//! SNAP token claims version 1.

use std::{collections::BTreeMap, fmt::Display, time::SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use scion_sdk_token_validator::validator::Token;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The version 1 pseudo SCION subscription identifier.
///
/// It is derived as Base64URL(0x00 || UUID_Bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pssid(Uuid);

impl Pssid {
    /// Creates a new V1 PSSID from the given subscription_id.
    pub fn new(subscription_id: Uuid) -> Self {
        Self(subscription_id)
    }
}

impl Display for Pssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Vec::with_capacity(17);
        bytes.push(0x00);
        bytes.extend_from_slice(self.0.as_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        write!(f, "{}", encoded)
    }
}

impl Serialize for Pssid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Pssid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;

        if bytes.len() != 17 {
            return Err(serde::de::Error::custom(format!(
                "invalid PSSID length: expected 17, got {}",
                bytes.len()
            )));
        }
        if bytes[0] != 0x00 {
            return Err(serde::de::Error::custom(format!(
                "invalid PSSID version: expected 0, got {}",
                bytes[0]
            )));
        }

        let uuid_bytes: [u8; 16] = bytes[1..].try_into().unwrap();
        Ok(Pssid(Uuid::from_bytes(uuid_bytes)))
    }
}

/// The V1 SNAP token claims.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapTokenClaims {
    /// Version of the token format.
    pub ver: usize,
    /// Issuer (SSR).
    pub iss: String,
    /// Audience (SNAP).
    pub aud: String,
    /// Expiration time (Seconds since epoch).
    pub exp: u64,
    /// Not before (Seconds since epoch).
    pub nbf: u64,
    /// Issued at (Seconds since epoch).
    pub iat: u64,
    /// JWT ID.
    pub jti: String,

    /// The pseudo SCION subscription identifier.
    pub pssid: Pssid,

    /// Arbitrary private claims.
    ///
    /// Usage of `flatten` allows us to handle `aa_acc_subject_id` and other
    /// future claims dynamically without schema changes, while `Token::required_claims`
    /// ensures mandatory ones are present.
    #[serde(flatten)]
    private_claims: BTreeMap<String, serde_json::Value>,
}

impl SnapTokenClaims {
    /// Create a new SnapTokenClaims.
    pub fn new(pssid: Pssid, iat: SystemTime, nbf: SystemTime, exp: SystemTime) -> Self {
        let iat_secs = iat
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("issued at is before epoch")
            .as_secs();
        let nbf_secs = nbf
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("not before is before epoch")
            .as_secs();
        let exp_secs = exp
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("expiration is before epoch")
            .as_secs();

        Self {
            ver: 1,
            iss: "ssr".to_string(),
            aud: "snap".to_string(),
            exp: exp_secs,
            nbf: nbf_secs,
            iat: iat_secs,
            jti: Uuid::new_v4().to_string(),
            pssid,
            private_claims: BTreeMap::new(),
        }
    }

    /// Set a private claim.
    ///
    /// Returns an error if the key is reserved.
    pub fn set_private_claim(
        &mut self,
        key: String,
        value: serde_json::Value,
    ) -> Result<(), String> {
        let reserved = ["ver", "iss", "aud", "exp", "nbf", "iat", "jti", "pssid"];
        if reserved.contains(&key.as_str()) {
            return Err(format!("claim key '{}' is reserved", key));
        }
        self.private_claims.insert(key, value);
        Ok(())
    }

    /// Get private claims.
    pub fn private_claims(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.private_claims
    }
}

impl Token for SnapTokenClaims {
    fn id(&self) -> String {
        self.jti.clone()
    }

    fn exp_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.exp)
    }

    fn required_claims() -> Vec<&'static str> {
        vec!["ver", "iss", "aud", "exp", "nbf", "iat", "jti", "pssid"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pssid_derivation() {
        let subscription_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let pssid = Pssid::new(subscription_id);
        assert_eq!(pssid.to_string(), "ABI-RWfomxLTpFZCZhQXQAA");

        // Map back to subscription_id
        let decoded = URL_SAFE_NO_PAD.decode(pssid.to_string()).unwrap();
        assert_eq!(decoded.len(), 17);
        assert_eq!(decoded[0], 0x00);
        let uuid_bytes: [u8; 16] = decoded[1..].try_into().unwrap();
        let derived_uuid = Uuid::from_bytes(uuid_bytes);
        assert_eq!(derived_uuid, subscription_id);

        // Serialization
        let json = serde_json::to_string(&pssid).unwrap();
        assert_eq!(json, "\"ABI-RWfomxLTpFZCZhQXQAA\"");

        // Deserialization
        let pssid2: Pssid = serde_json::from_str(&json).unwrap();
        assert_eq!(pssid2, pssid);
    }
}
