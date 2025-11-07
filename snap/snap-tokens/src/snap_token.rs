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
//! SNAP token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use scion_sdk_token_validator::validator::{Token, insecure_const_ed25519_key_pair_pem};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Pssid;

// The default validity period for SNAP tokens, in seconds.
const DEFAULT_SNAP_TOKEN_VALIDITY: u64 = 86400; // 1d

/// Represents the SNAP token claims contained in a JWT.
///
/// The claims include the pseudo SCION subscriber identity (`pssid`) and the expiration
/// time (`exp`) of the JWT.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapTokenClaims {
    /// The pseudo SCION subscriber identity (PSSID).
    pub pssid: Pssid,
    /// The expiration time of the JWT, represented as a Unix timestamp.
    pub exp: u64,
}

impl Token for SnapTokenClaims {
    fn id(&self) -> String {
        self.pssid.to_string()
    }
    fn exp_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.exp)
    }
    fn required_claims() -> Vec<&'static str> {
        vec!["exp", "pssid"]
    }
}

/// Creates mock SNAP tokens
#[derive(Clone)]
pub struct MockSnapTokenCreator {
    uuid: Uuid,
    token_validity: u64,
}

impl MockSnapTokenCreator {
    /// Create a new `MockSnapTokenCreator` with the provided token validity in seconds.
    pub fn new_with_expiry(token_validity: u64) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            token_validity,
        }
    }

    /// Create a new `MockSnapTokenCreator` with a deterministic PSSID based on the provided seed.
    pub fn new_seeded(seed: String) -> Self {
        Self {
            uuid: Uuid::new_v5(&SSID_NAMESPACE, seed.as_bytes()),
            token_validity: DEFAULT_SNAP_TOKEN_VALIDITY,
        }
    }

    /// Returns a SNAP token.
    pub fn token(&self) -> String {
        insecure_snap_token(self.uuid, self.token_validity)
    }
}

/// Returns a dummy SNAP token for testing purposes with a random PSSID.
pub fn dummy_snap_token() -> String {
    insecure_snap_token(Uuid::new_v4(), DEFAULT_SNAP_TOKEN_VALIDITY)
}

/// Returns a dummy SNAP token for testing purposes with a random PSSID that is valid for the
/// specified duration.
///
/// # Arguments
/// * `valid_seconds` - Number of seconds the SNAP token is valid.
pub fn dummy_snap_token_with_validity(valid_seconds: u64) -> String {
    // JWT expiry is exclusive, so we need to add 1 sec to make the token valid for `expiry`
    // seconds
    insecure_snap_token(Uuid::new_v4(), valid_seconds + 1)
}

const SSID_NAMESPACE: Uuid = Uuid::from_bytes([
    126, 135, 110, 147, 40, 228, 76, 8, 164, 39, 42, 4, 3, 103, 82, 211,
]);

/// Returns a dummy SNAP token for testing purposes with a deterministic PSSID based on the provided
/// seed.
pub fn seeded_dummy_snap_token(seed: String) -> String {
    insecure_snap_token(
        Uuid::new_v5(&SSID_NAMESPACE, seed.as_bytes()),
        DEFAULT_SNAP_TOKEN_VALIDITY,
    )
}

/// Returns a SNAP token with the given UUID and expiry (in seconds).
/// Uses a constant key pair thus it is insecure and only for testing purposes.
fn insecure_snap_token(uuid: Uuid, expiry: u64) -> String {
    let (encoding_key, _) = insecure_const_snap_token_key_pair();
    let claims = SnapTokenClaims {
        pssid: Pssid(uuid),
        exp: (SystemTime::now() + Duration::from_secs(expiry))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap()
}

/// Returns constant key pair for testing purposes.
pub fn insecure_const_snap_token_key_pair() -> (EncodingKey, DecodingKey) {
    let (private_pem, public_pem) = insecure_const_ed25519_key_pair_pem();

    let encoding_key = EncodingKey::from_ed_pem(pem::encode(&private_pem).as_bytes()).unwrap();
    let decoding_key = DecodingKey::from_ed_pem(pem::encode(&public_pem).as_bytes()).unwrap();

    (encoding_key, decoding_key)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, Header, encode};
    use scion_sdk_token_validator::validator::{TokenValidator, TokenValidatorError, Validator};
    use test_log::test;

    use super::*;

    #[test]
    fn validate_valid_token_succeeds() {
        let (_, decoding_key) = insecure_const_snap_token_key_pair();
        let validator: Validator<SnapTokenClaims> = Validator::new(decoding_key, None);
        let token = dummy_snap_token();
        let result = validator.validate(SystemTime::now(), &token);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_invalid_token_returns_error() {
        let (_encoding_key, decoding_key) = insecure_const_snap_token_key_pair();
        let validator: Validator<SnapTokenClaims> = Validator::new(decoding_key, None);
        let token = "invalid-jwt-token";
        let result = validator.validate(SystemTime::now(), token);
        assert!(matches!(result, Err(TokenValidatorError::JwtError(_))));
    }

    #[test]
    fn validate_expired_token_returns_error() {
        // A token expires at the exact expiry time. So if expiry == now
        let (encoding_key, decoding_key) = insecure_const_snap_token_key_pair();
        let validator: Validator<SnapTokenClaims> = Validator::new(decoding_key, None);

        let now = SystemTime::now();
        let expiry = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = SnapTokenClaims {
            pssid: Pssid(Uuid::new_v4()),
            exp: expiry,
        };
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

        let result = validator.validate(now, &token);
        assert!(matches!(result, Err(TokenValidatorError::TokenExpired(_))));
    }
}
