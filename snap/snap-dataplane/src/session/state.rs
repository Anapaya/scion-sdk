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
//! SNAP data plane session state.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{
    SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use pem::Pem;
use rand::RngCore;
use scion_sdk_common_types::ed25519::Ed25519SigningKeyPem;
use serde::{Deserialize, Serialize};
use snap_tokens::{Pssid, session_token::SessionTokenClaims};

use super::manager::{SessionTokenError, TokenIssuer};
use crate::state::Hostname;

pub mod dto;

const DEFAULT_SESSION_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// SNAP data plane session ID.
#[derive(Debug, Ord, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Clone)]
pub struct SessionId {
    pssid: Pssid,
    hostname: Hostname,
}

impl SessionId {
    /// Creates a new SNAP data plane session ID.
    pub fn new(pssid: Pssid, hostname: Hostname) -> Self {
        Self { pssid, hostname }
    }
}

/// Manages data plane sessions.
///
/// A session is identified by the pseudo SCION subscriber identity (PSSID) from the SNAP token. At
/// any point in time, there is at most one session open with a data plane per PSSID.
///
/// Note: We might need to weaken this constraint in the future to allow multiple session per data
/// plane to allow session failover in case only a single data plane is running.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct SessionManagerState {
    /// The maximum duration of a session.
    session_duration: Duration,
    /// The currently open sessions.
    sessions: BTreeMap<SessionId, Session>,
}

impl SessionManagerState {
    /// Creates a new session manager state with the given session duration.
    pub fn new(session_duration: Duration) -> Self {
        Self {
            session_duration,
            sessions: BTreeMap::new(),
        }
    }

    /// Opens a new SNAP data plane session for the given PSSID and data plane ID.
    // XXX(bunert): We allow multiple sessions per PSSID for now. Later we might want to
    // disallow this when we properly remove sessions from terminated connections.
    pub fn open(
        &mut self,
        pssid: Pssid,
        hostname: Hostname,
    ) -> Result<SessionGrant, SessionOpenError> {
        let session_id = SessionId::new(pssid.clone(), hostname);
        let session_expiry = SystemTime::now() + self.session_duration;

        // XXX(bunert): For now it does not matter if we create a new session or update an existing
        // one.
        let _res = self
            .sessions
            .insert(session_id, Session::new(session_expiry));

        Ok(SessionGrant {
            expiry: session_expiry,
        })
    }
}

/// Errors that can occur during session management.
#[derive(Debug, thiserror::Error)]
pub enum SessionOpenError {}

impl Default for SessionManagerState {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_DURATION)
    }
}

/// Grant for a session required to issue session tokens.
pub struct SessionGrant {
    // The expiration time of the session.
    expiry: SystemTime,
}

/// Open data plane session.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct Session {
    expiry: SystemTime,
}

impl Session {
    fn new(expiry: SystemTime) -> Self {
        Self { expiry }
    }
}

/// Session token issuer state. Allows issuing session tokens for the opened data plane sessions
/// depending on the SNAP token validity of the session.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct SessionTokenIssuerState {
    /// The encoding key (PEM format) used to issue session tokens.
    key: Ed25519SigningKeyPem,
}

impl SessionTokenIssuerState {
    /// Creates a new session token issuer state with the given signing key.
    pub fn new(key: Ed25519SigningKeyPem) -> Self {
        Self { key }
    }
}

impl TokenIssuer for SessionTokenIssuerState {
    fn issue(
        &self,
        pssid: Pssid,
        hostname: Hostname,
        session_grant: SessionGrant,
    ) -> Result<String, SessionTokenError> {
        let claims = SessionTokenClaims {
            pssid,
            hostname: hostname.to_string(),
            exp: session_grant
                .expiry
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let encoding_key = (&self.key).into();
        let token = jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key)
            .map_err(SessionTokenError::EncodingError)?;
        Ok(token)
    }
}

/// Returns a session key pair for the given SNAP ID.
///
/// Note: This is only for testing purposes.
pub fn insecure_const_session_key_pair(input: usize) -> (EncodingKey, DecodingKey) {
    let (private_pem, public_pem) = insecure_const_session_key_pair_pem(input);

    let encoding_key = EncodingKey::from_ed_pem(pem::encode(&private_pem).as_bytes()).unwrap();
    let decoding_key = DecodingKey::from_ed_pem(pem::encode(&public_pem).as_bytes()).unwrap();

    (encoding_key, decoding_key)
}

/// Returns a session key pair for the given SNAP ID in PEM format.
///
/// Note: This is only for testing purposes.
pub fn insecure_const_session_key_pair_pem(input: usize) -> (Pem, Pem) {
    let dalek_keypair = insecure_const_ed25519_signing_key(input);
    let public_key =
        ed25519_dalek::pkcs8::PublicKeyBytes(*dalek_keypair.verifying_key().as_bytes());

    let kp = ed25519_dalek::pkcs8::KeypairBytes {
        secret_key: *dalek_keypair.as_bytes(),
        public_key: Some(public_key),
    };

    let private_pem = pem::Pem::new("PRIVATE KEY", kp.to_pkcs8_der().unwrap().as_bytes());

    let public_pem = pem::Pem::new(
        "PUBLIC KEY",
        public_key.to_public_key_der().unwrap().as_bytes(),
    );

    (private_pem, public_pem)
}

/// Returns a seeded Ed25519 signing key.
pub fn insecure_const_ed25519_signing_key(input: usize) -> SigningKey {
    let mut seed = [43u8; 32];
    let id_bytes = input.to_le_bytes();
    seed[..id_bytes.len()].copy_from_slice(&id_bytes);

    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// Returns a random Ed25519 signing key.
pub fn random_ed25519_signing_key() -> SigningKey {
    let mut trng = rand::rng();
    let mut seed = [0u8; 32];
    trng.fill_bytes(&mut seed[..]);

    ed25519_dalek::SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use scion_sdk_token_validator::validator::{TokenValidator, Validator};
    use snap_tokens::snap_token::SnapTokenClaims;
    use test_log::test;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn session_management_lifecycle() {
        let claims = SnapTokenClaims {
            pssid: Pssid(Uuid::new_v4()),
            exp: (SystemTime::now() + Duration::from_secs(360))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let hostname: Hostname = "test-host".try_into().expect("valid hostname");

        let signing_key = insecure_const_ed25519_signing_key(0);
        let signing_key = Ed25519SigningKeyPem::from(signing_key);
        let decoding_key = signing_key.to_decoding_key();
        let issuer = SessionTokenIssuerState::new(signing_key);

        let mut session_manager = SessionManagerState::default();

        let session_grant = session_manager
            .open(claims.pssid.clone(), hostname.clone())
            .unwrap();

        let session_token = issuer
            .issue(claims.pssid.clone(), hostname.clone(), session_grant)
            .unwrap();

        Validator::<SessionTokenClaims>::new(decoding_key, None)
            .validate(SystemTime::now(), &session_token)
            .expect("validation failed");

        // Open another session with the same PSSID should succeed for now.
        let _ = session_manager
            .open(claims.pssid.clone(), hostname.clone())
            .expect("open second session");
    }
}
