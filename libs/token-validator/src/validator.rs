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
//! Token validator and token trait.

use std::{marker::PhantomData, time::SystemTime};

use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, errors::Error as JwtError,
};
use pem::Pem;
use serde::Deserialize;
use thiserror::Error;

/// Token is the interface for tokens. It provides methods to get the expiration
/// time and the required claims.
pub trait Token: std::fmt::Debug + Send + Clone + 'static {
    /// Returns the ID of the token.
    fn id(&self) -> String;
    /// Returns the absolute expiration time of the token.
    fn exp_time(&self) -> SystemTime;
    /// Returns the required claims for the token. This is enforced during
    /// JWT validation.
    fn required_claims() -> Vec<&'static str>;
}

/// TokenValidator is the interface to validate a JWT token and extract the
/// claims.
pub trait TokenValidator<C>: Send + Sync
where
    C: for<'de> Deserialize<'de> + Token + Clone,
{
    /// Validates the token and returns the claims if the token is valid.
    fn validate(&self, now: SystemTime, token: &str) -> Result<C, TokenValidatorError>;
}

/// Token validation errors.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum TokenValidatorError {
    /// JWT errors.
    #[error("JWT error: {0}")]
    JwtError(JwtError),
    /// JWT signature is invalid.
    #[error("JWT signature is invalid")]
    JwtSignatureInvalid(),
    /// Expired token error.
    #[error("token expired: {0:?}")]
    TokenExpired(SystemTime),
}

/// A validator for JWT tokens using the EdDSA algorithm. The validator also
/// checks for the required claims in the token and checks if the token is
/// expired.
#[derive(Clone)]
pub struct Validator<C>
where
    C: for<'de> Deserialize<'de> + Token,
{
    public_key: DecodingKey,
    validator: Validation,

    // Here, we need to pull a type-foo trick to make `Validator: Sync`, even
    // though `C` is `!Sync`: `fn() -> C` is `Sync`, even if `C: !Sync`.
    _marker: PhantomData<fn() -> C>,
}

impl<C> Validator<C>
where
    C: for<'de> Deserialize<'de> + Token,
{
    /// Creates a new token validator.
    ///
    /// # Arguments
    /// * `public_key`: The public key to verify the token signature.
    /// * `audience`: Optional audience to validate the token against. If `None`, the audience is
    ///   not validated.
    pub fn new(public_key: DecodingKey, audience: Option<&[&str]>) -> Self {
        let mut validator = Validation::new(Algorithm::EdDSA);
        validator.set_required_spec_claims(&C::required_claims());
        if let Some(audience) = audience {
            validator.set_audience(audience);
        } else {
            validator.validate_aud = false;
        }

        Self {
            public_key,
            validator,
            _marker: PhantomData,
        }
    }
}

impl<C> TokenValidator<C> for Validator<C>
where
    C: for<'de> Deserialize<'de> + Token,
{
    fn validate(&self, now: SystemTime, token: &str) -> Result<C, TokenValidatorError> {
        let token_data: TokenData<C> = decode::<C>(token, &self.public_key, &self.validator)?;

        let token_exp = token_data.claims.exp_time();
        if now > token_exp {
            return Err(TokenValidatorError::TokenExpired(token_exp));
        }

        Ok(token_data.claims)
    }
}

/// Returns constant key pair in PEM format for testing purposes.
pub fn insecure_const_ed25519_key_pair_pem() -> (Pem, Pem) {
    let signing_key = insecure_const_ed25519_signing_key();

    let public_key = ed25519_dalek::pkcs8::PublicKeyBytes(*signing_key.verifying_key().as_bytes());

    let kp = ed25519_dalek::pkcs8::KeypairBytes {
        secret_key: *signing_key.as_bytes(),
        public_key: Some(public_key),
    };

    let private_pem = pem::Pem::new("PRIVATE KEY", kp.to_pkcs8_der().unwrap().as_bytes());
    let public_pem = pem::Pem::new(
        "PUBLIC KEY",
        public_key.to_public_key_der().unwrap().as_bytes(),
    );

    (private_pem, public_pem)
}

/// Returns a constant Ed25519 signing key for testing purposes.
pub fn insecure_const_ed25519_signing_key() -> ed25519_dalek::SigningKey {
    let seed = [43u8; 32];
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

impl From<JwtError> for TokenValidatorError {
    fn from(value: JwtError) -> Self {
        use jsonwebtoken::errors::*;
        // For now, we only explicitly expose signature errors and don't commit
        // to report all other jsonwebtoken-errors, so we can swap out the
        // underlying implementation.
        if let ErrorKind::InvalidSignature = value.kind() {
            return TokenValidatorError::JwtSignatureInvalid();
        }
        TokenValidatorError::JwtError(value)
    }
}
