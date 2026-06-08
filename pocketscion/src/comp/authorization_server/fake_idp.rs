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
//! This module provides a fake identity provider for testing purposes. The fake
//! identity provider provides a public key and can issue access tokens. The
//! access tokens are signed with an EdDSA key pair.

use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode};
use pem::Pem;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::token_exchanger::{
    EDGE_APP_CLIENT_ID, IdentityProvider, OpenIdToken, VerifyIdTokenError,
};

pub(crate) const FAKE_IDP_ISSUER: &str = "fake_idp";

/// Returns the public key PEM of the dummy identity provider.
pub fn fake_idp_public_key() -> Pem {
    let (_, public_pem) = const_fake_idp_key_pair();
    public_pem
}

/// Returns a OIDC ID token from the fake identity provider for the given
/// subject.
#[allow(unused)]
pub fn oidc_id_token(sub: String) -> String {
    let (idp_private_pem, _) = const_fake_idp_key_pair();

    let access_token_claims = OpenIdToken {
        iss: FAKE_IDP_ISSUER.to_string(),
        sub,
        aud: EDGE_APP_CLIENT_ID.to_string(),
        exp: (Utc::now() + chrono::Duration::from_std(Duration::from_secs(3600)).unwrap())
            .timestamp(),
        iat: Utc::now().timestamp(),
    };
    let idp_enc_key =
        EncodingKey::from_ed_pem(pem::encode(&idp_private_pem).as_bytes()).expect("no fail");
    jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &access_token_claims,
        &idp_enc_key,
    )
    .unwrap()
}

fn const_fake_idp_key_pair() -> (Pem, Pem) {
    let seed = [22u8; 32];
    let dalek_keypair = ed25519_dalek::SigningKey::from_bytes(&seed);

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

/// A fake identity provider for testing purposes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct FakeIdp {
    #[schema(value_type = String, example = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")]
    public_key: Pem,
}

impl FakeIdp {
    /// Creates a new fake identity provider with the given public key.
    pub fn new(public_key: Pem) -> Self {
        Self { public_key }
    }
}

impl Default for FakeIdp {
    fn default() -> Self {
        Self::new(fake_idp_public_key())
    }
}

impl IdentityProvider for FakeIdp {
    fn verify_id_token(
        &self,
        id_token: &str,
    ) -> Result<TokenData<OpenIdToken>, VerifyIdTokenError> {
        let decoding_key =
            DecodingKey::from_ed_pem(pem::encode(&self.public_key).as_bytes()).expect("no fail");

        let mut validator = Validation::new(Algorithm::EdDSA);
        validator.set_audience(&[EDGE_APP_CLIENT_ID.to_string()]);
        decode::<OpenIdToken>(id_token, &decoding_key, &validator).map_err(VerifyIdTokenError::from)
    }
}
