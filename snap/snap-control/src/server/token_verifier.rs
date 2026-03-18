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
//! SNAP token verifier supporting both static keys and JWKS-based key resolution.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use scion_sdk_token_validator::validator::Token;
use snap_tokens::AnyClaims;
use thiserror::Error;

use crate::server::jwks_key_store::JwksKeyStore;

/// Errors returned by [`SnapTokenVerifier::verify`].
#[derive(Debug, Error)]
pub enum SnapTokenVerifyError {
    /// Could not decode the JWT header.
    #[error("failed to decode JWT header: {0}")]
    HeaderDecodeError(jsonwebtoken::errors::Error),
    /// Token carries a `kid` that could not be resolved from the JWKS store.
    #[error("JWKS key not found for kid '{0}'")]
    UnknownKid(String),
    /// JWT signature/claims validation failed.
    #[error("token verification failed: {0}")]
    VerificationFailed(jsonwebtoken::errors::Error),
}

/// Verifies SNAP tokens against either a statically configured key or keys fetched
/// from a JWKS endpoint.
///
/// - Tokens **without** a `kid` JWT header claim are verified using the static key.
/// - Tokens **with** a `kid` are verified using a key resolved from the `JwksKeyStore`. If no JWKS
///   store is configured, the static key is used as a fallback.
#[derive(Clone)]
pub struct SnapTokenVerifier {
    static_key: DecodingKey,
    jwks_store: Option<Arc<JwksKeyStore>>,
    validation: Validation,
}

impl SnapTokenVerifier {
    /// Creates a verifier that only uses the statically configured key.
    /// Tokens with a `kid` header claim also use this key as a fallback when no JWKS
    /// store is configured.
    pub fn new(static_key: DecodingKey) -> Self {
        Self {
            static_key,
            jwks_store: None,
            validation: build_validation(),
        }
    }

    /// Attaches a JWKS store for resolving `kid`-bearing tokens.
    pub fn with_jwks_store(mut self, store: Arc<JwksKeyStore>) -> Self {
        self.jwks_store = Some(store);
        self
    }

    /// Verifies a SNAP token JWT and returns the parsed claims on success.
    ///
    /// # Key selection
    ///
    /// - If the JWT header has a `kid` and a JWKS store is configured, the key is resolved from the
    ///   JWKS store.
    /// - Otherwise (no `kid`, or `kid` present but no JWKS store configured), the static key is
    ///   used.
    pub async fn verify(&self, token: &str) -> Result<AnyClaims, SnapTokenVerifyError> {
        let header = decode_header(token).map_err(SnapTokenVerifyError::HeaderDecodeError)?;

        let key = match (header.kid, &self.jwks_store) {
            (Some(kid), Some(store)) => {
                match store.await_key(&kid).await {
                    Some(k) => k,
                    None => return Err(SnapTokenVerifyError::UnknownKid(kid)),
                }
            }
            _ => self.static_key.clone(),
        };

        let token_data = decode::<AnyClaims>(token, &key, &self.validation)
            .map_err(SnapTokenVerifyError::VerificationFailed)?;

        Ok(token_data.claims)
    }
}

fn build_validation() -> Validation {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_required_spec_claims(&AnyClaims::required_claims());
    v.set_audience(&["snap"]);
    v
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use scion_sdk_token_validator::validator::insecure_const_ed25519_signing_key;
    use snap_tokens::v0::{self, SnapTokenClaims, insecure_const_snap_token_key_pair};
    use tokio_util::sync::CancellationToken;

    use super::*;

    // --- helpers ---

    fn static_verifier() -> SnapTokenVerifier {
        let (_, decoding_key) = insecure_const_snap_token_key_pair();
        SnapTokenVerifier::new(decoding_key)
    }

    fn v0_token() -> String {
        v0::dummy_snap_token()
    }

    fn expired_v0_token() -> String {
        let (encoding_key, _) = insecure_const_snap_token_key_pair();
        let claims = SnapTokenClaims {
            pssid: v0::Pssid::new(),
            exp: 1, // far in the past
        };
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap()
    }

    fn v1_token_with_kid_and_static_key(kid: &str) -> String {
        let (encoding_key, _) = insecure_const_snap_token_key_pair();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "ver": 1,
            "iss": "ssr",
            "aud": "snap",
            "exp": now + 3600,
            "nbf": now,
            "iat": now,
            "jti": "test-jti",
            "pssid": "AAAAAAAAAAAAAAAAAAAAAAA",
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
    }

    fn v1_token_with_kid(kid: &str) -> String {
        let signing_key = insecure_const_ed25519_signing_key();
        let der = signing_key.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ed_der(der.as_bytes());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build a minimal v1 claims payload.
        // pssid = base64url-no-pad of [0x00; 17] = 23 'A' chars.
        let claims = serde_json::json!({
            "ver": 1,
            "iss": "ssr",
            "aud": "snap",
            "exp": now + 3600,
            "nbf": now,
            "iat": now,
            "jti": "test-jti",
            "pssid": "AAAAAAAAAAAAAAAAAAAAAAA",
        });

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());

        jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
    }

    fn jwks_json_for_kid(kid: &str) -> serde_json::Value {
        let signing_key = insecure_const_ed25519_signing_key();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().as_bytes());
        serde_json::json!({
            "keys": [{
                "kid": kid,
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "crv": "Ed25519",
                "x": x
            }]
        })
    }

    async fn verifier_with_jwks_server(kid: &str) -> SnapTokenVerifier {
        use axum::{Json, Router, routing::get};

        let jwks = jwks_json_for_kid(kid);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let url = format!("http://{}/.well-known/jwks.json", addr)
            .parse()
            .unwrap();
        let (_, static_key) = insecure_const_snap_token_key_pair();
        let store = JwksKeyStore::new(url, Duration::from_secs(3600), CancellationToken::new());
        SnapTokenVerifier::new(static_key).with_jwks_store(Arc::new(store))
    }

    // --- tests ---

    #[tokio::test]
    async fn no_kid_uses_static_key_and_succeeds() {
        let verifier = static_verifier();
        let token = v0_token();
        let result = verifier.verify(&token).await;
        assert!(
            result.is_ok(),
            "valid V0 token should be accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn no_kid_invalid_signature_rejected() {
        let verifier = static_verifier();
        // Use a different key to sign the token (wrong key)
        let different_key = {
            let seed = [99u8; 32];
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let der = sk.to_pkcs8_der().unwrap();
            EncodingKey::from_ed_der(der.as_bytes())
        };
        let claims = SnapTokenClaims {
            pssid: v0::Pssid::new(),
            exp: (SystemTime::now() + Duration::from_secs(3600))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let bad_token =
            jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &different_key).unwrap();
        let result = verifier.verify(&bad_token).await;
        assert!(
            result.is_err(),
            "token signed with wrong key should be rejected"
        );
    }

    #[tokio::test]
    async fn no_kid_expired_token_rejected() {
        let verifier = static_verifier();
        let token = expired_v0_token();
        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[tokio::test]
    async fn kid_with_no_jwks_url_falls_back_to_static_key() {
        let verifier = static_verifier(); // no JWKS store
        let token = v1_token_with_kid_and_static_key("some-kid");
        let result = verifier.verify(&token).await;
        assert!(
            result.is_ok(),
            "token with kid but no JWKS URL should fall back to static key: {result:?}"
        );
    }

    #[tokio::test]
    async fn kid_resolved_via_jwks_succeeds() {
        let kid = "ssr-key-1";
        let verifier = verifier_with_jwks_server(kid).await;
        let token = v1_token_with_kid(kid);
        let result = verifier.verify(&token).await;
        assert!(
            result.is_ok(),
            "V1 token with JWKS-resolved key should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn unknown_kid_rejected() {
        let verifier = verifier_with_jwks_server("other-kid").await;
        let token = v1_token_with_kid("unknown-kid");
        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "token with unknown kid should be rejected");
    }
}
