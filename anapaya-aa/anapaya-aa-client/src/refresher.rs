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

//! [`ApiKeyTokenRefresher`] fetches and renews SNAP tokens using static API key credentials via the
//! Anapaya AA (Auth/n Auth/z) AuthService.
//!
//! [`ApiKeyTokenRefresher`] implements [`TokenRefresher`] so it can be composed directly with
//! [`scion_sdk_reqwest_connect_rpc::token_source::refresh::RefreshTokenSource`]:
//!
//! ```no_run
//! use anapaya_aa_client::{ApiKeyTokenRefresher, CrpcAaAuthClient};
//! use scion_sdk_reqwest_connect_rpc::token_source::refresh::RefreshTokenSource;
//!
//! async fn setup(aa_url: url::Url, api_key: String) -> anyhow::Result<()> {
//!     let client = CrpcAaAuthClient::new(&aa_url)?;
//!     let refresher = ApiKeyTokenRefresher::new(client, api_key, "my-device-id".into());
//!     let token_source = RefreshTokenSource::builder("aa-api-key", refresher).build();
//!     Ok(())
//! }
//! ```

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anapaya_aa_protobuf::v1::Metadata;
use async_trait::async_trait;
use scion_sdk_reqwest_connect_rpc::token_source::{
    TokenSourceError,
    refresh::{TokenRefresher, TokenWithExpiry},
};
use serde::Deserialize;
use thiserror::Error;

use crate::client::AaAuthClient;

/// Errors returned when refreshing a SNAP token via an API key.
#[derive(Debug, Error)]
pub enum ApiKeyTokenRefresherError {
    /// The Anapaya AA service returned an error.
    #[error("AA authenticate-by-key error: {0:#}")]
    RpcError(#[from] scion_sdk_reqwest_connect_rpc::client::CrpcClientError),
    /// The SNAP token returned by the AA service could not be decoded.
    #[error("failed to decode SNAP token JWT: {0}")]
    JwtDecodeError(#[from] jsonwebtoken::errors::Error),
    /// The `exp` claim in the SNAP token could not be converted to a valid
    /// future point in time.
    #[error("SNAP token exp claim ({exp_unix}) is too far in the past to derive a valid Instant")]
    ExpInThePast {
        /// The raw Unix timestamp from the `exp` claim.
        exp_unix: u64,
    },
}

/// Minimal JWT claims used solely to read the `exp` field.
#[derive(Deserialize)]
struct SnapClaims {
    /// JWT expiration time as a Unix timestamp (seconds).
    exp: u64,
}

/// Extract the `exp` claim from a SNAP token (JWT) and convert it to an
/// [`Instant`].
///
/// Signature validation is intentionally skipped as the SNAP will verify the token.
fn expires_at_from_token(token: &str) -> Result<Instant, ApiKeyTokenRefresherError> {
    // Disable signature verification - we trust the AA server over TLS.
    let token_data = jsonwebtoken::dangerous::insecure_decode::<SnapClaims>(token)?;

    let exp_unix = token_data.claims.exp;
    let exp_system = UNIX_EPOCH + Duration::from_secs(exp_unix);

    let duration_until_exp = exp_system
        .duration_since(SystemTime::now())
        .map_err(|_| ApiKeyTokenRefresherError::ExpInThePast { exp_unix })?;

    Ok(Instant::now() + duration_until_exp)
}

/// Fetches and renews SNAP tokens from the Anapaya AA service using a static
/// API key.
pub struct ApiKeyTokenRefresher<C: AaAuthClient + 'static = crate::client::CrpcAaAuthClient> {
    client: C,
    api_key: String,
    device_id: String,
    requested_validity: i32,
}

impl<C: AaAuthClient + 'static> ApiKeyTokenRefresher<C> {
    /// Creates a new [`ApiKeyTokenRefresher`].
    ///
    /// # Arguments
    ///
    /// * `client` - An AA authentication client.
    /// * `api_key` - The API key (secret) for authenticating with the AA service.
    /// * `device_id` - Client-supplied device identifier.
    pub fn new(client: C, api_key: String, device_id: String) -> Self {
        Self {
            client,
            api_key,
            device_id,
            requested_validity: 0, // use default TTL
        }
    }

    /// Fetches a fresh SNAP token and returns it together with the optional
    /// [`Metadata`] from the AA response.
    ///
    /// Use this instead of [`TokenRefresher::refresh`] when you need the
    /// metadata (e.g. the endhost API discovery URL) from the bootstrap call.
    pub async fn refresh_with_metadata(
        &self,
    ) -> Result<(TokenWithExpiry, Option<Metadata>), TokenSourceError> {
        let result = self
            .client
            .authenticate_by_key(
                self.api_key.clone(),
                self.device_id.clone(),
                self.requested_validity,
            )
            .await
            .map_err(ApiKeyTokenRefresherError::RpcError)?;

        let snap_token = result.snap_token;
        let expires_at =
            expires_at_from_token(&snap_token).map_err(|e| Box::new(e) as TokenSourceError)?;

        // Assuming signed, JWT-token, the signature should provide a unique
        // identifier for the token.
        let token_sig = snap_token.rsplit('.').next().unwrap_or("");
        tracing::debug!(
            token_sig,
            expires_at_secs = expires_at
                .checked_duration_since(Instant::now())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "Fetched new SNAP token via API key"
        );

        Ok((
            TokenWithExpiry {
                token: snap_token,
                expires_at,
            },
            result.metadata,
        ))
    }
}

#[async_trait]
impl<C: AaAuthClient + 'static> TokenRefresher for ApiKeyTokenRefresher<C> {
    async fn refresh(&self) -> Result<TokenWithExpiry, TokenSourceError> {
        let (token_with_expiry, _metadata) = self.refresh_with_metadata().await?;
        Ok(token_with_expiry)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::client::{AuthResult, MockAaAuthClient};

    /// Create a signed HS256 JWT with the given `exp` Unix timestamp.
    ///
    /// The signature is not verified during [`ApiKeyTokenRefresher::refresh`], so
    /// any HMAC key is acceptable here.
    fn make_test_token(exp: u64) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde::Serialize;

        #[derive(Serialize)]
        struct TestClaims {
            exp: u64,
        }

        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims { exp },
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("should encode test JWT")
    }

    /// Returns the Unix timestamp for `now + duration`.
    fn unix_now_plus(duration: Duration) -> u64 {
        (SystemTime::now() + duration)
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_secs()
    }

    #[test]
    fn expires_at_from_token_extracts_exp() {
        let exp_unix = unix_now_plus(Duration::from_secs(3600));
        let token = make_test_token(exp_unix);

        let expires_at =
            expires_at_from_token(&token).expect("should extract exp from valid token");

        // The derived Instant should be approximately 1 hour in the future.
        let secs_until_expiry = expires_at
            .checked_duration_since(Instant::now())
            .expect("expires_at should be in the future")
            .as_secs();

        assert!(
            (3550..=3650).contains(&secs_until_expiry),
            "expected ~3600 s until expiry, got {secs_until_expiry}"
        );
    }

    #[test]
    fn expires_at_from_token_rejects_expired_token() {
        // Already-expired token: exp is 1 second before now.
        let exp_unix = unix_now_plus(Duration::ZERO).saturating_sub(1);
        let token = make_test_token(exp_unix);

        let result = expires_at_from_token(&token);

        assert!(
            matches!(result, Err(ApiKeyTokenRefresherError::ExpInThePast { .. })),
            "expected ExpInThePast, got {result:?}"
        );
    }

    #[test]
    fn expires_at_from_token_rejects_malformed_jwt() {
        let result = expires_at_from_token("not.a.token");
        assert!(
            matches!(result, Err(ApiKeyTokenRefresherError::JwtDecodeError(_))),
            "expected JwtDecodeError, got {result:?}"
        );
    }

    #[tokio::test]
    async fn refresh_returns_token_with_correct_expiry() {
        let exp_unix = unix_now_plus(Duration::from_secs(1800));
        let snap_token = make_test_token(exp_unix);
        let snap_token_clone = snap_token.clone();

        let mut mock_client = MockAaAuthClient::new();
        mock_client
            .expect_authenticate_by_key()
            .once()
            .returning(move |_, _, _| {
                Ok(AuthResult {
                    snap_token: snap_token_clone.clone(),
                    metadata: None,
                })
            });

        let refresher =
            ApiKeyTokenRefresher::new(mock_client, "test-api-key".into(), "test-device".into());

        let result = refresher.refresh().await.expect("refresh should succeed");

        assert_eq!(result.token, snap_token);

        let secs_until_expiry = result
            .expires_at
            .checked_duration_since(Instant::now())
            .expect("token should not be expired")
            .as_secs();

        assert!(
            (1750..=1850).contains(&secs_until_expiry),
            "expected ~1800 s until expiry, got {secs_until_expiry}"
        );
    }

    #[tokio::test]
    async fn refresh_propagates_rpc_error() {
        let mut mock_client = MockAaAuthClient::new();
        mock_client.expect_authenticate_by_key().once().returning(
            |_, _, _| -> Result<AuthResult, _> {
                Err(
                    scion_sdk_reqwest_connect_rpc::client::CrpcClientError::ConnectionError {
                        context: "test: connection refused".into(),
                        source: Box::new(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "connection refused",
                        )),
                    },
                )
            },
        );

        let refresher =
            ApiKeyTokenRefresher::new(mock_client, "test-api-key".into(), "test-device".into());

        let result = refresher.refresh().await;

        assert!(result.is_err(), "expected error from RPC failure");
    }
}
