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

use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Error as JwtError,
};
use pem::Pem;
use serde::{Deserialize, Serialize};
use snap_tokens::v0::{Pssid, SnapTokenClaims};
use thiserror::Error;
use uuid::Uuid;

use super::{
    api::{TokenRequest, TokenResponse},
    fake_idp::FakeIdp,
};
use crate::{
    authorization_server::fake_idp::FAKE_IDP_ISSUER,
    dto::{TokenExchangerConfigDto, TokenExchangerStateDto},
};

/// If the issued token is not an access token or usable as an access token,
/// then the token_type value N_A is used to indicate that an OAuth 2.0
/// token_type identifier is not applicable in that context.
pub const NO_ACCESS_TOKEN_TYPE: &str = "N_A";

/// Token type identifier indicating that the token is a JWT.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The token exchange grant type.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Token type identifier indicating that the token is an ID token.
pub const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

/// The OAuth 2.0 client ID of the edge app. The openID connect ID tokens
/// audience must match this.
pub const EDGE_APP_CLIENT_ID: &str = "edge_app";

/// Identity provider trait.
pub trait IdentityProvider {
    /// Verifies the ID token and returns the token data.
    fn verify_id_token(&self, id_token: &str)
    -> Result<TokenData<OpenIdToken>, VerifyIdTokenError>;
}

/// Verify ID token error.
#[derive(Debug, Error, PartialEq)]
pub enum VerifyIdTokenError {
    /// JWT error.
    #[error("JWT error: {0}")]
    JwtError(#[from] JwtError),
}

/// TokenExchange is the interface for the auhtorization server to exchange an
/// openID connect (OIDC) ID token for a SNAP token.
pub trait TokenExchange: Send + Sync {
    /// exchanges an OIDC ID token for a SNAP token.
    fn exchange(&mut self, req: TokenRequest) -> Result<TokenResponse, TokenExchangeError>;
}

/// Token exchange errors.
#[derive(Debug, Error, PartialEq)]
pub enum TokenExchangeError {
    /// JWT error.
    #[error("JWT error: {0}")]
    JwtError(#[from] JwtError),
    /// Verify ID token error.
    #[error("token ID verification error: {0}")]
    VerifyIdTokenError(#[from] VerifyIdTokenError),
    /// Invalid grant type.
    #[error("invalid grant type: {0}")]
    InvalidGrantType(String),
    /// Invalid subject token type.
    #[error("unsupported subject token type: {0}")]
    InvalidSubjectTokenType(String),
    /// Unknown identity provider.
    #[error("unknown identity provider: {0}")]
    UnknownIdentityProvider(String),
}

/// OpenID connect ID token claims:
/// <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdToken {
    // REQUIRED. Issuer Identifier for the Issuer of the response.
    pub(crate) iss: String,
    // REQUIRED. Subject Identifier. A locally unique and never reassigned
    // identifier within the Issuer for the End-User.
    pub(crate) sub: String,
    // REQUIRED. Audience(s) that this ID Token is intended for.
    pub(crate) aud: String,
    // REQUIRED. Expiration time on or after which the ID Token MUST NOT be
    // accepted by the RP when performing authentication with the OP.
    pub(crate) exp: i64,
    // REQUIRED. Time at which the JWT was issued.
    pub(crate) iat: i64,
}

/// Configuration for the [TokenExchangeImpl].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenExchangeConfig {
    /// The private key to sign the SNAP tokens (PEM encoded).
    private_key: Pem,
    /// The lifetime of the SNAP tokens.
    token_lifetime: Duration,
    /// The fake identity provider for testing.
    fake_idp: FakeIdp,
}

impl From<&TokenExchangeConfig> for TokenExchangerConfigDto {
    fn from(config: &TokenExchangeConfig) -> Self {
        Self {
            private_key: config.private_key.to_string(),
            token_lifetime: config.token_lifetime,
            fake_idp: (&config.fake_idp).into(),
        }
    }
}

impl TryFrom<TokenExchangerConfigDto> for TokenExchangeConfig {
    type Error = anyhow::Error;

    fn try_from(value: TokenExchangerConfigDto) -> Result<Self, Self::Error> {
        Ok(Self {
            private_key: Pem::from_str(&value.private_key)
                .context("invalid PEM format for session token issuer key")?,
            token_lifetime: value.token_lifetime,
            fake_idp: FakeIdp::try_from(value.fake_idp)
                .context("invalid fake IDP configuration")?,
        })
    }
}

impl TokenExchangeConfig {
    /// Creates a new [TokenExchangeConfig].
    pub fn new(private_key: Pem, token_lifetime: Duration) -> Self {
        Self {
            private_key,
            token_lifetime,
            fake_idp: FakeIdp::default(),
        }
    }
}

/// The SCION subscription ID (SSID).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Ssid(pub String);

/// [TokenExchangeImpl] is responsible for exchanging ID tokens for SNAP tokens.
///
/// The SNAP token contains the pseudo SCION subsription ID (PSSID) such that
/// the SNAP only knows the PSSID of the endhost. The authorization server needs
/// to keep track of the mapping between the SCION subscription ID (SSID) and
/// the PSSID.
///
/// The SNAP token JWTs are signed with the EdDSA algorithm with the configured
/// private key. The corresponding public key is needed by the SNAPs to verify
/// the SNAP tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenExchangeImpl {
    config: TokenExchangeConfig,
    id_mapping: HashMap<Ssid, Pssid>,
}

impl From<&TokenExchangeImpl> for TokenExchangerStateDto {
    fn from(value: &TokenExchangeImpl) -> Self {
        Self {
            config: (&value.config).into(),
            id_mapping: value
                .id_mapping
                .iter()
                .map(|(id, pssid)| (id.0.clone(), pssid.0.to_string()))
                .collect(),
        }
    }
}

impl TryFrom<TokenExchangerStateDto> for TokenExchangeImpl {
    type Error = anyhow::Error;

    fn try_from(value: TokenExchangerStateDto) -> Result<Self, Self::Error> {
        let config = TokenExchangeConfig::try_from(value.config)?;
        let id_mapping = value
            .id_mapping
            .into_iter()
            .map(|(id, uuid)| {
                Ok((
                    Ssid(id),
                    Pssid(Uuid::from_str(&uuid).context("invalid UUID")?),
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        Ok(Self { config, id_mapping })
    }
}

impl TokenExchangeImpl {
    /// Creates a new [TokenExchangeImpl] with the given configuration.
    pub fn new(config: TokenExchangeConfig) -> Self {
        Self {
            config,
            id_mapping: HashMap::new(),
        }
    }
}

impl TokenExchange for TokenExchangeImpl {
    fn exchange(&mut self, req: TokenRequest) -> Result<TokenResponse, TokenExchangeError> {
        tracing::debug!(request=?req, "Received token exchange request");

        if req.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
            tracing::debug!(grant_type=%req.grant_type, "Invalid grant type");
            return Err(TokenExchangeError::InvalidGrantType(req.grant_type));
        }

        if req.subject_token_type != ID_TOKEN_TYPE {
            tracing::debug!(subject_token_type=%req.subject_token_type, "Unsupported subject token type");
            return Err(TokenExchangeError::InvalidSubjectTokenType(
                req.subject_token_type,
            ));
        }

        let id_token = &req.subject_token;

        // First decode the ID token to get the issuer of the ID token for verification.
        let mut validator = Validation::new(Algorithm::EdDSA);
        validator.insecure_disable_signature_validation();
        validator.set_audience(&[EDGE_APP_CLIENT_ID.to_string()]);

        let decoded_token =
            decode::<OpenIdToken>(id_token, &DecodingKey::from_secret(b""), &validator)?;

        tracing::debug!(token=?decoded_token, "Exchanging token");

        let verified_id_token = match decoded_token.claims.iss.as_str() {
            FAKE_IDP_ISSUER => self.config.fake_idp.verify_id_token(id_token)?,
            _ => {
                return Err(TokenExchangeError::UnknownIdentityProvider(
                    decoded_token.claims.iss,
                ));
            }
        };

        // The authorization server is configured with a mapping of identities
        // (sub claims) to SCION subscription IDs (SSID). If the ID token is not
        // found no SNAP token is granted. In addition, the authorization server
        // derives a pseudo SCION subscription ID (PSSID) from the SSID for
        // privacy reasons. This mapping must be kept for for the accounting
        // service.
        //
        // In the scope of pocket SCION we don't care about the SSID and just
        // generate PSSID for the sub claim.
        let pssid = self
            .id_mapping
            .entry(Ssid(verified_id_token.claims.sub.clone()))
            .or_insert_with(|| Pssid(Uuid::new_v4()));

        // SNAP token claims
        let snap_token_claims = SnapTokenClaims {
            pssid: pssid.clone(),
            exp: (SystemTime::now() + self.config.token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let snap_token_enc_key =
            EncodingKey::from_ed_pem(pem::encode(&self.config.private_key).as_bytes())
                .expect("no fail");
        let snap_token = encode(
            &Header::new(Algorithm::EdDSA),
            &snap_token_claims,
            &snap_token_enc_key,
        )?;

        Ok(TokenResponse {
            access_token: snap_token,
            issued_token_type: JWT_TOKEN_TYPE.to_string(),
            token_type: NO_ACCESS_TOKEN_TYPE.to_string(),
            expires_in: self.config.token_lifetime.as_secs(),
            // Optional if the scope is identical to the scope requested by the
            // client.
            scope: None,
        })
    }
}
