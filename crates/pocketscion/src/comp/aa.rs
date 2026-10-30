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

//! PocketSCION AA: a simple Authentication and Authorization (AA) service in a local PocketSCION
//! network.
//!
//! The PocketSCION AA gives a SNAP token to each caller so the AA does not really enforce
//! authentication and authorization in this test environment.
//!
//! A stack gets its tokens from the AA through [`PocketScionAaTokenSource`].
//!
//! On a real SCION network, you must use a production AA.

pub mod api;
pub mod token_source;

use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pem::Pem;
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use snap_tokens::v0::{Pssid, SnapTokenClaims};
pub use token_source::PocketScionAaTokenSource;
use uuid::Uuid;

use crate::{comp::aa::api::SnapTokenResponse, state::PocketScionState};

/// The default validity of a SNAP token from the PocketSCION AA.
pub const DEFAULT_TOKEN_VALIDITY: Duration = Duration::from_secs(3600);

/// The shortest token validity that the PocketSCION AA accepts.
///
/// A token source renews a token 60 seconds before it expires. With a shorter validity, it renews
/// the token without a pause.
pub const MIN_TOKEN_VALIDITY: Duration = Duration::from_secs(120);

/// Configuration of the PocketSCION AA.
#[derive(Debug, Clone)]
pub struct AaConfig {
    /// How long a SNAP token stays valid.
    pub token_validity: Duration,
    /// The Ed25519 private key, in PEM format, that signs the SNAP tokens.
    ///
    /// The SNAPs verify the tokens with the public key from
    /// [`PocketScionState::set_snap_token_public_pem`]. The two keys must be a pair.
    pub signing_key: Pem,
}

impl Default for AaConfig {
    /// Returns a configuration with [`DEFAULT_TOKEN_VALIDITY`] and the key that pairs with the
    /// default SNAP token public key.
    fn default() -> Self {
        Self {
            token_validity: DEFAULT_TOKEN_VALIDITY,
            signing_key: insecure_const_ed25519_key_pair_pem().0,
        }
    }
}

impl AaConfig {
    /// Issues a SNAP token.
    pub(crate) fn issue_token(&self) -> jsonwebtoken::errors::Result<SnapTokenResponse> {
        let claims = SnapTokenClaims {
            pssid: Pssid::new(),
            exp: (Utc::now() + self.token_validity).timestamp() as u64,
            jti: Uuid::new_v4().to_string(),
        };
        let key = self.encoding_key()?;
        let snap_token = jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &key)?;

        Ok(SnapTokenResponse {
            snap_token,
            expires_in: self.token_validity.as_secs(),
        })
    }

    fn encoding_key(&self) -> jsonwebtoken::errors::Result<EncodingKey> {
        EncodingKey::from_ed_pem(pem::encode(&self.signing_key).as_bytes())
    }
}

impl PocketScionState {
    /// Adds the PocketSCION AA to the simulation. The runtime starts it.
    ///
    /// Fails if the token validity is shorter than [`MIN_TOKEN_VALIDITY`], or if the signing key
    /// is not an Ed25519 private key.
    pub fn set_aa(&mut self, config: AaConfig) -> anyhow::Result<()> {
        anyhow::ensure!(
            config.token_validity >= MIN_TOKEN_VALIDITY,
            "the token validity of the PocketSCION AA must be at least {MIN_TOKEN_VALIDITY:?}"
        );
        config
            .encoding_key()
            .context("the signing key of the PocketSCION AA is not an Ed25519 private key")?;

        self.write().aa = Some(config);
        Ok(())
    }

    /// Returns the configuration of the PocketSCION AA, if the simulation has one.
    pub fn aa(&self) -> Option<AaConfig> {
        self.read().aa.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_aa_refuses_a_short_token_validity() {
        let mut pstate = PocketScionState::new(Utc::now());
        let config = AaConfig {
            token_validity: MIN_TOKEN_VALIDITY - Duration::from_secs(1),
            ..Default::default()
        };

        let error = pstate
            .set_aa(config)
            .expect_err("the validity is too short");

        assert!(error.to_string().contains("at least"), "{error:#}");
        assert!(pstate.aa().is_none());
    }

    #[test]
    fn set_aa_refuses_a_key_that_is_not_ed25519() {
        let mut pstate = PocketScionState::new(Utc::now());
        let config = AaConfig {
            signing_key: insecure_const_ed25519_key_pair_pem().1,
            ..Default::default()
        };

        pstate
            .set_aa(config)
            .expect_err("a public key cannot sign tokens");

        assert!(pstate.aa().is_none());
    }
}
