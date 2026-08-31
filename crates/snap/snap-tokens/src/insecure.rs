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
//! The constant key the test tokens of this crate are signed with, as a JWKS endpoint serves it.
//!
//! A SNAP resolves every verification key from the JWKS endpoint it is configured with, by the
//! `kid` the token header carries. A test that wants a SNAP to accept the tokens minted here
//! therefore has to serve [`jwks_document`] somewhere and point the SNAP at it, which
//! [`spawn_jwks_server`] does under the `jwks-server` feature.
//!
//! Insecure by construction: the key pair is a constant, published in this crate's source.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scion_sdk_token_validator::validator::insecure_const_ed25519_signing_key;

/// The `kid` every token minted by this crate's test helpers carries, and the one
/// [`jwks_document`] publishes the key under.
pub const KID: &str = "insecure-const-test-key";

/// Where a JWKS endpoint is served.
#[cfg(feature = "jwks-server")]
const JWKS_PATH: &str = "/.well-known/jwks.json";

/// The JWK set that resolves [`KID`] to the constant public key, as a JWKS endpoint serves it.
pub fn jwks_document() -> String {
    let public_key = insecure_const_ed25519_signing_key().verifying_key();
    let x = URL_SAFE_NO_PAD.encode(public_key.as_bytes());

    serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": KID,
            "x": x,
        }]
    })
    .to_string()
}

/// Serves [`jwks_document`] on a loopback port, and returns the URL.
///
/// The SNAP resolves the verification key of a token from the JWKS endpoint it is configured with,
/// by the `kid` the token header carries, so a test whose tokens must be accepted has to serve
/// one.
#[cfg(feature = "jwks-server")]
pub async fn spawn_jwks_server() -> std::io::Result<url::Url> {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::{Router, http::header, routing::get};

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let address = listener.local_addr()?;

    let app = Router::new().route(
        JWKS_PATH,
        get(|| {
            async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    jwks_document(),
                )
            }
        }),
    );
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("the JWKS endpoint stopped serving: {err}");
        }
    });

    Ok(url::Url::parse(&format!("http://{address}{JWKS_PATH}"))
        .expect("a URL composed from a socket address"))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::JwkSet;

    use super::*;

    /// The document has to parse as the JWK set a key store reads, under the `kid` the tokens
    /// carry, or nothing minted here is verifiable.
    #[test]
    fn the_document_is_a_jwk_set_holding_the_test_key() {
        let set: JwkSet = serde_json::from_str(&jwks_document()).expect("a JWK set");

        let jwk = set.find(KID).expect("the test key");
        jsonwebtoken::DecodingKey::from_jwk(jwk).expect("a usable verification key");
    }
}
