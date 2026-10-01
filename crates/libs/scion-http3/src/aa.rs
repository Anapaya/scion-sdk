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

//! Exchanging an Anapaya AA API key for tokens, see
//! [`Config::with_api_key`](crate::Config::with_api_key).

use std::{fmt, sync::OnceLock, time::Duration};

use anapaya_aa_client::{ApiKeyTokenRefresher, CrpcAaAuthClient};
use async_trait::async_trait;
use scion_stack::{
    reqwest,
    reqwest_connect_rpc::token_source::{
        TokenSource, TokenSourceError, TokenSourceWatch, refresh::RefreshTokenSource,
    },
};
use tokio::sync::watch;
use url::Url;

/// The name the refresh task logs under.
const SOURCE_NAME: &str = "aa-api-key";
/// How long one exchange may take. `CrpcClient::new` sets the same timeout on
/// the client it builds itself.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An Anapaya AA API key and where to exchange it, see
/// [`Config::with_api_key`](crate::Config::with_api_key).
#[derive(Clone)]
pub struct ApiKeyAuth {
    /// The API key.
    pub key: String,
    /// The Anapaya AA service that exchanges the key for tokens.
    pub aa_url: Url,
    /// Identifies this device to the AA. The AA puts it in the token and
    /// refuses a device on its blocklist, so the same device has to present
    /// the same value every time.
    pub device_id: String,
    trust_anchors: Option<Vec<reqwest::Certificate>>,
    allow_insecure_http: bool,
}

impl ApiKeyAuth {
    /// Creates the credential.
    #[must_use]
    pub fn new(key: impl Into<String>, aa_url: Url, device_id: impl Into<String>) -> Self {
        ApiKeyAuth {
            key: key.into(),
            aa_url,
            device_id: device_id.into(),
            trust_anchors: None,
            allow_insecure_http: false,
        }
    }

    /// Trusts `anchors` instead of the default roots when reaching the AA, for
    /// a deployment that signs its own certificate.
    #[must_use]
    pub fn with_trust_anchors(mut self, anchors: Vec<reqwest::Certificate>) -> Self {
        self.trust_anchors = Some(anchors);
        self
    }

    /// Allows an `http` AA URL. The API key then crosses the network in
    /// cleartext. Use it only for local testing.
    #[must_use]
    pub fn allow_insecure_http(mut self) -> Self {
        self.allow_insecure_http = true;
        self
    }
}

impl fmt::Debug for ApiKeyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyAuth")
            .field("key", &"<redacted>")
            .field("aa_url", &self.aa_url)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// A [`TokenSource`] that exchanges an API key at the AA and renews the token
/// in the background.
///
/// The refreshing source underneath spawns its task when it is built, which
/// needs a Tokio runtime. It is therefore built on the first `watch` or
/// `get_token`, which the stack calls from async code, and never at
/// construction. The task then lives on the runtime of that first call.
pub(crate) struct AaTokenSource {
    auth: ApiKeyAuth,
    source: OnceLock<Result<RefreshTokenSource, TokenSourceError>>,
}

impl AaTokenSource {
    pub(crate) fn new(auth: ApiKeyAuth) -> Self {
        AaTokenSource {
            auth,
            source: OnceLock::new(),
        }
    }

    /// The refreshing source, or the failure that kept it from being built.
    fn source(&self) -> Result<&RefreshTokenSource, TokenSourceError> {
        self.source
            .get_or_init(|| build(&self.auth))
            .as_ref()
            .map_err(Clone::clone)
    }
}

#[async_trait]
impl TokenSource for AaTokenSource {
    fn watch(&self) -> TokenSourceWatch {
        match self.source() {
            Ok(source) => source.watch(),
            // A receiver keeps the value it was created with after the sender goes, and every
            // caller reads that value before it waits for a change.
            Err(error) => watch::channel(Some(Err(error))).1,
        }
    }

    async fn get_token(&self) -> Result<String, TokenSourceError> {
        self.source()?.get_token().await
    }
}

/// Builds the refreshing source, which spawns the task that renews the token.
///
/// A client that cannot be built fails for good, so the failure is returned and
/// no task is spawned for it. The first request reports it.
fn build(auth: &ApiKeyAuth) -> Result<RefreshTokenSource, TokenSourceError> {
    if auth.aa_url.scheme() != "https" && !auth.allow_insecure_http {
        return Err(TokenSourceError::broken(format!(
            "the AA URL `{}` is not https, so the API key would cross the network in cleartext;              call `ApiKeyAuth::allow_insecure_http` to permit it",
            auth.aa_url
        )));
    }
    // The request body holds the API key, and a 307 or 308 redirect resends the
    // body to the new location.
    let mut http = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(anchors) = auth.trust_anchors.as_deref() {
        http = http.tls_certs_only(anchors.to_vec());
    }
    let http = http.build().map_err(TokenSourceError::broken)?;
    let client = CrpcAaAuthClient::new_with_client(&auth.aa_url, http).map_err(|e| {
        TokenSourceError::broken(format!("cannot reach the AA at `{}`: {e}", auth.aa_url))
    })?;
    let refresher = ApiKeyTokenRefresher::new(client, auth.key.clone(), auth.device_id.clone());
    Ok(RefreshTokenSource::builder(SOURCE_NAME, refresher).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(aa_url: &str) -> ApiKeyAuth {
        ApiKeyAuth::new("super-secret-key", aa_url.parse().unwrap(), "device")
    }

    #[test]
    fn construction_needs_no_runtime() {
        let source = AaTokenSource::new(auth("https://aa.example.org"));
        assert!(source.source.get().is_none());
    }

    #[tokio::test]
    async fn an_unreachable_authority_is_transient() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let source = AaTokenSource::new(auth("http://127.0.0.1:1").allow_insecure_http());
        let error = tokio::time::timeout(REQUEST_TIMEOUT, source.get_token())
            .await
            .expect("the source answers")
            .expect_err("nothing listens on port 1");
        assert!(error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn an_http_authority_is_refused() {
        let source = AaTokenSource::new(auth("http://aa.example.org"));
        let error = source
            .get_token()
            .await
            .expect_err("http would send the key in cleartext");
        assert!(!error.is_transient(), "{error}");
        assert!(error.to_string().contains("https"), "{error}");
    }

    #[tokio::test]
    async fn the_flag_allows_an_http_authority() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let auth = auth("http://aa.example.org").allow_insecure_http();
        assert!(build(&auth).is_ok());
    }

    #[test]
    fn debug_redacts_the_key() {
        let debug = format!("{:?}", auth("https://aa.example.org"));
        assert!(!debug.contains("super-secret-key"));
        assert!(debug.contains("aa.example.org"));
    }
}
