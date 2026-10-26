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

//! [`AnapayaAaTokenSource`] exchanges an API key for SNAP tokens at the Anapaya AA.

use std::fmt;

use anyhow::Context;
use async_trait::async_trait;
use reqwest_connect_rpc::token_source::{
    TokenSource, TokenSourceError, TokenSourceWatch, refresh::RefreshTokenSource,
};
use thiserror::Error;
use url::Url;

use crate::{
    client::CrpcAaAuthClient,
    endhost_api_source::AnapayaAaEndhostApiSource,
    refresher::{ApiKeyTokenRefresher, ApiKeyTokenRefresherError},
};

const SOURCE_NAME: &str = "aa-api-key";

/// A [`TokenSource`] that exchanges an API key for tokens at the Anapaya AA, and renews the token.
///
/// The source also gives the endhost API source that uses the discovery URL of the AA answers, see
/// [`Self::endhost_api_source`].
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use anapaya_aa_client::AnapayaAaTokenSource;
/// use scion_stack::ScionStackBuilder;
///
/// let aa_url = "https://auth.scion.anapaya.net".parse()?;
/// let source = AnapayaAaTokenSource::new("aakey_...", &aa_url, "my-device-id")?;
/// let stack = ScionStackBuilder::new()
///     .with_endhost_api_discovery_source(source.endhost_api_source())
///     .with_auth_token_source(source)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct AnapayaAaTokenSource {
    source: RefreshTokenSource,
    endhost_api_source: AnapayaAaEndhostApiSource,
}

impl AnapayaAaTokenSource {
    /// Creates a source that exchanges `api_key` at the AA at `aa_url`. The first exchange starts
    /// at once, on the current Tokio runtime.
    ///
    /// Fails outside a Tokio runtime, because the source spawns its renewal task.
    pub fn new(
        api_key: impl Into<String>,
        aa_url: &Url,
        device_id: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Self::spawn(refresher(api_key, aa_url, device_id, None)?)
    }

    /// Like [`Self::new`], with the HTTP client for the AA built from `builder`. See
    /// [`CrpcAaAuthClient::new_with_client_builder`].
    pub fn new_with_client_builder(
        api_key: impl Into<String>,
        aa_url: &Url,
        device_id: impl Into<String>,
        builder: reqwest::ClientBuilder,
    ) -> anyhow::Result<Self> {
        Self::spawn(refresher(api_key, aa_url, device_id, Some(builder))?)
    }

    /// Runs the first exchange now, and returns the source. The arguments are the same as for
    /// [`Self::new`].
    pub async fn start(
        api_key: impl Into<String>,
        aa_url: &Url,
        device_id: impl Into<String>,
    ) -> Result<Self, AnapayaAaStartError> {
        Self::start_from(refresher(api_key, aa_url, device_id, None)).await
    }

    /// Like [`Self::start`], with the HTTP client for the AA built from `builder`. See
    /// [`CrpcAaAuthClient::new_with_client_builder`].
    pub async fn start_with_client_builder(
        api_key: impl Into<String>,
        aa_url: &Url,
        device_id: impl Into<String>,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, AnapayaAaStartError> {
        Self::start_from(refresher(api_key, aa_url, device_id, Some(builder))).await
    }

    /// Returns the endhost API source that discovers through the discovery URL that the AA sends
    /// with the token, or through the global discovery service if the AA sends none. See
    /// [`AnapayaAaEndhostApiSource`].
    pub fn endhost_api_source(&self) -> AnapayaAaEndhostApiSource {
        self.endhost_api_source.clone()
    }

    fn spawn(refresher: ApiKeyTokenRefresher) -> anyhow::Result<Self> {
        tokio::runtime::Handle::try_current()
            .context("the AA token source needs a Tokio runtime")?;
        let endhost_api_source = refresher.endhost_api_source();
        Ok(Self {
            source: RefreshTokenSource::builder(SOURCE_NAME, refresher).build(),
            endhost_api_source,
        })
    }

    async fn start_from(
        refresher: anyhow::Result<ApiKeyTokenRefresher>,
    ) -> Result<Self, AnapayaAaStartError> {
        let refresher = refresher.map_err(|error| AnapayaAaStartError::Client(error.into()))?;
        let (token, _metadata) = refresher.refresh_with_metadata().await?;
        let endhost_api_source = refresher.endhost_api_source();
        let source = RefreshTokenSource::builder(SOURCE_NAME, refresher)
            .with_initial_token(token)
            .build();
        Ok(Self {
            source,
            endhost_api_source,
        })
    }
}

fn refresher(
    api_key: impl Into<String>,
    aa_url: &Url,
    device_id: impl Into<String>,
    client_builder: Option<reqwest::ClientBuilder>,
) -> anyhow::Result<ApiKeyTokenRefresher> {
    let client = match client_builder {
        Some(builder) => CrpcAaAuthClient::new_with_client_builder(aa_url, builder)?,
        None => CrpcAaAuthClient::new(aa_url)?,
    };
    Ok(ApiKeyTokenRefresher::new(
        client,
        api_key.into(),
        device_id.into(),
    ))
}

#[async_trait]
impl TokenSource for AnapayaAaTokenSource {
    fn watch(&self) -> TokenSourceWatch {
        self.source.watch()
    }

    async fn get_token(&self) -> Result<String, TokenSourceError> {
        self.source.get_token().await
    }
}

impl fmt::Debug for AnapayaAaTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnapayaAaTokenSource")
            .finish_non_exhaustive()
    }
}

/// Why [`AnapayaAaTokenSource::start`] did not get a first token.
#[derive(Debug, Error)]
pub enum AnapayaAaStartError {
    /// The Anapaya AA client could not be built.
    #[error("cannot build the Anapaya AA client: {0}")]
    Client(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The AA refused the key, or could not be reached.
    #[error(transparent)]
    Exchange(#[from] ApiKeyTokenRefresherError),
}

impl AnapayaAaStartError {
    /// Returns whether the failure is transient.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Exchange(error) => error.is_transient(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use anapaya_aa_protobuf::proto::anapaya::aa::v1::{
        AuthenticateByKeyRequest, AuthenticateByKeyResponse, Metadata,
    };
    use axum::{Router, routing::post};
    use axum_connect_rpc::extractor::ConnectRpc;
    use tokio::net::TcpListener;

    use super::*;
    use crate::client::InsecureAaUrl;

    const DISCOVERY_URL: &str = "https://discovery.example.org/";
    const API_KEY: &str = "super-secret-key";

    fn source(aa_url: &str) -> anyhow::Result<AnapayaAaTokenSource> {
        AnapayaAaTokenSource::new(API_KEY, &aa_url.parse().unwrap(), "device")
    }

    async fn start(aa_url: &str) -> Result<AnapayaAaTokenSource, AnapayaAaStartError> {
        AnapayaAaTokenSource::start(API_KEY, &aa_url.parse().unwrap(), "device").await
    }

    fn token_valid_for(validity: Duration) -> String {
        #[derive(serde::Serialize)]
        struct Claims {
            exp: u64,
        }
        let exp = (SystemTime::now() + validity)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &Claims { exp },
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    async fn serve_aa(token: String, exchanges: Arc<AtomicUsize>) -> Url {
        let app = Router::new().route(
            "/anapaya.aa.v1.AuthService/AuthenticateByKey",
            post(
                move |ConnectRpc(_request): ConnectRpc<AuthenticateByKeyRequest>| {
                    exchanges.fetch_add(1, Ordering::SeqCst);
                    let token = token.clone();
                    async move {
                        ConnectRpc(AuthenticateByKeyResponse {
                            snap_token: token,
                            metadata: Metadata {
                                endhost_api_discovery_url: Some(DISCOVERY_URL.to_string()),
                            }
                            .into(),
                        })
                    }
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        url
    }

    #[tokio::test]
    async fn start_keeps_the_first_token_and_publishes_the_discovery_url() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let token = token_valid_for(Duration::from_secs(3600));
        let aa_url = serve_aa(token.clone(), exchanges.clone()).await;

        let source = AnapayaAaTokenSource::start("key", &aa_url, "device")
            .await
            .unwrap();

        assert_eq!(
            source.endhost_api_source().published(),
            Some(Some(DISCOVERY_URL.parse().unwrap()))
        );
        assert_eq!(source.get_token().await.unwrap(), token);
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn new_exchanges_the_key_without_a_token_request() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let token = token_valid_for(Duration::from_secs(3600));
        let aa_url = serve_aa(token.clone(), exchanges.clone()).await;

        let source = AnapayaAaTokenSource::new("key", &aa_url, "device").unwrap();
        let mut watch = source.watch();
        let first = watch
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .clone()
            .unwrap();

        assert_eq!(first.unwrap(), token);
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn new_fails_outside_a_runtime() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let error = source("https://aa.example.org").expect_err("no Tokio runtime");
        assert!(format!("{error:#}").contains("Tokio runtime"), "{error:#}");
    }

    #[test]
    fn new_refuses_an_insecure_aa_url_also_outside_a_runtime() {
        let error = source("http://aa.example.org")
            .expect_err("http to a remote host would send the key in cleartext");
        assert!(error.downcast_ref::<InsecureAaUrl>().is_some(), "{error:#}");
    }

    #[tokio::test]
    async fn an_unreachable_aa_is_transient() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let source = source("http://127.0.0.1:1").unwrap();
        let error = tokio::time::timeout(Duration::from_secs(30), source.get_token())
            .await
            .expect("the source answers")
            .expect_err("nothing listens on port 1");
        assert!(error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn start_reports_an_unreachable_aa_as_transient() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let error = start("http://127.0.0.1:1")
            .await
            .expect_err("nothing listens on port 1");
        assert!(error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn start_reports_an_insecure_aa_url_as_permanent() {
        let error = start("http://aa.example.org")
            .await
            .expect_err("http to a remote host would send the key in cleartext");
        assert!(!error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn debug_shows_no_key() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let debug = format!("{:?}", source("http://127.0.0.1:1").unwrap());
        assert!(!debug.contains(API_KEY), "{debug}");
    }
}
