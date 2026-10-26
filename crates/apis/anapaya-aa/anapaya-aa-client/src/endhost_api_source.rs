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

//! [`AnapayaAaEndhostApiSource`] finds the endhost APIs through the Anapaya AA.
//!
//! The AA answer to an API key exchange can carry a discovery URL for the endhost APIs of the user.
//! [`ApiKeyTokenRefresher`](crate::ApiKeyTokenRefresher) publishes the discovery URL of each
//! answer. [`AnapayaAaEndhostApiSource`] waits for the first answer, then discovers the endhost
//! APIs through that URL, or through the global discovery service if the AA sent none.

use std::fmt;

use async_trait::async_trait;
use scion_stack::ea_source::{
    EndhostApiSource, EndhostApiSourceError, StaticEndhostApiDiscovery, models::EndhostApiGroup,
};
use tokio::sync::watch;
use url::Url;

/// What the last AA answer said about discovery. `None` until the first answer.
pub(crate) type DiscoveryState = Option<Result<Option<Url>, AaFailure>>;

#[derive(Clone, Debug)]
pub(crate) struct AaFailure {
    pub(crate) message: String,
    pub(crate) transient: bool,
}

/// An [`EndhostApiSource`] that discovers the endhost APIs through the discovery URL that the
/// Anapaya AA sends with the token.
///
/// If the AA sends no discovery URL, the source uses the global discovery service
/// ([`StaticEndhostApiDiscovery::global`]). The source ignores a discovery URL that is not valid.
/// It then keeps the discovery URL of an earlier answer, or uses the global discovery service.
///
/// The source waits for the first answer of the AA, and an AA that fails before its first answer
/// fails the source with the same transient flag.
///
/// Get the source from
/// [`AnapayaAaTokenSource::endhost_api_source`](crate::AnapayaAaTokenSource::endhost_api_source),
/// or from
/// [`ApiKeyTokenRefresher::endhost_api_source`](crate::ApiKeyTokenRefresher::endhost_api_source).
#[derive(Clone)]
pub struct AnapayaAaEndhostApiSource {
    state: watch::Receiver<DiscoveryState>,
    http_client: Option<reqwest::Client>,
}

impl AnapayaAaEndhostApiSource {
    pub(crate) fn new(state: watch::Receiver<DiscoveryState>) -> Self {
        Self {
            state,
            http_client: None,
        }
    }

    /// Sends the discovery requests through the given `http_client` instead of creating a new one.
    #[must_use]
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    fn discovery(&self, url: Option<Url>) -> StaticEndhostApiDiscovery {
        let discovery = match url {
            Some(url) => StaticEndhostApiDiscovery::new(vec![url]),
            None => StaticEndhostApiDiscovery::global(),
        };
        match &self.http_client {
            Some(http_client) => discovery.with_http_client(http_client.clone()),
            None => discovery,
        }
    }
}

#[async_trait]
impl EndhostApiSource for AnapayaAaEndhostApiSource {
    async fn endhost_apis(&self) -> Result<Vec<EndhostApiGroup>, EndhostApiSourceError> {
        // Wait for the first AA answer.
        let mut receiver = self.state.clone();
        let state = receiver
            .wait_for(Option::is_some)
            .await
            .map_err(|_| EndhostApiSourceError::new("the AA token source stopped", false))?
            .as_ref()
            .expect("wait_for(Option::is_some) only returns a value that is Some")
            .clone();

        match state {
            Ok(url) => self.discovery(url).endhost_apis().await,
            Err(failure) => {
                Err(EndhostApiSourceError::new(
                    failure.message,
                    failure.transient,
                ))
            }
        }
    }
}

#[cfg(test)]
impl AnapayaAaEndhostApiSource {
    /// The discovery URL of the last AA answer. `None` before the first answer.
    pub(crate) fn published(&self) -> Option<Option<Url>> {
        self.state
            .borrow()
            .clone()
            .map(|state| state.expect("the AA answered"))
    }
}

impl fmt::Debug for AnapayaAaEndhostApiSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnapayaAaEndhostApiSource")
            .field("state", &*self.state.borrow())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anapaya_aa_protobuf::proto::anapaya::aa::v1::Metadata;
    use anapaya_ead_models::{
        RpcEndhostApiDiscoveryService,
        proto::endhost::discovery::v1::{
            RpcEndhostApiGroup, RpcEndhostApiInfo, RpcGetEndhostApisRequest,
            RpcGetEndhostApisResponse,
        },
    };
    use axum::{Router, routing::post};
    use axum_connect_rpc::extractor::ConnectRpc;
    use reqwest_connect_rpc::client::CrpcClientError;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{
        ApiKeyTokenRefresher,
        client::{AuthResult, MockAaAuthClient},
    };

    const ENDHOST_API: &str = "https://endhost-api.example.org/";

    fn token() -> String {
        #[derive(serde::Serialize)]
        struct Claims {
            exp: u64,
        }
        let exp = (SystemTime::now() + Duration::from_secs(3600))
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

    fn answer(discovery_url: Option<&str>) -> Result<AuthResult, CrpcClientError> {
        Ok(AuthResult {
            snap_token: token(),
            metadata: discovery_url.map(|url| {
                Metadata {
                    endhost_api_discovery_url: Some(url.to_string()),
                }
            }),
        })
    }

    fn unreachable() -> Result<AuthResult, CrpcClientError> {
        Err(CrpcClientError::ConnectionError {
            context: "test: connection refused".into(),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
        })
    }

    /// A refresher whose AA gives the answers in `answers`, in order.
    fn refresher(
        answers: Vec<Result<AuthResult, CrpcClientError>>,
    ) -> ApiKeyTokenRefresher<MockAaAuthClient> {
        let mut client = MockAaAuthClient::new();
        let mut answers = answers.into_iter();
        client
            .expect_authenticate_by_key()
            .returning(move |_, _, _| answers.next().expect("no more AA answers"));
        ApiKeyTokenRefresher::new(client, "key".into(), "device".into())
    }

    async fn serve_discovery() -> Url {
        let path = format!(
            "{}{}",
            RpcEndhostApiDiscoveryService::SERVICE_PATH,
            RpcEndhostApiDiscoveryService::GET_ENDHOST_APIS_PATH
        );
        let app = Router::new().route(
            &path,
            post(
                |ConnectRpc(_request): ConnectRpc<RpcGetEndhostApisRequest>| {
                    async {
                        ConnectRpc(RpcGetEndhostApisResponse {
                            groups: vec![RpcEndhostApiGroup {
                                apis: vec![RpcEndhostApiInfo {
                                    address: ENDHOST_API.to_string(),
                                }],
                            }],
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
    async fn the_source_discovers_through_the_url_of_the_aa() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let discovery_url = serve_discovery().await;
        let refresher = refresher(vec![answer(Some(discovery_url.as_str()))]);
        refresher.refresh_with_metadata().await.unwrap();

        let groups = refresher.endhost_api_source().endhost_apis().await.unwrap();

        let apis: Vec<&str> = groups
            .iter()
            .flat_map(|group| group.apis.iter())
            .map(|api| api.address.as_str())
            .collect();
        assert_eq!(apis, [ENDHOST_API]);
    }

    #[tokio::test]
    async fn an_answer_without_a_url_selects_the_global_discovery() {
        let refresher = refresher(vec![answer(None), answer(Some(""))]);

        refresher.refresh_with_metadata().await.unwrap();
        assert_eq!(refresher.endhost_api_source().published(), Some(None));

        refresher.refresh_with_metadata().await.unwrap();
        assert_eq!(refresher.endhost_api_source().published(), Some(None));
    }

    #[tokio::test]
    async fn a_bad_discovery_url_selects_the_global_discovery() {
        let refresher = refresher(vec![answer(Some("not a URL"))]);

        refresher.refresh_with_metadata().await.unwrap();

        assert_eq!(refresher.endhost_api_source().published(), Some(None));
    }

    #[tokio::test]
    async fn a_bad_discovery_url_keeps_the_earlier_url() {
        let discovery_url = "https://discovery.example.org/";
        let refresher = refresher(vec![answer(Some(discovery_url)), answer(Some("not a URL"))]);

        refresher.refresh_with_metadata().await.unwrap();
        refresher.refresh_with_metadata().await.unwrap();

        assert_eq!(
            refresher.endhost_api_source().published(),
            Some(Some(discovery_url.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn an_unreachable_aa_fails_the_source_as_transient() {
        let refresher = refresher(vec![unreachable()]);
        refresher.refresh_with_metadata().await.unwrap_err();

        let error = refresher
            .endhost_api_source()
            .endhost_apis()
            .await
            .expect_err("the AA did not answer");

        assert!(error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn a_failed_renewal_keeps_the_earlier_url() {
        let discovery_url = "https://discovery.example.org/";
        let refresher = refresher(vec![answer(Some(discovery_url)), unreachable()]);

        refresher.refresh_with_metadata().await.unwrap();
        refresher.refresh_with_metadata().await.unwrap_err();

        assert_eq!(
            refresher.endhost_api_source().published(),
            Some(Some(discovery_url.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn the_source_fails_when_the_token_source_stops() {
        let refresher = refresher(Vec::new());
        let source = refresher.endhost_api_source();
        drop(refresher);

        let error = source.endhost_apis().await.expect_err("no AA answer comes");

        assert!(!error.is_transient(), "{error}");
    }
}
