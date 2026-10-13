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

//! Client for the Anapaya AA (Auth/n Auth/z) AuthService.

use std::time::Duration;

use anapaya_aa_protobuf::proto::anapaya::aa::v1::{
    AuthenticateByKeyRequest, AuthenticateByKeyResponse, Metadata,
};
use reqwest_connect_rpc::client::{CrpcClient, CrpcClientError};
use thiserror::Error;
use url::{Host, Url};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Anapaya AA base path.
pub const ANAPAYA_AA_V1: &str = "anapaya.aa.v1";
/// Authentication service.
pub const AUTH_SERVICE: &str = "AuthService";
/// Authenticate by key endpoint.
pub const AUTHENTICATE_BY_KEY: &str = "/AuthenticateByKey";

/// Result of a successful `authenticate_by_key` call.
pub struct AuthResult {
    /// The signed SNAP token returned by the AA.
    pub snap_token: String,
    /// Optional metadata from the AA service, carrying e.g. a user-scoped discovery URL.
    pub metadata: Option<Metadata>,
}

/// Trait for the AA authentication client, enabling mock injection in tests.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait AaAuthClient: Send + Sync {
    /// Authenticates a client using an API key and returns an [`AuthResult`].
    ///
    /// # Parameters
    /// - `api_key`: The API key credential for authentication.
    /// - `device_id`: An identifier for the device requesting authentication.
    /// - `requested_validity`: Desired token validity period in seconds (0 for default (3600), max
    ///   86400).
    async fn authenticate_by_key(
        &self,
        api_key: String,
        device_id: String,
        requested_validity: i32,
    ) -> Result<AuthResult, CrpcClientError>;
}

/// An AA URL that [`check_aa_url`] refuses.
#[derive(Debug, Error)]
#[error("the AA URL `{url}` has to be https, or http to a loopback host")]
pub struct InsecureAaUrl {
    /// The refused URL.
    pub url: Url,
}

/// Checks that `url` is `https`, or `http` to a loopback host.
pub fn check_aa_url(url: &Url) -> Result<(), InsecureAaUrl> {
    let loopback = match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(InsecureAaUrl { url: url.clone() }),
    }
}

/// Connect-RPC client for the Anapaya AA `AuthService`.
///
/// The request carries the API key, so the client refuses a URL that [`check_aa_url`] refuses and
/// follows no redirect.
pub struct CrpcAaAuthClient {
    client: CrpcClient,
}

impl CrpcAaAuthClient {
    /// Creates a client for the AA at `base_url`, with a 30-second request timeout.
    pub fn new(base_url: &Url) -> anyhow::Result<Self> {
        Self::new_with_client_builder(
            base_url,
            reqwest::Client::builder().timeout(REQUEST_TIMEOUT),
        )
    }

    /// Creates a client for the AA at `base_url` from `builder`, with redirects turned off.
    pub fn new_with_client_builder(
        base_url: &Url,
        builder: reqwest::ClientBuilder,
    ) -> anyhow::Result<Self> {
        check_aa_url(base_url)?;
        let http_client = builder
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client: CrpcClient::new_with_client(base_url, http_client)?,
        })
    }
}

#[async_trait::async_trait]
impl AaAuthClient for CrpcAaAuthClient {
    async fn authenticate_by_key(
        &self,
        api_key: String,
        device_id: String,
        requested_validity: i32,
    ) -> Result<AuthResult, CrpcClientError> {
        let resp = self
            .client
            .unary_request::<AuthenticateByKeyRequest, AuthenticateByKeyResponse>(
                &format!("{ANAPAYA_AA_V1}.{AUTH_SERVICE}{AUTHENTICATE_BY_KEY}"),
                &AuthenticateByKeyRequest {
                    api_key,
                    device_id,
                    requested_validity,
                },
            )
            .await?;

        Ok(AuthResult {
            snap_token: resp.snap_token,
            metadata: resp.metadata.into_option(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{Router, http::StatusCode, response::Redirect};
    use tokio::net::TcpListener;

    use super::*;

    async fn serve(app: Router) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        url
    }

    #[test]
    fn https_and_loopback_http_are_accepted() {
        for url in [
            "https://auth.scion.anapaya.net",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://[::1]:8080",
        ] {
            check_aa_url(&url.parse().unwrap()).unwrap_or_else(|e| panic!("{url}: {e}"));
        }
    }

    #[test]
    fn other_urls_are_refused() {
        for url in [
            "http://auth.scion.anapaya.net",
            "http://10.0.2.2:8080",
            "http://[::2]",
            "http://localhost.example.org",
            "ftp://localhost",
        ] {
            assert!(
                check_aa_url(&url.parse().unwrap()).is_err(),
                "{url} was accepted"
            );
        }
    }

    #[test]
    fn the_client_refuses_an_insecure_url() {
        let error = CrpcAaAuthClient::new(&"http://auth.example.org".parse().unwrap())
            .err()
            .expect("an http URL to a remote host is refused");
        assert!(error.is::<InsecureAaUrl>(), "{error}");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let followed = Arc::new(AtomicUsize::new(0));
        let counter = followed.clone();
        let target = serve(Router::new().fallback(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::OK }
        }))
        .await;
        let aa_url = serve(Router::new().fallback(move || {
            let target = target.clone();
            async move { Redirect::temporary(target.as_str()) }
        }))
        .await;

        let error = CrpcAaAuthClient::new(&aa_url)
            .unwrap()
            .authenticate_by_key("key".into(), "device".into(), 0)
            .await
            .err()
            .expect("a redirect is not an answer");

        assert!(!error.is_transient(), "{error}");
        assert!(error.to_string().contains("307"), "{error}");
        assert_eq!(followed.load(Ordering::SeqCst), 0);
    }
}
