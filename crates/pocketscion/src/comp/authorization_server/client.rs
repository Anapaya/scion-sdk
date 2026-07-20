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
//! A client for the PocketSCION Authorization Server API.

use std::time::Duration;

use reqwest::ClientBuilder;
use thiserror::Error;
use url::Url;

use super::api::{TokenRequest, TokenResponse};

/// A client for interacting with the Authorization server API.
#[allow(unused)]
pub struct ApiClient {
    client: reqwest::Client,
    api: Url,
}

impl ApiClient {
    /// Creates a new [`ApiClient`] with the given base URL for the Auhtorization server.
    #[allow(unused)]
    pub fn new(url: &Url) -> Result<Self, ClientError> {
        let api = url.join("api/v1/")?;

        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()?;

        Ok(ApiClient { client, api })
    }

    /// Exchange a access token for a SNAP token.
    #[allow(unused)]
    pub async fn post_token(&self, req: TokenRequest) -> Result<TokenResponse, ClientError> {
        let endpoint = self.api.join("token")?;
        let response = self.client.post(endpoint).form(&req).send().await?;

        if !response.status().is_success() {
            return Err(ClientError::ReqwestError(
                response.error_for_status().unwrap_err(),
            ));
        }

        let snap_token_resp = response
            .json::<TokenResponse>()
            .await
            .expect("parse token exchange response");
        Ok(snap_token_resp)
    }
}

/// Errors that can occur when using the `ApiClient`.
#[derive(Error, Debug)]
pub enum ClientError {
    /// An error occurred while parsing the URL.
    #[error("URL error: {0:?}")]
    InvalidUrl(#[from] url::ParseError),
    /// An error occurred while making a request with `reqwest`.
    #[error("reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
    /// An error occurred while serializing or deserializing JSON.
    #[error("JSON error: {0:?}")]
    SerdeJsonError(#[from] serde_json::Error),
}
