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
//! Client for the PocketScion management API.

use std::time::Duration;

use bytes::Bytes;
use reqwest::ClientBuilder;
use thiserror::Error;
use url::Url;

use super::api::{AuthServerResponse, SnapsResponse, StatusResponse};
use crate::{api::admin::api::EndhostApisResponse, dto::IoConfigDto};

/// A client for interacting with the PocketScion API.
#[derive(Debug, Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    api: Url,
}

impl ApiClient {
    /// Creates a new [`ApiClient`] with the given base URL for the PocketScion
    /// management API.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pocketscion::api::admin::client::ApiClient;
    /// let url: url::Url = "http://localhost:9000".parse().unwrap();
    /// let client = ApiClient::new(&url).expect("Failed to create ApiClient");
    /// ```
    pub fn new(url: &Url) -> Result<Self, ClientError> {
        let api = url.join("api/v1/")?;

        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()?;

        Ok(ApiClient { client, api })
    }

    /// Retrieves the status from the PocketScion.
    pub async fn get_status(&self) -> Result<StatusResponse, ClientError> {
        self.get("status").await
    }

    /// Retrieves a list of SNAPs with their control plane API addresses.
    pub async fn get_snaps(&self) -> Result<SnapsResponse, ClientError> {
        self.get("snaps").await
    }

    /// Retrieves a Map of Endhost APIs with their configuration and state.
    pub async fn get_endhost_apis(&self) -> Result<EndhostApisResponse, ClientError> {
        self.get("endhost_apis").await
    }

    /// Retrieves the IO configuration from the PocketScion.
    pub async fn get_io_config(&self) -> Result<IoConfigDto, ClientError> {
        self.get("io_config").await
    }

    /// Retrieves the authorization server.
    pub async fn get_auth_server(&self) -> Result<AuthServerResponse, ClientError> {
        self.get("auth_server").await
    }

    async fn get<T>(&self, endpoint: &str) -> Result<T, ClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = self.api.join(endpoint)?;
        let response = self.client.get(url).send().await?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let result = response.json::<T>().await?;
                Ok(result)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(ClientError::Unauthorized(response.bytes().await?))
            }
            _ => {
                Err(ClientError::InvalidResponseStatus(
                    response.status(),
                    response.bytes().await?,
                ))
            }
        }
    }
}

/// Errors that can occur when using the `ApiClient`.
#[derive(Error, Debug)]
pub enum ClientError {
    /// An error occurred while parsing the URL.
    #[error("invalid URL: {0:?}")]
    InvalidURL(#[from] url::ParseError),
    /// An error occurred while making a request with `reqwest`.
    #[error("reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
    /// The request could not be authorized.
    #[error("the request could not be authorized: {0:?}")]
    Unauthorized(Bytes),
    /// Invalid response status.
    #[error("invalid response status ({0}): {1:?}")]
    InvalidResponseStatus(reqwest::StatusCode, Bytes),
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_api_client {
        ($name:ident, $base_url:expr, $expected_url:expr) => {
            #[test]
            fn $name() {
                let client = ApiClient::new($base_url).expect("Failed to create ApiClient");
                assert_eq!(client.api, Url::parse($expected_url).unwrap());
            }
        };
    }

    test_api_client!(
        should_normalize_url_with_http_schema,
        &"http://localhost:9000".parse().unwrap(),
        "http://localhost:9000/api/v1/"
    );
    test_api_client!(
        should_normalize_url_with_trailing_slash,
        &"http://localhost:9000/".parse().unwrap(),
        "http://localhost:9000/api/v1/"
    );
    test_api_client!(
        should_normalize_url_with_https_schema,
        &"https://localhost:9000".parse().unwrap(),
        "https://localhost:9000/api/v1/"
    );
}
