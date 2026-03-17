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

use anapaya_aa_protobuf::v1::{AuthenticateByKeyRequest, AuthenticateByKeyResponse};
use scion_sdk_reqwest_connect_rpc::client::{CrpcClient, CrpcClientError};

/// Anapaya AA base path.
pub const ANAPAYA_AA_V1: &str = "anapaya.aa.v1";
/// Authentication service.
pub const AUTH_SERVICE: &str = "AuthService";
/// Authenticate by key endpoint.
pub const AUTHENTICATE_BY_KEY: &str = "/AuthenticateByKey";

/// Trait for the AA authentication client, enabling mock injection in tests.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait AaAuthClient: Send + Sync {
    /// Authenticates a client using an API key and returns a SNAP token.
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
    ) -> Result<String, CrpcClientError>;
}

/// Connect-RPC client for the Anapaya AA `AuthService`.
pub struct CrpcAaAuthClient {
    client: CrpcClient,
}

impl CrpcAaAuthClient {
    /// Creates a new [`CrpcAaAuthClient`] for the given base URL.
    pub fn new(base_url: &url::Url) -> anyhow::Result<Self> {
        Ok(Self {
            client: CrpcClient::new(base_url)?,
        })
    }

    /// Creates a new [`CrpcAaAuthClient`] using an existing [`reqwest::Client`].
    pub fn new_with_client(base_url: &url::Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(Self {
            client: CrpcClient::new_with_client(base_url, client)?,
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
    ) -> Result<String, CrpcClientError> {
        let resp = self
            .client
            .unary_request::<AuthenticateByKeyRequest, AuthenticateByKeyResponse>(
                &format!("{ANAPAYA_AA_V1}.{AUTH_SERVICE}{AUTHENTICATE_BY_KEY}"),
                AuthenticateByKeyRequest {
                    api_key,
                    device_id,
                    requested_validity,
                },
            )
            .await?;

        Ok(resp.snap_token)
    }
}
