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
//! Connect RPC client for the SNAP control plane API.

use std::{net::SocketAddr, ops::Deref, sync::Arc};

use async_trait::async_trait;
use endhost_api_client::client::CrpcEndhostApiClient;
use scion_sdk_reqwest_connect_rpc::{client::CrpcClientError, token_source::TokenSource};
use url::Url;
use x25519_dalek::PublicKey;

use crate::{
    crpc_api::api_service::{GET_SNAP_DATA_PLANE_ADDRESS, REGISTER_SNAPTUN_IDENTITY, SERVICE_PATH},
    protobuf::anapaya::snap::v1::api_service as proto,
};

/// Re-export the endhost API client and the reqwest connect RPC cllient.
pub mod re_export {
    pub use endhost_api_client::client::{CrpcEndhostApiClient, EndhostApiClient};
    pub use scion_sdk_reqwest_connect_rpc::{client::CrpcClientError, token_source::*};
}

/// SNAP data plane address response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDataPlaneAddressResponse {
    /// The UDP endpoint (host:port) of the SNAP data plane.
    pub address: SocketAddr,
    /// The URL of the SNAPtun control plane API. This can be the same as the data plane address.
    /// XXX(uniquefine): Make this required once all servers have been updated.
    pub snap_tun_control_address: Option<Url>,
    /// The static identity of the snaptun-ng server.
    /// XXX(uniquefine): Make this required once all servers have been updated.
    pub snap_static_x25519: Option<PublicKey>,
}

/// SNAP control plane API trait.
#[async_trait]
pub trait ControlPlaneApi: Send + Sync {
    /// Get the SNAP data plane address.
    async fn get_data_plane_address(&self) -> Result<GetDataPlaneAddressResponse, CrpcClientError>;

    /// Register a static identity for a snaptun connection.
    async fn register_snaptun_identity(
        &self,
        initiator_identity: PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, CrpcClientError>;
}

/// Connect RPC client for the SNAP control plane API.
pub struct CrpcSnapControlClient {
    client: CrpcEndhostApiClient,
}

impl Deref for CrpcSnapControlClient {
    type Target = CrpcEndhostApiClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl CrpcSnapControlClient {
    /// Creates a new client with default settings
    pub fn new(base_url: &Url) -> anyhow::Result<Self> {
        let client = CrpcEndhostApiClient::new(base_url)?;
        Ok(Self { client })
    }

    /// Creates a new client with the provided `reqwest::Client`.
    pub fn new_with_client(base_url: &Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(Self {
            client: CrpcEndhostApiClient::new_with_client(base_url, client)?,
        })
    }

    /// Uses the provided token source for authentication.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.client.use_token_source(token_source);
        self
    }
}

#[async_trait]
impl ControlPlaneApi for CrpcSnapControlClient {
    async fn get_data_plane_address(&self) -> Result<GetDataPlaneAddressResponse, CrpcClientError> {
        let res: proto::GetSnapDataPlaneResponse = self
            .client
            .unary_request::<proto::GetSnapDataPlaneRequest, proto::GetSnapDataPlaneResponse>(
                &format!("{SERVICE_PATH}{GET_SNAP_DATA_PLANE_ADDRESS}"),
                proto::GetSnapDataPlaneRequest::default(),
            )
            .await?;
        let address = res.address.parse().map_err(|e: std::net::AddrParseError| {
            CrpcClientError::DecodeError {
                context: "parsing data plane address".into(),
                source: Some(e.into()),
                body: None,
            }
        })?;

        let snap_tun_control_address = res
            .snap_tun_control_address
            .map(|address| {
                // Try to parse the address as a URL first.
                if let Ok(url) = Url::parse(&address) {
                    return Ok(url);
                }
                match address.parse::<SocketAddr>() {
                    Ok(addr) => {
                        let mut u = Url::parse("http://.").unwrap();
                        let _ = u.set_ip_host(addr.ip());
                        let _ = u.set_port(Some(addr.port()));
                        Ok(u)
                    }
                    Err(e) => {
                        Err(CrpcClientError::DecodeError {
                            context: "parsing server control address".into(),
                            source: Some(e.into()),
                            body: None,
                        })
                    }
                }
            })
            .transpose()?;
        let snap_static_x25519 = res
            .snap_static_x25519
            .map(|key| {
                let key_bytes: [u8; 32] =
                    key.as_slice()
                        .try_into()
                        .map_err(|e: std::array::TryFromSliceError| {
                            CrpcClientError::DecodeError {
                                context: "server static identity is not 32 bytes".into(),
                                source: Some(e.into()),
                                body: None,
                            }
                        })?;
                Ok::<_, CrpcClientError>(PublicKey::from(key_bytes))
            })
            .transpose()?;
        Ok(GetDataPlaneAddressResponse {
            address,
            snap_tun_control_address,
            snap_static_x25519,
        })
    }

    async fn register_snaptun_identity(
        &self,
        initiator_identity: PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, CrpcClientError> {
        let res = self.client.unary_request::<proto::RegisterSnapTunIdentityRequest, proto::RegisterSnapTunIdentityResponse>(
            &format!("{SERVICE_PATH}{REGISTER_SNAPTUN_IDENTITY}"),
            proto::RegisterSnapTunIdentityRequest { initiator_static_x25519: initiator_identity.to_bytes().to_vec(), psk_share: psk_share.unwrap_or([0u8;32]).to_vec() },
        ).await?;
        let psk_share = if res.psk_share.as_slice() == [0u8; 32] {
            None
        } else {
            Some(res.psk_share.as_slice().try_into().map_err(
                |e: std::array::TryFromSliceError| {
                    CrpcClientError::DecodeError {
                        context: "psk share is not 32 bytes".into(),
                        source: Some(e.into()),
                        body: None,
                    }
                },
            )?)
        };
        Ok(psk_share)
    }
}
