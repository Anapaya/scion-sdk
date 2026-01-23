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
//! # Endhost API client
//!
//! An [EndhostApiClient] provides the application with the information
//! necessary to send and receive SCION-packets in the routing domain that is
//! associated with the endhost API.
//!
//! The implementation [CrpcEndhostApiClient] is a concrete implementation
//! following the current specification of the endhost-API.
//!
//! ## Example Usage
//!
//! ```no_run
//! use std::{net::SocketAddr, str::FromStr};
//!
//! use endhost_api_client::client::{CrpcEndhostApiClient, EndhostApiClient};
//! use scion_proto::address::IsdAsn;
//!
//! pub async fn get_all_udp_sockaddrs() -> anyhow::Result<Vec<SocketAddr>> {
//!     let crpc_client =
//!         CrpcEndhostApiClient::new(&url::Url::parse("http://10.0.0.1:48080/").unwrap())?;
//!
//!     let res = crpc_client
//!         .list_underlays(IsdAsn::from_str("1-ff00:0:110").unwrap())
//!         .await?
//!         .udp_underlay
//!         .iter()
//!         .map(|router| router.internal_interface)
//!         .collect();
//!
//!     Ok(res)
//! }
//! ```

use std::{ops::Deref, sync::Arc};

use endhost_api::routes::{
    ENDHOST_API_V1, LIST_PATHS, LIST_UNDERLAYS, PATH_SERVICE, UNDERLAY_SERVICE,
};
use endhost_api_models::underlays::Underlays;
use endhost_api_protobuf::endhost::api_service::v1::{
    ListSegmentsRequest, ListSegmentsResponse, ListUnderlaysRequest, ListUnderlaysResponse,
};
use scion_proto::{address::IsdAsn, path::segment::SegmentsPage};
use scion_sdk_reqwest_connect_rpc::{
    client::{CrpcClient, CrpcClientError},
    token_source::TokenSource,
};

/// Endhost API client trait.
///
/// This allows for a client mock implementation in tests.
#[async_trait::async_trait]
pub trait EndhostApiClient: Send + Sync {
    /// List the available underlays for a given ISD-AS.
    ///
    /// # Arguments
    /// * `isd_as` - The ISD-AS to list the underlays for. For a wildcard ISD AS
    ///   (`IsdAsn::WILDCARD`), all existing underlays will be returned.
    ///
    /// # Returns
    /// A future that resolves to the list of underlays.
    async fn list_underlays(&self, isd_as: IsdAsn) -> Result<Underlays, CrpcClientError>;
    /// List the available segments between a source and destination ISD-AS.
    ///
    /// # Arguments
    /// * `src` - The source ISD-AS.
    /// * `dst` - The destination ISD-AS.
    /// * `page_size` - The maximum number of segments to return.
    /// * `page_token` - The token to use for pagination.
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        page_size: i32,
        page_token: String,
    ) -> Result<SegmentsPage, CrpcClientError>;
}

/// Connect RPC endhost API client.
pub struct CrpcEndhostApiClient {
    client: CrpcClient,
}

impl Deref for CrpcEndhostApiClient {
    type Target = CrpcClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl CrpcEndhostApiClient {
    /// Creates a new endhost API client from the given base URL.
    pub fn new(base_url: &url::Url) -> anyhow::Result<Self> {
        Ok(CrpcEndhostApiClient {
            client: CrpcClient::new(base_url)?,
        })
    }

    /// Creates a new endhost API client from the given base URL and [`reqwest::Client`].
    pub fn new_with_client(base_url: &url::Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(CrpcEndhostApiClient {
            client: CrpcClient::new_with_client(base_url, client)?,
        })
    }

    /// Uses the provided token source for authentication.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.client.use_token_source(token_source);
        self
    }
}

#[async_trait::async_trait]
impl EndhostApiClient for CrpcEndhostApiClient {
    async fn list_underlays(&self, isd_as: IsdAsn) -> Result<Underlays, CrpcClientError> {
        self.client
            .unary_request::<ListUnderlaysRequest, ListUnderlaysResponse>(
                &format!("{ENDHOST_API_V1}.{UNDERLAY_SERVICE}{LIST_UNDERLAYS}"),
                ListUnderlaysRequest {
                    isd_as: Some(isd_as.into()),
                },
            )
            .await?
            .try_into()
            .map_err(|e: url::ParseError| {
                CrpcClientError::DecodeError {
                    context: "parsing underlay address as URL".into(),
                    source: e.into(),
                    body: None,
                }
            })
            .inspect(|resp| {
                tracing::debug!(%resp, "Listed underlays");
            })
    }

    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        page_size: i32,
        page_token: String,
    ) -> Result<SegmentsPage, CrpcClientError> {
        self.client
            .unary_request::<ListSegmentsRequest, ListSegmentsResponse>(
                &format!("{ENDHOST_API_V1}.{PATH_SERVICE}{LIST_PATHS}"),
                ListSegmentsRequest {
                    src_isd_as: src.0,
                    dst_isd_as: dst.0,
                    page_size,
                    page_token,
                },
            )
            .await?
            .try_into()
            .map_err(
                |e: scion_proto::path::convert::segment::InvalidSegmentError| {
                    CrpcClientError::DecodeError {
                        context: "decoding segments".into(),
                        source: e.into(),
                        body: None,
                    }
                },
            )
            .inspect(|resp| {
                tracing::debug!(%resp, "Listed segments");
            })
    }
}
