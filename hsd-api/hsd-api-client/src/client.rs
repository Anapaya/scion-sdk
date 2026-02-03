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

//! # Hidden Segment Directory API client
//!
//! An [HsdApiClient] provides the application with hidden path segments from the hidden segment
//! directory (HSD).
//!
//! ## Example
//!
//! ```ignore
//! use hsd_api_client::client::{HsdClient, ANAPAYA_HSD_V1};
//! use scion_sdk_scion_connect_rpc::client::ConnectClient;
//!
//! // ... create your connect RPC client ...
//! let hsd_client = HsdClient::new_with_client(crpc_client, ANAPAYA_HSD_V1);
//! let resp = hsd_client
//!     .list_segments(src_isd_as, dst_isd_as)
//!     .await;
//! ```

use hsd_api_protobuf::hsd::api_service::v1::{ListSegmentsRequest, ListSegmentsResponse};
use scion_proto::{address::IsdAsn, path::convert::segment::InvalidSegmentError};
use scion_sdk_scion_connect_rpc::{
    Method,
    client::{ConnectRpcClient, RequestError},
    url::Url,
};
use scion_stack::path::fetcher::traits::{SegmentFetchError, SegmentFetcher, Segments};
use thiserror::Error;

/// Anapaya hidden segment directory API namespace.
pub const ANAPAYA_HSD_V1: &str = "anapaya.scion.hsd.segments.v1";

/// HSD API base
const BASE_URL: &str = "https://localhost";

/// Segment lookup service.
const SEGMENT_SERVICE: &str = "SegmentLookupService";

/// List segments endpoint.
const LIST_SEGMENTS: &str = "ListSegments";

/// List segments error.
#[derive(Debug, Error)]
pub enum ListSegmentsError {
    /// Request error.
    #[error("request error: {0}")]
    RequestError(#[from] RequestError),
    /// Invalid segments received.
    #[error("invalid segments received: {0}")]
    InvalidSegmentsError(#[from] InvalidSegmentError),
}

/// Hidden Segment Directory (HSD) API client trait.
// This allows for a client mock implementation in tests.
#[async_trait::async_trait]
pub trait HsdApiClient: Send + Sync {
    /// List the hidden segments between a source and destination ISD-AS.
    ///
    /// # Arguments
    /// * `src` - The source ISD-AS.
    /// * `dst` - The destination ISD-AS.
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<scion_proto::path::Segments, ListSegmentsError>;
}

/// HSD API client.
pub struct HsdClient<C: ConnectRpcClient> {
    pub(crate) client: C,
    base_url: Url,
    api_version: String,
}

impl<C: ConnectRpcClient> HsdClient<C> {
    /// Creates a new hidden segment directory client.
    ///
    /// # Arguments
    /// * `client` - The Connect-RPC client to use for communication.
    /// * `api_namespace` - The API namespace to use (e.g., [`ANAPAYA_HSD_V1`]).
    pub fn new(client: C, api_namespace: impl Into<String>) -> Self {
        HsdClient {
            client,
            base_url: Url::parse(BASE_URL).expect("no fail"),
            api_version: api_namespace.into(),
        }
    }

    /// Sets the base URL for the hidden segment directory client.
    pub fn set_base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }
}

#[async_trait::async_trait]
impl<C> HsdApiClient for HsdClient<C>
where
    C: ConnectRpcClient + Send + Sync + 'static,
{
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<scion_proto::path::Segments, ListSegmentsError> {
        let url = self
            .base_url
            .join(&format!("{}.{}/", self.api_version, SEGMENT_SERVICE))
            .expect("no fail")
            .join(LIST_SEGMENTS)
            .expect("no fail");

        let resp = self
            .client
            .unary_request::<ListSegmentsRequest, ListSegmentsResponse>(
                Method::POST,
                url,
                ListSegmentsRequest {
                    src_isd_as: src.0,
                    dst_isd_as: dst.0,
                },
            )
            .await?;

        Ok(resp.try_into()?)
    }
}

#[async_trait::async_trait]
impl<C> SegmentFetcher for HsdClient<C>
where
    C: ConnectRpcClient + Send + Sync + 'static,
{
    async fn fetch_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<Segments, SegmentFetchError> {
        let resp = self.list_segments(src, dst).await?;

        let (core_segments, non_core_segments) = resp.split_parts();
        Ok(Segments {
            core_segments,
            non_core_segments,
        })
    }
}
