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

//! A [PathFetcher] is responsible for providing paths between two ISD-ASes.
//!
//! The default implementation [PathFetcherImpl] uses a [SegmentFetcher] to fetch path segments and
//! combine them into end-to-end paths.
//!
//! The default [SegmentFetcher] implementation is [ConnectRpcSegmentFetcher], requesting segments
//! from the Endhost API.

use std::sync::Arc;

use endhost_api_client::client::EndhostApiClient;
use scion_proto::{
    address::IsdAsn,
    path::{self, Path},
};

use crate::path::fetcher::traits::{
    PathFetchError, PathFetcher, SegmentFetchError, SegmentFetcher, Segments,
};

/// Path fetcher traits and types.
pub mod traits {
    use std::borrow::Cow;

    use scion_proto::{
        address::IsdAsn,
        path::{Path, PathSegment},
    };

    use crate::types::ResFut;

    /// Path fetcher trait.
    pub trait PathFetcher: Send + Sync + 'static {
        /// Fetch paths between source and destination ISD-AS.
        fn fetch_paths(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
        ) -> impl ResFut<'_, Vec<Path>, PathFetchError>;
    }

    /// Path fetch errors.
    #[derive(Debug, thiserror::Error)]
    pub enum PathFetchError {
        /// Segment fetch failed.
        #[error("failed to fetch segments: {0}")]
        FetchSegments(#[from] SegmentFetchError),

        /// No paths found.
        #[error("no paths found")]
        NoPathsFound,

        /// Non network related internal error.
        #[error("internal error: {0}")]
        InternalError(Cow<'static, str>),
    }

    /// Segment fetcher trait.
    pub trait SegmentFetcher: Send + Sync + 'static {
        /// Fetch path segments between src and dst.
        fn fetch_segments<'a>(
            &'a self,
            src: IsdAsn,
            dst: IsdAsn,
        ) -> impl Future<Output = Result<Segments, SegmentFetchError>> + Send + 'a;
    }

    /// Segment fetch error.
    pub type SegmentFetchError = Box<dyn std::error::Error + Send + Sync>;

    /// Path segments.
    pub struct Segments {
        /// Core segments.
        pub core_segments: Vec<PathSegment>,
        /// Non-core segments.
        pub non_core_segments: Vec<PathSegment>,
    }
}

/// Path fetcher.
pub struct PathFetcherImpl<F: SegmentFetcher = ConnectRpcSegmentFetcher> {
    segment_fetcher: F,
}

impl<F: SegmentFetcher> PathFetcherImpl<F> {
    /// Creates a new path fetcher.
    pub fn new(segment_fetcher: F) -> Self {
        Self { segment_fetcher }
    }
}

impl<L: SegmentFetcher> PathFetcher for PathFetcherImpl<L> {
    async fn fetch_paths(&self, src: IsdAsn, dst: IsdAsn) -> Result<Vec<Path>, PathFetchError> {
        let Segments {
            core_segments,
            non_core_segments,
        } = self.segment_fetcher.fetch_segments(src, dst).await?;

        tracing::trace!(
            n_core_segments = core_segments.len(),
            n_non_core_segments = non_core_segments.len(),
            src = %src,
            dst = %dst,
            "Fetched segments"
        );

        let paths = path::combinator::combine(src, dst, core_segments, non_core_segments);
        Ok(paths)
    }
}

/// Connect RPC segment fetcher.
pub struct ConnectRpcSegmentFetcher {
    client: Arc<dyn EndhostApiClient>,
}

impl ConnectRpcSegmentFetcher {
    /// Creates a new connect RPC segment fetcher.
    pub fn new(client: Arc<dyn EndhostApiClient>) -> Self {
        Self { client }
    }
}

impl SegmentFetcher for ConnectRpcSegmentFetcher {
    async fn fetch_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<Segments, SegmentFetchError> {
        let resp = self
            .client
            .list_segments(src, dst, 128, "".to_string())
            .await?;

        tracing::debug!(
            n_core=resp.segments.core_segments.len(),
            n_up=resp.segments.up_segments.len(),
            n_down=resp.segments.down_segments.len(),
            src = %src,
            dst = %dst,
            "Received segments from control plane"
        );

        let (core_segments, non_core_segments) = resp.segments.split_parts();
        Ok(Segments {
            core_segments,
            non_core_segments,
        })
    }
}
