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
    #[async_trait::async_trait]
    pub trait SegmentFetcher: Send + Sync + 'static {
        /// Fetch path segments between src and dst.
        async fn fetch_segments(
            &self,
            src: IsdAsn,
            dst: IsdAsn,
        ) -> Result<Segments, SegmentFetchError>;
    }

    /// Segment fetch error.
    pub type SegmentFetchError = Box<dyn std::error::Error + Send + Sync>;

    /// Path segments.
    #[derive(Debug)]
    pub struct Segments {
        /// Core segments.
        pub core_segments: Vec<PathSegment>,
        /// Non-core segments.
        pub non_core_segments: Vec<PathSegment>,
    }
}

/// Path fetcher.
pub struct PathFetcherImpl {
    segment_fetchers: Vec<Box<dyn SegmentFetcher>>,
}

impl PathFetcherImpl {
    /// Creates a new path fetcher.
    pub fn new(segment_fetchers: Vec<Box<dyn SegmentFetcher>>) -> Self {
        Self { segment_fetchers }
    }
}

impl PathFetcher for PathFetcherImpl {
    async fn fetch_paths(&self, src: IsdAsn, dst: IsdAsn) -> Result<Vec<Path>, PathFetchError> {
        let mut all_core_segments = Vec::new();
        let mut all_non_core_segments = Vec::new();

        // Fetch segments from all fetchers concurrently
        let fetch_tasks: Vec<_> = self
            .segment_fetchers
            .iter()
            .map(|fetcher| fetcher.fetch_segments(src, dst))
            .collect();

        let results = futures::future::join_all(fetch_tasks).await;

        // Track errors and successes
        let mut errors = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(Segments {
                    core_segments,
                    non_core_segments,
                }) => {
                    tracing::trace!(
                        fetcher_index = i,
                        n_core_segments = core_segments.len(),
                        n_non_core_segments = non_core_segments.len(),
                        %src,
                        %dst,
                        "Segment fetcher succeeded"
                    );
                    all_core_segments.extend(core_segments);
                    all_non_core_segments.extend(non_core_segments);
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        let paths = path::combinator::combine(src, dst, all_core_segments, all_non_core_segments);

        for (i, error) in errors.iter().enumerate() {
            tracing::warn!(
                error_index = i,
                %error,
                %src,
                %dst,
                "Segment fetcher failed"
            );
        }

        // If there were errors but we still have paths, we still return the paths and only log the
        // fetcher errors.
        if !errors.is_empty() && paths.is_empty() {
            return Err(PathFetchError::FetchSegments(
                errors.into_iter().next().unwrap(),
            ));
        }

        Ok(paths)
    }
}

/// Segment fetcher that uses the endhost API via Connect-RPC to fetch segments.
pub struct EndhostApiSegmentFetcher {
    client: Arc<dyn EndhostApiClient>,
}

impl EndhostApiSegmentFetcher {
    /// Creates a new endhost API segment fetcher.
    pub fn new(client: Arc<dyn EndhostApiClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl SegmentFetcher for EndhostApiSegmentFetcher {
    async fn fetch_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
    ) -> Result<Segments, SegmentFetchError> {
        let resp = self
            .client
            .list_segments(src, dst, 128, "".to_string())
            .await?;

        tracing::trace!(
            n_core=resp.segments.core_segments.len(),
            n_up=resp.segments.up_segments.len(),
            n_down=resp.segments.down_segments.len(),
            src = %src,
            dst = %dst,
            "Received segments from endhost API"
        );

        let (core_segments, non_core_segments) = resp.segments.split_parts();
        Ok(Segments {
            core_segments,
            non_core_segments,
        })
    }
}
