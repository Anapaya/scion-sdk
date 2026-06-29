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

//! Control service for looking up segments
use std::{collections::HashMap, fmt::Debug, time::Duration};

use anyhow::Context;
use axum::{Router, extract::State, routing::post};
use chrono::Utc;
use scion_protobuf::control_plane::v1::{
    SegmentsRequest, SegmentsResponse,
    segment_lookup_service_server::{SegmentLookupService, SegmentLookupServiceServer},
    segments_response::Segments,
};
use scion_sdk_axum_connect_rpc::{
    error::{CrpcError, CrpcErrorCode},
    extractor::ConnectRpc,
};
use sciparse::{dataplane_path::standard::types::EXP_TIME_UNIT, identifier::isd_asn::IsdAsn};
use tokio::task::spawn_blocking;

use crate::state::PocketScionState;

const SERVICE_PATH: &str = "/proto.control_plane.v1.SegmentLookupService";

/// Nests the SegmentLookupService routes into the provided `router`.
pub fn nest_api(router: Router, service: PsSegmentLookupService) -> Router {
    router.nest(
        SERVICE_PATH,
        Router::new()
            .route("/Segments", post(lookup_segments))
            .with_state(service),
    )
}

/// Builds a tonic gRPC server for the segment lookup service.
pub fn grpc_server(
    service: PsSegmentLookupService,
) -> SegmentLookupServiceServer<PsSegmentLookupGrpcService> {
    SegmentLookupServiceServer::new(PsSegmentLookupGrpcService { inner: service })
}

/// Tonic gRPC adapter delegating to [PsSegmentLookupService].
#[derive(Clone)]
pub struct PsSegmentLookupGrpcService {
    inner: PsSegmentLookupService,
}

#[tonic::async_trait]
impl SegmentLookupService for PsSegmentLookupGrpcService {
    async fn segments(
        &self,
        request: tonic::Request<SegmentsRequest>,
    ) -> Result<tonic::Response<SegmentsResponse>, tonic::Status> {
        let res = self
            .inner
            .lookup_segments(request.into_inner())
            .await
            .inspect_err(|e| tracing::error!("Error looking up segments: {:?}", e))
            .map_err(|e| tonic::Status::internal(format!("Failed to lookup segments: {:?}", e)))?;

        Ok(tonic::Response::new(res))
    }
}

/// Handler for the ListSegments endpoint of the SegmentLookupService.
pub async fn lookup_segments(
    State(svc): State<PsSegmentLookupService>,
    req: ConnectRpc<SegmentsRequest>,
) -> Result<ConnectRpc<SegmentsResponse>, CrpcError> {
    let res = svc
        .lookup_segments(req.into_inner())
        .await
        .inspect_err(|e| tracing::error!("Error looking up segments: {:?}", e))
        .map_err(|e| {
            CrpcError::new(
                CrpcErrorCode::Internal,
                format!("Failed to lookup segments: {:?}", e),
            )
        })?;

    Ok(ConnectRpc(res))
}

/// Service for looking up segments
#[derive(Clone)]
pub struct PsSegmentLookupService {
    local_ia: IsdAsn,
    ps_state: PocketScionState,
}

impl PsSegmentLookupService {
    /// Creates a new PsSegmentLookupService with the given local IA and shared PocketScion state.
    pub fn new(local_ia: IsdAsn, ps_state: PocketScionState) -> Self {
        Self { local_ia, ps_state }
    }

    /// Looks up segments between the source and destination ISD-AS specified in the request.
    pub async fn lookup_segments(&self, req: SegmentsRequest) -> anyhow::Result<SegmentsResponse> {
        const EXP_UNITS: u8 = 255;

        let (cache_enabled, cached_entry) = {
            let guard = self.ps_state.read();
            let cache = &guard.segment_listing_cache;

            let cache_enabled = cache.is_some();
            let cached_entry = cache
                .as_ref()
                .and_then(|cache| cache.get(req.src_isd_as.into(), req.dst_isd_as.into()));

            (cache_enabled, cached_entry)
        };

        if let Some(cached_response) = cached_entry {
            tracing::debug!(
                src_isd_as = ?req.src_isd_as,
                dst_isd_as = ?req.dst_isd_as,
                "Cache hit for segment listing"
            );
            return Ok(cached_response);
        }

        tracing::debug!(
            src_isd_as = ?req.src_isd_as,
            dst_isd_as = ?req.dst_isd_as,
            "Looking up segments"
        );

        let this = self.clone();
        let task = spawn_blocking(move || {
            let ps_state = this.ps_state.read();
            let topology = &ps_state.topology;
            let this_as = topology
                .as_map
                .get(&this.local_ia)
                .context("local IA must be in topology")?;

            let segment_registry = &ps_state.segment_registry;

            let res = match this_as.is_core() {
                true => {
                    segment_registry
                        .core_list_segments(
                            this.local_ia,
                            req.src_isd_as.into(),
                            req.dst_isd_as.into(),
                        )
                        .context("failed to lookup segments at core AS")?
                }
                false => {
                    segment_registry
                        .non_core_list_segments(
                            this.local_ia,
                            req.src_isd_as.into(),
                            req.dst_isd_as.into(),
                        )
                        .context("failed to lookup segments at non-core AS")?
                }
            };

            tracing::debug!(
                res = %res,
                "Looked up segments, converting to path segments and preparing response"
            );

            let path_segment = res.into_path_segments(topology, Utc::now(), 0, EXP_UNITS)?;

            let mut segments: HashMap<i32, Segments> = HashMap::new();
            segments.insert(
                scion_protobuf::control_plane::v1::SegmentType::Up.into(),
                Segments {
                    segments: path_segment.up.into_iter().map(|s| s.into_rpc()).collect(),
                },
            );
            segments.insert(
                scion_protobuf::control_plane::v1::SegmentType::Core.into(),
                Segments {
                    segments: path_segment
                        .core
                        .into_iter()
                        .map(|s| s.into_rpc())
                        .collect(),
                },
            );
            segments.insert(
                scion_protobuf::control_plane::v1::SegmentType::Down.into(),
                Segments {
                    segments: path_segment
                        .down
                        .into_iter()
                        .map(|s| s.into_rpc())
                        .collect(),
                },
            );

            Ok::<_, anyhow::Error>(segments)
        });

        let segments = task
            .await
            .context("failed to join blocking task for segment lookup")??;

        let res = SegmentsResponse {
            segments: segments.clone(),
            deprecated_signed_revocations: Vec::new(),
        };

        if cache_enabled {
            let mut guard = self.ps_state.write();
            let ttl_secs =
                (EXP_TIME_UNIT * EXP_UNITS as u32).saturating_sub(Duration::from_secs(120)); // Cache entries expire slightly before the segments do

            if let Some(cache) = guard.segment_listing_cache.as_mut() {
                cache.add(req.src_isd_as.into(), req.dst_isd_as.into(), &res, ttl_secs);
            }

            tracing::debug!(
                src_isd_as = ?req.src_isd_as,
                dst_isd_as = ?req.dst_isd_as,
                "Added segment listing to cache"
            );
        }

        Ok(SegmentsResponse {
            segments,
            deprecated_signed_revocations: Vec::new(),
        })
    }
}

/// Global cache for segment listing
#[derive(Default, Clone, PartialEq)]
pub struct SegmentListingCache {
    cache: HashMap<(IsdAsn, IsdAsn), SegmentsListingCacheEntry>,
}

impl Debug for SegmentListingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentListingCache")
            .field("cache_entries", &self.cache.len())
            .finish()
    }
}

impl SegmentListingCache {
    /// Returns a future that periodically cleans up expired entries from the cache.
    pub(crate) async fn cleanup_loop(state: PocketScionState, interval: Duration) {
        loop {
            state
                .write()
                .segment_listing_cache
                .as_mut()
                .expect("Cleanup task should only be started if cache exists")
                .cleanup();

            tracing::trace!("Cleaned up segment listing cache");

            tokio::time::sleep(interval).await;
        }
    }

    /// Removes expired entries from the cache.
    fn cleanup(&mut self) {
        let now = Utc::now();
        self.cache.retain(|_, entry| entry.valid_until > now);
    }

    /// Adds a new entry to the cache
    fn add(
        &mut self,
        src: IsdAsn,
        dst: IsdAsn,
        response: &SegmentsResponse,
        ttl_duration: Duration,
    ) {
        if ttl_duration.as_secs() == 0 {
            return; // Don't cache entries that are already expired
        }

        let valid_until = Utc::now() + ttl_duration;
        self.cache.insert(
            (src, dst),
            SegmentsListingCacheEntry {
                response: response.clone(),
                valid_until,
            },
        );
    }

    /// Retrieves cached response
    fn get(&self, src: IsdAsn, dst: IsdAsn) -> Option<SegmentsResponse> {
        self.cache.get(&(src, dst)).and_then(|entry| {
            if entry.valid_until > Utc::now() {
                Some(entry.response.clone())
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SegmentsListingCacheEntry {
    response: SegmentsResponse,
    valid_until: chrono::DateTime<chrono::Utc>,
}

impl PocketScionState {
    /// Enables the segment listing cache, if it is not already enabled.
    pub fn enable_segment_listing_cache(&self) {
        let mut guard = self.write();
        if guard.segment_listing_cache.is_none() {
            tracing::info!("Enabling segment listing cache");
            guard.segment_listing_cache = Some(SegmentListingCache::default());
        }
    }
}
