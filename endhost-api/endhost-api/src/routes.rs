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
//! Endhost API endpoint definitions and endpoint handlers.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::post};
use endhost_api_models::{SegmentsDiscovery, UnderlayDiscovery};
use endhost_api_protobuf::v1::{
    ListSegmentsRequest, ListSegmentsResponse, ListUnderlaysRequest, ListUnderlaysResponse,
};
use scion_proto::{address::IsdAsn, path::SegmentsError};
use scion_sdk_axum_connect_rpc::extractor::ConnectRpc;

/// Endhost API base path.
pub const ENDHOST_API_V1: &str = "scion.endhost.v1";

/// Underlay service.
pub const UNDERLAY_SERVICE: &str = "UnderlayService";
/// Segments service.
pub const SEGMENTS_SERVICE: &str = "SegmentsService";

/// Path service.
#[deprecated(note = "Use SEGMENTS_SERVICE instead")]
pub const PATH_SERVICE: &str = "PathService";

/// List underlays endpoint.
pub const LIST_UNDERLAYS: &str = "/ListUnderlays";
/// List segments endpoint.
pub const LIST_SEGMENTS: &str = "/ListSegments";

/// List paths endpoint.
#[deprecated(note = "Use LIST_SEGMENTS instead")]
pub const LIST_PATHS: &str = "/ListPaths";

/// Nests the endhost API routes into the provided `base_router`.
pub fn nest_endhost_api(
    base_router: axum::Router,
    underlay_service: Arc<dyn UnderlayDiscovery>,
    path_service: Arc<dyn SegmentsDiscovery>,
) -> axum::Router {
    let underlay_router = axum::Router::new()
        .route(LIST_UNDERLAYS, post(list_underlays_handler))
        .with_state(underlay_service);
    let base_router = base_router.nest(
        &service_path(ENDHOST_API_V1, UNDERLAY_SERVICE),
        underlay_router,
    );

    // XXX(bunert): deprecated path service
    #[allow(deprecated)]
    let path_router = axum::Router::new()
        .route(LIST_PATHS, post(list_segments_handler))
        .with_state(path_service.clone());
    #[allow(deprecated)]
    let base_router = base_router.nest(&service_path(ENDHOST_API_V1, PATH_SERVICE), path_router);

    let segment_router = axum::Router::new()
        .route(LIST_SEGMENTS, post(list_segments_handler))
        .with_state(path_service);
    base_router.nest(
        &service_path(ENDHOST_API_V1, SEGMENTS_SERVICE),
        segment_router,
    )
}

async fn list_underlays_handler(
    State(underlay_service): State<Arc<dyn UnderlayDiscovery>>,
    ConnectRpc(request): ConnectRpc<ListUnderlaysRequest>,
) -> ConnectRpc<ListUnderlaysResponse> {
    ConnectRpc(
        underlay_service
            .list_underlays(request.isd_as.map(IsdAsn::from).unwrap_or(IsdAsn::WILDCARD))
            .into(),
    )
}

async fn list_segments_handler(
    State(path_service): State<Arc<dyn SegmentsDiscovery>>,
    ConnectRpc(request): ConnectRpc<ListSegmentsRequest>,
) -> Result<ConnectRpc<ListSegmentsResponse>, axum::response::Response> {
    let (src, dst) = (
        IsdAsn::from(request.src_isd_as),
        IsdAsn::from(request.dst_isd_as),
    );
    match path_service
        .list_segments(src, dst, request.page_size, request.page_token)
        .await
    {
        Ok(segments) => Ok(ConnectRpc(segments.into())),
        Err(SegmentsError::InvalidArgument(msg)) => {
            Err((axum::http::StatusCode::BAD_REQUEST, msg).into_response())
        }
        Err(SegmentsError::InternalError(msg)) => {
            Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg).into_response())
        }
    }
}

fn service_path(api: &str, service: &str) -> String {
    format!("/{api}.{service}")
}
