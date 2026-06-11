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
//! HTTP API endpoint definitions and endpoint handlers.

use std::sync::Arc;

use axum::{Json, routing::get};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::api::http::model::PgWapSessionManager;

mod v1;

#[derive(OpenApi)]
#[openapi(info(
    title = "SNAP HTTP API",
    version = "0.1.0",
    description = "Anapaya SNAP HTTP API"
))]
struct SnapApi;

/// HTTP API models.
pub mod model {
    use std::net::IpAddr;

    /// Information about an authenticated IP address.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct IpAuthInfo {
        /// The authenticated IP address.
        pub ip: IpAddr,
        /// The AP ID to use for sessions authenticated with this IP address.
        pub ap_id: String,
        /// The time until which the authentication is valid. After this time, the client needs to
        /// reauthenticate.
        pub valid_until: chrono::DateTime<chrono::Utc>,
        // More fields may be added here, e.g. information about the subscription, restrictions to
        // the targets etc.
    }

    /// Pathguard WAP session manager.
    pub trait PgWapSessionManager: Send + Sync {
        /// Create a new session for the given client IP address.
        fn new_session(&self, client_ip: IpAddr) -> Result<IpAuthInfo, anyhow::Error>;
    }
}

/// Nests the SNAP HTTP API routes into the provided `base_router`.
pub fn nest_http_api(
    router: axum::Router,
    pg_wap_session_manager: Arc<dyn PgWapSessionManager>,
) -> axum::Router {
    let mut doc = SnapApi::openapi();

    let (api_router, api_spec) = OpenApiRouter::new()
        .nest(v1::PG_WAP_API_V1, v1::pg_wap_router(pg_wap_session_manager))
        .split_for_parts();

    doc.merge(api_spec);

    router
        .merge(api_router)
        .route("/.well-known/openapi.json", get(|| async { Json(doc) }))
}
