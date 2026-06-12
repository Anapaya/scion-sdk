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
//! HTTP API v1 endpoint handlers.

use std::sync::Arc;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::http::model::PgWapSessionManager;

/// Path for API v1 endpoints.
pub const PG_WAP_API_V1: &str = "/pg-wap/api/v1";

pub fn pg_wap_router(pg_wap_session_manager: Arc<dyn PgWapSessionManager>) -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(pg_wap::new_session))
        .with_state(pg_wap_session_manager)
}

mod pg_wap {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::Arc,
    };

    use axum::{
        Json,
        extract::{ConnectInfo, State},
    };
    use chrono::DateTime;

    use crate::api::http::model::PgWapSessionManager;

    /// New session response.
    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub struct SessionResponse {
        #[schema(value_type = String, example = "1.2.3.4")]
        client_ip: IpAddr,
        ap_id: String,
        data_plane_port: u16,
        until: DateTime<chrono::Utc>,
    }

    /// Authenticate the client IP to allow creating new sessions.
    ///
    /// The response includes the AP ID to use for the session and the time until which the
    /// authentication is valid.
    ///
    /// The authentication needs to be renewed periodically by calling this endpoint again,
    /// otherwise the client will lose access to the AP and existing sessions will be
    /// terminated.
    #[utoipa::path(
        post,
        path = "/sessions", // Appended to the root: /pg-wap/api/v1/sessions
        responses(
            (status = 200, description = "HTTP request processed successfully", body = SessionResponse),
            (status = 400, description = "Invalid HTTP request"),
            (status = 500, description = "Internal server error")
        ),
        tag = "Control"
    )]
    #[axum::debug_handler]
    pub async fn new_session(
        State(pg_wap_session_manager): State<Arc<dyn PgWapSessionManager>>,
        ip: ConnectInfo<SocketAddr>,
    ) -> Result<Json<SessionResponse>, axum::http::StatusCode> {
        match pg_wap_session_manager.new_session(ip.ip()) {
            Ok(session) => {
                Ok(Json(SessionResponse {
                    client_ip: session.ip,
                    ap_id: session.ap_id.to_string(),
                    data_plane_port: session.data_plane_port,
                    until: session.valid_until,
                }))
            }
            Err(err) => {
                tracing::debug!(?err, "Error creating new session");
                Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}
