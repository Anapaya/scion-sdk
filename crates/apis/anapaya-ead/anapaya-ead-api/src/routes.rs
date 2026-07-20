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

use std::{net::IpAddr, sync::Arc};

use anapaya_ead_models::{
    EndhostApiDiscovery, RpcEndhostApiDiscoveryService,
    proto::endhost::discovery::v1::{RpcGetEndhostApisRequest, RpcGetEndhostApisResponse},
};
use axum::{
    extract::{FromRequestParts, State},
    http::request::Parts,
    routing::post,
};
use axum_client_ip::{ClientIp, ClientIpSource};
use axum_connect_rpc::extractor::ConnectRpc;

struct GcpClientIp(pub IpAddr);

impl<S> FromRequestParts<S> for GcpClientIp
where
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1. Try to extract from X-Forwarded-For specifically for GCP (second to last IP)
        if let Some(forwarded_for) = parts.headers.get("x-forwarded-for")
            && let Ok(value) = forwarded_for.to_str()
        {
            let ips: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
            if ips.len() >= 2 {
                let second_to_last = ips[ips.len() - 2];
                if let Ok(ip) = second_to_last.parse::<IpAddr>() {
                    return Ok(GcpClientIp(ip));
                }
            }
        }

        // 2. Fallback to standard axum client IP extraction
        match ClientIp::from_request_parts(parts, state).await {
            Ok(ClientIp(ip)) => Ok(GcpClientIp(ip)),
            Err(rej) => Err(axum::response::IntoResponse::into_response(rej)),
        }
    }
}

/// Nests the endhost API routes into the provided `base_router`.
///
/// To correctly extract the client IP, the final router must be registed using
/// [axum::Router::into_make_service_with_connect_info()]
///
/// # Parameters
/// - `base_router`: The base axum router to nest the endhost API routes into.
/// - `discovery_service`: The EndhostApiDiscovery service implementation.
/// - `client_ip_source`: Client IP extraction strategy, see [axum_client_ip::ClientIp].
pub fn nest_endhost_discovery_api(
    base_router: axum::Router,
    discovery_service: Arc<dyn EndhostApiDiscovery>,
    client_ip_source: ClientIpSource,
) -> axum::Router {
    let nested_router = axum::Router::new()
        .route(
            RpcEndhostApiDiscoveryService::GET_ENDHOST_APIS_PATH,
            post(get_endhost_apis),
        )
        .layer(client_ip_source.into_extension())
        .with_state(discovery_service);

    base_router.nest(RpcEndhostApiDiscoveryService::SERVICE_PATH, nested_router)
}

async fn get_endhost_apis(
    State(discovery_service): State<Arc<dyn EndhostApiDiscovery>>,
    GcpClientIp(client_ip): GcpClientIp,
    ConnectRpc(_): ConnectRpc<RpcGetEndhostApisRequest>,
) -> ConnectRpc<RpcGetEndhostApisResponse> {
    let apis = discovery_service.discover_endhost_apis(client_ip).await;

    let response = RpcGetEndhostApisResponse {
        groups: apis.into_iter().map(Into::into).collect(),
    };

    ConnectRpc(response)
}
