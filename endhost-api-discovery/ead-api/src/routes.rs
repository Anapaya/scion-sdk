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

use axum::{extract::State, routing::post};
use axum_client_ip::{ClientIp, ClientIpSource};
use endhost_api_discovery_models::{
    EndhostApiDiscovery, RpcEndhostApiDiscoveryService,
    proto::endhost::discovery::v1::{RpcGetEndhostApisRequest, RpcGetEndhostApisResponse},
};
use scion_sdk_axum_connect_rpc::extractor::ConnectRpc;

/// Nests the endhost API routes into the provided `base_router`.
///
/// To correctly extract the client IP, the final router must be registed using
/// [axum::Router::into_make_service_with_connect_info()]
///
/// # Parameters
/// - `base_router`: The base axum router to nest the endhost API routes into.
/// - `discovery_service`: The EndhostApiDiscovery service implementation.
/// - `client_ip_source`: Client IP extraction strategy, see [axum_client_ip::ClientIp].
pub fn nest_endhost_api(
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
    ClientIp(client_ip): ClientIp,
    ConnectRpc(_): ConnectRpc<RpcGetEndhostApisRequest>,
) -> ConnectRpc<RpcGetEndhostApisResponse> {
    let apis = discovery_service.discover_endhost_api(client_ip).await;

    let response = RpcGetEndhostApisResponse {
        endhost_apis: apis.into_iter().map(|api_info| api_info.into()).collect(),
    };

    ConnectRpc(response)
}
