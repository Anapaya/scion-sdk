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

//! [Currently unused] Connect-RPC API for the SCION Daemon service.

use std::sync::Arc;

use axum::{Router, extract::State, routing::post};
use scion_protobuf::daemon::v1::{
    AsRequest, AsResponse, DrKeyAsHostRequest, DrKeyAsHostResponse, DrKeyHostAsRequest,
    DrKeyHostAsResponse, DrKeyHostHostRequest, DrKeyHostHostResponse, InterfacesRequest,
    InterfacesResponse, NotifyInterfaceDownRequest, NotifyInterfaceDownResponse, PathsRequest,
    PathsResponse, ServicesRequest, ServicesResponse,
};
use scion_sdk_axum_connect_rpc::{error::CrpcError, extractor::ConnectRpc};

use super::super::model::{
    DaemonService, PATH_AS, PATH_DR_KEY_AS_HOST, PATH_DR_KEY_HOST_AS, PATH_DR_KEY_HOST_HOST,
    PATH_INTERFACES, PATH_NOTIFY_INTERFACE_DOWN, PATH_PATHS, PATH_SERVICES, SERVICE_PREFIX,
};

type DynDaemonService = Arc<dyn DaemonService + Send + 'static>;

/// Nests the DaemonService Connect-RPC routes into the provided base_router.
pub fn nest_api<DaemonType: DaemonService>(
    base_router: Router,
    service: Arc<DaemonType>,
) -> Router {
    base_router.nest(
        &format!("/{}", SERVICE_PREFIX),
        Router::new()
            .route(PATH_PATHS, post(paths_handler))
            .route(PATH_AS, post(as_handler))
            .route(PATH_INTERFACES, post(interfaces_handler))
            .route(PATH_SERVICES, post(services_handler))
            .route(
                PATH_NOTIFY_INTERFACE_DOWN,
                post(notify_interface_down_handler),
            )
            .route(PATH_DR_KEY_AS_HOST, post(dr_key_as_host_handler))
            .route(PATH_DR_KEY_HOST_AS, post(dr_key_host_as_handler))
            .route(PATH_DR_KEY_HOST_HOST, post(dr_key_host_host_handler))
            .with_state(service),
    )
}

async fn paths_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<PathsRequest>,
) -> Result<ConnectRpc<PathsResponse>, CrpcError> {
    let res = svc
        .paths(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling Paths request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn as_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<AsRequest>,
) -> Result<ConnectRpc<AsResponse>, CrpcError> {
    let res = svc
        .as_info(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling AS request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn interfaces_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<InterfacesRequest>,
) -> Result<ConnectRpc<InterfacesResponse>, CrpcError> {
    let res = svc
        .interfaces(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling Interfaces request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn services_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<ServicesRequest>,
) -> Result<ConnectRpc<ServicesResponse>, CrpcError> {
    let res = svc
        .services(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling Services request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn notify_interface_down_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<NotifyInterfaceDownRequest>,
) -> Result<ConnectRpc<NotifyInterfaceDownResponse>, CrpcError> {
    let res = svc
        .notify_interface_down(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling NotifyInterfaceDown request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn dr_key_as_host_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<DrKeyAsHostRequest>,
) -> Result<ConnectRpc<DrKeyAsHostResponse>, CrpcError> {
    let res = svc
        .dr_key_as_host(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling DRKeyASHost request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn dr_key_host_as_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<DrKeyHostAsRequest>,
) -> Result<ConnectRpc<DrKeyHostAsResponse>, CrpcError> {
    let res = svc
        .dr_key_host_as(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling DRKeyHostAS request: {:?}", e))?;
    Ok(ConnectRpc(res))
}

async fn dr_key_host_host_handler(
    State(svc): State<DynDaemonService>,
    ConnectRpc(req): ConnectRpc<DrKeyHostHostRequest>,
) -> Result<ConnectRpc<DrKeyHostHostResponse>, CrpcError> {
    let res = svc
        .dr_key_host_host(req)
        .await
        .inspect_err(|e| tracing::error!("Error handling DRKeyHostHost request: {:?}", e))?;
    Ok(ConnectRpc(res))
}
