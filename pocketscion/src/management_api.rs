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
//! PocketSCION management API server.

use std::sync::{Arc, atomic::AtomicBool};

use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use utoipa_redoc::{Redoc, Servable};

use super::api::admin;
use crate::{
    io_config::SharedPocketScionIoConfig,
    state::{SharedPocketScionState, TunnelGatewayStates},
};

/// Starts the management API.
pub async fn start(
    cancellation_token: CancellationToken,
    ready_state: Arc<AtomicBool>,
    system_state: SharedPocketScionState,
    io_config: SharedPocketScionIoConfig,
    tunnel_gateway_states: TunnelGatewayStates,
    listener: TcpListener,
) -> std::io::Result<()> {
    let (router, openapi) = admin::api::build_management_api(
        ready_state,
        system_state,
        io_config,
        tunnel_gateway_states,
    )
    .split_for_parts();

    let final_router = Router::new()
        .nest("/api/v1", router)
        .merge(Redoc::with_url("/docs", openapi));

    if let Err(e) = axum::serve(listener, final_router.into_make_service())
        .with_graceful_shutdown(cancellation_token.cancelled_owned())
        .await
    {
        tracing::error!(error=%e, "Management API server unexpectedly stopped");
    }

    tracing::info!("Shutting down Management API server");
    Ok(())
}
