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
//! Tunnel gateway.

use std::sync::Arc;

use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_token_validator::validator::{Token, TokenValidator};
use scion_sdk_utils::task_handler::CancelTaskSet;
use serde::Deserialize;

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::metrics::TunnelGatewayMetrics,
    tunnel_gateway_deprecated::{gateway::TunnelGateway, state::SharedTunnelGatewayState},
};

pub mod dispatcher;
pub mod gateway;
pub mod state;

/// Starts the tunnel gateway.
///
/// # Arguments
/// * `tasks`: The task set to spawn cancellable tasks.
/// * `shared_tunnel_gw_state`: Shared state for the tunnel gateway.
/// * `address_allocator`: The address allocator for assigning addresses to clients.
/// * `token_validator`: The token validator for validating client tokens.
/// * `tunnel_gateway_endpoint`: The QUIC endpoint for the tunnel gateway.
/// * `lan_gateway_dispatcher`: The dispatcher to forward packets to the LAN gateway.
/// * `metrics_registry`: The metrics registry for registering metrics.
pub fn start_tunnel_gateway_deprecated<T, D>(
    tasks: &mut CancelTaskSet,
    shared_tunnel_gw_state: SharedTunnelGatewayState<T>,
    token_validator: Arc<dyn TokenValidator<T>>,
    tunnel_gateway_endpoint: quinn::Endpoint,
    lan_gateway_dispatcher: Arc<D>,
    metrics_registry: MetricsRegistry,
) where
    T: for<'de> Deserialize<'de> + Token + Clone,
    D: Dispatcher + 'static,
{
    let snaptun_server = snap_tun::server_deprecated::Server::new(
        token_validator.clone(),
        snap_tun::metrics::Metrics::new(&metrics_registry.clone()),
    );

    let tunnel_gateway = TunnelGateway::new(
        shared_tunnel_gw_state.clone(),
        snaptun_server,
        TunnelGatewayMetrics::new(&metrics_registry),
    );

    let cancel_token = tasks.cancellation_token();
    tasks.spawn_cancellable_task(async move {
        tunnel_gateway
            .start_server(
                cancel_token,
                tunnel_gateway_endpoint,
                lan_gateway_dispatcher,
            )
            .await
    });
}
