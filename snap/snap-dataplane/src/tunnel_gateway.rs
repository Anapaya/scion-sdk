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
//! Tunnel gateway

use std::sync::Arc;

use scion_sdk_utils::task_handler::CancelTaskSet;
use snap_tun::server::SnapTunAuthorization;
use tokio::net::UdpSocket;

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{dispatcher::TunnelGatewayDispatcherReceiver, gateway::TunnelGateway},
};

pub mod dispatcher;
pub mod gateway;
pub mod metrics;
pub(crate) mod packet_policy;

/// Start the tunnel gateway.
///
/// # Arguments
/// * `tasks`: The task set used to launch the asynchronous tasks.
/// * `authz`: The authorization layer for the snaptun.
/// * `dispatcher_rs`: The receiving end of the dispatcher interface.
/// * `server_static_secret`: The static secret of the tunnel gateway's tunnel endpoint.
pub fn start_tunnel_gateway<A, D>(
    tasks: &mut CancelTaskSet,
    socket: UdpSocket,
    authz: Arc<A>,
    dispatcher: Arc<D>,
    tun_dispatcher_rx: TunnelGatewayDispatcherReceiver,
    server_static_secret: x25519_dalek::StaticSecret,
) where
    A: SnapTunAuthorization + 'static,
    D: Dispatcher + 'static,
{
    let tun_gateway = TunnelGateway::new(
        socket,
        server_static_secret,
        authz,
        dispatcher,
        tun_dispatcher_rx,
    );
    let token = tasks.cancellation_token();
    tasks.spawn_cancellable_task(async move {
        tun_gateway.start_server(token).await;
        Ok(())
    });
}
