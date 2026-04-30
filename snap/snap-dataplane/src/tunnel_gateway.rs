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

use std::{sync::Arc, time::Instant};

use scion_sdk_utils::task_handler::CancelTaskSet;
use sciparse::identifier::isd_asn::IsdAsn;
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
pub mod state;

/// The direction in which the observed packet crossed the SNAP tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedPacketDirection {
    /// The packet arrived from the client over the SNAP tunnel and is headed
    /// toward the SCION router.
    Ingress,
    /// The packet arrived from the SCION side and was encapsulated toward the
    /// client over the SNAP tunnel.
    Egress,
}

/// Packet metadata captured at the point where a packet has successfully
/// crossed the SNAP tunnel boundary and can be accounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedPacketMeta {
    /// Source ISD-AS from the parsed SCION packet.
    pub src_ia: IsdAsn,
    /// Destination ISD-AS from the parsed SCION packet.
    pub dst_ia: IsdAsn,
    /// Total packet length in bytes used for accounting.
    pub packet_len: usize,
    /// Direction in which the packet crossed the tunnel.
    pub direction: ObservedPacketDirection,
}

/// Observes successfully tunneled packets together with the session data that produced them.
pub trait TunnelGatewayObserver<S>: Send + Sync {
    /// Called once a packet has successfully crossed the SNAP tunnel boundary
    /// and the gateway has recovered the relevant accounting metadata.
    ///
    /// `now` is the timestamp captured while processing the relevant packet path.
    fn observe_packet(&self, now: Instant, session_data: &S, packet: ObservedPacketMeta);
}

/// A tunnel-gateway observer that ignores all observed packets.
#[derive(Debug, Default)]
pub struct NoopTunnelGatewayObserver;

impl<S> TunnelGatewayObserver<S> for NoopTunnelGatewayObserver {
    fn observe_packet(&self, _now: Instant, _session_data: &S, _packet: ObservedPacketMeta) {}
}

/// Start the tunnel gateway.
///
/// # Arguments
/// * `tasks`: The task set used to launch the asynchronous tasks.
/// * `socket`: The UDP socket that terminates SNAP tunnels.
/// * `authz`: The authorization layer for the snaptun.
/// * `dispatcher`: Receives validated SCION packets for forwarding.
/// * `observer`: Receives observed packet metadata together with the resolved current session data.
///   Used for flow accounting and metrics.
/// * `tun_dispatcher_rx`: The receiving end of the dispatcher interface.
/// * `server_static_secret`: The static secret of the tunnel gateway's tunnel endpoint.
pub fn start_tunnel_gateway<A, D, O>(
    tasks: &mut CancelTaskSet,
    socket: UdpSocket,
    authz: Arc<A>,
    dispatcher: Arc<D>,
    observer: Arc<O>,
    tun_dispatcher_rx: TunnelGatewayDispatcherReceiver,
    server_static_secret: x25519_dalek::StaticSecret,
) where
    A: SnapTunAuthorization + 'static,
    D: Dispatcher + 'static,
    O: TunnelGatewayObserver<A::SessionData> + ?Sized + 'static,
{
    let tun_gateway = TunnelGateway::new(
        socket,
        server_static_secret,
        authz,
        dispatcher,
        observer,
        tun_dispatcher_rx,
    );
    let token = tasks.cancellation_token();
    tasks.spawn_cancellable_task(async move {
        tun_gateway.start_server(token).await;
        Ok(())
    });
}
