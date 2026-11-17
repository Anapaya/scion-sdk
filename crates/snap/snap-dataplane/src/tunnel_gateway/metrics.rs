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
//! Tunnel gateway metrics.

use prometheus::{IntCounter, IntGauge};
use scion_sdk_observability::metrics::registry::MetricsRegistry;

use crate::metrics::{DataPlaneMetrics, Direction, TrafficCounters};

/// Tunnel gateway metrics.
///
/// The packet counters come from the [`DataPlaneMetrics`] of the SNAP. This type registers the
/// metrics of the tunnels and the diagnostic metrics of the gateway. Get the metrics of the
/// dispatcher with [`TunnelGatewayMetrics::dispatcher`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelGatewayMetrics {
    /// The SCION packets to endhosts that passed the SNAP, including the SCMP errors that the SNAP
    /// creates.
    ///
    /// The gateway counts a packet when a tunnel accepts it, before the gateway sends it on the
    /// tunnel socket. The tunnel can still drop the packet, for example when the packet waits for
    /// a handshake and the queue of the tunnel is full. The batch sender or the socket can
    /// still drop the datagram, and `dropped_datagrams` counts that drop.
    pub to_endhost: TrafficCounters,
    /// Current number of tunnels. The gateway keeps one tunnel for each remote socket address,
    /// so one endhost can have more than one tunnel. A tunnel stays until it expires, also after
    /// the authorization of its endhost ends.
    pub tunnels: IntGauge,
    /// Current number of packets in the dispatch queue. The gateway sets it from the length of
    /// the queue on each timer tick.
    pub dispatch_queue_size: IntGauge,
    /// SCION packets that the gateway dropped, by reason.
    pub dropped_packets: TunnelGatewayPacketDropMetrics,
    /// Datagrams on the tunnel socket that the gateway dropped, by reason.
    pub dropped_datagrams: TunnelGatewayDatagramDropMetrics,
}

impl TunnelGatewayMetrics {
    /// Registers the metrics of the tunnel gateway in `metrics_registry`, and takes the packet
    /// counters from `data_plane`.
    pub fn new(metrics_registry: &MetricsRegistry, data_plane: &DataPlaneMetrics) -> Self {
        TunnelGatewayMetrics {
            to_endhost: data_plane.passed(Direction::ToEndhost),
            tunnels: metrics_registry.int_gauge(
                "snap_tunnels",
                "Current number of tunnels. The SNAP keeps one tunnel for each remote socket \
                 address. A tunnel stays until it expires.",
            ),
            dispatch_queue_size: metrics_registry.int_gauge(
                "snap_tunnel_gw_dispatch_queue_size",
                "Current number of packets in the tunnel gateway dispatch queue.",
            ),
            dropped_packets: TunnelGatewayPacketDropMetrics::new(data_plane),
            dropped_datagrams: TunnelGatewayDatagramDropMetrics::new(metrics_registry),
        }
    }

    /// The metrics of the [`TunnelGatewayDispatcher`] that queues the packets for this gateway.
    ///
    /// [`TunnelGatewayDispatcher`]: crate::tunnel_gateway::dispatcher::TunnelGatewayDispatcher
    pub fn dispatcher(&self) -> TunnelGatewayDispatcherMetrics {
        TunnelGatewayDispatcherMetrics {
            invalid_destination: self.dropped_packets.to_endhost_invalid_destination.clone(),
            queue_full: self.dropped_packets.to_endhost_queue_full.clone(),
            queue_closed: self.dropped_packets.to_endhost_queue_closed.clone(),
            too_large: self.dropped_packets.to_endhost_too_large.clone(),
        }
    }
}

/// The SCION packets that the tunnel gateway dropped, by reason.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelGatewayPacketDropMetrics {
    /// Packets from an endhost that are not valid SCION packets.
    pub to_scion_router_malformed: IntCounter,
    /// Packets from an endhost with a SCION source address that is not the address of the
    /// endhost.
    pub to_scion_router_invalid_source_address: IntCounter,
    /// Packets from an endhost with a path type that the SNAP does not forward.
    pub to_scion_router_invalid_path_type: IntCounter,
    /// Packets to an endhost whose destination address the dispatcher cannot read.
    pub to_endhost_invalid_destination: IntCounter,
    /// Packets to an endhost that the dispatcher dropped because the dispatch queue was full.
    pub to_endhost_queue_full: IntCounter,
    /// Packets to an endhost that the dispatcher dropped because the gateway closed the
    /// dispatch queue.
    pub to_endhost_queue_closed: IntCounter,
    /// Packets to an endhost that are too large for a datagram of the tunnel after encryption.
    pub to_endhost_too_large: IntCounter,
    /// Packets to an endhost that has no tunnel, or whose tunnel is no longer authorized.
    pub to_endhost_no_authorized_tunnel: IntCounter,
}

impl TunnelGatewayPacketDropMetrics {
    fn new(data_plane: &DataPlaneMetrics) -> Self {
        let to_scion_router = |reason| data_plane.dropped(Direction::ToScionRouter, reason);
        let to_endhost = |reason| data_plane.dropped(Direction::ToEndhost, reason);

        TunnelGatewayPacketDropMetrics {
            to_scion_router_malformed: to_scion_router("malformed"),
            to_scion_router_invalid_source_address: to_scion_router("invalid_source_address"),
            to_scion_router_invalid_path_type: to_scion_router("invalid_path_type"),
            to_endhost_invalid_destination: to_endhost("invalid_destination"),
            to_endhost_queue_full: to_endhost("queue_full"),
            to_endhost_queue_closed: to_endhost("queue_closed"),
            to_endhost_too_large: to_endhost("too_large"),
            to_endhost_no_authorized_tunnel: to_endhost("no_authorized_tunnel"),
        }
    }
}

/// The datagrams on the tunnel socket that the tunnel gateway dropped, by reason.
///
/// Each datagram is a WireGuard message. Only a data message carries a SCION packet.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelGatewayDatagramDropMetrics {
    /// Datagrams that WireGuard refused. Examples are a datagram that is not a WireGuard message,
    /// a handshake that is not valid, and data that the tunnel cannot decrypt. Any host can send
    /// such a datagram, so the sender is not always an endhost.
    pub to_scion_router_wireguard_error: IntCounter,
    /// Datagrams from a peer whose identity is not authorized, for example an endhost whose
    /// authorization ended.
    pub to_scion_router_unauthorized: IntCounter,
    /// Datagrams that the SNAP dropped because of an internal error. This does not occur in
    /// normal operation.
    pub to_scion_router_internal_error: IntCounter,

    /// Datagrams that the batch sender refused because it stayed full.
    pub to_endhost_sender_full: IntCounter,
    /// Datagrams that are larger than the batch sender accepts.
    pub to_endhost_too_large: IntCounter,
    /// Datagrams that the SNAP dropped because of an internal error. This does not occur in
    /// normal operation.
    pub to_endhost_internal_error: IntCounter,
    /// Datagrams that the tunnel socket refused.
    pub to_endhost_socket_refused: IntCounter,
}

impl TunnelGatewayDatagramDropMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        let to_scion_router = metrics_registry.int_counter_vec(
            "snap_to_scion_router_dropped_datagrams_total",
            "Total number of datagrams that arrived on the tunnel socket and that the SNAP \
             dropped, by reason.",
            &["reason"],
        );
        let to_endhost = metrics_registry.int_counter_vec(
            "snap_to_endhost_dropped_datagrams_total",
            "Total number of datagrams that the SNAP could not send on the tunnel socket, by \
             reason.",
            &["reason"],
        );
        let to_scion_router = |reason| to_scion_router.with_label_values(&[reason]);
        let to_endhost = |reason| to_endhost.with_label_values(&[reason]);

        TunnelGatewayDatagramDropMetrics {
            to_scion_router_wireguard_error: to_scion_router("wireguard_error"),
            to_scion_router_unauthorized: to_scion_router("unauthorized"),
            to_scion_router_internal_error: to_scion_router("internal_error"),
            to_endhost_sender_full: to_endhost("sender_full"),
            to_endhost_too_large: to_endhost("too_large"),
            to_endhost_internal_error: to_endhost("internal_error"),
            to_endhost_socket_refused: to_endhost("socket_refused"),
        }
    }
}

/// Tunnel gateway dispatcher metrics: the packets to endhosts that the dispatcher dropped.
///
/// Get them with [`TunnelGatewayMetrics::dispatcher`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelGatewayDispatcherMetrics {
    /// Packets whose destination address the dispatcher cannot read.
    pub invalid_destination: IntCounter,
    /// Packets that the dispatcher dropped because the dispatch queue was full.
    pub queue_full: IntCounter,
    /// Packets that the dispatcher dropped because the gateway closed the dispatch queue.
    pub queue_closed: IntCounter,
    /// Packets that are too large for a datagram of the tunnel after encryption.
    pub too_large: IntCounter,
}
