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

/// Tunnel gateway dispatcher metrics.
#[derive(Debug, Clone)]
pub struct TunnelGatewayDispatcherMetrics {
    // dispatch queue metrics:
    /// Current size of the tunnel gateway dispatch queue.
    pub dispatch_queue_size: IntGauge,
    /// Total number of errors when the dispatch queue is full.
    pub full_dispatch_queue_errors: IntCounter,
    /// Total number of errors when the dispatch queue is closed.
    pub closed_dispatch_queue_errors: IntCounter,
    // dispatcher error metrics:
    /// Total number of errors when dispatching a packet to the tunnel gateway.
    pub invalid_packets_errors: IntCounter,
    /// Total number of errors when the connection is closed.
    pub connection_closed_errors: IntCounter,
    /// Total number of errors when a new assigned address is received.
    pub new_assigned_address_errors: IntCounter,
    /// Total number of errors when no address is assigned.
    pub no_address_assigned_errors: IntCounter,
    /// Total number of errors when sending a datagram to the snaptun.
    pub send_datagram_errors: IntCounter,
    /// Total number of errors when the tunnel is missing.
    pub missing_tunnel_errors: IntCounter,
}

impl TunnelGatewayDispatcherMetrics {
    /// Create new tunnel gateway dispatcher metrics instance with the given registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let dispatch_errors = metrics_registry.int_counter_vec(
            "snap_tunnel_gw_dispatch_errors_total",
            "Total number of errors when dispatching a packet to the tunnel gateway.",
            &["error_type"],
        );

        let forwarding_errors = metrics_registry.int_counter_vec(
            "snap_tunnel_gw_forwarding_errors_total",
            "Total number of errors when forwarding a packet to corresponding snaptun.",
            &["error_type"],
        );

        TunnelGatewayDispatcherMetrics {
            dispatch_queue_size: metrics_registry.int_gauge(
                "snap_tunnel_gw_dispatch_queue_size",
                "Current size of the tunnel gateway dispatch queue.",
            ),
            full_dispatch_queue_errors: dispatch_errors.with_label_values(&["queue_full"]),
            closed_dispatch_queue_errors: dispatch_errors.with_label_values(&["queue_closed"]),
            invalid_packets_errors: forwarding_errors.with_label_values(&["invalid_packet"]),
            connection_closed_errors: forwarding_errors.with_label_values(&["connection_closed"]),
            new_assigned_address_errors: forwarding_errors
                .with_label_values(&["new_assigned_address"]),
            no_address_assigned_errors: forwarding_errors
                .with_label_values(&["no_address_assigned"]),
            send_datagram_errors: forwarding_errors.with_label_values(&["send_datagram_error"]),
            missing_tunnel_errors: forwarding_errors.with_label_values(&["tunnel_missing"]),
        }
    }
}
