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

use prometheus::IntCounter;
use scion_sdk_observability::metrics::registry::MetricsRegistry;

use crate::fragmenting::metrics::{DefragmentMetrics, FragmentMetrics};

/// Combined metrics for an edge-tun connection (incoming, outgoing, fragmentation).
#[derive(Debug, Clone)]
pub struct EdgeTunMetrics {
    /// Metrics for the incoming (receive) path.
    pub incoming: IncomingMetrics,
    /// Metrics for the outgoing (send) path.
    pub outgoing: OutgoingMetrics,
    /// Metrics for the defragmenter.
    pub defrag: DefragmentMetrics,
    /// Metrics for the fragmenter.
    pub fragment: FragmentMetrics,
}

impl EdgeTunMetrics {
    /// Create a new [`EdgeTunMetrics`] instance, registering all counters into `metrics_registry`.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        EdgeTunMetrics {
            incoming: IncomingMetrics::new(metrics_registry),
            outgoing: OutgoingMetrics::new(metrics_registry),
            defrag: DefragmentMetrics::new(metrics_registry),
            fragment: FragmentMetrics::new(metrics_registry),
        }
    }
}

/// Metrics for the incoming (receive) side of an edge-tun connection.
#[derive(Debug, Clone)]
pub struct IncomingMetrics {
    /// Total number of QUIC datagrams received.
    pub datagrams_received_total: IntCounter,
    /// Total number of reassembled IP packets received.
    pub packets_received_total: IntCounter,
    /// Total number of stream receive errors.
    pub stream_receive_errors_total: IntCounter,
}

impl IncomingMetrics {
    /// Create and register incoming metrics in `metrics_registry`.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        IncomingMetrics {
            datagrams_received_total: metrics_registry.int_counter(
                "edgetun_datagrams_received_total",
                "Total number of datagrams received by the incoming stream.",
            ),
            packets_received_total: metrics_registry.int_counter(
                "edgetun_packets_received_total",
                "Total number of assembled packets received by the incoming stream.",
            ),
            stream_receive_errors_total: metrics_registry.int_counter(
                "edgetun_stream_receive_errors_total",
                "Total number of stream receive errors that occurred.",
            ),
        }
    }
}

/// Metrics for the outgoing (send) side of an edge-tun connection.
#[derive(Debug, Clone)]
pub struct OutgoingMetrics {
    /// Total number of QUIC datagrams sent.
    pub datagrams_sent_total: IntCounter,
    /// Total number of reassembled IP packets sent.
    pub packets_sent_total: IntCounter,
}

impl OutgoingMetrics {
    /// Create and register outgoing metrics in `metrics_registry`.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        OutgoingMetrics {
            datagrams_sent_total: metrics_registry.int_counter(
                "edgetun_datagrams_sent_total",
                "Total number of datagrams sent by the outgoing stream.",
            ),
            packets_sent_total: metrics_registry.int_counter(
                "edgetun_assembled_packets_sent_total",
                "Total number of assembled packets sent by the outgoing stream.",
            ),
        }
    }
}
