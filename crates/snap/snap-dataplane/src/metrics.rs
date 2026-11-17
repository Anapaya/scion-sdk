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
//! The metrics of the SNAP data plane.

use prometheus::{IntCounter, IntCounterVec};
use scion_sdk_observability::metrics::registry::MetricsRegistry;

/// The direction of a packet through the SNAP. Each direction has its own metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// From an endhost to a SCION router.
    ToScionRouter,
    /// From the SCION network to an endhost.
    ToEndhost,
}

/// The metrics of the SNAP data plane.
#[derive(Debug, Clone)]
pub struct DataPlaneMetrics {
    to_scion_router: DirectionMetrics,
    to_endhost: DirectionMetrics,
}

#[derive(Debug, Clone)]
struct DirectionMetrics {
    packets: IntCounter,
    bytes: IntCounter,
    dropped: IntCounterVec,
}

impl DataPlaneMetrics {
    /// Registers the metrics of the data plane in `metrics_registry`.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            to_scion_router: DirectionMetrics {
                packets: metrics_registry.int_counter(
                    "snap_to_scion_router_packets_total",
                    "Total number of packets from endhosts that the SNAP sent to a SCION router.",
                ),
                bytes: metrics_registry.int_counter(
                    "snap_to_scion_router_bytes_total",
                    "Total number of bytes of the packets in snap_to_scion_router_packets_total.",
                ),
                dropped: metrics_registry.int_counter_vec(
                    "snap_to_scion_router_dropped_packets_total",
                    "Total number of packets from endhosts to a SCION router that the SNAP \
                     dropped, by reason.",
                    &["reason"],
                ),
            },
            to_endhost: DirectionMetrics {
                packets: metrics_registry.int_counter(
                    "snap_to_endhost_packets_total",
                    "Total number of packets to endhosts that passed the SNAP.",
                ),
                bytes: metrics_registry.int_counter(
                    "snap_to_endhost_bytes_total",
                    "Total number of bytes of the packets in snap_to_endhost_packets_total.",
                ),
                dropped: metrics_registry.int_counter_vec(
                    "snap_to_endhost_dropped_packets_total",
                    "Total number of packets to endhosts that the SNAP dropped, by reason.",
                    &["reason"],
                ),
            },
        }
    }

    /// The counters of the packets that pass the SNAP in `direction`.
    pub fn passed(&self, direction: Direction) -> TrafficCounters {
        let metrics = self.of(direction);
        TrafficCounters {
            packets: metrics.packets.clone(),
            bytes: metrics.bytes.clone(),
        }
    }

    /// The counter of the packets that the SNAP drops in `direction` for `reason`.
    pub fn dropped(&self, direction: Direction, reason: &'static str) -> IntCounter {
        self.of(direction).dropped.with_label_values(&[reason])
    }

    fn of(&self, direction: Direction) -> &DirectionMetrics {
        match direction {
            Direction::ToScionRouter => &self.to_scion_router,
            Direction::ToEndhost => &self.to_endhost,
        }
    }
}

/// The packet and byte counters of one direction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrafficCounters {
    /// The number of packets.
    pub packets: IntCounter,
    /// The number of bytes of the packets in `packets`.
    pub bytes: IntCounter,
}

impl TrafficCounters {
    /// Counts one packet of `len` bytes.
    pub fn count(&self, len: usize) {
        self.packets.inc();
        self.bytes.inc_by(len as u64);
    }
}
