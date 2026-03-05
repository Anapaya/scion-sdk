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

//! Beaconing implementation

use std::{
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::network::scion::{
    segment::{
        model::LinkSegment,
        registry::{LinkSegmentStore, SegmentRegistry},
    },
    topology::{ScionGlobalInterfaceId, ScionLinkType, ScionTopology},
};

/// The beaconing state for a specific interface
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InterfaceBeaconState {
    /// Beacon egress interface
    pub interface: ScionGlobalInterfaceId,
    /// Whether the AS is a core AS, which determines the beacon generation logic
    pub is_core: bool,
    /// The number of hop expiry units to set for generated beacons, which determines the
    /// validity
    pub hop_expiry_units: u8,
    /// If beacons which would pass through this interface's AS should be generated and sent on
    /// this interface
    pub generate_forward_beacons: bool,
    /// The interval at which beacons should be sent on this interface
    pub beacon_interval: Duration,
    /// The interval to wait before retrying beacon sending after a failure
    pub beacon_retry_interval: Duration,
    /// The next scheduled time to send beacons on this interface
    pub next_send_time: DateTime<Utc>,
}

impl InterfaceBeaconState {
    /// Creates a new InterfaceBeaconState for the given interface and AS type, with default
    /// beaconing parameters.
    pub fn new(
        is_core: bool,
        interface: ScionGlobalInterfaceId,
        generate_forward_beacons: bool,
    ) -> Self {
        Self {
            interface,
            is_core,
            hop_expiry_units: 255,
            generate_forward_beacons,
            beacon_interval: Duration::from_secs(600),
            beacon_retry_interval: Duration::from_secs(10),
            next_send_time: Utc::now(),
        }
    }

    /// Overrides the beacon interval for this interface, which determines how often beacons are
    /// sent on this interface after a successful send.
    pub fn with_beacon_interval(mut self, beacon_interval: Duration) -> Self {
        self.beacon_interval = beacon_interval;
        self
    }

    /// Overrides the beacon retry interval for this interface, which determines how long to wait
    /// before retrying to send beacons on this interface after a failure.
    pub fn with_beacon_retry_interval(mut self, beacon_retry_interval: Duration) -> Self {
        self.beacon_retry_interval = beacon_retry_interval;
        self
    }
}

/// The action to be taken after ticking the beaconing state for an interface.
pub enum InterfaceBeaconAction {
    /// Send the given beacons on the interface
    ///
    /// After beacons are sent, the beacon state should be marked with `mark_success` or
    /// `mark_failure` the state machine should be ticked again to schedule the next send time
    /// based on whether sending was successful or not.
    SendBeacons(Vec<scion_protobuf::control_plane::v1::BeaconRequest>),
    /// Wait until the given time and tick again to check if beacons should be sent
    Wait(SystemTime),
}

impl InterfaceBeaconState {
    /// Ticks the beaconing state to determine whether beacons should be sent on this interface
    /// at the current time, and if so, generates the beacons to be sent based on the
    /// current topology and segments in the system state.
    pub fn tick(
        &self,
        current_time: SystemTime,
        segment_registry: &SegmentRegistry,
        topology: &ScionTopology,
    ) -> anyhow::Result<InterfaceBeaconAction> {
        if chrono::DateTime::<Utc>::from(current_time) >= self.next_send_time {
            // Beacons should be sent
            let mut beacons = if self.generate_forward_beacons {
                tracing::debug!(
                    interface = %self.interface,
                    "Generating forwarding beacons for interface",
                );
                BeaconGen::generate_forwarding_beacons(
                    self.interface,
                    self.is_core,
                    segment_registry,
                    topology,
                    current_time.into(),
                    self.hop_expiry_units,
                )?
            } else {
                Vec::new()
            };

            if self.is_core {
                tracing::debug!(
                    interface = %self.interface,
                    "Generating originating beacon for interface",
                );

                let originating_beacon = BeaconGen::generate_originating_beacons(
                    self.interface,
                    topology,
                    current_time.into(),
                    self.hop_expiry_units,
                )?;

                beacons.push(originating_beacon);
            }

            return Ok(InterfaceBeaconAction::SendBeacons(beacons));
        }

        Ok(InterfaceBeaconAction::Wait(self.next_send_time.into()))
    }

    /// Marks that sending beacons was successful, and schedules the next send time based on the
    /// beacon interval
    pub fn mark_success(&mut self, current_time: SystemTime) {
        self.next_send_time = chrono::DateTime::<Utc>::from(current_time) + self.beacon_interval;
    }

    /// Marks that sending beacons failed, and schedules the next send time based on the beacon
    /// retry
    pub fn mark_failure(&mut self, current_time: SystemTime) {
        self.next_send_time =
            chrono::DateTime::<Utc>::from(current_time) + self.beacon_retry_interval;
    }
}

/// Generates beacons at the External AS interface based on the current topology and segments in
/// the system state.
pub struct BeaconGen;

impl BeaconGen {
    /// Generates all beacons which the given AS would forward to another AS in construction
    /// direction
    pub fn generate_forwarding_beacons(
        egress_if: ScionGlobalInterfaceId,
        is_core: bool,
        segments: &SegmentRegistry,
        topology: &ScionTopology,
        timestamp: DateTime<Utc>,
        hop_expiry_units: u8,
    ) -> anyhow::Result<Vec<scion_protobuf::control_plane::v1::BeaconRequest>> {
        let egress_link = topology
            .scion_link(&egress_if.isd_as, egress_if.if_id)
            .context("Given interface does not exist in topology")?
            .get_directed_from(&egress_if.isd_as)
            .expect(
                "Topology is inconsistent, link does not have a direction from the expected AS",
            );

        let empty_segment_store = LinkSegmentStore::new(Default::default(), Default::default());
        let our_as = egress_if.isd_as;

        let forward_segments: Vec<_> = match is_core {
            true => {
                // All segments which end at a our AS would be forwarded
                segments
                    .core_segments()
                    .segments_by_end_as(our_as)
                    .iter()
                    .map(|seg| {
                        segments
                            .core_segments()
                            .segment(seg)
                            .expect("segment index and segment registry must be consistent")
                    })
                    .cloned()
                    .collect()
            }
            false => {
                // Select all interfaces where we would receive beacons from parent ASes, as
                // those are the ones which would be forwarded to the External AS
                let our_relevant_interfaces: HashSet<_> = topology.iter_scion_links_by_as(&our_as).filter_map(|link| {
                    let directed = link.get_directed_to(&our_as).expect(
                        "Link in AS is not connected to the expected AS, topology is inconsistent with External AS state",
                    );

                    let our_interface = directed.to;

                    let relevant = match directed.link_type {
                        ScionLinkType::Parent => true, // Our parent will send us beacons
                        ScionLinkType::Core => false,  // Core links do not exiast for non-core ASes
                        ScionLinkType::Peer => false,  // TODO: Handling peer links
                        ScionLinkType::Child => false,
                    };

                    match relevant {
                        true => Some(our_interface),
                        false => None,
                    }
                }).collect();

                // All segments, ending at our AS, which we received on a relevant interface
                // would be forwarded
                let isd_segment_store = segments
                    .isd_segments(&our_as.isd())
                    .unwrap_or(&empty_segment_store);

                isd_segment_store
                    .segments_by_end_as(our_as)
                    .iter()
                    .map(|seg| {
                        isd_segment_store
                            .segment(seg)
                            .expect("segment index and segment registry must be consistent")
                    })
                    .filter(|seg| {
                        // We only forward segments which we received on a relevant interface
                        seg.links
                            .iter()
                            .last()
                            .map(|link| our_relevant_interfaces.contains(&link.to))
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };

        let mut beacons = Vec::new();

        // Collect all path segments for each beacon source AS which need to be sent to the
        // External AS, and create requests for them
        for mut segment in forward_segments {
            // we need to add a hop going to the external AS
            segment.links.push_back(egress_link.clone());

            let mut hasher = DefaultHasher::new();
            timestamp.hash(&mut hasher);
            let segment_id = hasher.finish() as u16;
            let path_segment = segment
                .to_path_segment(topology, timestamp, segment_id, hop_expiry_units, true)
                .context("Failed to convert segment to path segment for beacon generation")?;

            let beacon_req = scion_protobuf::control_plane::v1::BeaconRequest {
                segment: Some(path_segment.into()),
            };

            beacons.push(beacon_req);
        }

        tracing::debug!(
            num_beacons = beacons.len(),
            asn = %egress_if,
            "Generated forwarding beacons for AS",
        );

        Ok(beacons)
    }

    /// Generates a beacon which the given Core AS would originate to its neighbors, based on
    /// the given interface and the current topology.
    ///
    /// This function is only relevant for core ASes, as non-core ASes do not originate beacons.
    pub fn generate_originating_beacons(
        sending_as_interface: ScionGlobalInterfaceId,
        topology: &ScionTopology,
        timestamp: DateTime<Utc>,
        hop_expiry_units: u8,
    ) -> anyhow::Result<scion_protobuf::control_plane::v1::BeaconRequest> {
        let link = topology
            .scion_link(&sending_as_interface.isd_as, sending_as_interface.if_id)
            .context("Given interface does not exist in topology")?
            .get_directed_from(&sending_as_interface.isd_as)
            .expect(
                "Topology is inconsistent, link does not have a direction from the expected AS",
            );

        let peer_as = link.to;

        let link_segment = LinkSegment {
            start_as: sending_as_interface.isd_as,
            end_as: peer_as.isd_as,
            links: VecDeque::from_iter([link]),
        };

        // Convert to Beacon Request
        let mut hasher = DefaultHasher::new();
        timestamp.hash(&mut hasher);
        let segment_id = hasher.finish() as u16;
        let path_segment = link_segment
            .to_path_segment(topology, timestamp, segment_id, hop_expiry_units, true)
            .context("Failed to convert segment to path segment for beacon generation")?;

        let beacon_req = scion_protobuf::control_plane::v1::BeaconRequest {
            segment: Some(path_segment.into()),
        };

        Ok(beacon_req)
    }
}
