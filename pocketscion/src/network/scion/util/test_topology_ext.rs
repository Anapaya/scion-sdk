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

//! Extension trait for building a ScionTopology from a TestPathContext

use scion_proto::{
    address::{Asn, Isd, IsdAsn},
    path::test_builder::{TestPathContext, TestRoutingLinkType},
};

use crate::network::scion::{
    routing::AsRoutingLinkType,
    topology::{ScionAs, ScionLink, ScionLinkType, ScionTopology},
};

/// Extension trait for building a ScionTopology from a TestPathContext
pub trait TestPathContextTopologyExt {
    /// Builds a simple test topology where the packet in this context is valid
    ///
    /// If SRC and DST are in different ISDs, a Core Segment with at least 3 hops is required.
    ///
    /// Function will inject at least one Core AS to the topology.
    ///
    /// Note: Currently ignores per hop IsdAsn specified in the TestBuilder
    fn build_topology(&self) -> ScionTopology;
}

impl TestPathContextTopologyExt for TestPathContext {
    fn build_topology(&self) -> ScionTopology {
        let mut topology = ScionTopology::new();

        let src_as = self.src_address.isd_asn();
        let dst_as = self.dst_address.isd_asn();

        let mut using_isd = src_as.isd().to_u16();
        let mut as_counter = src_as.asn().to_u64();

        let mut previous_egress: Option<(IsdAsn, u16, bool)> = None;

        let mut after_segment_change = false;
        let mut has_changed_isd = false;

        // Determine the final hop
        let Some(final_hop) = self.test_segments.iter().flat_map(|s| &s.hop_fields).last() else {
            assert_eq!(
                src_as, dst_as,
                "If path is empty, src and dst AS must be the same"
            );

            let other_as = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter + 1));
            // If the path is empty, we just create a basic topology with two ASes
            topology
                .add_as(ScionAs::new_core(src_as))
                .unwrap()
                .add_as(ScionAs::new_core(other_as))
                .unwrap()
                .add_link(ScionLink::new(src_as, 1, ScionLinkType::Core, other_as, 1).unwrap())
                .unwrap();

            return topology;
        };

        for (seg_idx, segment) in self.test_segments.iter().enumerate() {
            for hop in &segment.hop_fields {
                if after_segment_change {
                    // If we switched to core segment - check if we need to change ISD
                    if hop.egress_link_type == Some(TestRoutingLinkType::LinkToCore)
                        && dst_as.isd() != src_as.isd()
                    {
                        assert!(
                            segment.hop_fields.len() >= 3,
                            "Need at least three core hops to change ISDs"
                        );
                        using_isd = dst_as.isd().to_u16();
                        has_changed_isd = true;
                    }

                    // update previous egress interface
                    let (isd, ..) = previous_egress
                        .take()
                        .expect("Previous egress should be set");

                    previous_egress = Some((isd, hop.egress_if, hop.egress_interface_down));

                    after_segment_change = false;
                    continue;
                }

                after_segment_change = hop.segment_change_next;

                // Get the next ASN
                let curr_as = if std::ptr::eq(hop, final_hop) {
                    dst_as // use our dst AS at the final hop
                } else {
                    // Count up from src AS
                    let mut next = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter));

                    // Avoid overlap with destination AS
                    if next == dst_as {
                        as_counter += 1;
                        next = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter));
                    }

                    as_counter += 1;
                    next
                };

                // Create a new AS for each hop
                let scion_as = match segment.uplink_type {
                    TestRoutingLinkType::LinkToCore => ScionAs::new_core(curr_as),
                    _ => {
                        // If this is a segment change, we need to see if the next AS might need to
                        // be a core
                        match hop.segment_change_next {
                            false => ScionAs::new(curr_as),
                            true => {
                                let next_segment = self
                                    .test_segments
                                    .get(seg_idx + 1)
                                    .expect("Next segment should exist on segment change");

                                if next_segment.uplink_type == TestRoutingLinkType::LinkToCore {
                                    ScionAs::new_core(curr_as)
                                } else {
                                    ScionAs::new(curr_as)
                                }
                            }
                        }
                    }
                };

                topology
                    .add_as(scion_as.with_forwarding_key(hop.forwarding_key.into()))
                    .expect("Should not fail to add AS");

                // Update previous AS
                let prev_as =
                    previous_egress.replace((curr_as, hop.egress_if, hop.egress_interface_down));
                let Some((prev_as, prev_egress, link_down)) = prev_as else {
                    // If this is the first hop no need to create a link
                    continue;
                };

                // Create a link between the previous AS and the current AS
                let link_type = match hop.ingress_link_type {
                    Some(link_type) => {
                        match link_type {
                            TestRoutingLinkType::LinkToCore => ScionLinkType::Core,
                            TestRoutingLinkType::LinkToParent => ScionLinkType::Parent,
                            TestRoutingLinkType::LinkToChild => ScionLinkType::Child,
                            TestRoutingLinkType::LinkToPeer => ScionLinkType::Peer,
                        }
                    }
                    None => continue, // Segment change
                };

                let mut link =
                    ScionLink::new(prev_as, prev_egress, link_type, curr_as, hop.ingress_if)
                        .expect("Should not fail to create links");

                link.set_is_up(!link_down);

                topology
                    .add_link(link)
                    .expect("Should not fail to add link");
            }
        }

        // Check if we have done a required ISD change
        if dst_as.isd() != src_as.isd() && !has_changed_isd {
            panic!(
                "If dst_ia is set, and ISD is not the same as start, the path must have at least one core segment with 3 hops to change ISD"
            );
        }

        // If there is no core AS, add one
        if !topology.as_map.values().any(|as_entry| as_entry.core) {
            let core_ia = IsdAsn::new(
                Isd::new(using_isd),
                Asn::new(as_counter.saturating_add(100)),
            ); // Could collide with another AS, not worth to worry about

            let core_as = ScionAs::new_core(core_ia);
            topology.add_as(core_as).expect("Failed to add core AS");

            // Add links from both src and dst AS to the core AS
            // Will make sure there are no orphans along the way
            let src_link = ScionLink::new(src_as, 50, ScionLinkType::Child, core_ia, 50)
                .expect("Failed to create link");
            let dst_link = ScionLink::new(dst_as, 51, ScionLinkType::Child, core_ia, 51)
                .expect("Failed to create link");
            topology.add_link(src_link).expect("Failed to add link");
            topology.add_link(dst_link).expect("Failed to add link");
        }

        topology
    }
}

impl From<TestRoutingLinkType> for AsRoutingLinkType {
    fn from(value: TestRoutingLinkType) -> Self {
        match value {
            TestRoutingLinkType::LinkToCore => AsRoutingLinkType::LinkToCore,
            TestRoutingLinkType::LinkToParent => AsRoutingLinkType::LinkToParent,
            TestRoutingLinkType::LinkToChild => AsRoutingLinkType::LinkToChild,
            TestRoutingLinkType::LinkToPeer => AsRoutingLinkType::LinkToPeer,
        }
    }
}
