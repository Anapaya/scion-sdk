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
//! AsVisitors for collecting links in a segment

use std::collections::VecDeque;

use anyhow::Context;

use crate::network::scion::{
    segment::model::LinkSegment,
    topology::{
        DirectedScionLink, ScionAs, ScionLink, ScionLinkType, visitor::TopologyLinkVisitor,
    },
};

/// Follows all core links to collect segments.
#[derive(Clone, Default)]
pub struct CoreSegmentCollector {
    pub links: DirectedLinks,
}

impl TopologyLinkVisitor for CoreSegmentCollector {
    type Output = LinkSegment;

    fn visit(&mut self, used_link: Option<&ScionLink>, current_as: &ScionAs) {
        if let Some(link) = used_link {
            let _ = self
                .links
                .add_link(current_as, link.clone(), true)
                .inspect_err(|e| {
                    debug_assert!(false, "Should never fail to add hop to segment");
                    tracing::error!(error = %e, "Failed to add hop to segment in core path aggregator");
                });
        }
    }

    fn finish(self, _final_link: bool) -> Option<Self::Output> {
        self.links.finalize().ok()
    }

    // Only follow core AS links that are not external.
    fn should_follow_link(
        &self,
        current_as: &ScionAs,
        next_link: &ScionLink,
        next_as: &ScionAs,
    ) -> bool {
        if self.links.links.len() >= 63 {
            tracing::warn!(
                isd_as = %current_as.isd_as(),
                "Segment has reached maximum length of 63 links, not following more links"
            );

            return false;
        }

        !next_as.is_external() && next_link.link_type == ScionLinkType::Core
    }
}

/// Follows all downlinks to collect segments.
#[derive(Clone, Default)]
pub struct DownSegmentCollector {
    pub links: DirectedLinks,
}

impl TopologyLinkVisitor for DownSegmentCollector {
    type Output = LinkSegment;

    fn visit(&mut self, used_link: Option<&ScionLink>, current_as: &ScionAs) {
        if let Some(link) = used_link {
            let _ = self
                .links
                .add_link(current_as, link.clone(), true)
                .inspect_err(|e| {
                    debug_assert!(false, "Should never fail to add hop to links");
                    tracing::error!(error = %e, "Failed to add hop to links in down segment collector");
                });
        }
    }

    fn finish(self, _final_link: bool) -> Option<Self::Output> {
        self.links.finalize().ok()
    }

    /// Should only follow parent links, as these are the only links that can be part of a down
    /// segment.
    ///
    /// If a link goes to a external AS, we do not follow it.
    fn should_follow_link(
        &self,
        current_as: &ScionAs,
        next_link: &ScionLink,
        next_as: &ScionAs,
    ) -> bool {
        if self.links.links.len() >= 63 {
            tracing::warn!(
                isd_as = %current_as.isd_as(),
                "Segment has reached maximum length of 63 links, not following more links"
            );

            return false;
        }

        let link_type = next_link.get_link_type(&current_as.isd_as());

        if next_as.is_external() {
            return false;
        }

        match link_type {
            Some(ScionLinkType::Parent) => true,
            None => {
                tracing::warn!(
                    link_id = %next_link.id,
                    isd_as = %current_as.isd_as(),
                    "Link type for link in AS is none, this should not happen"
                );

                false
            }
            _ => false, // Ignore other link types
        }
    }
}

/// Aggregated list of links in a segment
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DirectedLinks {
    /// All links for this segment
    pub links: VecDeque<DirectedScionLink>,
}

impl DirectedLinks {
    /// Appends an empty hop for ingress and egress and returns the [LinkSegment].
    pub fn finalize(self) -> anyhow::Result<LinkSegment> {
        let first_hop_if = self.links.front().context("links empty")?.from;
        let last_hop_if = self.links.back().context("links empty")?.to;

        Ok(LinkSegment {
            start_as: first_hop_if.isd_as.into(),
            end_as: last_hop_if.isd_as.into(),
            links: self.links,
        })
    }

    pub fn add_link(
        &mut self,
        to_as: &ScionAs,
        used_link: ScionLink,
        is_construction_dir: bool,
    ) -> anyhow::Result<()> {
        let hop = match is_construction_dir {
            true => used_link.get_directed_to(&to_as.isd_as()),
            false => used_link.get_directed_from(&to_as.isd_as()),
        };

        let hop = hop.context("error getting directed link from hop AS")?;

        match is_construction_dir {
            true => self.links.push_back(hop),
            false => self.links.push_front(hop),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::scion::{
        topology::{
            FastTopologyLookup,
            visitor::{walk_all_links, walk_all_links_parallel},
        },
        util::test_helper::{parse_segment, test_topology},
    };

    #[test_log::test]
    fn should_discover_all_complete_down_segments() {
        let topo = test_topology().unwrap();

        let all_segments = walk_all_links_parallel(
            DownSegmentCollector::default(),
            "1-1".parse().unwrap(),
            &FastTopologyLookup::new(&topo),
            4,
        );

        let expected_segments = [
            "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
            "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4;",
            "1-1#1 -> 1-2#2; 1-2#17 -> 1-4#18;",
            "1-1#1 -> 1-2#2;",
        ]
        .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap());

        assert_eq!(all_segments.len(), expected_segments.len());
        all_segments.iter().enumerate().for_each(|(i, lnk)| {
            assert!(
                expected_segments.contains(lnk),
                "segment {i}: {lnk} was not expected"
            );
        });

        let all_segments = walk_all_links_parallel(
            DownSegmentCollector::default(),
            "1-11".parse().unwrap(),
            &FastTopologyLookup::new(&topo),
            4,
        );

        let expected_segments = [
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#17 -> 1-4#18;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11;",
            "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10; 1-3#15 -> 1-4#16;",
            "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10;",
            "1-11#7 -> 1-12#8; 1-12#19 -> 1-4#20;",
            "1-11#7 -> 1-12#8;",
        ]
        .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap());

        assert_eq!(all_segments.len(), expected_segments.len());
        all_segments.iter().enumerate().for_each(|(i, lnk)| {
            assert!(
                expected_segments.contains(lnk),
                "segment {i}: {lnk} was not expected"
            );
        });
    }

    #[test]
    fn should_discover_all_complete_core_segments() {
        let topo = test_topology().unwrap();
        let all_segments = walk_all_links(
            CoreSegmentCollector::default(),
            "1-1".parse().unwrap(),
            &FastTopologyLookup::new(&topo),
        );

        let expected_segments = [
            "1-1#5 -> 1-11#6; 1-11#15 -> 1-21#22; 1-21#23 -> 2-1#24;",
            "1-1#5 -> 1-11#6; 1-11#15 -> 1-21#22;",
            "1-1#5 -> 1-11#6; 1-11#23 -> 2-1#1; 2-1#24 -> 1-21#23;",
            "1-1#5 -> 1-11#6; 1-11#23 -> 2-1#1;",
            "1-1#5 -> 1-11#6;",
            "1-1#32 -> 1-21#17; 1-21#22 -> 1-11#15; 1-11#23 -> 2-1#1;",
            "1-1#32 -> 1-21#17; 1-21#22 -> 1-11#15;",
            "1-1#32 -> 1-21#17; 1-21#23 -> 2-1#24; 2-1#1 -> 1-11#23;",
            "1-1#32 -> 1-21#17; 1-21#23 -> 2-1#24;",
            "1-1#32 -> 1-21#17;            ",
        ]
        .map(|s| parse_segment(s, ScionLinkType::Core).unwrap());

        assert_eq!(all_segments.len(), expected_segments.len());
        all_segments.iter().enumerate().for_each(|(i, lnk)| {
            assert!(
                expected_segments.contains(lnk),
                "segment {i}: {lnk} was not expected"
            );
        });
    }

    /// Builds a topology with N fully-connected core ASes (1-1 .. 1-N) and
    /// runs the core segment collector with 10 threads.
    #[test_log::test]
    fn single_and_multi_thread_should_have_same_results() {
        use crate::network::scion::topology::ScionTopology;

        const NUM_CORE_ASES: u16 = 6;
        // Build topology: N core ASes, all connected to each other.
        let mut topo = ScionTopology::new();
        for i in 1..=NUM_CORE_ASES {
            topo.add_as(ScionAs::new_core(format!("1-{i}").parse().unwrap()))
                .unwrap();
        }

        // Create core links between every pair.  Interface IDs are derived
        // deterministically from the (i, j) pair so they are unique.
        // id_from = i*10 + j, id_to = j*10 + i
        for i in 1..=NUM_CORE_ASES {
            for j in (i + 1)..=NUM_CORE_ASES {
                let link_str = format!("1-{i}#{} core 1-{j}#{}", i * 10 + j, j * 10 + i);
                topo.add_link(link_str.parse().unwrap()).unwrap();
            }
        }

        let lookup = FastTopologyLookup::new(&topo);

        let start = std::time::Instant::now();
        // Run single-threaded as reference.
        let segments_single = walk_all_links(
            CoreSegmentCollector::default(),
            "1-1".parse().unwrap(),
            &lookup,
        );
        let elapsed_single = start.elapsed();

        let start = std::time::Instant::now();
        // Run multi-threaded
        let segments_parallel = walk_all_links_parallel(
            CoreSegmentCollector::default(),
            "1-1".parse().unwrap(),
            &lookup,
            10,
        );

        tracing::info!(
            "Core segment discovery for {} fully connected core ASes took {:?} single-threaded counting {} segments",
            NUM_CORE_ASES,
            elapsed_single,
            segments_single.len()
        );
        tracing::info!(
            "Core segment discovery for {} fully connected core ASes took {:?} with threads counting {} segments",
            NUM_CORE_ASES,
            start.elapsed(),
            segments_parallel.len()
        );

        // Both must produce the same set of segments (order may differ).
        assert_eq!(
            segments_single.len(),
            segments_parallel.len(),
            "segment count mismatch: single={} parallel={}",
            segments_single.len(),
            segments_parallel.len(),
        );

        for (i, seg) in segments_parallel.iter().enumerate() {
            assert!(
                segments_single.contains(seg),
                "parallel segment {i}: {seg} was not found in single-threaded results"
            );
        }
    }
}
