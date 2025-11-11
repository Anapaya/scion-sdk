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
//! Registry for available segments in a Topology

use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use scion_proto::address::{Isd, IsdAsn};

use crate::network::scion::{
    segment::{
        model::LinkSegment,
        visitors::{CoreSegmentCollector, DownSegmentCollector},
    },
    topology::{FastTopologyLookup, ScionTopology, visitor::walk_all_links},
};

/// Keeps all available [LinkSegment] for a topology.
///
/// A [LinkSegment] is a more general representation of a [scion_proto::path::PathSegment]
#[derive(Debug, Clone)]
pub struct SegmentRegistry {
    core_segments: LinkSegmentStore,
    isd_segments: HashMap<Isd, LinkSegmentStore>,
}
// Public
impl SegmentRegistry {
    /// Creates a new [SegmentRegistry] containing all valid paths from given topology
    pub fn new(topo_lookup: &FastTopologyLookup<'_>) -> Self {
        let mut isd_segments = HashMap::new();

        // Compute segments for each ISD
        for isd in topo_lookup
            .topology
            .as_map
            .keys()
            .map(|asn| asn.isd())
            .collect::<HashSet<_>>()
        {
            isd_segments.insert(
                isd,
                LinkSegmentStore::new(
                    Self::compute_isd_down_segments(topo_lookup, isd),
                    topo_lookup
                        .topology
                        .as_map
                        .values()
                        .filter(|as_entry| as_entry.isd_as.isd() == isd)
                        .map(|as_entry| as_entry.isd_as)
                        .collect(),
                ),
            );
        }

        let core_segments = LinkSegmentStore::new(
            Self::compute_core_segments(topo_lookup),
            topo_lookup
                .topology
                .as_map
                .values()
                .filter(|as_entry| as_entry.core)
                .map(|as_entry| as_entry.isd_as)
                .collect(),
        );

        Self {
            core_segments,
            isd_segments,
        }
    }

    /// Creates a new [SegmentRegistry] from a [ScionTopology].
    ///
    /// Prefer [`SegmentRegistry::new`] if you already have a [FastTopologyLookup].
    pub fn from_topology(topo: &ScionTopology) -> Self {
        let topo_lookup = FastTopologyLookup::new(topo);
        Self::new(&topo_lookup)
    }

    /// Returns all segments for a specific ISD, if any.
    pub fn isd_segments(&self, isd: &Isd) -> Option<&LinkSegmentStore> {
        self.isd_segments.get(isd)
    }

    /// Returns all core segments.
    pub fn core_segments(&self) -> &LinkSegmentStore {
        &self.core_segments
    }

    /// Prints all segments in the registry.
    pub fn print_segments(&self) -> String {
        let mut output = String::new();

        output.push_str("Core Segments:\n");

        for (_, segments) in self.core_segments.all_segments.iter() {
            for segment in segments {
                output.push_str(&format!("{segment}\n"));
            }
        }

        for (isd, segments) in &self.isd_segments {
            output.push_str(&format!("ISD {isd} Down Segments: \n"));

            for (_, segments) in segments.all_segments.iter() {
                for segment in segments {
                    output.push_str(&format!("{segment}\n"));
                }
            }
        }

        output
    }
}
// Computation
impl SegmentRegistry {
    fn compute_core_segments(topo_lookup: &FastTopologyLookup<'_>) -> Vec<LinkSegment> {
        // Get All Core ASes
        let core_ases: Vec<IsdAsn> = topo_lookup
            .topology
            .as_map
            .values()
            .filter(|as_entry| as_entry.core)
            .map(|as_entry| as_entry.isd_as)
            .collect();

        // For each core AS, find all segments
        core_ases
            .iter()
            .flat_map(|core_as| {
                walk_all_links(CoreSegmentCollector::default(), *core_as, topo_lookup)
            })
            .collect::<Vec<_>>()
    }

    fn compute_isd_down_segments(
        topo_lookup: &FastTopologyLookup<'_>,
        isd: Isd,
    ) -> Vec<LinkSegment> {
        // Get All Core ASes in the ISD
        let core_ases: Vec<IsdAsn> = topo_lookup
            .topology
            .as_map
            .values()
            .filter(|as_entry| as_entry.core && as_entry.isd_as.isd() == isd)
            .map(|as_entry| as_entry.isd_as)
            .collect();

        // For each core AS, find all segments that start at this AS

        core_ases
            .iter()
            .flat_map(|core_as| {
                walk_all_links(DownSegmentCollector::default(), *core_as, topo_lookup)
            })
            .collect::<Vec<_>>()
    }
}

// ############################################################
// Segment Cache

/// Pair of ASes.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AsPair {
    pub(crate) start_as: IsdAsn,
    pub(crate) leaf_as: IsdAsn,
}

impl AsPair {
    fn new(core_as: IsdAsn, leaf_as: IsdAsn) -> Self {
        Self {
            start_as: core_as,
            leaf_as,
        }
    }
}

/// Identifier for a specific [LinkSegment] in a [LinkSegmentStore]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentId {
    pub(crate) bucket: AsPair,
    pub(crate) bucket_index: usize,
}

impl SegmentId {
    fn new(bucket: AsPair, bucket_index: usize) -> Self {
        Self {
            bucket,
            bucket_index,
        }
    }

    /// Resolves the segment ID to a [LinkSegment] in the given store.
    pub fn resolve<'store>(&self, store: &'store LinkSegmentStore) -> Option<&'store LinkSegment> {
        store.segment(self)
    }
}

/// Type alias for a unique path hash.
pub type UniquePathHash = u64;

/// Store of many [LinkSegment] across multiple ASes
#[derive(Debug, Clone)]
pub struct LinkSegmentStore {
    all_segments: HashMap<AsPair, Vec<LinkSegment>>,

    // All ASes known in the store
    known_ases: HashSet<IsdAsn>,

    // All segments ending at an AS
    end_as_to_segment: HashMap<IsdAsn, Vec<SegmentId>>,

    // All segments starting at an AS
    start_as_to_segment: HashMap<IsdAsn, Vec<SegmentId>>,

    // All segments crossing a specific AS
    as_to_crossing_segment_map: HashMap<IsdAsn, HashSet<SegmentId>>,
}

// required to allow returning references to collections
static EMPTY_HS: LazyLock<HashSet<SegmentId>> = LazyLock::new(HashSet::new);
static EMPTY_SEG_ID_VEC: LazyLock<Vec<SegmentId>> = LazyLock::new(Vec::new);
static EMPTY_LINK_VEC: LazyLock<Vec<LinkSegment>> = LazyLock::new(Vec::new);

impl LinkSegmentStore {
    /// Creates a new link segment store.
    ///
    /// `segments` - all segments known to this store
    /// `contained_ases` - all ASes contained in this store
    pub fn new(segments: Vec<LinkSegment>, contained_ases: HashSet<IsdAsn>) -> Self {
        let mut cache = LinkSegmentStore {
            all_segments: Default::default(),
            as_to_crossing_segment_map: Default::default(),
            end_as_to_segment: Default::default(),
            known_ases: contained_ases,
            start_as_to_segment: Default::default(),
        };

        for segment in segments.into_iter() {
            let bucket_id = AsPair::new(segment.start_as, segment.end_as);

            let all_segment_bucket = cache.all_segments.entry(bucket_id).or_default();
            let bucket_index = all_segment_bucket.len();
            let segment_id = SegmentId::new(bucket_id, bucket_index);

            // Index crossing segments
            for link in segment.links.iter() {
                if link.from.if_id != 0 {
                    let isd = link.from.isd_as;
                    cache
                        .as_to_crossing_segment_map
                        .entry(isd)
                        .or_default()
                        .insert(segment_id);
                }

                if link.to.if_id != 0 {
                    let isd = link.to.isd_as;
                    cache
                        .as_to_crossing_segment_map
                        .entry(isd)
                        .or_default()
                        .insert(segment_id);
                }
            }

            cache
                .end_as_to_segment
                .entry(segment.end_as)
                .or_default()
                .push(segment_id);

            cache
                .start_as_to_segment
                .entry(segment.start_as)
                .or_default()
                .push(segment_id);

            // Add the segment to the cache
            all_segment_bucket.push(segment);
        }

        cache
    }

    /// Returns the total number of segments in the store.
    pub fn segment_count(&self) -> usize {
        self.all_segments.values().map(Vec::len).sum()
    }

    /// Returns true if the AS is known in the store.
    pub fn is_known_as(&self, asn: IsdAsn) -> bool {
        self.known_ases.contains(&asn)
    }

    /// Returns an iterator over all known ASes in the store.
    pub fn iter_known_ases(&self) -> impl Iterator<Item = &IsdAsn> {
        self.known_ases.iter()
    }

    /// Returns all segments starting at a specific AS and ending at another AS.
    pub fn segments(&self, start_as: IsdAsn, end_as: IsdAsn) -> &Vec<LinkSegment> {
        self.all_segments
            .get(&AsPair::new(start_as, end_as))
            .unwrap_or(&EMPTY_LINK_VEC)
    }

    /// Returns a HashSet containing all segments crossing a specific AS.
    pub fn segments_crossing_as(&self, asn: IsdAsn) -> &HashSet<SegmentId> {
        self.as_to_crossing_segment_map
            .get(&asn)
            .unwrap_or(&EMPTY_HS)
    }

    /// Returns a all segments ending at a specific AS.
    pub fn segments_by_end_as(&self, asn: IsdAsn) -> &Vec<SegmentId> {
        self.end_as_to_segment
            .get(&asn)
            .unwrap_or(&EMPTY_SEG_ID_VEC)
    }

    /// Returns a all segments starting at a specific AS.
    pub fn segments_by_start_as(&self, asn: IsdAsn) -> &Vec<SegmentId> {
        self.start_as_to_segment
            .get(&asn)
            .unwrap_or(&EMPTY_SEG_ID_VEC)
    }

    /// Returns an iterator over all segments that start at a specific ISD.
    pub fn segments_by_start_isd(&self, isd: Isd) -> impl Iterator<Item = &LinkSegment> {
        self.all_segments
            .iter()
            .filter(move |(bucket_id, _)| bucket_id.start_as.isd() == isd)
            .flat_map(|(_, segments)| segments.iter())
    }

    /// Returns an iterator over all segments that end at a specific ISD.
    pub fn segments_by_end_isd(&self, isd: Isd) -> impl Iterator<Item = &LinkSegment> {
        self.all_segments
            .iter()
            .filter(move |(bucket_id, _)| bucket_id.leaf_as.isd() == isd)
            .flat_map(|(_, segments)| segments.iter())
    }

    /// Returns an iterator over all segments that start or end at a specific ISD.
    pub fn iter_segments_filtered(
        &self,
        predicate: impl Fn(&AsPair) -> bool,
    ) -> impl Iterator<Item = &LinkSegment> {
        self.all_segments
            .iter()
            .filter(move |(bucket_id, _)| predicate(bucket_id))
            .flat_map(|(_, segments)| segments.iter())
    }

    /// Returns an iterator over all segments that contain two ASes and end at either one.
    pub fn iter_shared_segments(
        &self,
        ias_a: IsdAsn,
        ias_b: IsdAsn,
    ) -> impl Iterator<Item = &LinkSegment> {
        let viable_a = self.segments_crossing_as(ias_a);
        let viable_b = self.segments_crossing_as(ias_b);

        viable_a
            .intersection(viable_b)
            .filter_map(|segment_id| self.segment(segment_id))
    }

    /// Returns a specific segment.
    pub fn segment(&self, id: &SegmentId) -> Option<&LinkSegment> {
        self.all_segments
            .get(&id.bucket)
            .and_then(|segments| segments.get(id.bucket_index))
    }
}

#[cfg(test)]
mod tests {
    use scion_proto::address::Isd;

    use crate::network::scion::{
        segment::registry::SegmentRegistry,
        topology::{FastTopologyLookup, ScionLinkType},
        util::test_helper::{parse_segment, test_topology},
    };

    #[test_log::test]
    fn should_get_all_segments() {
        let topo = test_topology().unwrap();
        let topo_lookup = FastTopologyLookup::new(&topo);
        let segment_store = SegmentRegistry::new(&topo_lookup);

        let core_segments = segment_store.core_segments;
        let expected_core_segments = [
            "1-1#32 -> 1-21#17;",
            "1-1#32 -> 1-21#17; 1-21#22 -> 1-11#15;",
            "1-1#32 -> 1-21#17; 1-21#22 -> 1-11#15; 1-11#23 -> 2-1#1;",
            "1-1#32 -> 1-21#17; 1-21#23 -> 2-1#24;",
            "1-1#32 -> 1-21#17; 1-21#23 -> 2-1#24; 2-1#1 -> 1-11#23;",
            "1-1#5 -> 1-11#6;",
            "1-1#5 -> 1-11#6; 1-11#15 -> 1-21#22;",
            "1-1#5 -> 1-11#6; 1-11#15 -> 1-21#22; 1-21#23 -> 2-1#24;",
            "1-1#5 -> 1-11#6; 1-11#23 -> 2-1#1;",
            "1-1#5 -> 1-11#6; 1-11#23 -> 2-1#1; 2-1#24 -> 1-21#23;",
            "1-11#15 -> 1-21#22;",
            "1-11#15 -> 1-21#22; 1-21#17 -> 1-1#32;",
            "1-11#15 -> 1-21#22; 1-21#23 -> 2-1#24;",
            "1-11#23 -> 2-1#1;",
            "1-11#23 -> 2-1#1; 2-1#24 -> 1-21#23;",
            "1-11#23 -> 2-1#1; 2-1#24 -> 1-21#23; 1-21#17 -> 1-1#32;",
            "1-11#6 -> 1-1#5;",
            "1-11#6 -> 1-1#5; 1-1#32 -> 1-21#17;",
            "1-11#6 -> 1-1#5; 1-1#32 -> 1-21#17; 1-21#23 -> 2-1#24;",
            "1-21#17 -> 1-1#32;",
            "1-21#17 -> 1-1#32; 1-1#5 -> 1-11#6;",
            "1-21#17 -> 1-1#32; 1-1#5 -> 1-11#6; 1-11#23 -> 2-1#1;",
            "1-21#22 -> 1-11#15;",
            "1-21#22 -> 1-11#15; 1-11#23 -> 2-1#1;",
            "1-21#22 -> 1-11#15; 1-11#6 -> 1-1#5;",
            "1-21#23 -> 2-1#24;",
            "1-21#23 -> 2-1#24; 2-1#1 -> 1-11#23;",
            "1-21#23 -> 2-1#24; 2-1#1 -> 1-11#23; 1-11#6 -> 1-1#5;",
            "2-1#1 -> 1-11#23;",
            "2-1#1 -> 1-11#23; 1-11#15 -> 1-21#22;",
            "2-1#1 -> 1-11#23; 1-11#15 -> 1-21#22; 1-21#17 -> 1-1#32;",
            "2-1#1 -> 1-11#23; 1-11#6 -> 1-1#5;",
            "2-1#1 -> 1-11#23; 1-11#6 -> 1-1#5; 1-1#32 -> 1-21#17;",
            "2-1#24 -> 1-21#23;",
            "2-1#24 -> 1-21#23; 1-21#17 -> 1-1#32;",
            "2-1#24 -> 1-21#23; 1-21#17 -> 1-1#32; 1-1#5 -> 1-11#6;",
            "2-1#24 -> 1-21#23; 1-21#22 -> 1-11#15;",
            "2-1#24 -> 1-21#23; 1-21#22 -> 1-11#15; 1-11#6 -> 1-1#5;",
        ]
        .iter()
        .map(|s| parse_segment(s, ScionLinkType::Core).unwrap())
        .collect::<Vec<_>>();

        assert_eq!(
            core_segments.segment_count(),
            expected_core_segments.len(),
            "core segments count should match expected number of segments"
        );
        core_segments
            .all_segments
            .values()
            .flatten()
            .for_each(|segment| {
                assert!(
                    expected_core_segments.contains(segment),
                    "Segment {segment} was not expected"
                );
            });

        let isd1_segments = [
            "1-1#1 -> 1-2#2;",
            "1-1#1 -> 1-2#2; 1-2#17 -> 1-4#18;",
            "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4;",
            "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
            "1-11#7 -> 1-12#8;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#17 -> 1-4#18;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4;",
            "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
            "1-11#7 -> 1-12#8; 1-12#19 -> 1-4#20;",
            "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10;",
            "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10; 1-3#15 -> 1-4#16;",
        ]
        .iter()
        .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap())
        .collect::<Vec<_>>();

        let isd1_store = segment_store
            .isd_segments
            .get(&Isd(1))
            .expect("ISD 1 segments not found");

        assert_eq!(
            isd1_store.segment_count(),
            isd1_segments.len(),
            "ISD 1 segment count should match expected number of segments"
        );
        isd1_store
            .all_segments
            .values()
            .flatten()
            .for_each(|segment| {
                assert!(
                    isd1_segments.contains(segment),
                    "Segment not found in ISD 1 segments: {segment}"
                );
            });

        let isd2_segments = [
            "2-1#2 -> 2-2#3",
            "2-1#2 -> 2-2#3; 2-2#4 -> 2-3#5;",
            "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;",
            "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6",
        ]
        .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap());

        let isd2_store = segment_store
            .isd_segments
            .get(&Isd(2))
            .expect("ISD 2 segments not found");

        isd2_store
            .all_segments
            .values()
            .flatten()
            .for_each(|segment| {
                assert!(
                    isd2_segments.contains(segment),
                    "Segment not found in ISD 2 segments: {segment}"
                );
            });
        assert_eq!(
            isd2_store.segment_count(),
            isd2_segments.len(),
            "ISD 2 segment count should match expected number of segments"
        );
    }

    mod link_segment_store {
        use std::{collections::HashSet, str::FromStr};

        use scion_proto::address::IsdAsn;

        use super::*;
        use crate::network::scion::segment::{model::LinkSegment, registry::LinkSegmentStore};

        fn create_link_store() -> (Vec<LinkSegment>, LinkSegmentStore) {
            let all_link_segments = [
                "1-1#1 -> 1-2#2;",
                "1-1#1 -> 1-2#2; 1-2#17 -> 1-4#19;",
                "1-1#1 -> 1-5#2; 1-5#3 -> 1-4#18;",
                "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4;",
                "1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
                "1-11#7 -> 1-12#8;",
                "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11;",
                "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#17 -> 1-4#18;",
                "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4;",
                "1-11#7 -> 1-12#8; 1-12#12 -> 1-2#11; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16;",
                "1-11#7 -> 1-12#8; 1-12#19 -> 1-4#20;",
                "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10;",
                "1-11#7 -> 1-12#8; 1-12#9 -> 1-3#10; 1-3#15 -> 1-4#16;",
            ]
            .iter()
            .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap())
            .collect::<Vec<LinkSegment>>();

            let known_ases = all_link_segments
                .iter()
                .flat_map(|segment| {
                    segment
                        .links
                        .iter()
                        .map(|link| link.from.isd_as)
                        .chain(segment.links.iter().map(|link| link.to.isd_as))
                })
                .collect::<HashSet<_>>();

            let store = LinkSegmentStore::new(all_link_segments.clone(), known_ases);
            (all_link_segments, store)
        }

        #[test_log::test]
        fn should_correctly_return_by_end_as() {
            let (_, store) = create_link_store();

            let check = move |ias: IsdAsn, expected_count: usize| {
                let segments = store
                    .segments_by_end_as(ias)
                    .iter()
                    .map(|id| store.segment(id).unwrap())
                    .map(|s| {
                        assert_eq!(s.end_as, ias, "Segment does not end at expected AS");
                    })
                    .collect::<Vec<_>>();
                assert_eq!(segments.len(), expected_count);
            };

            // Should correctly return segments by start and end AS
            check(IsdAsn::from_str("1-4").unwrap(), 7);
            check(IsdAsn::from_str("1-2").unwrap(), 2);
            check(IsdAsn::from_str("2-2").unwrap(), 0);
        }

        #[test_log::test]
        fn should_correctly_return_by_start_as() {
            let (_, store) = create_link_store();
            let check = move |ias: IsdAsn, expected_count: usize| {
                let segments = store
                    .segments_by_start_as(ias)
                    .iter()
                    .map(|id| store.segment(id).unwrap())
                    .map(|s| {
                        assert_eq!(s.start_as, ias, "Segment does not start at expected AS");
                    })
                    .collect::<Vec<_>>();
                assert_eq!(segments.len(), expected_count);
            };

            // Should correctly return segments by start and end AS
            check(IsdAsn::from_str("1-1").unwrap(), 5);
            check(IsdAsn::from_str("1-11").unwrap(), 8);
            check(IsdAsn::from_str("2-2").unwrap(), 0);
        }

        #[test_log::test]
        fn should_correctly_return_by_start_end_as() {
            let (_, store) = create_link_store();

            let check = move |start: IsdAsn, end: IsdAsn, expected_count: usize| {
                let segments = store.segments(start, end);
                segments.iter().for_each(|s| {
                    assert_eq!(s.start_as, start, "Segment does not start at expected AS");
                    assert_eq!(s.end_as, end, "Segment does not end at expected AS");
                });
                assert_eq!(segments.len(), expected_count);
            };

            // Should correctly return segments by start and end AS
            check(
                IsdAsn::from_str("1-1").unwrap(),
                IsdAsn::from_str("1-2").unwrap(),
                1,
            );

            check(
                IsdAsn::from_str("1-1").unwrap(),
                IsdAsn::from_str("1-4").unwrap(),
                3,
            );

            check(
                IsdAsn::from_str("1-11").unwrap(),
                IsdAsn::from_str("1-4").unwrap(),
                4,
            );

            check(
                IsdAsn::from_str("2-12").unwrap(),
                IsdAsn::from_str("2-13").unwrap(),
                0,
            );
        }

        #[test_log::test]
        fn should_correctly_list_crossing_as() {
            let (_, store) = create_link_store();
            let check = move |ias: IsdAsn, expected_count: usize| {
                let segments = store.segments_crossing_as(ias);
                assert_eq!(segments.len(), expected_count);

                segments.iter().for_each(|segment_id| {
                    let segment = store.segment(segment_id).unwrap();
                    assert!(
                        segment.links.iter().any(|link| link.from.isd_as == ias)
                            || segment.links.iter().any(|link| link.to.isd_as == ias),
                        "Segment {segment} does not cross AS {ias}"
                    );
                });
            };

            check(IsdAsn::from_str("1-2").unwrap(), 8);
            check(IsdAsn::from_str("1-5").unwrap(), 1);
        }

        #[test_log::test]
        fn should_correctly_list_shared_segments() {
            let (_, store) = create_link_store();

            let check = move |ias_a: IsdAsn, ias_b: IsdAsn, expected_count: usize| {
                let segments = store.iter_shared_segments(ias_a, ias_b).collect::<Vec<_>>();
                println!("Checking segments from {ias_a} to {ias_b}");
                segments.iter().for_each(|segment| {
                    let crosses_ias_a = segment
                        .links
                        .iter()
                        .any(|link| link.from.isd_as == ias_a || link.to.isd_as == ias_a);
                    let crosses_ias_b = segment
                        .links
                        .iter()
                        .any(|link| link.from.isd_as == ias_b || link.to.isd_as == ias_b);

                    println!("Segment: {segment}");
                    assert!(
                        crosses_ias_a || crosses_ias_b,
                        "Segment {segment} does not share AS {ias_a} and {ias_b}"
                    );
                });
                assert_eq!(segments.len(), expected_count);
            };

            check("1-2".parse().unwrap(), "1-12".parse().unwrap(), 4);
            check("1-3".parse().unwrap(), "1-4".parse().unwrap(), 3);
            check("1-1".parse().unwrap(), "1-11".parse().unwrap(), 0);
        }
    }
}
