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
//! General Representation of a Path Segment

use std::{
    collections::{VecDeque, vec_deque},
    fmt::Display,
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use scion_proto::{
    address::IsdAsn,
    path::{
        ASEntry, HopEntry, PathSegment, PeerEntry, SegmentHopField, SignedMessage,
        crypto::{ForwardingKey, calculate_hop_mac, mac_chaining_step},
    },
};

use crate::network::scion::topology::{DirectedScionLink, ScionLinkType, ScionTopology};

/// More general representation of a [scion_proto::path::PathSegment]
///
/// Use: `to_path_segment` to convert to a [scion_proto::path::PathSegment]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinkSegment {
    pub(crate) start_as: IsdAsn,
    pub(crate) end_as: IsdAsn,

    // All links in the segment
    pub(crate) links: VecDeque<DirectedScionLink>,
}

impl Display for LinkSegment {
    /// Format:
    /// 0-0#0 -> 1-1#1; 1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16; 1-4#16 -> 0-0#0;
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for entry in &self.links {
            write!(f, "{} -> {};", entry.from, entry.to)?;
        }
        Ok(())
    }
}

impl LinkSegment {
    /// Returns an iterator over all hops in the link segment.
    pub fn iter_hops(&self) -> HopIter<'_> {
        HopIter {
            last_ingress_link: None,
            link_iter: self.links.iter(),
        }
    }

    /// Converts [LinkSegment] into a [PathSegment].
    ///
    /// `timestamp` is the time when the segment was created.
    /// `segment_id` is a random number identifying the segment.
    /// `hop_entry_expiry` is expiry time for each hop entry in the segment.
    pub fn to_path_segment(
        &self,
        topo: &ScionTopology,
        timestamp: DateTime<Utc>,
        segment_id: u16,
        hop_entry_expiry: u8,
    ) -> anyhow::Result<PathSegment> {
        let mut as_entries = Vec::with_capacity(self.links.len());
        let mut accumulator = segment_id; // Beta for MAC chaining

        // Iterate through all hop pairs in construction direction
        for hop in self.iter_hops() {
            let hop_as = topo
                .as_map
                .get(&hop.local_ias)
                .with_context(|| format!("error getting AS {} from topology", hop.local_ias))?;

            let epoch_s = timestamp
                .timestamp()
                .try_into()
                .context("error converting current time to u32")?;

            let local_peer_entries = Self::create_peer_entries(
                topo,
                hop_entry_expiry,
                &hop,
                accumulator,
                epoch_s,
                &hop_as.forwarding_key.into(),
            );

            let entry = Self::create_as_entry(
                hop_entry_expiry,
                hop,
                accumulator,
                epoch_s,
                local_peer_entries,
                &hop_as.forwarding_key.into(),
            );

            // Update accumulator with the MAC of the new hop
            accumulator = mac_chaining_step(accumulator, entry.hop_entry.hop_field.mac);

            as_entries.push(entry);
        }

        PathSegment::new(timestamp, segment_id, as_entries).context("error creating path segment")
    }
}
// AS Entry conversion
impl LinkSegment {
    const HARDCODED_MTU: u16 = 1280;

    fn create_as_entry(
        hop_entry_expiry: u8,
        hop: Hop,
        accumulator: u16,
        timestamp: u32,
        local_peer_entries: Vec<PeerEntry>,
        forwarding_key: &ForwardingKey,
    ) -> ASEntry {
        let mac = calculate_hop_mac(
            accumulator,
            timestamp,
            hop_entry_expiry,
            hop.ingress_if,
            hop.egress_if,
            forwarding_key,
        );

        let hop_entry = HopEntry {
            ingress_mtu: Self::HARDCODED_MTU,
            hop_field: SegmentHopField {
                exp_time: hop_entry_expiry,
                cons_ingress: hop.ingress_if,
                cons_egress: hop.egress_if,
                mac,
            },
        };

        ASEntry {
            local: hop.local_ias,
            next: hop.next_ias,
            mtu: Self::HARDCODED_MTU as u32,
            hop_entry,
            peer_entries: local_peer_entries,
            extensions: Vec::new(),
            unsigned_extensions: Vec::new(),
            signed: SignedMessage {
                header_and_body: Vec::new(),
                signature: Vec::new(),
            }, // TODO: Signing
        }
    }

    fn create_peer_entries(
        topo: &ScionTopology,
        hop_entry_expiry: u8,
        hop: &Hop,
        accumulator: u16,
        timestamp: u32,
        forwarding_key: &ForwardingKey,
    ) -> Vec<PeerEntry> {
        let peer_links = topo
            .iter_scion_links_by_as(&hop.local_ias)
            .filter(|link| link.link_type == ScionLinkType::Peer)
            .filter_map(|link| link.get_directed_from(&hop.local_ias))
            .collect::<Vec<_>>();

        let mut peer_entries = Vec::with_capacity(peer_links.len());
        for peer_lnk in peer_links {
            // Peer entries have to be created as if the beacon came from the peer AS.
            // Meaning:
            //
            // Ingress = Our interface connected to the peer
            // Egress  = Our interface connected to the next AS in the segment

            let cons_ingress = peer_lnk.from.if_id;
            let cons_egress = hop.egress_if;

            let mac = calculate_hop_mac(
                accumulator,
                timestamp,
                hop_entry_expiry,
                cons_ingress,
                cons_egress,
                forwarding_key,
            );

            peer_entries.push(PeerEntry {
                peer: peer_lnk.to.isd_as,
                peer_interface: peer_lnk.to.if_id, // The interface connecting the peer to us
                peer_mtu: Self::HARDCODED_MTU,
                hop_field: SegmentHopField {
                    exp_time: hop_entry_expiry,
                    cons_ingress,
                    cons_egress,
                    mac,
                },
            });
        }

        peer_entries
    }
}

/// Single hop in a [LinkSegment]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub(crate) ingress_if: u16,
    pub(crate) local_ias: IsdAsn,
    pub(crate) egress_if: u16,
    pub(crate) next_ias: IsdAsn,
}

/// Iterator over hops in a [LinkSegment]
pub struct HopIter<'links> {
    last_ingress_link: Option<&'links DirectedScionLink>,
    link_iter: vec_deque::Iter<'links, DirectedScionLink>,
}

impl Iterator for HopIter<'_> {
    type Item = Hop;

    fn next(&mut self) -> Option<Self::Item> {
        let ingress_link = self.last_ingress_link;
        let egress_link = self.link_iter.next();

        let hop = match (ingress_link, egress_link) {
            (None, None) => return None, // No more hops
            (None, Some(egr)) => {
                // First hop is egress only
                Hop {
                    ingress_if: 0,
                    local_ias: egr.from.isd_as,
                    egress_if: egr.from.if_id,
                    next_ias: egr.to.isd_as,
                }
            }
            (Some(ing), Some(egr)) => {
                Hop {
                    ingress_if: ing.to.if_id,
                    local_ias: egr.from.isd_as,
                    egress_if: egr.from.if_id,
                    next_ias: egr.to.isd_as,
                }
            }
            (Some(ing), None) => {
                // Last hop is ingress only
                Hop {
                    ingress_if: ing.to.if_id,
                    local_ias: ing.to.isd_as,
                    egress_if: 0,
                    next_ias: IsdAsn(0),
                }
            }
        };

        self.last_ingress_link = egress_link;

        Some(hop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod hop_iter {
        use super::*;
        use crate::network::scion::topology::{ScionGlobalInterfaceId, ScionLinkType};

        #[test]
        fn should_iterate_as_expected_with_1_hop() {
            let as_1 = IsdAsn(1);
            let as_1_egress = 1;
            let as_2_ingress = 2;
            let as_2 = IsdAsn(2);

            let link_segment = LinkSegment {
                start_as: as_1,
                end_as: as_2,
                links: VecDeque::from(vec![DirectedScionLink {
                    from: ScionGlobalInterfaceId {
                        isd_as: as_1,
                        if_id: as_1_egress,
                    },
                    to: ScionGlobalInterfaceId {
                        isd_as: as_2,
                        if_id: as_2_ingress,
                    },
                    link_type: ScionLinkType::Core,
                }]),
            };
            let mut iter = link_segment.iter_hops();
            assert_eq!(
                iter.next(),
                Some(Hop {
                    ingress_if: 0,
                    local_ias: as_1,
                    egress_if: as_1_egress,
                    next_ias: as_2,
                })
            );
            assert_eq!(
                iter.next(),
                Some(Hop {
                    ingress_if: as_2_ingress,
                    local_ias: as_2,
                    egress_if: 0,
                    next_ias: 0.into(),
                })
            );
        }

        #[test]
        fn should_iterate_as_expected_with_n_hops() {
            let as_1 = IsdAsn(1);
            let as_1_egress = 1;
            let as_2_ingress = 2;
            let as_2 = IsdAsn(2);
            let as_2_egress = 3;
            let as_3_ingress = 4;
            let as_3 = IsdAsn(3);

            let link_segment = LinkSegment {
                start_as: as_1,
                end_as: as_3,
                links: VecDeque::from(vec![
                    DirectedScionLink {
                        from: ScionGlobalInterfaceId {
                            isd_as: as_1,
                            if_id: as_1_egress,
                        },
                        to: ScionGlobalInterfaceId {
                            isd_as: as_2,
                            if_id: as_2_ingress,
                        },
                        link_type: ScionLinkType::Core,
                    },
                    DirectedScionLink {
                        from: ScionGlobalInterfaceId {
                            isd_as: as_2,
                            if_id: as_2_egress,
                        },
                        to: ScionGlobalInterfaceId {
                            isd_as: as_3,
                            if_id: as_3_ingress,
                        },
                        link_type: ScionLinkType::Core,
                    },
                ]),
            };
            let mut iter = link_segment.iter_hops();
            assert_eq!(
                iter.next(),
                Some(Hop {
                    ingress_if: 0,
                    local_ias: as_1,
                    egress_if: as_1_egress,
                    next_ias: as_2,
                })
            );
            assert_eq!(
                iter.next(),
                Some(Hop {
                    ingress_if: as_2_ingress,
                    local_ias: as_2,
                    egress_if: as_2_egress,
                    next_ias: as_3,
                })
            );
            assert_eq!(
                iter.next(),
                Some(Hop {
                    ingress_if: as_3_ingress,
                    local_ias: as_3,
                    egress_if: 0,
                    next_ias: 0.into(),
                })
            );
        }
    }

    fn validate_hop_macs(segment: &PathSegment, topo: &ScionTopology) {
        let mut accumulator = segment.info.segment_id;

        for (i, entry) in segment.as_entries.iter().enumerate() {
            let hop = &entry.hop_entry.hop_field;
            let forwarding_key = &topo
                .as_map
                .get(&entry.local)
                .expect("Failed to get AS from topology")
                .forwarding_key
                .into();

            let expected_mac = calculate_hop_mac(
                accumulator,
                segment.info.timestamp.timestamp() as u32,
                hop.exp_time,
                hop.cons_ingress,
                hop.cons_egress,
                forwarding_key,
            );

            for peer_entry in &entry.peer_entries {
                let peer_mac = calculate_hop_mac(
                    accumulator,
                    segment.info.timestamp.timestamp() as u32,
                    hop.exp_time,
                    peer_entry.hop_field.cons_ingress,
                    peer_entry.hop_field.cons_egress,
                    forwarding_key,
                );
                assert_eq!(
                    peer_entry.hop_field.mac, peer_mac,
                    "At as_entry {i} MAC mismatch for peer entry {:?} at as {:?}",
                    peer_entry.peer, entry.local
                );
            }

            accumulator = mac_chaining_step(accumulator, expected_mac);

            assert_eq!(hop.mac, expected_mac, "MAC mismatch for hop {i}");
        }
    }

    mod segment_generation {
        use std::str::FromStr;

        use super::*;
        use crate::network::scion::{topology::ScionAs, util::test_helper::parse_segment};

        struct TestTopo {
            topo: ScionTopology,
            as0: IsdAsn,
            as1: IsdAsn,
            as2: IsdAsn,
            as3: IsdAsn,
            as_2_peer: IsdAsn,
        }
        fn simple_test_topo() -> TestTopo {
            let as0 = IsdAsn::from_str("0-0").unwrap();
            let as1 = IsdAsn::from_str("1-1").unwrap();
            let as2 = IsdAsn::from_str("1-2").unwrap();
            let as3 = IsdAsn::from_str("1-3").unwrap();
            let as_2_peer = IsdAsn::from_str("2-2").unwrap();

            let mut topo = ScionTopology::default();
            topo.add_as(ScionAs::new_core(as1).with_forwarding_key([1; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as2).with_forwarding_key([2; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as3).with_forwarding_key([3; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as_2_peer).with_forwarding_key([4; 16]))
                .unwrap();

            topo.add_link("1-1#1 core 1-2#2".parse().unwrap())
                .unwrap()
                .add_link("1-2#3 core 1-3#4".parse().unwrap())
                .unwrap()
                .add_link("1-2#10 peer 2-2#11".parse().unwrap())
                .unwrap();

            TestTopo {
                topo,
                as0,
                as1,
                as2,
                as3,
                as_2_peer,
            }
        }

        #[test]
        fn should_generate_correct_hop_macs() {
            let topo = simple_test_topo();

            let segment =
                parse_segment("1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4;", ScionLinkType::Core).unwrap();

            let timestamp = Utc::now();
            let segment_id = 42;
            let path_segment = segment
                .to_path_segment(&topo.topo, timestamp, segment_id, 1)
                .expect("Failed to create PathSegment");

            validate_hop_macs(&path_segment, &topo.topo);
        }

        #[test]
        fn should_generate_correct_hop_fields() {
            let topo = simple_test_topo();

            let segment =
                parse_segment("1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4;", ScionLinkType::Core).unwrap();

            let timestamp = Utc::now();
            let segment_id = 120;
            let path_segment = segment
                .to_path_segment(&topo.topo, timestamp, segment_id, 1)
                .expect("Failed to create PathSegment");

            assert_eq!(path_segment.info.timestamp, timestamp);
            assert_eq!(path_segment.info.segment_id, segment_id);

            assert_eq!(path_segment.as_entries.len(), 3);

            let entry = &path_segment.as_entries[0];
            assert_eq!(entry.local, topo.as1);
            assert_eq!(entry.next, topo.as2);
            assert_eq!(entry.hop_entry.hop_field.cons_ingress, 0);
            assert_eq!(entry.hop_entry.hop_field.cons_egress, 1);
            assert_eq!(entry.hop_entry.hop_field.exp_time, 1);
            assert_eq!(entry.peer_entries.len(), 0);

            let entry = &path_segment.as_entries[1];
            assert_eq!(entry.local, topo.as2);
            assert_eq!(entry.next, topo.as3);
            assert_eq!(entry.hop_entry.hop_field.cons_ingress, 2);
            assert_eq!(entry.hop_entry.hop_field.cons_egress, 3);
            assert_eq!(entry.hop_entry.hop_field.exp_time, 1);

            assert_eq!(entry.peer_entries.len(), 1);
            let peer_entry = &entry.peer_entries[0];
            assert_eq!(peer_entry.peer, topo.as_2_peer);
            assert_eq!(peer_entry.peer_interface, 11);
            assert_eq!(peer_entry.hop_field.cons_ingress, 10);
            assert_eq!(peer_entry.hop_field.cons_egress, 3);
            assert_eq!(peer_entry.hop_field.exp_time, 1);

            let entry = &path_segment.as_entries[2];
            assert_eq!(entry.local, topo.as3);
            assert_eq!(entry.next, topo.as0);
            assert_eq!(entry.hop_entry.hop_field.cons_ingress, 4);
            assert_eq!(entry.hop_entry.hop_field.cons_egress, 0);
            assert_eq!(entry.hop_entry.hop_field.exp_time, 1);
            assert_eq!(entry.peer_entries.len(), 0);
        }
    }
}
