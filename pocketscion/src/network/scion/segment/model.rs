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

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use p256::pkcs8::DecodePrivateKey;
use scion_protobuf::control_plane::v1::VerificationKeyId;
use scion_sdk_trc::trc::der_int_to_u64;
use sciparse::{
    identifier::isd_asn::IsdAsn,
    path::standard::types::HopFieldMac,
    segment::{AsEntry, HopEntry, PeerEntry, SegmentHopField, SignedPathSegment},
};

use crate::network::scion::topology::{DirectedScionLink, ScionAs, ScionLinkType, ScionTopology};

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
    pub fn iter_hops(&self, skip_tail: bool) -> HopIter<'_> {
        HopIter {
            last_ingress_link: None,
            link_iter: self.links.iter(),
            skip_tail,
        }
    }

    /// Converts [LinkSegment] into a [SignedPathSegment].
    ///
    /// * `timestamp` is the time when the segment was created.
    /// * `segment_id` is a random number identifying the segment.
    /// * `hop_entry_expiry` is expiry time for each hop entry in the segment.
    /// * `skip_tail` indicates that no final hop using egress 0 should be generated
    pub fn to_path_segment(
        &self,
        topo: &ScionTopology,
        timestamp: DateTime<Utc>,
        segment_id: u16,
        hop_entry_expiry: u8,
        skip_tail: bool,
    ) -> anyhow::Result<SignedPathSegment> {
        let timestamp = timestamp
            .timestamp()
            .try_into()
            .context("timestamp does not fit into u32")?;

        let mut path_segment =
            SignedPathSegment::with_capacity(timestamp, segment_id, self.links.len());

        // Iterate through all hop pairs in construction direction
        for hop in self.iter_hops(skip_tail) {
            let hop_as = topo
                .as_map
                .get(&hop.local_ias.into())
                .with_context(|| format!("error getting AS {} from topology", hop.local_ias))?;

            let (_isd_as, _is_core, forwarding_key) = match hop_as {
                ScionAs::Simulated {
                    isd_as,
                    core,
                    forwarding_key,
                } => (*isd_as, *core, forwarding_key),
                ScionAs::External { .. } => {
                    bail!(
                        "External AS {} was part of LinkSegments, but all ASes in the segment must be simulated",
                        hop.local_ias
                    )
                }
            };

            let as_key_pair = topo
                .trust_store
                .as_key_pair(&hop.local_ias.into())
                .with_context(|| {
                    format!(
                        "AS {} is missing an identity in the trust store",
                        hop.local_ias
                    )
                })?;

            let local_peer_entries = Self::create_peer_entries(topo, hop_entry_expiry, &hop);
            let entry = Self::create_unsigned_as_entry(hop_entry_expiry, hop, local_peer_entries);

            let ecdsa_key =
                ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_der(as_key_pair.key.secret_der())
                    .context("AS key is not a valid PKCS8 DER ECDSA P256 key")?;

            let key_id = as_key_pair
                .cert
                .subject_key_id()
                .context("AS certificate does not contain a Subject Key Identifier")?;

            let trc = topo
                .trust_store
                .trc(&hop_as.isd_as().isd())
                .with_context(|| {
                    format!(
                        "Failed to get TRC for ISD {} from TRC store",
                        hop_as.isd_as().isd()
                    )
                })?;

            let key_id = VerificationKeyId {
                isd_as: hop_as.isd_as().to_u64(),
                subject_key_id: key_id.clone(),
                trc_base: der_int_to_u64(&trc.raw_trc_payload().id.base_number)?,
                trc_serial: der_int_to_u64(&trc.raw_trc_payload().id.serial_number)?,
            };

            path_segment.add_entry(entry, &ecdsa_key, Some(key_id), forwarding_key, timestamp)?;
        }

        Ok(path_segment)
    }
}
// AS Entry conversion
impl LinkSegment {
    const HARDCODED_MTU: u16 = 1280;

    /// Creates an unsigned AS entry for the given hop.
    fn create_unsigned_as_entry(
        hop_entry_expiry: u8,
        hop: Hop,
        local_peer_entries: Vec<PeerEntry>,
    ) -> AsEntry {
        let hop_entry = HopEntry {
            ingress_mtu: Self::HARDCODED_MTU,
            hop_field: SegmentHopField {
                exp_time: hop_entry_expiry,
                cons_ingress: hop.ingress_if,
                cons_egress: hop.egress_if,
                mac: HopFieldMac::zero(),
            },
        };

        AsEntry {
            local: hop.local_ias,
            next: hop.next_ias,
            mtu: Self::HARDCODED_MTU as u32,
            hop_entry,
            peer_entries: local_peer_entries,
            extensions: Vec::new(),
            unsigned_extensions: Vec::new(),
        }
    }

    fn create_peer_entries(
        topo: &ScionTopology,
        hop_entry_expiry: u8,
        hop: &Hop,
    ) -> Vec<PeerEntry> {
        let peer_links = topo
            .iter_scion_links_by_as(&hop.local_ias.into())
            .filter(|link| link.link_type == ScionLinkType::Peer)
            .filter_map(|link| link.get_directed_from(&hop.local_ias.into()))
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

            peer_entries.push(PeerEntry {
                peer: peer_lnk.to.isd_as.into(),
                peer_interface: peer_lnk.to.if_id, // The interface connecting the peer to us
                peer_mtu: Self::HARDCODED_MTU,
                hop_field: SegmentHopField {
                    exp_time: hop_entry_expiry,
                    cons_ingress,
                    cons_egress,
                    mac: HopFieldMac::zero(),
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
    // If set, the iterator will skip the last hop
    skip_tail: bool,
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
                    local_ias: egr.from.isd_as.into(),
                    egress_if: egr.from.if_id,
                    next_ias: egr.to.isd_as.into(),
                }
            }
            (Some(ing), Some(egr)) => {
                Hop {
                    ingress_if: ing.to.if_id,
                    local_ias: egr.from.isd_as.into(),
                    egress_if: egr.from.if_id,
                    next_ias: egr.to.isd_as.into(),
                }
            }
            (Some(ing), None) if !self.skip_tail => {
                // Last hop is ingress only
                Hop {
                    ingress_if: ing.to.if_id,
                    local_ias: ing.to.isd_as.into(),
                    egress_if: 0,
                    next_ias: IsdAsn(0),
                }
            }
            (Some(_), None) => {
                // No more hops, and we are skipping the tail
                return None;
            }
        };

        self.last_ingress_link = egress_link;

        Some(hop)
    }
}

#[cfg(test)]
mod tests {
    use scion_proto::path::crypto::mac_chaining_step;
    use sciparse::path::standard::mac::algo::calculate_hop_mac;

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
                        isd_as: as_1.into(),
                        if_id: as_1_egress,
                    },
                    to: ScionGlobalInterfaceId {
                        isd_as: as_2.into(),
                        if_id: as_2_ingress,
                    },
                    link_type: ScionLinkType::Core,
                }]),
            };
            let mut iter = link_segment.iter_hops(false);
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
                            isd_as: as_1.into(),
                            if_id: as_1_egress,
                        },
                        to: ScionGlobalInterfaceId {
                            isd_as: as_2.into(),
                            if_id: as_2_ingress,
                        },
                        link_type: ScionLinkType::Core,
                    },
                    DirectedScionLink {
                        from: ScionGlobalInterfaceId {
                            isd_as: as_2.into(),
                            if_id: as_2_egress,
                        },
                        to: ScionGlobalInterfaceId {
                            isd_as: as_3.into(),
                            if_id: as_3_ingress,
                        },
                        link_type: ScionLinkType::Core,
                    },
                ]),
            };
            let mut iter = link_segment.iter_hops(false);
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

    fn validate_hop_macs(segment: &SignedPathSegment, topo: &ScionTopology) {
        let mut accumulator = segment.info().segment_id;

        for (i, entry) in segment.as_entries.iter().enumerate() {
            let hop = &entry.hop_entry.hop_field;
            let forwarding_key = &topo
                .as_map
                .get(&(entry.local).into())
                .expect("Failed to get AS from topology")
                .forwarding_key()
                .expect("All ASes in the segment should be simulated");

            let expected_mac = calculate_hop_mac(
                accumulator,
                segment.info().timestamp,
                hop.exp_time,
                hop.cons_ingress,
                hop.cons_egress,
                forwarding_key,
            );

            for peer_entry in &entry.peer_entries {
                let peer_mac = calculate_hop_mac(
                    accumulator,
                    segment.info().timestamp,
                    hop.exp_time,
                    peer_entry.hop_field.cons_ingress,
                    peer_entry.hop_field.cons_egress,
                    forwarding_key,
                );
                assert_eq!(
                    peer_entry.hop_field.mac.0, peer_mac,
                    "At as_entry {i} MAC mismatch for peer entry {:?} at as {:?}",
                    peer_entry.peer, entry.local
                );
            }

            accumulator = mac_chaining_step(accumulator, expected_mac);

            assert_eq!(hop.mac.0, expected_mac, "MAC mismatch for hop {i}");
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
            topo.add_as(ScionAs::new_core(as1.into()).with_forwarding_key([1; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as2.into()).with_forwarding_key([2; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as3.into()).with_forwarding_key([3; 16]))
                .unwrap()
                .add_as(ScionAs::new_core(as_2_peer.into()).with_forwarding_key([4; 16]))
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
                .to_path_segment(&topo.topo, timestamp, segment_id, 1, false)
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
                .to_path_segment(&topo.topo, timestamp, segment_id, 1, false)
                .expect("Failed to create PathSegment");

            assert_eq!(path_segment.info().timestamp, timestamp.timestamp() as u32);
            assert_eq!(path_segment.info().segment_id, segment_id);

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
