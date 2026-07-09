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

//! Test graph utilities for path combinator tests.
//!
//! Ported from the scion-proto crate's test graph module, adapted to use sciparse types.

use std::collections::{HashMap, HashSet};

use crate::{
    dataplane_path::standard::types::HopFieldMac,
    identifier::isd_asn::IsdAsn,
    segment::{AsEntry, HopEntry, PeerEntry, SegmentHopField, UnsignedPathSegment},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Link {
    #[allow(dead_code)]
    a: IsdAsn,
    a_ifid: u16,
    b: IsdAsn,
    b_ifid: u16,
    peer: bool,
}

/// Graph implements a graph of ASes and IfIDs for testing purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    ases: HashSet<IsdAsn>,
    links: HashMap<IsdAsn, HashMap<u16, Link>>,
}

/// Error types for operations on the [`Graph`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraphError {
    /// The referenced AS is not part of the graph.
    #[error("AS {0} not in graph")]
    AsNotInGraph(IsdAsn),
    /// A segment cannot be created without any hops.
    #[error("cannot create empty segment")]
    EmptySegment,
    /// The referenced interface id is not known.
    #[error("unknown interface id {0}")]
    UnknownIfId(u16),
}

/// Default hop field expiration time used in test beacons.
pub const DEFAULT_HOP_EXPIRATION: u8 = 63;

impl Graph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self {
            ases: HashSet::new(),
            links: HashMap::new(),
        }
    }

    /// Add an AS node to the graph.
    pub fn add_node(&mut self, ia: IsdAsn) {
        self.ases.insert(ia);
    }

    /// Add a bidirectional link between two ASes, creating the nodes if needed.
    pub fn add_link(
        &mut self,
        a: IsdAsn,
        a_if: u16,
        b: IsdAsn,
        b_if: u16,
        peer: bool,
    ) -> Result<(), GraphError> {
        self.add_node(a);
        self.add_node(b);
        self.links
            .entry(a)
            .or_default()
            .entry(a_if)
            .or_insert(Link {
                a,
                a_ifid: a_if,
                b,
                b_ifid: b_if,
                peer,
            });
        self.links
            .entry(b)
            .or_default()
            .entry(b_if)
            .or_insert(Link {
                a: b,
                a_ifid: b_if,
                b: a,
                b_ifid: a_if,
                peer,
            });
        Ok(())
    }

    /// Delete a single interface of an AS from the graph.
    pub fn delete_interface(&mut self, ia: IsdAsn, if_id: u16) -> Result<(), GraphError> {
        self.links
            .get_mut(&ia)
            .and_then(|links| links.remove(&if_id))
            .ok_or(GraphError::UnknownIfId(if_id))?;
        Ok(())
    }

    /// Remove a bidirectional link between two ASes by deleting both interfaces.
    pub fn remove_link(
        &mut self,
        a: IsdAsn,
        a_if: u16,
        b: IsdAsn,
        b_if: u16,
    ) -> Result<(), GraphError> {
        self.links
            .get_mut(&a)
            .and_then(|links| links.remove(&a_if))
            .ok_or(GraphError::UnknownIfId(a_if))?;
        self.links
            .get_mut(&b)
            .and_then(|links| links.remove(&b_if))
            .ok_or(GraphError::UnknownIfId(b_if))?;
        Ok(())
    }

    /// Beacon constructs path segments across a series of egress ifIDs.
    pub fn beacon(
        &self,
        start_ia: IsdAsn,
        egress_ifs: &[u16],
    ) -> Result<UnsignedPathSegment, GraphError> {
        if egress_ifs.is_empty() {
            return Err(GraphError::EmptySegment);
        }

        let mut as_entries = Vec::new();
        let mut curr_ia = start_ia;
        let mut ingress = 0u16;

        for (i, egress) in egress_ifs.iter().chain(std::iter::once(&0)).enumerate() {
            let exp_time = DEFAULT_HOP_EXPIRATION;

            let (next_ia, next_ingress) = if i < egress_ifs.len() {
                let out_link = self
                    .links
                    .get(&curr_ia)
                    .ok_or(GraphError::AsNotInGraph(curr_ia))?
                    .get(egress)
                    .ok_or(GraphError::UnknownIfId(*egress))?;
                (out_link.b, out_link.b_ifid)
            } else {
                (IsdAsn::from(0u64), 0)
            };

            let mut peer_entries = Vec::new();
            if let Some(links) = self.links.get(&curr_ia) {
                for (_, link) in links.iter() {
                    if !link.peer {
                        continue;
                    }
                    peer_entries.push(PeerEntry {
                        peer: link.b,
                        peer_interface: link.b_ifid,
                        peer_mtu: 1280,
                        hop_field: SegmentHopField {
                            expiration_units: exp_time,
                            cons_ingress: link.a_ifid,
                            cons_egress: *egress,
                            mac: HopFieldMac::zero(),
                        },
                    });
                }
            }

            let as_entry = AsEntry {
                local: curr_ia,
                next: next_ia,
                mtu: 2000,
                hop_entry: HopEntry {
                    ingress_mtu: 1280,
                    hop_field: SegmentHopField {
                        expiration_units: exp_time,
                        cons_ingress: ingress,
                        cons_egress: *egress,
                        mac: HopFieldMac::zero(),
                    },
                },
                peer_entries,
                extensions: Vec::new(),
                unsigned_extensions: Vec::new(),
            };

            as_entries.push(as_entry);

            if i < egress_ifs.len() {
                ingress = next_ingress;
                curr_ia = next_ia;
            }
        }

        Ok(UnsignedPathSegment::new(0, 42, as_entries))
    }
}

/// Returns the default graph used for testing, matching the scion-proto default.topo.
pub fn default_graph() -> Result<Graph, GraphError> {
    let mut g = Graph::new();

    // Core ASes
    let ia110: IsdAsn = "1-ff00:0:110".parse().unwrap();
    let ia120: IsdAsn = "1-ff00:0:120".parse().unwrap();
    let ia130: IsdAsn = "1-ff00:0:130".parse().unwrap();
    let ia210: IsdAsn = "2-ff00:0:210".parse().unwrap();
    let ia220: IsdAsn = "2-ff00:0:220".parse().unwrap();

    // Non-core ASes
    let ia111: IsdAsn = "1-ff00:0:111".parse().unwrap();
    let ia112: IsdAsn = "1-ff00:0:112".parse().unwrap();
    let ia121: IsdAsn = "1-ff00:0:121".parse().unwrap();
    let ia122: IsdAsn = "1-ff00:0:122".parse().unwrap();
    let ia131: IsdAsn = "1-ff00:0:131".parse().unwrap();
    let ia132: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let ia133: IsdAsn = "1-ff00:0:133".parse().unwrap();
    let ia211: IsdAsn = "2-ff00:0:211".parse().unwrap();
    let ia212: IsdAsn = "2-ff00:0:212".parse().unwrap();
    let ia221: IsdAsn = "2-ff00:0:221".parse().unwrap();
    let ia222: IsdAsn = "2-ff00:0:222".parse().unwrap();

    // Core links
    g.add_link(ia110, 1, ia120, 6, false)?;
    g.add_link(ia110, 2, ia130, 104, false)?;
    g.add_link(ia110, 3, ia210, 453, false)?;
    g.add_link(ia120, 1, ia130, 105, false)?;
    g.add_link(ia120, 2, ia220, 501, false)?;
    g.add_link(ia120, 3, ia220, 502, false)?;
    g.add_link(ia210, 450, ia220, 503, false)?;

    // Child links
    g.add_link(ia120, 4, ia121, 3, false)?;
    g.add_link(ia120, 5, ia111, 104, false)?;
    g.add_link(ia130, 111, ia131, 479, false)?;
    g.add_link(ia130, 112, ia111, 105, false)?;
    g.add_link(ia130, 113, ia112, 495, false)?;
    g.add_link(ia111, 103, ia112, 494, false)?;
    g.add_link(ia121, 2, ia122, 2, false)?;
    g.add_link(ia131, 478, ia132, 2, false)?;
    g.add_link(ia132, 1, ia133, 2, false)?;
    g.add_link(ia210, 451, ia211, 7, false)?;
    g.add_link(ia210, 452, ia211, 8, false)?;
    g.add_link(ia220, 500, ia221, 2, false)?;
    g.add_link(ia211, 2, ia212, 201, false)?;
    g.add_link(ia211, 3, ia212, 200, false)?;
    g.add_link(ia211, 4, ia222, 301, false)?;
    g.add_link(ia221, 1, ia222, 302, false)?;

    // Peer links
    g.add_link(ia111, 100, ia121, 4, true)?;
    g.add_link(ia111, 101, ia211, 5, true)?;
    g.add_link(ia111, 102, ia211, 6, true)?;
    g.add_link(ia121, 1, ia131, 480, true)?;
    g.add_link(ia122, 1, ia133, 1, true)?;
    g.add_link(ia211, 1, ia221, 3, true)?;

    Ok(g)
}
