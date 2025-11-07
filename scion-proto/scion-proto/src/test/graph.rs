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
//! SCION graph utilities for testing.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use thiserror::Error;

use super::topo::LinkType;
use crate::{
    address::IsdAsn,
    path::{
        ASEntry, HopEntry, NewSegmentError, PathSegment, PeerEntry, SegmentHopField, SignedMessage,
    },
    test::topo::Topo,
};

#[derive(Debug, Clone)]
struct Link {
    a: IsdAsn,
    a_ifid: u16,
    b: IsdAsn,
    b_ifid: u16,
    peer: bool,
}

/// Graph implements a graph of ASes and IfIDs for testing purposes.
///
/// ases: ASes in the graph
/// links: Map from (AS, egress IfID) to Link
#[derive(Debug, Clone)]
pub struct Graph {
    ases: HashSet<IsdAsn>,
    links: HashMap<IsdAsn, HashMap<u16, Link>>,
}

/// Error types for operations on the [`Graph`].
#[derive(Debug, Error)]
pub enum GraphError {
    /// The specified AS is not present in the graph.
    #[error("AS {0} not in graph")]
    AsNotInGraph(IsdAsn),
    /// The specified segment is empty.
    #[error("cannot create empty segment")]
    EmptySegment,
    /// The specified interface ID is not present in the graph.
    #[error("unknown interface id {0}")]
    UnknownIfId(u16),
    /// Error creating a new segment.
    #[error(transparent)]
    NewSegmentError(#[from] NewSegmentError),
}

impl Graph {
    /// Creates a new empty graph
    pub fn new() -> Self {
        Self {
            ases: HashSet::new(),
            links: HashMap::new(),
        }
    }

    /// add_node adds a new node to the graph.
    pub fn add_node(&mut self, ia: IsdAsn) {
        self.ases.insert(ia);
    }

    /// add_link adds a new edge between the ASes described by a and b, with
    /// a_if in a and b_if in b.
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

    /// delete_interface removes an interface from the graph without deleting its remote
    pub fn delete_interface(&mut self, ia: IsdAsn, if_id: u16) -> Result<(), GraphError> {
        self.links
            .get_mut(&ia)
            .and_then(|links| links.remove(&if_id))
            .ok_or(GraphError::UnknownIfId(if_id))?;
        Ok(())
    }

    /// remove_link removes a link between two ASes. This removes the link from both directions.
    pub fn remove_link(
        &mut self,
        a: IsdAsn,
        a_if: u16,
        b: IsdAsn,
        b_if: u16,
    ) -> Result<(), GraphError> {
        // Remove the link from A to B
        self.links
            .get_mut(&a)
            .and_then(|links| links.remove(&a_if))
            .ok_or(GraphError::UnknownIfId(a_if))?;

        // Remove the link from B to A
        self.links
            .get_mut(&b)
            .and_then(|links| links.remove(&b_if))
            .ok_or(GraphError::UnknownIfId(b_if))?;

        Ok(())
    }

    /// Beacon constructs path segments across a series of egress ifIDs. The parent
    /// AS of the first IfID is the origin of the beacon, and the beacon propagates
    /// down to the parent AS of the remote counterpart of the last IfID.
    ///
    /// For example, with start_ia = 1-1 and if_ids = [1, 2], and a topology:
    /// links:
    /// 1-1#1 -> 1-2#1
    /// 1-2#2 -> 1-3#1
    ///
    /// The resulting beacon will traverse the following interfaces:
    /// 1-1#1, 1-2#1, 1-2#2, 1-3#1
    pub fn beacon(&self, start_ia: IsdAsn, egress_ifs: &[u16]) -> Result<PathSegment, GraphError> {
        if egress_ifs.is_empty() {
            return Err(GraphError::EmptySegment);
        }

        let mut as_entries = Vec::new();
        let mut curr_ia = start_ia;
        // The ingress interface for the first AS entry is always 0.
        let mut ingress = 0u16;

        // We need to create one AS entry (with the respective peer entries) for each egress
        // interface plus one extra for the final AS entry that has egress interface 0.
        // See https://docs.scion.org/en/latest/control-plane.html#as-entries for more details.
        for (i, egress) in egress_ifs.iter().chain(std::iter::once(&0)).enumerate() {
            // Find the next AS and the ingress interface id by following the link
            // from the current AS's egress interface.
            let (next_ia, next_ingress) = if i < egress_ifs.len() {
                let out_link = self
                    .links
                    .get(&curr_ia)
                    .ok_or(GraphError::AsNotInGraph(curr_ia))?
                    .get(egress)
                    .ok_or(GraphError::UnknownIfId(*egress))?;
                (out_link.b, out_link.b_ifid)
            } else {
                (IsdAsn::from(0u64), 0) // End of path
            };

            // Create peer entries for this AS
            let mut peer_entries = Vec::new();
            for (_, link) in self.links.get(&curr_ia).unwrap().iter() {
                if !link.peer {
                    continue;
                }

                // Example of a peer entry construction between A and B.
                // The arrow indicates the direction of the beacon construction.
                //    ┌──────┐
                //    │ core │
                //    └──┬───┘
                //       │
                //       │1
                //    ┌──▼──┐            ┌─────┐
                //    │     │    peer   4│     │
                //    │  A  ┼────────────┼  B  │
                //    │     │2           │     │
                //    └──┬──┘            └─────┘
                //       │3
                //       │
                //    ┌──▼──┐
                //    │ ... │
                //    └─────┘
                //
                // This will result in the following peer entry:
                // - peer: B
                // - peer_interface: 4
                // - hop_field:
                //   - cons_ingress: 2
                //   - cons_egress: 3
                //
                // The entry (in this orientation) can be used to traverse the peer link
                // from B to A.

                peer_entries.push(PeerEntry {
                    peer: link.b,
                    peer_interface: link.b_ifid,
                    peer_mtu: 1280,
                    hop_field: SegmentHopField {
                        exp_time: 63,
                        // Ingress is set to the interface ID where the beacon was received.
                        cons_ingress: link.a_ifid,
                        //
                        cons_egress: *egress,
                        mac: [i as u8, 0, 0, 0, 0, 0], // Simplified MAC
                    },
                });
            }

            // Add the AS entry for the current AS.
            let as_entry = ASEntry {
                local: curr_ia,
                next: next_ia,
                mtu: 2000,
                hop_entry: HopEntry {
                    ingress_mtu: 1280,
                    hop_field: SegmentHopField {
                        exp_time: 63,
                        cons_ingress: ingress,
                        cons_egress: *egress,
                        mac: i.to_le_bytes()[2..].try_into().unwrap(),
                    },
                },
                peer_entries,
                extensions: Vec::new(),
                unsigned_extensions: Vec::new(),
                signed: SignedMessage {
                    header_and_body: Vec::new(),
                    signature: Vec::new(),
                },
            };

            as_entries.push(as_entry);

            // Move to next AS
            if i < egress_ifs.len() {
                ingress = next_ingress;
                curr_ia = next_ia;
            }
        }

        // Create segment with current timestamp and a test segment ID
        Ok(PathSegment::new(Utc::now(), rand::random(), as_entries)?)
    }

    /// Generates a mermaid flowchart representation of the graph.
    pub fn mermaid_flowchart(&self) -> String {
        let mut flowchart = String::new();
        flowchart.push_str("graph TD;\n");
        let mut seen_links = HashSet::new();
        for (_, links) in self.links.iter() {
            for (_, link) in links.iter() {
                if seen_links.contains(&(link.a, link.a_ifid))
                    || seen_links.contains(&(link.b, link.b_ifid))
                {
                    continue;
                }
                seen_links.insert((link.a, link.a_ifid));
                // edge is <src ia> --->|<ifid>-><dstifid>[,peer]| <dst ia>
                flowchart.push_str(&format!(
                    "{} -->|{}->{}{}| {};\n",
                    link.a,
                    link.a_ifid,
                    link.b_ifid,
                    if link.peer { ",peer" } else { "" },
                    link.b,
                ));
            }
        }
        flowchart
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

/// Error types for converting a [`Topo`] to a [`Graph`].
#[derive(Error, Debug)]
pub enum GraphFromTopoError {
    /// Invalid interface ID format.
    #[error("Interfaces {0} and {1} cannot be combined to form a valid ifID")]
    InvalidIfIdFormat(u16, u16),
    /// Graph error.
    #[error(transparent)]
    GraphError(#[from] GraphError),
}

impl TryFrom<Topo> for Graph {
    type Error = GraphFromTopoError;

    fn try_from(topo: Topo) -> Result<Self, GraphFromTopoError> {
        let mut graph = Self::new();
        for (ia, _) in topo.ases {
            graph.add_node(ia);
        }
        for link in topo.links {
            graph.add_link(
                link.a.ia,
                link.a.ifid,
                link.b.ia,
                link.b.ifid,
                matches!(link.link_type, LinkType::Peer),
            )?;
        }
        Ok(graph)
    }
}

/// Returns the default graph used for testing.
pub fn default_graph() -> Result<Graph, GraphFromTopoError> {
    let topo = Topo::default_testing();
    Graph::try_from(topo)
}

// Test to print the mermaid flowchard of the default.topo file
#[test]
fn mermaid_flowchart_generates_correctly() {
    let topo = Topo::default_testing();
    let graph = Graph::try_from(topo).unwrap();
    println!("{}", graph.mermaid_flowchart());
}
