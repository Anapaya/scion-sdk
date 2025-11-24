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
//! Graph based path combinator.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hasher,
};

use crate::{
    address::IsdAsn,
    packet::ByEndpoint,
    path::{
        HopField, InfoField, Metadata, Path, PathInterface, PathSegment, SegmentID, StandardPath,
    },
};

/// Multigraph is the graph used to find valid paths.
/// Vertices are either ASes (IA) or Peering vertices that represent the use of a peering link
/// in one direction.
/// Edges represent the valid use of a segment to send data from one vertex to another.
/// Edges are bidirectional i.e. they are added in both directions.
/// The edges are annotated with the segment and with the weight calculated by the given weight
/// function.
pub struct MultiGraph<'a, F>
where
    F: Fn(&InputSegment, u64, bool) -> u64,
{
    /// Adjacency list of the graph. This maps Vertex -> (Vertex -> []Edge).
    adjacencies: HashMap<Vertex, VertexInfo<'a>>,
    /// Function to calculate the weight of an edge. towards_peer is true if the edge is towards a
    /// Peering vertex. This can be used to adjust the weight for the use of the peering link.
    /// Weight(segment, shortcut_idx, towards_peer) -> weight
    weight_fn: F,
}

/// Edge in the graph.
#[derive(Clone)]
pub struct Edge {
    /// The weight of the edge calculated by the given weight_fn.
    pub weight: u64,
    /// The ASEntry index on where the forwarding portion of this
    /// segment should end (for up-segments) or start (for down-segments).
    /// This is also set when crossing peering links. If 0, the full segment is
    /// used.
    pub shortcut_idx: usize,
    /// If set, this is the index in the peer entry of
    /// the index in the peer entries array for ASEntry defined by the
    /// shortcut index. This is 0 for non-peer shortcuts.
    pub peer: Option<usize>,
}

/// Map to store the set of edges between two vertices. The edges are keyed by the segment hash.
type EdgeMap<'a> = HashMap<&'a InputSegment<'a>, Edge>;
/// Maps destination vertices to the list of edges that point towards them.
type VertexInfo<'a> = HashMap<Vertex, EdgeMap<'a>>;

/// A vertex in the graph is either an IA or represents a peering link.
#[derive(Hash, Eq, PartialEq, Clone)]
pub enum Vertex {
    /// IA vertex.
    AS(IsdAsn),
    /// Peering represents the use of a peering link in one direction.
    /// I.e. from local_ia#local_ifid to peer_ia#peer_ifid.
    Peering {
        /// Local IA.
        local_ia: IsdAsn,
        /// Local interface ID.
        local_ifid: u16,
        /// Peer IA.
        peer_ia: IsdAsn,
        /// Peer interface ID.
        peer_ifid: u16,
    },
}

impl std::fmt::Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Vertex::AS(ia) => write!(f, "IA({ia})"),
            Vertex::Peering {
                local_ia,
                local_ifid: local_ifif,
                peer_ia,
                peer_ifid,
            } => {
                write!(
                    f,
                    "Peering({local_ia}#{local_ifif} -> {peer_ia}#{peer_ifid})"
                )
            }
        }
    }
}

impl Vertex {
    /// Generate a valid mermaid node id for the vertex.
    fn mermaid_id(&self) -> String {
        match self {
            Vertex::AS(ia) => ia.to_u64().to_string(),
            Vertex::Peering {
                local_ia,
                local_ifid: local_ifif,
                peer_ia,
                peer_ifid,
            } => {
                format!(
                    "{}-{}-{}-{}",
                    local_ia.to_u64(),
                    local_ifif,
                    peer_ia.to_u64(),
                    peer_ifid
                )
            }
        }
    }

    /// Generate a valid mermaid node for the vertex.
    pub fn mermaid_node(&self) -> String {
        format!("{}[\"{}\"]", self.mermaid_id(), self)
    }

    fn ia(&self) -> Option<IsdAsn> {
        match self {
            Vertex::AS(ia) => Some(*ia),
            _ => None,
        }
    }
}

/// Input segment is a wrapper around PathSegment that also includes the segment type (core or
/// non-core).
pub enum InputSegment<'a> {
    /// Core segment.
    Core(&'a PathSegment, SegmentID),
    /// Non-core segment.
    NonCore(&'a PathSegment, SegmentID),
}

impl<'a> InputSegment<'a> {
    /// Create a new core input segment.
    pub fn new_core(path_segment: &'a PathSegment) -> Self {
        let id = path_segment.id();
        Self::Core(path_segment, id)
    }

    /// Create a new non-core input segment.
    pub fn new_non_core(path_segment: &'a PathSegment) -> Self {
        let id = path_segment.id();
        Self::NonCore(path_segment, id)
    }

    fn is_non_core(&self) -> bool {
        matches!(self, Self::NonCore(_, _))
    }

    fn is_core(&self) -> bool {
        matches!(self, Self::Core(_, _))
    }

    fn id(&self) -> &SegmentID {
        match self {
            Self::Core(_, id) => id,
            Self::NonCore(_, id) => id,
        }
    }

    fn path_segment(&self) -> &PathSegment {
        match self {
            Self::Core(path_segment, _) => path_segment,
            Self::NonCore(path_segment, _) => path_segment,
        }
    }
}

impl<'a> std::hash::Hash for InputSegment<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl<'a> PartialEq for InputSegment<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl<'a> std::cmp::Eq for InputSegment<'a> {}

/// Segment type.
#[derive(Debug)]
pub enum SegmentType {
    /// Core segment.
    Core,
    /// Non-core segment.
    NonCore,
}

pub(crate) fn number_of_hops(segment: &InputSegment, shortcut_idx: u64, towards_peer: bool) -> u64 {
    // The weight is the number of links traversed when using the segment.
    // We substract 1 to get from the #hops to the #links.
    // We substract the shortcut index to get the number of links that are actually used.
    let weight = segment.path_segment().len() as u64 - 1 - shortcut_idx;
    if !towards_peer {
        weight
    } else {
        // We add 1 to the weight to account for the peer link.
        weight + 1
    }
}

impl<'a, F> MultiGraph<'a, F>
where
    F: Fn(&InputSegment, u64, bool) -> u64,
{
    /// Create a new empty graph with the given weight function.
    pub fn new(weight_fn: F) -> Self {
        Self {
            adjacencies: HashMap::new(),
            weight_fn,
        }
    }

    /// Add a list of segments to the graph.
    /// For each segment we add edges to the graph that represent the vertices that
    /// can be reached using the segment.
    /// See add_core_segment and add_non_core_segment for more details.
    pub fn add_segments(&mut self, segments: &'a [InputSegment]) {
        for segment in segments {
            self.add_segment(segment);
        }
    }

    fn add_segment(&mut self, segment: &'a InputSegment) {
        match segment {
            InputSegment::Core(..) => {
                self.add_core_segment(segment);
            }
            InputSegment::NonCore(..) => {
                self.add_non_core_segment(segment);
            }
        }
    }

    /// For core segments we just add a bidirectional edge between the first and last IA.
    /// Core edges cannot be shortcut i.e. they can only be used to connect from the
    /// first to the last IA (or vice versa).
    fn add_core_segment(&mut self, segment: &'a InputSegment) {
        self.add_edge(
            Vertex::AS(segment.path_segment().first_ia()),
            Vertex::AS(segment.path_segment().last_ia()),
            segment,
            Edge {
                weight: (self.weight_fn)(segment, 0, false),
                shortcut_idx: 0,
                peer: None,
            },
        )
    }

    /// For non-core segments we add
    /// - An edge from the last AS in the segment (leaf) to every other AS in the segment. These
    ///   links represent the "shortcut" use of the segment.
    /// - An edge from the last AS in the segment (leaf) to every peering link in the segment
    ///   (peering vertex). These links represent the use of the peering link in this direction.
    fn add_non_core_segment(&mut self, segment: &'a InputSegment) {
        let leaf = segment.path_segment().last_ia();
        for (idx, entry) in segment.path_segment().iter().enumerate().rev() {
            // For the last entry in the segment (the leaf) we don't need to add an edge.
            if idx != segment.path_segment().len() - 1 {
                self.add_edge(
                    Vertex::AS(leaf),
                    Vertex::AS(entry.local),
                    segment,
                    Edge {
                        weight: (self.weight_fn)(segment, idx as u64, false),
                        shortcut_idx: idx,
                        peer: None,
                    },
                );
            }

            for (peer_idx, peer) in entry.peer_entries.iter().enumerate() {
                // The peering vertices are oriented in the direction that the peering link is used.
                // We add two edges, one for each direction.
                self.add_directed_edge(
                    Vertex::AS(leaf),
                    Vertex::Peering {
                        local_ia: entry.local,
                        local_ifid: peer.hop_field.cons_ingress,
                        peer_ia: peer.peer,
                        peer_ifid: peer.peer_interface,
                    },
                    segment,
                    Edge {
                        // We set the towards_peer flag to true to account for the peer link.
                        // But only in one direction.
                        weight: (self.weight_fn)(segment, idx as u64, true),
                        shortcut_idx: idx,
                        peer: Some(peer_idx),
                    },
                );
                self.add_directed_edge(
                    Vertex::Peering {
                        local_ia: peer.peer,
                        local_ifid: peer.peer_interface,
                        peer_ia: entry.local,
                        peer_ifid: peer.hop_field.cons_ingress,
                    },
                    Vertex::AS(leaf),
                    segment,
                    Edge {
                        weight: (self.weight_fn)(segment, idx as u64, false),
                        shortcut_idx: idx,
                        peer: Some(peer_idx),
                    },
                )
            }
        }
    }

    /// Add an from src to dst and back.
    fn add_edge(&mut self, src: Vertex, dst: Vertex, segment: &'a InputSegment, edge: Edge) {
        self.add_directed_edge(src.clone(), dst.clone(), segment, edge.clone());
        self.add_directed_edge(dst, src, segment, edge);
    }

    fn add_directed_edge(
        &mut self,
        src: Vertex,
        dst: Vertex,
        segment: &'a InputSegment,
        edge: Edge,
    ) {
        self.adjacencies
            .entry(src.clone())
            .or_default()
            .entry(dst.clone())
            .or_default()
            .insert(segment, edge.clone());
    }

    /// Finds and returns all possible valid paths from src to dst.
    pub fn get_paths(&self, src: IsdAsn, dst: IsdAsn) -> Vec<PathSolution<'_>> {
        let mut solutions = Vec::new();
        let mut queue = VecDeque::from([PathSolution::new(Vertex::AS(src))]);
        while let Some(current_solution) = queue.pop_front() {
            if let Some(next_vertex) = self.adjacencies.get(&current_solution.current_vertex) {
                for (next_vertex, edges) in next_vertex {
                    for (segment, edge) in edges {
                        let new_solution = match current_solution.try_add_edge(SolutionEdge {
                            edge: edge.clone(),
                            src: current_solution.current_vertex.clone(),
                            dst: next_vertex.clone(),
                            segment,
                        }) {
                            Some(s) => s,
                            None => continue,
                        };
                        if *next_vertex == Vertex::AS(dst) {
                            solutions.push(new_solution);
                        } else {
                            queue.push_back(new_solution);
                        }
                    }
                }
            }
        }
        // To make the output deterministic we sort the solutions by cost, then by number of edges,
        // then by segment id.
        solutions.sort_by(|a, b| {
            let d = a.cost.cmp(&b.cost).then(a.edges.len().cmp(&b.edges.len()));
            if d.is_ne() {
                return d;
            }

            for (edge_a, edge_b) in a.edges.iter().zip(b.edges.iter()) {
                // Prefer solutions that use a peer link.
                let d = edge_a.edge.peer.cmp(&edge_b.edge.peer);
                if d.is_ne() {
                    return d;
                }
                // Prefer solutions with a higher shortcut index.
                let d = edge_a
                    .edge
                    .shortcut_idx
                    .cmp(&edge_b.edge.shortcut_idx)
                    .reverse();
                if d.is_ne() {
                    return d;
                }
                // Finally, use the segment id to break ties.
                let d = edge_a.segment.id().cmp(edge_b.segment.id());
                if d.is_ne() {
                    return d;
                }
            }
            std::cmp::Ordering::Equal
        });
        solutions
    }

    /// Generate a mermaid flowchart of the graph. Useful for debugging.
    /// Visualize with <https://mermaid.live>.
    pub fn mermaid_flowchart(&self) -> String {
        let mut flowchart = String::new();
        flowchart.push_str("flowchart TD;\n");
        let mut seen = HashSet::new();
        for (src, dsts) in &self.adjacencies {
            for (dst, edges) in dsts {
                for (segment, edge) in edges {
                    if let (Vertex::AS(_), Vertex::AS(_)) = (src, dst) {
                        // Add undirected edge for edges between IA vertices.
                        if seen.contains(&(dst, src, segment.id())) {
                            continue;
                        } else {
                            flowchart.push_str(&format!(
                                "{} ---|Seg: {} {} Weight: {} Shortcut: {}{}| {}\n",
                                src.mermaid_node(),
                                segment.path_segment().info.segment_id,
                                if segment.is_core() {
                                    "Core"
                                } else {
                                    "Non-Core"
                                },
                                edge.weight,
                                edge.shortcut_idx,
                                if let Some(peer) = edge.peer {
                                    format!(" Peer: {peer}")
                                } else {
                                    "".to_string()
                                },
                                dst.mermaid_node()
                            ));
                            seen.insert((src, dst, segment.id()));
                        }
                    } else {
                        // Add directed edge for edges between IA and Peering vertices.
                        flowchart.push_str(&format!(
                            "{} -->|Seg: {} {} Weight: {} Shortcut: {}{}| {}\n",
                            src.mermaid_node(),
                            segment.path_segment().info.segment_id,
                            if segment.is_core() {
                                "Core"
                            } else {
                                "Non-Core"
                            },
                            edge.weight,
                            edge.shortcut_idx,
                            if let Some(peer) = edge.peer {
                                format!(" Peer: {peer}")
                            } else {
                                "".to_string()
                            },
                            dst.mermaid_node()
                        ));
                    }
                }
            }
        }
        flowchart
    }
}

/// An edge that is part of a path solution.
#[derive(Clone)]
pub struct SolutionEdge<'a> {
    /// The edge in the graph.
    pub edge: Edge,
    /// Source vertex.
    pub src: Vertex,
    /// Destination vertex.
    pub dst: Vertex,
    /// The segment associated with this edge, used during forwarding path construction.
    pub segment: &'a InputSegment<'a>,
}

impl<'a> SolutionEdge<'a> {
    /// Initialize the segment id for the infofield that is created from this edge.
    /// The segment id needs to be set to the beta_i where i is the index of the
    /// first as entry from this segment that will be traversed.
    ///
    /// First identify the index (stop_at) of the first AS entry that will be traversed.
    /// If we are traversing the segment in construction order, this will be the edges shortcut
    /// index. If not, this will be the last index in the segment (len(as_entries) - 1).
    ///
    /// Then calculate beta_(stop_at) starting with the beacons segment id and XORing
    /// MAC[0:16] of each AS entry until the stop_at index.
    ///
    /// If the segment is used to traverse a peer link we need to add 1 to the stop_at index
    /// in order to get the beta after the as_entry where the peer link is used.
    ///
    /// This is because this peering hop has a MAC that chains to its non-peering
    /// counterpart, the same as what the next hop (in construction order) chains to.
    /// So both this and the next hop are to be validated from the same SegID
    /// accumulator value: the one for the *next* hop, calculated on the regular
    /// non-peering segment.
    ///
    /// Note that, when traversing peer hops, the SegID accumulator is left untouched for the
    /// next router on the path to use.
    ///
    /// Please refer to "The Complete Guide To SCION (2022)" p. 100 section 5.3.3 for
    /// more details.
    fn initialize_segment_id(&self) -> u16 {
        let in_construction_order = self
            .dst
            .ia()
            .is_some_and(|dst| dst == self.segment.path_segment().last_ia());
        let mut stop_at = if in_construction_order {
            self.edge.shortcut_idx
        } else {
            self.segment.path_segment().len() - 1
        };
        if self.edge.peer.is_some() && self.edge.shortcut_idx == stop_at {
            stop_at += 1;
        }
        self.segment.path_segment().as_entries[..stop_at]
            .iter()
            .fold(
                self.segment.path_segment().info.segment_id,
                |beta, entry| {
                    beta ^ u16::from_be_bytes([
                        entry.hop_entry.hop_field.mac[0],
                        entry.hop_entry.hop_field.mac[1],
                    ])
                },
            )
    }
}

/// Path solution is a sequence of edges that form a valid path from src to dst.
#[derive(Clone)]
pub struct PathSolution<'a> {
    /// Edges that are already part of the solution.
    edges: Vec<SolutionEdge<'a>>,
    /// Current vertex being visited.
    current_vertex: Vertex,
    /// Cost is the sum of edge weights.
    cost: u64,
}

impl<'a> std::fmt::Debug for PathSolution<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PathSolution({})",
            self.edges
                .iter()
                .map(|e| format!("{}->{}", e.src, e.dst))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl<'a> PathSolution<'a> {
    /// Create a new [`PathSolution`] starting at the given vertex.
    pub fn new(current_vertex: Vertex) -> Self {
        Self {
            edges: Vec::new(),
            current_vertex,
            cost: 0,
        }
    }

    /// Create a new solution with the given edge added.
    /// Returns None if the solution with the new edge would be invalid.
    pub fn try_add_edge(&self, e: SolutionEdge<'a>) -> Option<Self> {
        if !self.valid_next_seg(e.segment) {
            return None;
        }
        let cost = self.cost + e.edge.weight;
        let current_vertex = e.dst.clone();
        let mut new_edges = self.edges.clone();
        new_edges.push(e);
        Some(Self {
            edges: new_edges,
            current_vertex,
            cost,
        })
    }

    fn valid_next_seg(&self, segment: &InputSegment) -> bool {
        match self.edges.as_slice() {
            [] => true,
            [last] => {
                // All two segment combinations are valid except core,core.
                last.segment.is_non_core() || segment.is_non_core()
            }
            [first, second] => {
                // Only non-core,core,non-core is valid.
                first.segment.is_non_core() && second.segment.is_core() && segment.is_non_core()
            }
            _ => {
                // This will never happen.
                false
            }
        }
    }

    /// Construct a path from the solution.
    pub fn path(&self) -> Path {
        if self.edges.is_empty() {
            return Path {
                metadata: None,
                underlay_next_hop: None,
                isd_asn: ByEndpoint {
                    source: self.current_vertex.ia().unwrap(),
                    destination: self.current_vertex.ia().unwrap(),
                },
                data_plane_path: crate::path::DataPlanePath::EmptyPath,
            };
        }

        let mut mtu = u16::MAX;
        let mut path = StandardPath::new();
        let mut interfaces = Vec::new();
        for solution_edge in self.edges.iter() {
            let mut segment_interfaces = Vec::new();
            let mut hops = Vec::new();

            // We traverse the segment from back to front against the beaconing direction.
            // and stop at the shortcut index (inclusive)
            for (idx, as_entry) in solution_edge
                .segment
                .path_segment()
                .as_entries
                .iter()
                .enumerate()
                .skip(solution_edge.edge.shortcut_idx)
                .rev()
            {
                let hopfield = match solution_edge.edge.peer {
                    Some(peer_idx) if idx == solution_edge.edge.shortcut_idx => {
                        // Peer hop field.
                        let peer = &as_entry.peer_entries[peer_idx];
                        let hopfield = HopField {
                            exp_time: peer.hop_field.exp_time,
                            cons_ingress: peer.hop_field.cons_ingress,
                            cons_egress: peer.hop_field.cons_egress,
                            mac: peer.hop_field.mac,
                            ingress_router_alert: false,
                            egress_router_alert: false,
                        };
                        // For peer hop fields, always include peer MTU
                        mtu = std::cmp::min(mtu, peer.peer_mtu);
                        hopfield
                    }
                    _ => {
                        // Regular hop field.
                        let hopfield = HopField {
                            exp_time: as_entry.hop_entry.hop_field.exp_time,
                            cons_ingress: as_entry.hop_entry.hop_field.cons_ingress,
                            cons_egress: as_entry.hop_entry.hop_field.cons_egress,
                            mac: as_entry.hop_entry.hop_field.mac,
                            ingress_router_alert: false,
                            egress_router_alert: false,
                        };
                        // For regular hop fields, only include ingress MTU if not zero and not a
                        // shortcut
                        let is_shortcut = idx == solution_edge.edge.shortcut_idx && idx != 0;
                        if as_entry.hop_entry.ingress_mtu != 0 && !is_shortcut {
                            mtu = std::cmp::min(mtu, as_entry.hop_entry.ingress_mtu);
                        }
                        hopfield
                    }
                };

                // Segment is traversed in reverse construction order, so the egress goes first.
                if hopfield.cons_egress != 0 {
                    segment_interfaces.push(PathInterface {
                        isd_asn: as_entry.local,
                        id: hopfield.cons_egress,
                    });
                }

                let is_shortcut = idx == solution_edge.edge.shortcut_idx && idx != 0;
                let is_peer =
                    idx == solution_edge.edge.shortcut_idx && solution_edge.edge.peer.is_some();
                if hopfield.cons_ingress != 0 && (!is_shortcut || is_peer) {
                    segment_interfaces.push(PathInterface {
                        isd_asn: as_entry.local,
                        id: hopfield.cons_ingress,
                    });
                }

                hops.push(hopfield);
                // Always include AS MTU in calculation
                mtu = std::cmp::min(mtu, as_entry.mtu as u16);
            }

            // Put the hops in forwarding order. Needed when the path segment in the solution
            // edge is oriented in the reverse direction of the solution edge i.e.
            // "core" segments that are traversed in the reverse direction and "down" segments.
            let cons_dir = solution_edge
                .dst
                .ia()
                .is_some_and(|dst| dst == solution_edge.segment.path_segment().last_ia());
            if cons_dir {
                hops.reverse();
                segment_interfaces.reverse();
            }

            interfaces.extend(segment_interfaces);

            path.add_segment(
                InfoField {
                    timestamp_epoch: solution_edge
                        .segment
                        .path_segment()
                        .info
                        .timestamp
                        .timestamp() as u32,
                    seg_id: solution_edge.initialize_segment_id(),
                    cons_dir,
                    peer: solution_edge.edge.peer.is_some(),
                },
                hops,
            )
            .unwrap();
        }

        let standard_path: crate::path::encoded::EncodedStandardPath = path.into();

        Path {
            metadata: Some(Metadata {
                interfaces: Some(interfaces),
                mtu,
                expiration: standard_path.expiry_time(),
                latency: None,
                bandwidth_kbps: None,
                geo: None,
                link_type: None,
                internal_hops: None,
                notes: None,
                epic_auths: None,
            }),
            underlay_next_hop: None,
            isd_asn: ByEndpoint {
                source: self.edges.first().unwrap().src.ia().unwrap(),
                destination: self.edges.last().unwrap().dst.ia().unwrap(),
            },
            data_plane_path: crate::path::DataPlanePath::Standard(standard_path),
        }
    }
}
