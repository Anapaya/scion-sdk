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

//! Graph based path combinator.

use std::collections::{HashMap, HashSet, VecDeque};

use tinyvec::TinyVec;

use crate::{
    core::{
        encode::{EncodeError, WireEncode},
        view::View,
    },
    dataplane_path::standard::{
        model::{InfoField, Segment, StandardPath},
        types::InfoFieldFlags,
        view::StandardPathView,
    },
    identifier::isd_asn::IsdAsn,
    path::{
        ScionPath,
        metadata::{InterfaceMetadata, PathMetadata, path_interface::PathInterface},
    },
    segment::{Entry, PathSegment, SegmentID},
};

/// Multigraph is the graph used to find valid paths.
/// Vertices are either ASes (IA) or Peering vertices that represent the use of a peering link
/// in one direction.
/// Edges represent the valid use of a segment to send data from one vertex to another.
/// Edges are bidirectional i.e. they are added in both directions.
/// The edges are annotated with the segment and with the weight calculated by the given weight
/// function.
pub struct MultiGraph<'a, WeightFn, EntryType: Entry>
where
    WeightFn: Fn(&InputSegment<'a, EntryType>, u64, bool) -> u64,
{
    /// Adjacency list of the graph. This maps Vertex -> (Vertex -> []Edge).
    adjacencies: HashMap<Vertex, VertexInfo<'a, EntryType>>,
    /// Function to calculate the weight of an edge. towards_peer is true if the edge is
    /// towards a Peering vertex. This can be used to adjust the weight for the use of
    /// the peering link. Weight(segment, shortcut_idx, towards_peer) -> weight
    weight_fn: WeightFn,
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
type EdgeMap<'a, EntryType> = HashMap<&'a InputSegment<'a, EntryType>, Edge>;
/// Maps destination vertices to the list of edges that point towards them.
type VertexInfo<'a, EntryType> = HashMap<Vertex, EdgeMap<'a, EntryType>>;

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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum InputSegment<'a, EntryType: Entry> {
    /// Core segment.
    Core(&'a PathSegment<EntryType>, SegmentID),
    /// Non-core segment.
    NonCore(&'a PathSegment<EntryType>, SegmentID),
}

impl<'a, EntryType: Entry> InputSegment<'a, EntryType> {
    /// Create a new core input segment.
    pub fn new_core(path_segment: &'a PathSegment<EntryType>) -> Self {
        let id = path_segment.id();
        Self::Core(path_segment, id)
    }

    /// Create a new non-core input segment.
    pub fn new_non_core(path_segment: &'a PathSegment<EntryType>) -> Self {
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

    fn path_segment(&self) -> &PathSegment<EntryType> {
        match self {
            Self::Core(path_segment, _) => path_segment,
            Self::NonCore(path_segment, _) => path_segment,
        }
    }
}

pub(crate) fn number_of_hops<EntryType: Entry>(
    segment: &InputSegment<EntryType>,
    shortcut_idx: u64,
    towards_peer: bool,
) -> u64 {
    // The weight is the number of links traversed when using the segment.
    // We subtract 1 to get from the #hops to the #links.
    // We subtract the shortcut index to get the number of links that are actually used.
    let weight = segment.path_segment().len() as u64 - 1 - shortcut_idx;
    if !towards_peer {
        weight
    } else {
        // We add 1 to the weight to account for the peer link.
        weight + 1
    }
}

impl<'a, EntryType: Entry, F> MultiGraph<'a, F, EntryType>
where
    F: Fn(&InputSegment<EntryType>, u64, bool) -> u64,
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
    ///
    /// Returns the count of segments which were successfully added.
    /// If a segment contains no hops, it is not added to the graph.``
    pub fn add_segments(&mut self, segments: &'a [InputSegment<EntryType>]) -> usize {
        let mut added = 0;
        for segment in segments {
            if self.add_segment(segment).is_ok() {
                added += 1;
            }
        }
        added
    }

    fn add_segment(&mut self, segment: &'a InputSegment<EntryType>) -> Result<(), &'static str> {
        match segment {
            InputSegment::Core(..) => {
                self.add_core_segment(segment)?;
            }
            InputSegment::NonCore(..) => {
                self.add_non_core_segment(segment)?;
            }
        }

        Ok(())
    }

    /// For core segments we just add a bidirectional edge between the first and last IA.
    /// Core edges cannot be shortcut i.e. they can only be used to connect from the
    /// first to the last IA (or vice versa).
    ///
    /// Returns Ok if the edge was added successfully, or an error if the segment does not
    /// contain any hops.
    fn add_core_segment(
        &mut self,
        segment: &'a InputSegment<EntryType>,
    ) -> Result<(), &'static str> {
        let first_ia = segment.path_segment().first_ia();
        let last_ia = segment.path_segment().last_ia();

        let (Some(first_ia), Some(last_ia)) = (first_ia, last_ia) else {
            // If the segment does not contain any hops, we cannot add any edges.
            return Err("Segment does not contain any hops");
        };

        self.add_edge(
            Vertex::AS(first_ia),
            Vertex::AS(last_ia),
            segment,
            Edge {
                weight: (self.weight_fn)(segment, 0, false),
                shortcut_idx: 0,
                peer: None,
            },
        );

        Ok(())
    }

    /// For non-core segments we add
    /// - An edge from the last AS in the segment (leaf) to every other AS in the segment. These
    ///   links represent the "shortcut" use of the segment.
    /// - An edge from the last AS in the segment (leaf) to every peering link in the segment
    ///   (peering vertex). These links represent the use of the peering link in this direction.
    ///
    /// Returns Ok if the edges were added successfully, or an error if the segment does not
    /// contain any hops.
    fn add_non_core_segment(
        &mut self,
        segment: &'a InputSegment<EntryType>,
    ) -> Result<(), &'static str> {
        let Some(leaf) = segment.path_segment().last_ia() else {
            // If the segment does not contain any hops, we cannot add any edges.
            return Err("Segment does not contain any hops");
        };

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
                // The peering vertices are oriented in the direction that the peering link is
                // used. We add two edges, one for each direction.
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

        Ok(())
    }

    /// Add a bidirectional edge from src to dst and back.
    fn add_edge(
        &mut self,
        src: Vertex,
        dst: Vertex,
        segment: &'a InputSegment<EntryType>,
        edge: Edge,
    ) {
        self.add_directed_edge(src.clone(), dst.clone(), segment, edge.clone());
        self.add_directed_edge(dst, src, segment, edge);
    }

    /// Add a directed edge from src to dst.
    fn add_directed_edge(
        &mut self,
        src: Vertex,
        dst: Vertex,
        segment: &'a InputSegment<EntryType>,
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
    pub fn get_paths(&self, src: IsdAsn, dst: IsdAsn) -> Vec<PathSolution<'_, EntryType>> {
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
        // To make the output deterministic we sort the solutions by cost, then by number of
        // edges, then by segment id.
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
    #[allow(dead_code)]
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
                                segment.path_segment().info().segment_id,
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
                            segment.path_segment().info().segment_id,
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
pub struct SolutionEdge<'a, EntryType: Entry> {
    /// The edge in the graph.
    pub edge: Edge,
    /// Source vertex.
    pub src: Vertex,
    /// Destination vertex.
    pub dst: Vertex,
    /// The segment associated with this edge, used during forwarding path construction.
    pub segment: &'a InputSegment<'a, EntryType>,
}

impl<'a, EntryType: Entry> SolutionEdge<'a, EntryType> {
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
        let in_construction_order = self.dst.ia().is_some_and(|dst| {
            dst == self
                .segment
                .path_segment()
                .last_ia()
                .expect("Segments are checked to have at least one hop")
        });
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
                self.segment.path_segment().info().segment_id,
                |beta, entry| {
                    beta ^ u16::from_be_bytes([
                        entry.get().hop_entry.hop_field.mac[0],
                        entry.get().hop_entry.hop_field.mac[1],
                    ])
                },
            )
    }
}

/// Path solution is a sequence of edges that form a valid path from src to dst.
#[derive(Clone)]
pub struct PathSolution<'a, EntryType: Entry> {
    /// Edges that are already part of the solution.
    edges: Vec<SolutionEdge<'a, EntryType>>,
    /// Current vertex being visited.
    current_vertex: Vertex,
    /// Cost is the sum of edge weights.
    cost: u64,
}

impl<'a, EntryType: Entry> std::fmt::Debug for PathSolution<'a, EntryType> {
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

impl<'a, EntryType: Entry> PathSolution<'a, EntryType> {
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
    pub fn try_add_edge(&self, e: SolutionEdge<'a, EntryType>) -> Option<Self> {
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

    fn valid_next_seg(&self, segment: &InputSegment<EntryType>) -> bool {
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
    pub fn path(&self) -> Result<Option<ScionPath>, EncodeError> {
        if self.edges.is_empty() {
            return Ok(None);
        }

        let mut mtu = u16::MAX;
        let mut path = StandardPath::new_empty();
        let mut interfaces = Vec::new();
        for solution_edge in self.edges.iter() {
            let mut segment_interfaces = Vec::new();
            let mut hops = TinyVec::with_capacity(
                solution_edge.segment.path_segment().len() - solution_edge.edge.shortcut_idx,
            );

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
                let as_entry = as_entry.get();
                let hopfield = match solution_edge.edge.peer {
                    Some(peer_idx) if idx == solution_edge.edge.shortcut_idx => {
                        // Peer hop field.expiry_time
                        let peer = as_entry.peer_entries.get(peer_idx).expect(
                            "Peer index is checked to be valid when adding edges to the graph",
                        );
                        let hopfield = peer.hop_field.to_dp_hopfield();
                        // Always update minimum MTU for the path
                        mtu = std::cmp::min(mtu, peer.peer_mtu);
                        hopfield
                    }
                    _ => {
                        // Regular hop field.
                        let hopfield = as_entry.hop_entry.hop_field.to_dp_hopfield();
                        // Only update minimum MTU for regular hops, not for shortcuts.
                        let is_shortcut = idx == solution_edge.edge.shortcut_idx && idx != 0;
                        if as_entry.hop_entry.ingress_mtu != 0 && !is_shortcut {
                            mtu = std::cmp::min(mtu, as_entry.hop_entry.ingress_mtu);
                        }
                        hopfield
                    }
                };

                // Segment is traversed in reverse construction order, so the egress goes first.
                if hopfield.cons_egress != 0 {
                    segment_interfaces.push(InterfaceMetadata::new_without_metadata(
                        PathInterface {
                            isd_asn: as_entry.local,
                            id: hopfield.cons_egress,
                        },
                    ));
                }

                let is_shortcut = idx == solution_edge.edge.shortcut_idx && idx != 0;
                let is_peer =
                    idx == solution_edge.edge.shortcut_idx && solution_edge.edge.peer.is_some();

                if hopfield.cons_ingress != 0 && (!is_shortcut || is_peer) {
                    segment_interfaces.push(InterfaceMetadata::new_without_metadata(
                        PathInterface {
                            isd_asn: as_entry.local,
                            id: hopfield.cons_ingress,
                        },
                    ));
                }

                hops.push(hopfield);
                // Always include AS MTU in calculation
                mtu = std::cmp::min(mtu, as_entry.mtu as u16);
            }

            // Put the hops in forwarding order. Needed when the path segment in the solution
            // edge is oriented in the reverse direction of the solution edge i.e.
            // "core" segments that are traversed in the reverse direction and "down" segments.
            let cons_dir = solution_edge.dst.ia().is_some_and(|dst| {
                dst == solution_edge
                    .segment
                    .path_segment()
                    .last_ia()
                    .expect("Segments are checked to have at least one hop")
            });

            if cons_dir {
                hops.reverse();
                segment_interfaces.reverse();
            }

            interfaces.extend(segment_interfaces);

            let mut flags = InfoFieldFlags::empty();
            flags.set(InfoFieldFlags::CONS_DIR, cons_dir);
            flags.set(InfoFieldFlags::PEERING, solution_edge.edge.peer.is_some());

            if path
                .segments
                .try_push(Segment {
                    info_field: InfoField {
                        flags,
                        segment_id: solution_edge.initialize_segment_id(),
                        timestamp: solution_edge.segment.path_segment().info().timestamp,
                    },
                    hop_fields: hops,
                })
                .is_some()
            {
                panic!("valid path segment should always fit in the path")
            }
        }

        let expiration = path.expiration();

        let encoded = path.encode_to_vec()?.into_boxed_slice();
        let encoded = crate::dataplane_path::view::ScionDpPathView::Standard(
            StandardPathView::from_boxed(encoded)
                .expect("valid path encoding should always produce a valid view"),
        );

        let start_ia = interfaces
            .first()
            .expect("edges are checked to be not empty")
            .interface
            .isd_asn;

        let end_ia = interfaces
            .last()
            .expect("edges are checked to be not empty")
            .interface
            .isd_asn;

        let metadata = PathMetadata {
            expiration: expiration.into(),
            mtu,
            interfaces: Some(interfaces),
            epic_auth: None,
            notes: None,
        };

        let path = ScionPath::new(start_ia, end_ia, encoded, Some(metadata), None);

        Ok(Some(path))
    }
}
