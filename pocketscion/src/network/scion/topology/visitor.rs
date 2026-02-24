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
//! Visitor for traversing a SCION topology.

use std::collections::HashSet;

use scion_proto::address::IsdAsn;

use crate::network::scion::topology::{FastTopologyLookup, ScionAs, ScionLink};

/// Traverses all Links in a ScionTopology, visiting each connected AS.
///
/// Is cloned on every branch allowing it to maintain state.
pub trait TopologyLinkVisitor: Clone {
    /// The output type produced by the visitor.
    type Output;

    /// Called for each visited AS
    ///
    /// `used_link` is the link taken to reach `current_as` from the previous AS.
    /// If `None`, this is the starting AS.
    fn visit(&mut self, used_link: Option<&ScionLink>, current_as: &ScionAs);

    /// Called to finalize the data collected by the visitor.
    ///
    /// Can return None if visitor has no useable output
    fn finish(self, final_link: bool) -> Option<Self::Output>;

    /// Determines whether the visitor should follow a link.
    ///
    /// Visitor already stops following links that have been visited before.
    #[expect(unused_variables)]
    fn should_follow_link(
        &self,
        current_as: &ScionAs,
        next_link: &ScionLink,
        next_as: &ScionAs,
    ) -> bool {
        // Default implementation follows all links
        true
    }
}

/// Walks all links their end starting at `start_as`.
///
/// On each branch, the visitor is cloned. \
/// On end of branch, the visitor's `finish` method is called.
///
/// The visitor will not visit the same AS twice.
pub fn walk_all_links<'topo, Visitor: TopologyLinkVisitor>(
    visitor: Visitor,
    start_as: IsdAsn,
    topo_lookup: &FastTopologyLookup<'topo>,
) -> Vec<Visitor::Output> {
    let Some(start_as) = topo_lookup.topology.as_map.get(&start_as) else {
        return vec![];
    };

    let mut visited: HashSet<IsdAsn> = HashSet::new();

    return visit_recurse(start_as, None, visitor, &mut visited, topo_lookup);

    fn visit_recurse<'topo, VisitorRec: TopologyLinkVisitor>(
        current_as: &'topo ScionAs,
        used_link: Option<&ScionLink>,
        mut visitor: VisitorRec,
        visited: &mut HashSet<IsdAsn>,
        topo_lookup: &FastTopologyLookup<'topo>,
    ) -> Vec<VisitorRec::Output> {
        let current_as_id = current_as.isd_as();
        if !visited.insert(current_as_id) {
            return vec![]; // If we have already visited this AS, skip.
        }

        visitor.visit(used_link, current_as);

        // Get Next Links
        let empty_vec = Vec::new();
        let links = topo_lookup
            .as_to_link_map
            .get(&current_as_id)
            .unwrap_or(&empty_vec);

        let mut result = Vec::new();
        for link in links {
            // Skip the link we just came from
            if Some(*link) == used_link {
                continue;
            }

            let Some(next_interface) = link.get_peer(&current_as_id) else {
                debug_assert!(false, "Link {link} has no peer for AS {current_as:?}");
                continue; // Unless the topo is malformed, this should never happen.
            };

            let Some(next_as) = topo_lookup.topology.as_map.get(&next_interface.isd_as) else {
                debug_assert!(false, "Missing as in topology: {next_interface:?}");
                continue; // Unless topo is malformed, this should never happen.
            };

            if visitor.should_follow_link(current_as, link, next_as) {
                let results =
                    visit_recurse(next_as, Some(link), visitor.clone(), visited, topo_lookup);

                result.extend(results.into_iter());
            }
        }

        visited.remove(&current_as_id);

        // If no child had any output, no links are left to follow.
        let final_link = result.is_empty();

        result.extend(visitor.finish(final_link));

        result
    }
}
