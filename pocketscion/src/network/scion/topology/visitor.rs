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

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use scion_proto::address::IsdAsn;

use crate::network::scion::topology::{FastTopologyLookup, ScionAs, ScionLink};

/// Traverses all Links in a ScionTopology, visiting each connected AS.
///
/// Is cloned on every branch allowing it to maintain state.
pub trait TopologyLinkVisitor: Clone + Send {
    /// The output type produced by the visitor.
    type Output: Send;

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

/// Walks all links to their end starting at `start_as`, single-threaded.
///
/// On each branch, the visitor is cloned. \
/// On end of branch, the visitor's `finish` method is called.
///
/// The visitor will not visit the same AS twice on the same path.
pub fn walk_all_links<'topo, Visitor: TopologyLinkVisitor>(
    visitor: Visitor,
    start_as: IsdAsn,
    topo_lookup: &FastTopologyLookup<'topo>,
) -> Vec<Visitor::Output> {
    walk_all_links_parallel(visitor, start_as, topo_lookup, 1)
}

/// Walks all links to their end starting at `start_as`, using up to
/// `max_threads` threads.
///
/// On each branch, the visitor is cloned. \
/// On end of branch, the visitor's `finish` method is called.
///
/// The visitor will not visit the same AS twice on the same path.
///
/// When `max_threads` is 1, execution is single-threaded. \
/// When `max_threads` > 1, sibling branches at each recursion level may be
/// explored concurrently on separate threads, each with its own copy of the
/// visited set.
pub fn walk_all_links_parallel<'topo, Visitor: TopologyLinkVisitor>(
    visitor: Visitor,
    start_as: IsdAsn,
    topo_lookup: &FastTopologyLookup<'topo>,
    max_threads: usize,
) -> Vec<Visitor::Output> {
    let max_extra_threads = max_threads.max(1) - 1;

    let Some(start_as) = topo_lookup.topology.as_map.get(&start_as) else {
        return vec![];
    };

    let index = Arc::new(BitsetIndex::new(
        topo_lookup.topology.as_map.keys().copied(),
    ));
    let visited = VisitedBitset::new(index);
    let thread_budget = Arc::new(ThreadBudget::new(max_extra_threads));
    let mut results = Vec::new();

    visit_recurse(
        start_as,
        None,
        visitor,
        visited,
        &mut results,
        topo_lookup,
        max_extra_threads,
        &thread_budget,
    );

    results
}
/// Collects the branches that should be followed from the current AS.
struct Branch<'topo, V: TopologyLinkVisitor> {
    next_as: &'topo ScionAs,
    link: &'topo ScionLink,
    visitor: V,
}

fn visit_recurse<'topo, Visitor: TopologyLinkVisitor>(
    current_as: &'topo ScionAs,
    used_link: Option<&ScionLink>,
    mut visitor: Visitor,
    mut visited: VisitedBitset<4>,
    result_collector: &mut Vec<Visitor::Output>,
    topo_lookup: &FastTopologyLookup<'topo>,
    max_threads: usize,
    thread_budget: &Arc<ThreadBudget>,
) {
    let current_as_id = current_as.isd_as();
    if !visited.insert(current_as_id) {
        return; // If we have already visited this AS, skip.
    }

    visitor.visit(used_link, current_as);

    // Get Next Links
    let empty_vec = Vec::new();
    let links = topo_lookup
        .as_to_link_map
        .get(&current_as_id)
        .unwrap_or(&empty_vec);

    // Collect valid branches
    let mut branches: Vec<Branch<'topo, Visitor>> = Vec::new();
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
            // Skip branches to already-visited ASes
            if visited.contains(next_as.isd_as()) {
                continue;
            }

            branches.push(Branch {
                next_as,
                link,
                visitor: visitor.clone(),
            });
        }
    }
    let has_branched = !branches.is_empty();

    // Attempt to do some heuristics to avoid spawning threads when it's unlikely to be beneficial.
    const MIN_BRANCHES_FOR_THREADING: usize = 3;
    const MIN_UNVISITED_FOR_THREADING: usize = 5;
    let ok_unvisited = visited.unvisited_count() > MIN_UNVISITED_FOR_THREADING;
    let ok_branches = branches.len() >= MIN_BRANCHES_FOR_THREADING;
    let may_multithread = max_threads > 1 && ok_unvisited && ok_branches;

    match may_multithread {
        // Single branch or single-threaded: recurse sequentially.
        false => {
            for branch in branches {
                visit_recurse(
                    branch.next_as,
                    Some(branch.link),
                    branch.visitor,
                    visited.clone(),
                    result_collector,
                    topo_lookup,
                    max_threads,
                    thread_budget,
                );
            }
        }
        // Try to multithread
        true => {
            thread::scope(|scope| {
                let mut handles = Vec::new();
                for branch in branches {
                    let permit = thread_budget.try_acquire();

                    match permit {
                        // Permit acquired, spawn a new thread for this branch.
                        Ok(permit) => {
                            let visited_clone = visited.clone();
                            let mut result_collector = Vec::new();
                            let active = Arc::clone(thread_budget);

                            handles.push(scope.spawn(move || {
                                visit_recurse(
                                    branch.next_as,
                                    Some(branch.link),
                                    branch.visitor,
                                    visited_clone,
                                    &mut result_collector,
                                    topo_lookup,
                                    max_threads,
                                    &active,
                                );

                                drop(permit); // Release the thread slot when done.
                                result_collector
                            }));
                        }
                        // No permit available, execute sequentially on this thread.
                        Err(_) => {
                            visit_recurse(
                                branch.next_as,
                                Some(branch.link),
                                branch.visitor,
                                visited.clone(),
                                result_collector,
                                topo_lookup,
                                max_threads,
                                thread_budget,
                            );
                        }
                    }
                }

                // Collect results from spawned threads.
                for handle in handles {
                    let thread_results = handle.join().expect("visitor thread panicked");
                    result_collector.extend(thread_results);
                }
            })
        }
    }

    result_collector.extend(visitor.finish(!has_branched));
}

struct BitsetIndex {
    map: HashMap<IsdAsn, u64>,
}
impl BitsetIndex {
    fn new(ases: impl Iterator<Item = IsdAsn>) -> Self {
        let map = ases
            .enumerate()
            .map(|(i, as_id)| (as_id, i as u64))
            .collect();
        Self { map }
    }

    fn get(&self, as_id: IsdAsn) -> Option<u64> {
        self.map.get(&as_id).copied()
    }
}

/// A compact visited set for ASes, using a bitset.
///
/// Supports up to N*128 ASes, where N is the size of the visited array.
#[derive(Clone)]
struct VisitedBitset<const N: usize> {
    index: Arc<BitsetIndex>,
    visited: [u128; N],
}
impl<const N: usize> VisitedBitset<N> {
    fn new(index: Arc<BitsetIndex>) -> Self {
        if index.map.len() > N * 128 {
            panic!(
                "Topology has more than {} ASes, this is currently not supported",
                N * 128
            );
        }
        Self {
            index,
            visited: [0; N],
        }
    }

    fn unvisited_count(&self) -> usize {
        let total_ases = self.index.map.len();
        let visited_count = self
            .visited
            .iter()
            .map(|bits| bits.count_ones() as usize)
            .sum::<usize>();
        total_ases - visited_count
    }

    fn contains(&self, as_id: IsdAsn) -> bool {
        let Some(bit_index) = self.index.get(as_id) else {
            return false;
        };
        let array_index = (bit_index / 128) as usize;
        let bit_position = bit_index % 128;
        if array_index >= self.visited.len() {
            return false;
        }
        self.visited[array_index] & (1 << bit_position) != 0
    }

    fn insert(&mut self, as_id: IsdAsn) -> bool {
        let Some(bit_index) = self.index.get(as_id) else {
            panic!("AS {} not found in BitsetIndex", as_id);
        };

        let array_index = (bit_index / 128) as usize;
        let bit_position = bit_index % 128;

        if array_index >= self.visited.len() {
            panic!(
                "Bit index {} for AS {} exceeds visited bitset size",
                bit_index, as_id
            );
        }

        let bit = 1 << bit_position;
        let already_visited = self.visited[array_index] & bit != 0;
        self.visited[array_index] |= bit;
        !already_visited
    }
}

/// A lightweight permit system for limiting the number of concurrent threads.
///
/// Uses an [`AtomicUsize`] counter to track available permits.
struct ThreadBudget {
    available: AtomicUsize,
}

impl ThreadBudget {
    /// Creates a new budget with `permits` available slots.
    fn new(permits: usize) -> Self {
        Self {
            available: AtomicUsize::new(permits),
        }
    }

    /// Tries to acquire a permit without blocking.
    ///
    /// Returns `Ok(ThreadPermit)` if a permit was available, or `Err(())` otherwise.
    fn try_acquire(&self) -> Result<ThreadPermit<'_>, ()> {
        let mut current = self.available.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return Err(());
            }
            match self.available.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(ThreadPermit { budget: self }),
                Err(updated) => current = updated,
            }
        }
    }
}

/// RAII guard that releases one permit back to the [`ThreadBudget`] on drop.
struct ThreadPermit<'a> {
    budget: &'a ThreadBudget,
}

impl Drop for ThreadPermit<'_> {
    fn drop(&mut self) {
        self.budget.available.fetch_add(1, Ordering::Release);
    }
}
