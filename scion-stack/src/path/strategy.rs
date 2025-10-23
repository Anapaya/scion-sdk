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

//! Path Selection defines how paths are filtered and ranked.

use std::{cmp::Ordering, sync::Arc};

use crate::path::{policy::PathPolicy, ranking::PathRanking, types::PathManagerPath};

pub mod policy;
pub mod ranking;

/// PathStrategy combines multiple path operations into a single strategy.
#[derive(Default)]
pub struct PathStrategy {
    /// The path policies to apply.
    pub policies: Vec<Arc<dyn PathPolicy>>,
    /// The path ranking functions to apply.
    pub ranking: Vec<Arc<dyn PathRanking>>,
}
impl PathStrategy {
    /// Appends a path policy to the list of policies.
    pub fn add_policy(&mut self, policy: impl PathPolicy) {
        self.policies.push(Arc::new(policy));
    }

    /// Appends a path ranking function to the list of ranking functions.
    pub fn add_ranking(&mut self, ranking: impl PathRanking) {
        self.ranking.push(Arc::new(ranking));
    }

    /// Returns true if the given path is accepted by all policies.
    ///
    /// If no policies are added, all paths are accepted.
    pub fn predicate(&self, path: &PathManagerPath) -> bool {
        self.policies.iter().all(|policy| policy.predicate(path))
    }

    /// Ranks the order of two paths based on preference.
    ///
    /// # Return
    /// Returns the **preference ordering** between two paths.
    ///
    /// - `Ordering::Less` if `this` is preferred over `other`
    /// - `Ordering::Greater` if `other` is preferred over `this`
    /// - `Ordering::Equal` if both paths are equally preferred
    pub fn rank_order(&self, this: &PathManagerPath, other: &PathManagerPath) -> Ordering {
        for ranker in &self.ranking {
            match ranker.rank_order(this, other) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }

    /// Filters the given paths based on all policies, removing paths that are not accepted.
    pub fn filter_inplace<'path: 'iter, 'iter>(&self, paths: &mut Vec<PathManagerPath>) {
        paths.retain(|p| self.predicate(p));
    }

    /// Sorts the given paths in place, placing the most preferred paths first.
    ///
    /// Uses the ranking functions in the order they were added.
    ///
    /// If no ranking functions are added, the paths are not modified.
    pub fn rank_inplace<'path: 'iter, 'iter>(&self, path: &mut [PathManagerPath]) {
        path.sort_by(|a, b| self.rank_order(a, b));
    }
}
