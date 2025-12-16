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

use std::{cmp::Ordering, sync::Arc, time::SystemTime};

use scion_proto::path::Path;

use crate::path::{
    policy::PathPolicy,
    scoring::{PathScorer, PathScoring},
    types::PathManagerPath,
};

pub mod policy;
pub mod scoring;

/// PathStrategy combines multiple path operations into a single strategy.
#[derive(Default)]
pub struct PathStrategy {
    /// The path policies to apply.
    pub policies: Vec<Arc<dyn PathPolicy>>,
    /// The path ranking functions to apply.
    pub scoring: PathScorer,
}
impl PathStrategy {
    /// Appends a path policy to the list of policies.
    pub fn add_policy(&mut self, policy: impl PathPolicy) {
        self.policies.push(Arc::new(policy));
    }

    /// Adds a path scorer with the given impact weight.
    ///
    /// Scores from paths are used to select the best path among multiple candidates.
    ///
    /// `scorer` - The path scorer to add.
    /// `impact` - The weight of the scorer in the final score aggregation.
    ///            e.g. Impact of 0.2 means the scorer can change the final score by up to ±0.2.
    ///
    /// Note:
    /// The impact weight does not need to sum to 1.0 across all scorers.
    pub fn add_scoring(&mut self, scoring: impl PathScoring, impact: f32) {
        self.scoring = self.scoring.clone().with_scorer(scoring, impact);
    }

    /// Ranks the order of two paths based on preference.
    ///
    /// # Return
    /// Returns the **preference ordering** between two paths.
    ///
    /// - `Ordering::Less` if `this` is preferred over `other`
    /// - `Ordering::Greater` if `other` is preferred over `this`
    /// - `Ordering::Equal` if both paths are equally preferred
    pub fn rank_order(
        &self,
        this: &PathManagerPath,
        other: &PathManagerPath,
        now: SystemTime,
    ) -> Ordering {
        let this_score = self.scoring.score(this, now);
        let other_score = self.scoring.score(other, now);

        this_score.total_cmp(&other_score).reverse() // Reverse: Greater score -> Less (more preferred)
    }

    /// Sorts the given paths in place, placing the most preferred paths first.
    ///
    /// If no ranking functions are added, the paths are not modified.
    pub fn rank_inplace(&self, path: &mut [PathManagerPath], now: SystemTime) {
        path.sort_by(|a, b| self.rank_order(a, b, now));
    }

    /// Returns true if the given path is accepted by all policies.
    ///
    /// If no policies are added, all paths are accepted.
    pub fn predicate(&self, path: &Path) -> bool {
        self.policies.iter().all(|policy| policy.predicate(path))
    }

    /// Filters the given paths based on all policies, removing paths that are not accepted.
    pub fn filter_inplace<'path: 'iter, 'iter>(&self, paths: &mut Vec<Path>) {
        paths.retain(|p| self.predicate(p));
    }
}
