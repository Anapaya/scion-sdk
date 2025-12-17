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

use std::time::{Duration, SystemTime};

use crate::path::{manager::algo::exponential_decay, types::Score};

/// Duration after which the reliability score decays to half its value.
/// After 20 half-lives, the score approaches zero.
const EXPONENTIAL_DECAY_HALFLIFE: Duration = Duration::from_secs(90); // Full decay in ~30 min

/// Reliability score for a path
///
/// A reliability score indicates how reliable a path is, based on reported issues.
/// The score decays over time, allowing paths to recover over time if no further issues are
/// reported.
#[derive(Debug, Clone)]
pub struct ReliabilityScore {
    score: f32,
    last_updated: SystemTime,
}

impl ReliabilityScore {
    /// Returns the current reliability score, decayed to `now`.
    pub fn score(&self, now: SystemTime) -> Score {
        Score::new_clamped(exponential_decay(
            self.score,
            now.duration_since(self.last_updated)
                .unwrap_or_else(|_| Duration::from_secs(0)),
            EXPONENTIAL_DECAY_HALFLIFE,
        ))
    }

    /// Creates a new ReliabilityScore with initial score of 0.0
    ///
    /// `now` is the current time for initialization, used for decay calculations.
    pub fn new_with_time(now: SystemTime) -> Self {
        ReliabilityScore {
            score: 0.0,
            last_updated: now,
        }
    }

    /// Updates the reliability score based on the reported issue.
    ///
    /// `penalty` is the penalty score to apply usually a negative value.
    /// `now` is the current time for decay calculations.
    pub fn update(&mut self, penalty: Score, now: SystemTime) {
        let current_score = self.score(now); // Get decayed score
        let new_score = current_score.value() + penalty.value(); // Apply penalty

        self.score = new_score.clamp(-1000.0, 1000.0); // For sanity, clamp score
        self.last_updated = now;
    }
}
