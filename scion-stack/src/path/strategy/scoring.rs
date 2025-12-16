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

//! Path scoring is the central component of path selection.
//!
//! Each path is scored based on multiple metrics, and the scores are aggregated to form a final
//! score. Higher scores indicate more preferred paths.
//!
//! The scoring system is designed to be extensible, allowing new scoring metrics to be added as
//! needed. Scores from multiple metrics can be weighted to reflect their relative importance in
//! path selection.

use std::{collections::BTreeMap, fmt::Display, sync::Arc, time::SystemTime};

use crate::path::types::{PathManagerPath, Score};

/// Trait for scoring paths based on specific metrics.
///
/// Implementors provide a method to score a path, returning a floating point score between -1.0 and
/// 1.0. Higher scores indicate more preferred paths.
///
/// Scores from multiple implementations are aggregated to form a composite path score, which is
/// used for selecting a preferred path.
pub trait PathScoring: 'static + Send + Sync {
    /// Name of the metric being scored.
    /// Used for debugging path scoring decisions.
    fn metric_name(&self) -> &'static str;
    /// Scores the given path, returning a floating point score.
    ///
    /// Higher scores indicate more preferred paths.
    ///
    /// `path` - The path to score.
    /// `now` - The current system time for time sensitive scores.
    fn score(&self, path: &PathManagerPath, now: SystemTime) -> Score;
}

/// Scores paths based on their length with a 0.02 penalty per hop.
///
/// Shorter paths receive slightly higher scores.
struct PathLengthScorer;

impl PathScoring for PathLengthScorer {
    fn metric_name(&self) -> &'static str {
        "Path Length"
    }

    fn score(&self, path: &PathManagerPath, _now: SystemTime) -> Score {
        let length = match &path.path.data_plane_path {
            scion_proto::path::DataPlanePath::EmptyPath => 0,
            scion_proto::path::DataPlanePath::Standard(encoded_standard_path) => {
                encoded_standard_path
                    .segments()
                    .map(|seg| seg.hop_fields().len() - 2)
                    .sum()
            }
            scion_proto::path::DataPlanePath::Unsupported { .. } => {
                HOP_COUNT_FOR_MIN_SCORE as usize
            }
        };

        const MAX_SCORE: f32 = 1.0;
        const MIN_SCORE: f32 = 0.0;
        const HOP_COUNT_FOR_MIN_SCORE: f32 = 50.0;
        const PER_HOP_PENALTY: f32 = (MAX_SCORE - MIN_SCORE) / HOP_COUNT_FOR_MIN_SCORE;
        let score_value = MAX_SCORE - (length as f32 * PER_HOP_PENALTY);
        Score::new_clamped(score_value)
    }
}

/// Scores paths based on their reliability metric.
///
/// Without this scorer, path issues will be ignored in path selection.
pub struct PathReliabilityScorer;

impl PathScoring for PathReliabilityScorer {
    fn metric_name(&self) -> &'static str {
        "Reliability"
    }

    fn score(&self, path: &PathManagerPath, now: SystemTime) -> Score {
        path.reliability.score(now)
    }
}

/// Aggregates multiple path scorers into a single scoring function.
#[derive(Clone)]
pub struct PathScorer {
    scorers: Vec<(Arc<dyn PathScoring>, f32)>,
}

impl Default for PathScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl PathScorer {
    fn new() -> Self {
        Self { scorers: vec![] }
    }

    /// Returns false if no scorers are configured.
    pub fn is_empty(&self) -> bool {
        self.scorers.is_empty()
    }

    /// Default impact weight for reliability scorer.
    pub const DEFAULT_RELIABILITY_IMPACT: f32 = 1.0;
    /// Default impact weight for length scorer.
    pub const DEFAULT_LENGTH_IMPACT: f32 = 0.1;

    /// Uses default path scorers
    ///
    /// - [PathReliabilityScorer] with weight [PathScorer::DEFAULT_RELIABILITY_IMPACT]
    /// - [PathLengthScorer] with weight [PathScorer::DEFAULT_LENGTH_IMPACT]
    ///
    /// The PathLengthScorer's impact on path decision is minimal, to avoid ignoring reliability.
    pub(crate) fn use_default_scorers(&mut self) {
        self.scorers.push((
            Arc::new(PathReliabilityScorer),
            Self::DEFAULT_RELIABILITY_IMPACT,
        ));
        self.scorers
            .push((Arc::new(PathLengthScorer), Self::DEFAULT_LENGTH_IMPACT));
    }

    /// Adds a scorer with the given impact weight.
    ///
    /// `scorer` - The path scorer to add.
    /// `impact` - The weight of the scorer in the final score aggregation.
    ///            e.g. Impact of 0.2 means the scorer can change the final score by up to ±0.2.
    ///
    /// Note:
    /// The impact weight does not need to sum to 1.0 across all scorers.
    pub fn with_scorer(mut self, scorer: impl PathScoring + 'static, impact: f32) -> Self {
        self.scorers.push((Arc::new(scorer), impact));
        self
    }

    /// Scores the given path by aggregating scores from all configured scorers.
    ///
    /// Total score is the weighted sum of individual scorer scores.
    /// No Normalization is applied.
    pub fn score(&self, path: &PathManagerPath, now: SystemTime) -> f32 {
        let mut total_score = 0.0;
        for (scorer, impact) in &self.scorers {
            let score = scorer.score(path, now).value();
            total_score += score * impact;
        }
        total_score
    }

    /// Generates a report detailing individual scorer contributions to the total score of the path.
    pub fn score_report(&self, path: &PathManagerPath, now: SystemTime) -> ScoreReport {
        let mut report = ScoreReport::default();
        for (scorer, impact) in &self.scorers {
            let score = scorer.score(path, now).value();
            report.add_score(scorer.metric_name(), score * impact);
        }
        report
    }
}

/// A report of weighted scores contributing to a path's total score.
///
/// Used for debugging path scoring decisions.
#[derive(Default, Debug)]
pub struct ScoreReport(pub BTreeMap<&'static str, f32>);

impl ScoreReport {
    fn add_score(&mut self, metric: &'static str, score: f32) {
        self.0.insert(metric, score);
    }
}

impl Display for ScoreReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: f32 = self.0.values().sum();
        for (metric, score) in &self.0 {
            write!(f, "{}: {:.3} ", metric, score)?;
        }
        write!(f, "Total: {:.3}", total)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        hash::{DefaultHasher, Hash, Hasher},
        net::{IpAddr, Ipv4Addr},
    };

    use scion_proto::{
        address::{Asn, EndhostAddr, Isd, IsdAsn},
        path::{Path, test_builder::TestPathBuilder},
    };

    use super::*;
    use crate::path::types::PathManagerPath;

    pub const SRC_ADDR: EndhostAddr = EndhostAddr::new(
        IsdAsn::new(Isd(1), Asn(1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );
    pub const DST_ADDR: EndhostAddr = EndhostAddr::new(
        IsdAsn::new(Isd(2), Asn(1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    );

    pub fn path(hop_count: u16, timestamp: u32, exp_units: u8, asn_seed: u32) -> Path {
        let mut builder = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
            .using_info_timestamp(timestamp)
            .with_hop_expiry(exp_units)
            .up();

        builder = builder.add_hop(0, 1);

        for cnt in 0..hop_count {
            let mut hash = DefaultHasher::new();
            asn_seed.hash(&mut hash);
            cnt.hash(&mut hash);
            let hash = hash.finish() as u32;

            builder = builder.with_asn(hash).add_hop(cnt + 1, cnt + 2);
        }

        builder = builder.add_hop(1, 0);

        builder.build(timestamp).path()
    }

    struct Simulation {
        paths: Vec<PathManagerPath>,
        current_path_index: usize,
        scoring: PathScorer,
        // (sec since start, action)
        actions: Vec<(usize, SimulationAction)>,
        switch_threshold: f32,
    }

    enum SimulationAction {
        UpdateReliability { path_index: usize, score: Score },
        Evaluate,
    }

    impl Simulation {
        fn new(
            scoring: PathScorer,
            initial_paths: Vec<PathManagerPath>,
            switch_threshold: f32,
        ) -> Self {
            Self {
                paths: initial_paths,
                current_path_index: 0,
                scoring,
                actions: vec![],
                switch_threshold,
            }
        }

        fn add_step(self, time: usize, action: SimulationAction) -> Self {
            let mut sim = self;
            sim.actions.push((time, action));
            sim
        }

        fn run(&mut self) {
            let actions = std::mem::take(&mut self.actions);
            const BASE_TIME: SystemTime = SystemTime::UNIX_EPOCH;
            for (time_delta, action) in actions.into_iter() {
                println!("(Time +{}s) -------------------", time_delta);
                let timestamp = BASE_TIME + std::time::Duration::from_secs(time_delta as u64);
                match action {
                    SimulationAction::UpdateReliability { path_index, score } => {
                        println!(
                            "Updating reliability of path {} to score {:.3}",
                            path_index,
                            score.value(),
                        );
                        let path = &mut self.paths[path_index];
                        path.reliability.update(score, timestamp);
                        self.maybe_switch_path(timestamp);
                    }
                    SimulationAction::Evaluate => {
                        println!("Evaluating paths");
                        self.maybe_switch_path(timestamp);
                    }
                }
                println!("-------------------------------");
                self.print_all(timestamp);
                println!("-------------------------------");
            }
        }

        fn maybe_switch_path(&mut self, now: SystemTime) {
            let best_path_index = self.best_path_idx(now);
            let current_path = &self.paths[self.current_path_index];
            let current_score = self.scoring.score(current_path, now);

            let best_path = &self.paths[best_path_index];
            let best_score = self.scoring.score(best_path, now);

            let diff = best_score - current_score;

            if best_path_index == self.current_path_index {
                println!(
                    "Staying on current path {} (score {:.3}) is best path",
                    self.current_path_index, current_score,
                );
                return;
            }

            if diff > self.switch_threshold {
                println!(
                    "Switching from path {} (score {:.3}) to path {} (score {:.3})",
                    self.current_path_index, current_score, best_path_index, best_score
                );
                println!("New path: {}", self.scoring.score_report(best_path, now));
                println!("Old path: {}", self.scoring.score_report(current_path, now));

                self.current_path_index = best_path_index;
            } else {
                println!(
                    "Staying on current path {} (score {:.3}), best path {} (score {:.3}) diff {:.3} below threshold {:.3}",
                    self.current_path_index,
                    current_score,
                    best_path_index,
                    best_score,
                    diff,
                    self.switch_threshold
                );
            }
        }

        fn print_all(&self, now: SystemTime) {
            let mut sorted = self.paths.iter().enumerate().collect::<Vec<_>>();
            sorted.sort_by(|(_, a), (_, b)| {
                let score_a = self.scoring.score(a, now);
                let score_b = self.scoring.score(b, now);
                score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
            });

            for (idx, path) in sorted.iter() {
                println!("Path {}: {}", idx, self.scoring.score_report(path, now));
            }
        }

        fn best_path_idx(&self, now: SystemTime) -> usize {
            self.paths
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    let score_a = self.scoring.score(a, now);
                    let score_b = self.scoring.score(b, now);
                    score_a.partial_cmp(&score_b).unwrap_or(Ordering::Equal)
                })
                .unwrap()
                .0
        }
    }

    #[test]
    #[ignore = "Simulation test for manual inspection"]
    fn simulation() {
        // Create some sample paths with different lengths and reliability scores.
        /// Score differences after which we switch preference between two paths.
        const SWITCH_THRESHOLD: f32 = 0.4;

        let paths: Vec<_> = (1..=10)
            .map(|len| {
                let path = path(len, 1000, 100, len as u32);
                PathManagerPath::new(path)
            })
            .collect();

        let scoring = PathScorer::new()
            .with_scorer(PathReliabilityScorer, 1.0)
            .with_scorer(PathLengthScorer, 0.125);

        use SimulationAction::*;
        Simulation::new(scoring, paths, SWITCH_THRESHOLD)
            .add_step(0, Evaluate)
            .add_step(
                10,
                UpdateReliability {
                    path_index: 0,
                    score: Score::new_clamped(-0.5),
                },
            )
            .add_step(
                20,
                UpdateReliability {
                    path_index: 5,
                    score: Score::new_clamped(0.5),
                },
            )
            .add_step(30, Evaluate)
            .add_step(60, Evaluate)
            .add_step(600, Evaluate)
            .add_step(1200, Evaluate)
            .run();
    }
}
