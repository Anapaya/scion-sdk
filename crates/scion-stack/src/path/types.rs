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

//! Path Manager specific types.

use std::time::SystemTime;

use sciparse::path::ScionPath;

use crate::path::manager::reliability::ReliabilityScore;

/// Entry in the path set cache.
#[derive(Debug)]
pub(crate) struct PathManagerPath {
    /// The underlying SCION path.
    pub path: ScionPath,
    /// The reliability score of the path.
    pub reliability: ReliabilityScore,
}

impl PathManagerPath {
    /// Wrap a scion path with metadata
    pub fn new(path: ScionPath) -> Self {
        Self {
            path,
            reliability: ReliabilityScore::new_with_time(SystemTime::now()),
        }
    }

    /// Get the underlying scion path
    pub fn scion_path(&self) -> &ScionPath {
        &self.path
    }
}

impl From<&ScionPath> for PathManagerPath {
    fn from(path: &ScionPath) -> Self {
        Self::new(path.clone())
    }
}

/// A Score represents a floating point score for path ranking.
///
/// Higher scores indicate more preferred paths.
/// Lower scores indicate less preferred paths.
///
/// Scores are clamped between -1.0 and 1.0.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Score(f32);

impl Eq for Score {}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Score {
    /// Creates a new Score, clamping the value between -1.0 and 1.0.
    pub fn new_clamped(value: f32) -> Self {
        let value = if value.is_nan() { 0.0 } else { value };
        Score(value.clamp(-1.0, 1.0))
    }

    /// Returns the inner floating point value of the score.
    pub fn value(self) -> f32 {
        self.0
    }
}
