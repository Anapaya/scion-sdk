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

use scion_proto::path::{Path, PathFingerprint};

use crate::path::manager::reliability::ReliabilityScore;

/// Entry in the path set cache.
#[derive(Debug)]
pub struct PathManagerPath {
    /// The underlying SCION path.
    pub path: Path,
    /// The fingerprint of the path.
    pub fingerprint: PathFingerprint,
    /// The reliability score of the path.
    pub reliability: ReliabilityScore,
}

impl PathManagerPath {
    /// Wrap a scion path with metadata
    pub fn new(path: Path) -> Self {
        let fingerprint = path.fingerprint().unwrap_or_else(|_| {
            // Local paths always succeed
            PathFingerprint::local(path.isd_asn.source)
        });

        Self {
            path,
            fingerprint,
            reliability: ReliabilityScore::new_with_time(SystemTime::now()),
        }
    }

    /// Get the underlying scion path
    pub fn scion_path(&self) -> &Path {
        &self.path
    }
}

impl From<&Path> for PathManagerPath {
    fn from(path: &Path) -> Self {
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
pub struct Score(f32);

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
        let value = match value.is_nan() {
            true => 0.0,
            false => value,
        };
        Score(value.clamp(-1.0, 1.0))
    }

    /// Returns the inner floating point value of the score.
    pub fn value(&self) -> f32 {
        self.0
    }
}
