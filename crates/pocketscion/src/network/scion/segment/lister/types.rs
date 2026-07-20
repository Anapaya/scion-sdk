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

//! Segment listing types

use core::fmt;

use chrono::{DateTime, Utc};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sciparse::segment::SignedPathSegment;

use crate::network::scion::{segment::model::LinkSegment, topology::ScionTopology};

/// Generic Output of Snap List Segments
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSegmentsOutput<'store> {
    pub(crate) up: Vec<&'store LinkSegment>,
    pub(crate) core: Vec<&'store LinkSegment>,
    pub(crate) down: Vec<&'store LinkSegment>,
}

impl std::fmt::Display for ListSegmentsOutput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ResolvedSegments (up: {}, core: {}, down: {})",
            self.up.len(),
            self.core.len(),
            self.down.len()
        )
    }
}

impl ListSegmentsOutput<'_> {
    /// Creates an empty list of segments.
    pub fn empty() -> Self {
        ListSegmentsOutput {
            up: vec![],
            core: vec![],
            down: vec![],
        }
    }

    /// Iterator over all link segments.
    pub fn iter_all(&self) -> impl Iterator<Item = &LinkSegment> {
        self.up
            .iter()
            .chain(self.core.iter())
            .chain(self.down.iter())
            .copied()
    }

    /// Returns a new `ListSegmentsOutput` with the direction of the segments inverted (up <->
    /// down).
    pub fn inverted(self) -> Self {
        ListSegmentsOutput {
            up: self.down,
            core: self.core,
            down: self.up,
        }
    }

    /// Merges another `ListSegmentsOutput` into this one, combining their segments.
    pub fn extend(&mut self, other: Self) {
        self.up.extend(other.up);
        self.core.extend(other.core);
        self.down.extend(other.down);
    }

    /// Converts the SCION topology into path segments.
    pub fn into_path_segments(
        self,
        topo: &ScionTopology,
        timestamp: DateTime<Utc>,
        segment_id: u16,
        hop_entry_expiry: u8,
    ) -> anyhow::Result<ListPathSegments> {
        let up = self
            .up
            .par_iter()
            .with_min_len(10)
            .map(|segment| {
                segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry, false)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let core = self
            .core
            .par_iter()
            .with_min_len(10)
            .map(|segment| {
                segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry, false)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let down = self
            .down
            .par_iter()
            .with_min_len(10)
            .map(|segment| {
                segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry, false)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(ListPathSegments {
            expire_after: timestamp + chrono::Duration::seconds(hop_entry_expiry as i64),
            up,
            core,
            down,
        })
    }

    /// Returns a pretty formatter for this `ListSegmentsOutput`, which can be used to display
    /// detailed information about the segments.
    pub fn pretty_format(&self) -> ListSegmentsOutputPrettyFormat<'_> {
        ListSegmentsOutputPrettyFormat(self)
    }
}

/// A helper struct for pretty-printing the details of a `ListSegmentsOutput`.
pub struct ListSegmentsOutputPrettyFormat<'a>(&'a ListSegmentsOutput<'a>);
impl fmt::Display for ListSegmentsOutputPrettyFormat<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Up Segments:")?;
        for seg in &self.0.up {
            writeln!(f, "  {}", seg)?;
        }

        writeln!(f, "Core Segments:")?;
        for seg in &self.0.core {
            writeln!(f, "  {}", seg)?;
        }

        writeln!(f, "Down Segments:")?;
        for seg in &self.0.down {
            writeln!(f, "  {}", seg)?;
        }

        Ok(())
    }
}

/// Realised path Segments
pub struct ListPathSegments {
    #[allow(unused)]
    pub(crate) expire_after: DateTime<Utc>,
    pub(crate) up: Vec<SignedPathSegment>,
    pub(crate) core: Vec<SignedPathSegment>,
    pub(crate) down: Vec<SignedPathSegment>,
}
impl ListPathSegments {
    /// Iterator over all path segments.
    pub fn iter_all(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.up
            .iter()
            .chain(self.core.iter())
            .chain(self.down.iter())
    }

    /// Iterator over all core segments.
    pub fn iter_cores(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.core.iter()
    }

    /// Iterator over all non-core segments.
    pub fn iter_non_cores(&self) -> impl Iterator<Item = &SignedPathSegment> {
        self.up.iter().chain(self.down.iter())
    }
}
