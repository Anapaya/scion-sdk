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

//! Listing paths at an AS

use bytes::Bytes;
use scion_proto::{
    address::IsdAsn,
    path::{Path, combinator::combine},
};

use crate::network::scion::{segment::registry::SegmentRegistry, topology::ScionTopology};

impl SegmentRegistry {
    // TODO: once sciparse is the norm, this should return sciparse paths instead of scion_proto
    // paths

    /// Returns valid Paths from `src` to `dst` as raw SCION packets, if they exist.
    ///
    /// ### Parameters
    /// - `src`: Source ISD-AS for the path lookup.
    /// - `dst`: Destination ISD-AS for the path lookup.
    /// - `valid_after`: Returned paths are valid after this timestamp.
    /// - `topo`: The SCION topology to use for path construction.
    pub fn paths(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        valid_after: chrono::DateTime<chrono::Utc>,
        topo: &ScionTopology,
    ) -> anyhow::Result<Vec<Path<Bytes>>> {
        let segments = self.endhost_list_segments(src.into(), src.into(), dst.into())?;

        let (core_segments, non_core_segments) = {
            let sciparse_segments = segments.into_path_segments(topo, valid_after, 0, 255)?;

            (
                sciparse_segments
                    .core
                    .into_iter()
                    .map(|seg| seg.into())
                    .collect(),
                sciparse_segments
                    .down
                    .into_iter()
                    .chain(sciparse_segments.up)
                    .map(|seg| seg.into())
                    .collect(),
            )
        };

        Ok(combine(src, dst, core_segments, non_core_segments))
    }
}
