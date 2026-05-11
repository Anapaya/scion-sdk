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
//! Listing segments at a Core AS

use anyhow::{Context, bail};
use sciparse::identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn};

use crate::network::scion::segment::{model::LinkSegment, registry::SegmentRegistry};

// Reference: https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/control/segreq/authoritative.go#L37
impl SegmentRegistry {
    /// Authoritative Lists segments between src_as and dst_as at a Core AS
    ///
    /// `local_as` is the as Handling the request
    pub fn core_list_segments(
        &self,
        local: IsdAsn,
        src_as: IsdAsn,
        dst_as: IsdAsn,
    ) -> anyhow::Result<Vec<&LinkSegment>> {
        let core_store = self.core_segments();
        let isd_store = self
            .isd_segments(&local.isd().into())
            .context("missing ISD store for this AS")?;

        if !core_store.is_known_as(local.into()) {
            bail!("only core ASes can use this function");
        }

        let query_type =
            Query::classify(local, src_as, dst_as, core_store.is_known_as(dst_as.into()))?;

        tracing::debug!(
            ?local,
            ?src_as,
            ?dst_as,
            query_type = ?query_type,
            "Listing segments"
        );

        let res: Vec<&LinkSegment> = match query_type {
            Query::Core(dst_asn) => {
                core_store
                    .segments(local.into(), dst_asn.into())
                    .iter()
                    .by_ref()
                    .collect()
            }
            Query::CoreWildcard(isd) => {
                core_store
                    .segments_by_start_as(local.into())
                    .iter()
                    .filter(|s| s.bucket.leaf_as.isd() == isd.into())
                    .filter_map(|s| core_store.segment(s))
                    .collect()
            }
            Query::Down(dst_asn) => {
                isd_store
                    .segments(local.into(), IsdAsn::new(local.isd(), dst_asn).into())
                    .iter()
                    .by_ref()
                    .collect()
            }
        };

        tracing::info!(
            ?local,
            ?src_as,
            ?dst_as,
            segment_count = res.len(),
            "Resolved segments"
        );

        #[cfg(debug_assertions)]
        {
            for segment in &res {
                tracing::trace!(%segment, "Segment details");
            }
        }

        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Query {
    // Specific AS in our ISD
    Down(Asn),
    // Specific Core AS
    Core(IsdAsn),
    // Any Core AS in a specific ISD
    CoreWildcard(Isd),
}

impl Query {
    pub fn classify(
        local: IsdAsn,
        src: IsdAsn,
        dst: IsdAsn,
        dst_is_core: bool,
    ) -> anyhow::Result<Query> {
        if local != src {
            bail!(
                "this core must be the source for the request: {} != {}",
                local,
                src
            );
        };

        if dst.isd() == Isd::WILDCARD {
            bail!("destination ISD cannot be a wildcard");
        }

        match (dst.is_wildcard(), dst_is_core) {
            (true, true) => Ok(Query::CoreWildcard(dst.isd())),
            (true, false) => Ok(Query::CoreWildcard(dst.isd())), /* Wildcard is always a */
            // core AS
            (false, true) => Ok(Query::Core(dst)),
            (false, false) => Ok(Query::Down(dst.asn())),
        }
    }
}
