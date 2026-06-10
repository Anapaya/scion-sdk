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

use crate::network::scion::segment::{
    lister::types::ListSegmentsOutput, registry::SegmentRegistry,
};

// Reference: https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/control/segreq/authoritative.go#L37
impl SegmentRegistry {
    /// Authoritative Lists segments between src_as and dst_as at a Core AS
    ///
    /// `local_as` is the as Handling the request
    pub fn core_list_segments<'a>(
        &'a self,
        local: IsdAsn,
        src_as: IsdAsn,
        dst_as: IsdAsn,
    ) -> anyhow::Result<ListSegmentsOutput<'a>> {
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

        let res: ListSegmentsOutput = match query_type {
            // Core to Core query
            Query::Core(dst_asn) => {
                let segs = core_store
                    // Core segments are fetched in a reversed fashion, because they are assumed to
                    // be stored in the direction of propagation in the appliance implementation.
                    // In other words, we must return segments originated from `dst_asn`, and
                    // terminated at `local`.
                    .segments(dst_asn.into(), local.into())
                    .iter()
                    .by_ref()
                    .collect();

                ListSegmentsOutput {
                    up: vec![],
                    core: segs,
                    down: vec![],
                }
            }
            // Core to Wildcard Core query
            Query::CoreWildcard(isd) => {
                let segs = core_store
                    // Core segments are fetched in a reversed fashion, because they are assumed to
                    // be stored in the direction of propagation in the appliance implementation.
                    // In other words, we must return segments originated from any core AS and
                    // terminated at `local`.
                    .segments_by_end_as(local.into())
                    .iter()
                    .filter(|s| s.bucket.start_as.isd() == isd.into())
                    .filter_map(|s| core_store.segment(s))
                    .collect();

                ListSegmentsOutput {
                    up: vec![],
                    core: segs,
                    down: vec![],
                }
            }
            // Core to Down query
            Query::Down(dst_asn) => {
                let segs = isd_store
                    .segments(local.into(), IsdAsn::new(local.isd(), dst_asn).into())
                    .iter()
                    .by_ref()
                    .collect();

                ListSegmentsOutput {
                    up: vec![],
                    core: vec![],
                    down: segs,
                }
            }
        };

        tracing::info!(
            ?local,
            ?src_as,
            ?dst_as,
            res = %res,
            "Resolved segments"
        );

        #[cfg(debug_assertions)]
        {
            tracing::debug!("Segment details: \n {}", res.pretty_format());
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
