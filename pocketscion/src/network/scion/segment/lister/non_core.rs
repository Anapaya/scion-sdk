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
//! Listing segments at a Non-Core AS

use anyhow::{Context, bail};
use sciparse::identifier::isd_asn::IsdAsn;

use crate::network::scion::segment::{
    lister::model::{QueryTarget, Scope},
    model::LinkSegment,
    registry::SegmentRegistry,
};

// Reference: https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/control/segreq/forwarder.go#L41
impl SegmentRegistry {
    /// Forwarding Lists segments between src_as and dst_as at a Non-Core AS
    ///
    /// `local` is the as Handling the request
    pub fn non_core_list_segments(
        &self,
        local: IsdAsn,
        src_as: IsdAsn,
        dst_as: IsdAsn,
    ) -> anyhow::Result<Vec<&LinkSegment>> {
        let core_store = self.core_segments();

        let src_is_core = core_store.is_known_as(src_as.into());
        let dst_is_core = core_store.is_known_as(dst_as.into());

        let src = QueryTarget::new(src_as, src_is_core).context("query source is invalid")?;
        let dst = QueryTarget::new(dst_as, dst_is_core).context("query destination is invalid")?;

        let query = classify_query(local, src, dst)?;

        tracing::debug!(
            ?local,
            ?src_as,
            ?dst_as,
            query = ?query,
            "Forwarding list segments"
        );

        let res: Result<Vec<&LinkSegment>, anyhow::Error> = match query {
            Query::Core(Scope::One(src), dst) => forward_request(self, src, src, dst.ias()),
            Query::Core(Scope::Wildcard(isd), dst) => {
                let isd_cores = core_store
                    .iter_known_ases()
                    .filter(|&ias| ias.isd() == isd.into())
                    .copied();

                let mut res = Vec::new();
                for core in isd_cores {
                    res.extend(forward_request(self, core.into(), core.into(), dst.ias())?);
                }

                Ok(res)
            }

            Query::Down(Scope::One(src), dst) => forward_request(self, src, src, dst),
            Query::Down(Scope::Wildcard(src), dst) => {
                let isd_cores = core_store
                    .iter_known_ases()
                    .filter(|&ias| ias.isd() == src.into())
                    .copied();

                let mut res = Vec::new();
                for core in isd_cores {
                    res.extend(forward_request(self, core.into(), core.into(), dst)?);
                }

                Ok(res)
            }

            // Up queries are just Down queries with us as the destination
            Query::Up(Scope::One(dst)) => forward_request(self, dst, dst, local),
            Query::Up(Scope::Wildcard(isd)) => {
                let isd_core_ases = core_store
                    .iter_known_ases()
                    .filter(|&ias| ias.isd() == isd.into())
                    .copied();

                let mut res = Vec::new();
                for core in isd_core_ases {
                    res.extend(forward_request(self, core.into(), core.into(), local)?);
                }

                Ok(res)
            }
        };

        let res = res.with_context(|| format!("error satisfying query: {query:?}"))?;

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

        return Ok(res);

        /// Simulates a core lookup
        fn forward_request(
            this: &SegmentRegistry,
            recipient: IsdAsn,
            src: IsdAsn,
            dst: IsdAsn,
        ) -> anyhow::Result<Vec<&LinkSegment>> {
            this.core_list_segments(recipient, src, dst)
                .with_context(|| {
                    format!(
                        "error fowarding list request from {src} to {dst} at processing AS {recipient}"
                    )
                })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Query {
    // Core to Core
    Core(Scope, Scope),
    // Core to Down
    Down(Scope, IsdAsn),
    // From Current AS to Core
    Up(Scope),
}

fn classify_query(this_as: IsdAsn, src: QueryTarget, dst: QueryTarget) -> anyhow::Result<Query> {
    if src.isd().is_wildcard() || dst.isd().is_wildcard() {
        bail!("ISD cannot be a Wildcard");
    }

    if dst.ias() == this_as {
        bail!("destination ISD-AS cannot be the source ISD-AS");
    }

    let res = match (src, dst) {
        // Core
        (QueryTarget::Core(src), QueryTarget::Core(dst)) => {
            if src.isd() != this_as.isd() {
                bail!("for core queries, source ISD must match own ISD");
            }
            Query::Core(src, dst)
        }

        // Down
        (QueryTarget::Core(src), QueryTarget::NonCore(dst)) => {
            if src.isd() != dst.isd() {
                bail!("for down queries, source ISD must match destination ISD");
            }

            Query::Down(src, dst)
        }

        // Up
        (QueryTarget::NonCore(src), QueryTarget::Core(dst)) => {
            if src != this_as {
                bail!("for up queries, src must be this AS");
            }
            if dst.isd() != this_as.isd() {
                bail!("for up queries, destination ISD must match own ISD");
            }

            Query::Up(dst)
        }

        // Invalid
        (QueryTarget::NonCore(_), QueryTarget::NonCore(_)) => {
            bail!("cannot list segments between non-core ASes {src:?} and {dst:?}");
        }
    };

    Ok(res)
}
