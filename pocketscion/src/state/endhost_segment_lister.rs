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
//! GRPC handler for listing segments

use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::Utc;
use endhost_api_models::{SegmentsDiscovery, SegmentsError};
use sciparse::{
    identifier::isd_asn::IsdAsn,
    segment::{Segments, SegmentsPage},
};

use crate::state::SharedPocketScionState;

/// GRPC handler for listing segments
///
/// This is scoped per Endhost API
pub struct StateEndhostSegmentLister {
    app_state: SharedPocketScionState,
    /// Valid local ASes of this segment lister
    /// If None, the segment lister will list segments from any AS
    local_ases: BTreeSet<IsdAsn>,
}
impl StateEndhostSegmentLister {
    /// Creates a new segment lister
    ///
    /// ### Parameters
    /// - `app_state` : The shared pocket SCION state
    /// - `local_ases`: The local ASes of this segment lister. Only segments from these ASes will be
    ///   listed.
    pub fn new(
        app_state: SharedPocketScionState,
        local_ases: BTreeSet<scion_proto::address::IsdAsn>,
    ) -> Self {
        Self {
            app_state,
            local_ases: local_ases.into_iter().map(Into::into).collect(),
        }
    }
}

#[async_trait]
impl SegmentsDiscovery for StateEndhostSegmentLister {
    async fn list_segments(
        &self,
        src: sciparse::identifier::isd_asn::IsdAsn,
        dst: sciparse::identifier::isd_asn::IsdAsn,
        _page_size: i32,
        _page_token: String,
    ) -> Result<SegmentsPage, SegmentsError> {
        let state_guard = self.app_state.system_state.read().unwrap();
        let segments = &state_guard.segment_registry;

        // Select correct local as
        let Some(local_as) = self.local_ases.iter().find(|ia| **ia == src) else {
            return Err(SegmentsError::InvalidArgument(
                format!(
                    "Can't list segments from IsdAs '{src}', allowed are {}",
                    self.local_ases
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                )
                .into(),
            ));
        };

        let resolved = match segments.endhost_list_segments(*local_as, src, dst) {
            Ok(segments) => segments,
            Err(e) => {
                tracing::error!(error = %e, "Failed to resolve segments");
                return Err(SegmentsError::InternalError(e.to_string().into()));
            }
        };

        //segment_id IRL is a random value
        let segment_id = (src.0 ^ (dst.0) << 8) as u16;

        let segments = resolved
            .into_path_segments(&state_guard.topology, Utc::now(), segment_id, 255)
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to convert segments");
                SegmentsError::InternalError(e.to_string().into())
            })?;

        Ok(SegmentsPage {
            segments: Segments {
                up_segments: segments.up,
                down_segments: segments.down,
                core_segments: segments.core,
            },
            next_page_token: "".to_string(),
        })
    }
}
