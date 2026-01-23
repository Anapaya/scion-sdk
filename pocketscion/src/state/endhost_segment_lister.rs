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
use endhost_api_models::PathDiscovery;
use scion_proto::{
    address::IsdAsn,
    path::{Segments, SegmentsError, SegmentsPage},
};
use snap_control::server::mock_segment_lister::MockSegmentLister;

use crate::state::SharedPocketScionState;

/// GRPC handler for listing segments
///
/// This is scoped per Endhost API
pub struct StateEndhostSegmentLister {
    app_state: SharedPocketScionState,
    fallback: MockSegmentLister,
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
    pub fn new(app_state: SharedPocketScionState, local_ases: BTreeSet<IsdAsn>) -> Self {
        Self {
            fallback: MockSegmentLister::default(),
            app_state,
            local_ases,
        }
    }
}

#[async_trait]
impl PathDiscovery for StateEndhostSegmentLister {
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        page_size: i32,
        page_token: String,
    ) -> Result<SegmentsPage, SegmentsError> {
        if !self.app_state.has_topology() {
            tracing::debug!("No topology available, falling back to mock segment lister");
            return self
                .fallback
                .list_segments(src, dst, page_size, page_token)
                .await;
        }

        let state_guard = self.app_state.system_state.read().unwrap();

        let Some(ref segments) = state_guard.topology_segments else {
            tracing::error!("Cannot list segments: topology store is missing");
            return Err(SegmentsError::InternalError(
                "missing topology store".to_string(),
            ));
        };

        // Select correct local as

        let Some(local_as) = self.local_ases.iter().find(|ia| **ia == src) else {
            return Err(SegmentsError::InvalidArgument(format!(
                "Can't list segments from IsdAs '{src}', allowed are {}",
                self.local_ases
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )));
        };

        let resolved = match segments.endhost_list_segments(*local_as, src, dst) {
            Ok(segments) => segments,
            Err(e) => {
                tracing::error!(error = %e, "Failed to resolve segments");
                return Err(SegmentsError::InternalError(e.to_string()));
            }
        };

        //segment_id IRL is a random value
        let segment_id = (src.0 ^ (dst.0) << 8) as u16;

        let segments = resolved
            .into_path_segments(
                state_guard
                    .topology
                    .as_ref()
                    .expect("Topology should be present"),
                Utc::now(),
                segment_id,
                255,
            )
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to convert segments");
                SegmentsError::InternalError(e.to_string())
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
