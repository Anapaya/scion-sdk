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
//! Conversions between HSD API protobuf types and HSD API models.

use scion_proto::path::convert::segment::InvalidSegmentError;

use crate::hsd::api_service::v1::ListSegmentsResponse;

impl From<scion_proto::path::segment::Segments> for ListSegmentsResponse {
    fn from(segments: scion_proto::path::segment::Segments) -> Self {
        Self {
            up_segments: segments.up_segments.into_iter().map(Into::into).collect(),
            down_segments: segments.down_segments.into_iter().map(Into::into).collect(),
            core_segments: segments.core_segments.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<ListSegmentsResponse> for scion_proto::path::segment::Segments {
    type Error = InvalidSegmentError;
    fn try_from(response: ListSegmentsResponse) -> Result<Self, Self::Error> {
        let convert = |segs: Vec<_>| {
            segs.into_iter()
                .map(scion_proto::path::PathSegment::try_from)
                .collect::<Result<_, _>>()
        };
        Ok(scion_proto::path::segment::Segments {
            up_segments: convert(response.up_segments)?,
            down_segments: convert(response.down_segments)?,
            core_segments: convert(response.core_segments)?,
        })
    }
}
