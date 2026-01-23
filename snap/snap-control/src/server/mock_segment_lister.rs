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
//! Mock segment lister for testing.

use endhost_api_models::PathDiscovery;
use scion_proto::{
    address::IsdAsn,
    path::{Segments, SegmentsError, SegmentsPage},
    test::graph::{Graph, default_graph},
};
use tonic::async_trait;

/// A mock segment lister that returns segments from the default test graph.
/// It only supports queries from 1-ff00:0:132 to 2-ff00:0:211 and back.
pub struct MockSegmentLister {
    graph: Graph,
    supported_ases: (IsdAsn, IsdAsn),
}

impl MockSegmentLister {
    pub(crate) fn new(graph: Graph) -> Self {
        Self {
            graph,
            supported_ases: (
                "1-ff00:0:132".parse().unwrap(),
                "2-ff00:0:212".parse().unwrap(),
            ),
        }
    }
}

impl Default for MockSegmentLister {
    fn default() -> Self {
        Self::new(default_graph().unwrap())
    }
}

#[async_trait]
impl PathDiscovery for MockSegmentLister {
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        _page_size: i32,
        _page_token: String,
    ) -> Result<scion_proto::path::SegmentsPage, scion_proto::path::SegmentsError> {
        if self.supported_ases != (src, dst) && self.supported_ases != (dst, src) {
            return Err(SegmentsError::InvalidArgument(format!(
                "Only queries from {} to {} and back are supported",
                self.supported_ases.0, self.supported_ases.1
            )));
        };

        Ok(SegmentsPage {
            segments: Segments {
                up_segments: vec![
                    self.graph
                        .beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                        .unwrap(),
                ],
                core_segments: vec![
                    self.graph
                        .beacon("2-ff00:0:210".parse().unwrap(), &[450, 502, 1])
                        .unwrap(),
                ],
                down_segments: vec![
                    self.graph
                        .beacon("2-ff00:0:210".parse().unwrap(), &[451, 2])
                        .unwrap(),
                ],
            },
            next_page_token: "".to_string(),
        })
    }
}
