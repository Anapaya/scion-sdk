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
//! Listing segments at a SNAP

use anyhow::bail;
use chrono::{DateTime, Utc};
use scion_proto::{
    address::IsdAsn,
    control_plane::list_segment_plan::{CoreHint, Dst, ListSegmentPlan, Src},
    path::PathSegment,
};

use crate::network::scion::{
    segment::{model::LinkSegment, registry::SegmentRegistry},
    topology::ScionTopology,
};

impl SegmentRegistry {
    /// Lists segments between src_as and dst_as at an Endhost API
    ///
    /// `local` is the AS handling the request
    pub fn endhost_list_segments(
        &self,
        local: IsdAsn,
        src_as: IsdAsn,
        dst_as: IsdAsn,
    ) -> anyhow::Result<SnapListSegmentsOutput<'_>> {
        let src = Src::new(src_as, self.core_segments().is_known_as(src_as))?;
        let dst = Dst::new(dst_as, self.core_segments().is_known_as(dst_as));

        let src_cores = self
            .core_segments()
            .iter_known_ases()
            .filter(|a| a.isd() == src.isd())
            .collect::<Vec<_>>();

        let core_hint = match src_cores.len() {
            0 => {
                bail!(
                    "There are no core ASes in ISD {} - can't list segments",
                    src_as.isd()
                )
            }
            1 => CoreHint::Single(*src_cores[0]),
            _ => CoreHint::Multiple,
        };

        let req = ListSegmentPlan::new(src, core_hint, dst)?;

        tracing::debug!(
            ?local,
            ?src_as,
            ?dst_as,
            plan = ?req,
            "listing segments"
        );

        let mut res = SnapListSegmentsOutput::empty();

        if let Some((src, dst)) = req.up {
            res.up = self.non_core_list_segments(local, src, dst)?;
        }

        if let Some((src, dst)) = req.core {
            res.core = self.non_core_list_segments(local, src, dst)?;
        }

        if let Some((src, dst)) = req.down {
            res.down = self.non_core_list_segments(local, src, dst)?;
        }

        tracing::debug!(
            ?local,
            ?src_as,
            ?dst_as,
            segments = %res,
            "fetched segments"
        );

        #[cfg(debug_assertions)]
        {
            for segment in &res.core {
                tracing::trace!(%segment, segment_type = "Core", "Segment details");
            }
            for segment in &res.up {
                tracing::trace!(%segment, segment_type = "Up", "Segment details");
            }
            for segment in &res.down {
                tracing::trace!(%segment, segment_type = "Down", "Segment details");
            }
        }

        Ok(res)
    }
}

/// Generic Output of Snap List Segments
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapListSegmentsOutput<'store> {
    pub(crate) up: Vec<&'store LinkSegment>,
    pub(crate) core: Vec<&'store LinkSegment>,
    pub(crate) down: Vec<&'store LinkSegment>,
}

impl std::fmt::Display for SnapListSegmentsOutput<'_> {
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

impl SnapListSegmentsOutput<'_> {
    /// Creates an empty list of segments.
    pub fn empty() -> Self {
        SnapListSegmentsOutput {
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

    /// Converts the SCION topology into path segments.
    pub fn into_path_segments(
        self,
        topo: &ScionTopology,
        timestamp: DateTime<Utc>,
        segment_id: u16,
        hop_entry_expiry: u8,
    ) -> anyhow::Result<SnapListPathSegments> {
        let up = self
            .up
            .into_iter()
            .map(|segment| segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let core = self
            .core
            .into_iter()
            .map(|segment| segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let down = self
            .down
            .into_iter()
            .map(|segment| segment.to_path_segment(topo, timestamp, segment_id, hop_entry_expiry))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(SnapListPathSegments {
            expire_after: timestamp + chrono::Duration::seconds(hop_entry_expiry as i64),
            up,
            core,
            down,
        })
    }
}

/// Realised path Segments
pub struct SnapListPathSegments {
    #[allow(unused)]
    pub(crate) expire_after: DateTime<Utc>,
    pub(crate) up: Vec<PathSegment>,
    pub(crate) core: Vec<PathSegment>,
    pub(crate) down: Vec<PathSegment>,
}
impl SnapListPathSegments {
    /// Iterator over all path segments.
    pub fn iter_all(&self) -> impl Iterator<Item = &PathSegment> {
        self.up
            .iter()
            .chain(self.core.iter())
            .chain(self.down.iter())
    }

    /// Iterator over all core segments.
    pub fn iter_cores(&self) -> impl Iterator<Item = &PathSegment> {
        self.core.iter()
    }

    /// Iterator over all non-core segments.
    pub fn iter_non_cores(&self) -> impl Iterator<Item = &PathSegment> {
        self.up.iter().chain(self.down.iter())
    }
}

#[cfg(test)]
mod test {

    use std::{collections::HashSet, panic};

    use super::*;
    use crate::network::scion::{
        topology::{FastTopologyLookup, ScionLinkType},
        util::test_helper::{parse_segment, test_topology},
    };

    #[test_log::test]
    fn should_list_up_segments() {
        // NonAS to Core
        Test::new("2-2", "2-1").expect(ExpectedSegments {
            up: vec!["2-1#2 -> 2-2#3;"],
            core: vec![],
            down: vec![],
        });

        Test::new("2-3", "2-1").expect(ExpectedSegments {
            up: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
            core: vec![],
            down: vec![],
        });
    }

    #[test_log::test]
    fn should_list_down_segments() {
        // Core to NonAS
        Test::new("2-1", "2-21").expect(ExpectedSegments {
            up: vec![],
            core: vec![],
            down: vec!["2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;"],
        });
        Test::new("2-1", "2-3").expect(ExpectedSegments {
            up: vec![],
            core: vec![],
            down: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
        });
    }

    #[test_log::test]
    fn should_list_core_segments() {
        // Core to Core
        Test::new("1-21", "2-1").expect(ExpectedSegments {
            up: vec![],
            core: vec![
                "1-21#17 -> 1-1#32;1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-21#23 -> 2-1#24;",
            ],
            down: vec![],
        });

        Test::new("1-1", "2-1").expect(ExpectedSegments {
            up: vec![],
            core: vec![
                "1-1#5 -> 1-11#6;1-11#15 -> 1-21#22;1-21#23 -> 2-1#24;",
                "1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#23 -> 2-1#24;",
            ],
            down: vec![],
        });
    }

    #[test_log::test]
    fn should_list_core_down_segments() {
        // Core to NonAS
        Test::new("1-21", "2-2").expect(ExpectedSegments {
            up: vec![],
            core: vec![
                "1-21#17 -> 1-1#32;1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-21#23 -> 2-1#24;",
            ],
            down: vec!["2-1#2 -> 2-2#3;"],
        });

        Test::new("1-1", "2-3").expect(ExpectedSegments {
            up: vec![],
            core: vec![
                "1-1#5 -> 1-11#6;1-11#15 -> 1-21#22;1-21#23 -> 2-1#24;",
                "1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#23 -> 2-1#24;",
            ],
            down: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
        });
    }

    #[test_log::test]
    fn should_list_up_core_segments() {
        // NonAS to Core to Core
        Test::new("2-2", "1-21").expect(ExpectedSegments {
            up: vec!["2-1#2 -> 2-2#3;"],
            core: vec![
                "2-1#1 -> 1-11#23;1-11#6 -> 1-1#5;1-1#32 -> 1-21#17;",
                "2-1#1 -> 1-11#23;1-11#15 -> 1-21#22;",
                "2-1#24 -> 1-21#23;",
            ],
            down: vec![],
        });

        Test::new("2-3", "1-1").expect(ExpectedSegments {
            up: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
            core: vec![
                "2-1#1 -> 1-11#23;1-11#6 -> 1-1#5;",
                "2-1#1 -> 1-11#23;1-11#15 -> 1-21#22;1-21#17 -> 1-1#32;",
                "2-1#24 -> 1-21#23;1-21#17 -> 1-1#32;",
                "2-1#24 -> 1-21#23;1-21#22 -> 1-11#15;1-11#6 -> 1-1#5;",
            ],
            down: vec![],
        });
    }

    #[test_log::test]
    fn should_list_up_down_segments() {
        // NonAS to Core to NonAS - single Core
        Test::new("2-3", "2-21").expect(ExpectedSegments {
            up: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
            core: vec![],
            down: vec!["2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;"],
        });
        // No more complex case available
    }

    #[test_log::test]
    fn should_list_up_core_down_segments() {
        // NonCore to Core to Core`to NonCore
        Test::new("2-2", "1-2").expect(ExpectedSegments {
            up: vec!["2-1#2 -> 2-2#3;"],
            core: vec![
                "2-1#1 -> 1-11#23;1-11#6 -> 1-1#5;1-1#32 -> 1-21#17;",
                "2-1#1 -> 1-11#23;1-11#15 -> 1-21#22;",
                "2-1#24 -> 1-21#23;",
                "2-1#1 -> 1-11#23;1-11#6 -> 1-1#5;",
                "2-1#1 -> 1-11#23;1-11#15 -> 1-21#22;1-21#17 -> 1-1#32;",
                "2-1#24 -> 1-21#23;1-21#17 -> 1-1#32;",
                "2-1#24 -> 1-21#23;1-21#22 -> 1-11#15;1-11#6 -> 1-1#5;",
                "2-1#1 -> 1-11#23;",
                "2-1#24 -> 1-21#23;1-21#17 -> 1-1#32;1-1#5 -> 1-11#6;",
                "2-1#24 -> 1-21#23;1-21#22 -> 1-11#15;",
            ],
            down: vec!["1-1#1 -> 1-2#2;", "1-11#7 -> 1-12#8;1-12#12 -> 1-2#11;"],
        });

        Test::new("1-4", "2-3").expect(ExpectedSegments {
            up: vec![
                "1-1#1 -> 1-2#2;1-2#3 -> 1-3#4;1-3#15 -> 1-4#16;",
                "1-1#1 -> 1-2#2;1-2#17 -> 1-4#18;",
                "1-11#7 -> 1-12#8;1-12#12 -> 1-2#11;1-2#3 -> 1-3#4;1-3#15 -> 1-4#16;",
                "1-11#7 -> 1-12#8;1-12#12 -> 1-2#11;1-2#17 -> 1-4#18;",
                "1-11#7 -> 1-12#8;1-12#9 -> 1-3#10;1-3#15 -> 1-4#16;",
                "1-11#7 -> 1-12#8;1-12#19 -> 1-4#20;",
            ],
            core: vec![
                "1-1#5 -> 1-11#6;1-11#15 -> 1-21#22;1-21#23 -> 2-1#24;",
                "1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-1#32 -> 1-21#17;1-21#23 -> 2-1#24;",
                "1-21#17 -> 1-1#32;1-1#5 -> 1-11#6;1-11#23 -> 2-1#1;",
                "1-21#22 -> 1-11#15;1-11#23 -> 2-1#1;",
                "1-21#23 -> 2-1#24;",
                "1-11#6 -> 1-1#5;1-1#32 -> 1-21#17;1-21#23 -> 2-1#24;",
                "1-11#15 -> 1-21#22;1-21#23 -> 2-1#24;",
                "1-11#23 -> 2-1#1;",
            ],
            down: vec![
                "2-1#2 -> 2-2#3;2-2#4 -> 2-3#5;",
                "2-1#2 -> 2-2#3;2-2#52 -> 2-21#2;2-21#7 -> 2-3#6;",
            ],
        });
    }

    struct Test {
        src: IsdAsn,
        dst: IsdAsn,
    }

    impl Test {
        fn new(src: &str, dst: &str) -> Self {
            let src = src.parse().unwrap();
            let dst = dst.parse().unwrap();
            Self { src, dst }
        }

        fn print_test_statement(&self, segments: &SnapListSegmentsOutput) {
            let up = segments
                .up
                .iter()
                .map(|s| format!("\"{s}\","))
                .collect::<Vec<_>>();
            let core = segments
                .core
                .iter()
                .map(|s| format!("\"{s}\","))
                .collect::<Vec<_>>();
            let down = segments
                .down
                .iter()
                .map(|s| format!("\"{s}\","))
                .collect::<Vec<_>>();

            println!(
                "Test::new(\"{}\", \"{}\").expect(ExpectedSegments {{ up: vec![{}], core: vec![{}], down: vec![{}] }});",
                self.src,
                self.dst,
                up.join(""),
                core.join(""),
                down.join("")
            );
        }

        fn expect(self, expected: ExpectedSegments) {
            let topo = test_topology().unwrap();
            let topo_lookup = FastTopologyLookup::new(&topo);
            let segment_store = SegmentRegistry::new(&topo_lookup);

            let segments = segment_store
                .endhost_list_segments(self.src, self.src, self.dst)
                .expect("Failed to list segments");

            let result = expected.check(&segments);

            match result {
                Ok(_) => println!("Test for {} -> {} passed", self.src, self.dst),
                Err(err) => {
                    println!(
                        "Test for {} -> {} failed - Error: {}",
                        self.src, self.dst, err
                    );
                    println!("If topology changed, maybe update the test:");
                    self.print_test_statement(&segments);

                    panic!("Test failed");
                }
            }
        }
    }

    #[derive(Debug, Default)]
    struct ExpectedSegments {
        up: Vec<&'static str>,
        core: Vec<&'static str>,
        down: Vec<&'static str>,
    }
    impl ExpectedSegments {
        fn check(&self, segments: &SnapListSegmentsOutput) -> anyhow::Result<()> {
            let up = self
                .up
                .iter()
                .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap())
                .collect::<HashSet<_>>();

            let core = self
                .core
                .iter()
                .map(|s| parse_segment(s, ScionLinkType::Core).unwrap())
                .collect::<Vec<_>>();

            let down = self
                .down
                .iter()
                .map(|s| parse_segment(s, ScionLinkType::Parent).unwrap())
                .collect::<Vec<_>>();

            for segment in &segments.up {
                if !up.contains(segment) {
                    bail!("Segment not found in expected up segments: {}", segment);
                }
            }

            if segments.up.len() != up.len() {
                bail!(
                    "Up segments count mismatch: expected {}, got {}",
                    up.len(),
                    segments.up.len()
                );
            }

            for segment in &segments.core {
                if !core.contains(segment) {
                    bail!("Segment not found in expected core segments: {}", segment);
                }
            }

            if segments.core.len() != core.len() {
                bail!(
                    "Core segments count mismatch: expected {}, got {}",
                    core.len(),
                    segments.core.len()
                );
            }

            for segment in &segments.down {
                if !down.contains(segment) {
                    bail!("Segment not found in expected down segments: {}", segment);
                }
            }

            if segments.down.len() != down.len() {
                bail!(
                    "Down segments count mismatch: expected {}, got {}",
                    down.len(),
                    segments.down.len()
                );
            }

            Ok(())
        }
    }
}
