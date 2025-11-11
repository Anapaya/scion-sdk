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
//! This module exports functions that allow combining SCION Path Segments into
//! end-to-end Paths. The main exported function is [combine] which serves the
//! same purpose as the `Combine`-method [1] of the SCION reference
//! implementation. The former also served as inspiration for this
//! implementation. Note, however, that we do not commit to maintaining a strict
//! equivalence between this implementation and the `Combine`-function [1].
//!
//! [1]: <https://github.com/scionproto/scion/blob/38e79c43faf38ebec719ac71fb65e1f814050e3b/private/path/combinator/combinator.go#L60>

use std::collections::HashMap;

use graph::number_of_hops;

use crate::{
    address::IsdAsn,
    path::{Path, PathFingerprint, PathSegment},
};

pub mod graph;

/// Finds all valid paths from `src` to `dst` that can be combined using the given core and
/// non-core segments using the number of hops as cost.
///
/// Core segments are segments between core ASes, non-core segments are all up and down segments,
/// the algorithm treats up and down segments symmetrically.
///
/// The resulting paths are sorted by cost, number of hops and filtered to remove paths with loops
/// and duplicates.
///
/// The algorithm is based on the scionproto go implementation.
pub fn combine(
    src: IsdAsn,
    dst: IsdAsn,
    cores: Vec<PathSegment>,
    non_cores: Vec<PathSegment>,
) -> Vec<Path> {
    combine_with_weight_fn(src, dst, cores, non_cores, number_of_hops)
}

/// Finds all valid paths from `src` to `dst` that can be combined using the given core and non-core
/// segments.
///
/// Core segments are segments between core ASes, non-core segments are all up and down segments,
/// the algorithm treats up and down segments symmetrically.
///
/// The weight function is used to calculate the cost using a segment given
/// the segment, the shortcut index and a boolean indicating if the segment is used towards a peer.
///
/// The resulting paths are sorted by cost, number of hops and filtered to remove paths with loops
/// and duplicates.
///
/// The algorithm is based on the scionproto go implementation.
pub fn combine_with_weight_fn(
    src: IsdAsn,
    dst: IsdAsn,
    cores: Vec<PathSegment>,
    non_cores: Vec<PathSegment>,
    weight_fn: impl Fn(&graph::InputSegment, u64, bool) -> u64,
) -> Vec<Path> {
    if src == dst {
        return vec![];
    }
    let mut graph = graph::MultiGraph::new(weight_fn);
    let segments = cores
        .iter()
        .map(graph::InputSegment::new_core)
        .chain(non_cores.iter().map(graph::InputSegment::new_non_core))
        .collect::<Vec<_>>();
    graph.add_segments(segments.as_slice());
    let solutions = graph.get_paths(src, dst);
    let paths = solutions
        .iter()
        .map(|s| s.path())
        .filter(|p| !has_loops(p))
        .collect();
    filter_duplicates(paths)
}

/// Returns true if the path has more than 2 interfaces from the same AS. I.e.
/// if it has a loop.
fn has_loops(path: &Path) -> bool {
    let mut ia_counts = HashMap::new();
    for i in path.metadata.as_ref().unwrap().interfaces.as_ref().unwrap() {
        *ia_counts.entry(i.isd_asn).or_insert(0) += 1;
    }
    ia_counts.values().any(|v| *v > 2)
}

/// filter_duplicates removes paths with identical sequences of path interfaces,
/// keeping only the one instance with latest expiry.
/// Duplicates can arise when multiple combinations of different path segments
/// result in the same "effective" path after applying short-cuts.
/// XXX(uniquefine): the duplicates could/should be avoided directly by reducing the
/// available options in the graph, as we could potentially create a large
/// number of duplicates in wide network topologies.
fn filter_duplicates(paths: Vec<Path>) -> Vec<Path> {
    // Store the index of the path with the latest expiry for every unique path fingerprint.
    let mut unique_paths: HashMap<PathFingerprint, usize> = HashMap::new();
    for (i, path) in paths.iter().enumerate() {
        let fingerprint = path.fingerprint().unwrap();
        if let Some(prev) = unique_paths.get(&fingerprint)
            && paths[*prev].metadata.as_ref().unwrap().expiration
                > path.metadata.as_ref().unwrap().expiration
        {
            continue;
        }
        unique_paths.insert(fingerprint, i);
    }
    let mut to_keep = unique_paths.into_values().collect::<Vec<_>>();
    to_keep.sort();
    to_keep.iter().map(|i| paths[*i].clone()).collect()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::{path::PathInterface, test::graph::default_graph};

    fn interfaces(intfs: &[&str]) -> Vec<PathInterface> {
        intfs
            .iter()
            .map(|i| PathInterface::from_str(i).unwrap())
            .collect()
    }

    struct TestCase {
        src: IsdAsn,
        dst: IsdAsn,
        cores: Vec<PathSegment>,
        non_cores: Vec<PathSegment>,
        expected_paths: Vec<Vec<PathInterface>>,
    }

    fn run_test(test_case: TestCase) {
        let paths = combine(
            test_case.src,
            test_case.dst,
            test_case.cores,
            test_case.non_cores,
        );
        assert_eq!(
            test_case.expected_paths,
            paths
                .iter()
                .map(|p| {
                    p.metadata
                        .as_ref()
                        .unwrap()
                        .interfaces
                        .as_ref()
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<_>>()
        );
    }

    /// Set the MTU for all ASes, links and peer links in the segment.
    fn set_mtus(segment: &mut PathSegment, mtu: u16) {
        for (i, as_entry) in segment.as_entries.iter_mut().enumerate() {
            as_entry.mtu = mtu as u32;
            if i != 0 {
                as_entry.hop_entry.ingress_mtu = mtu;
            }
            for peer_entry in as_entry.peer_entries.iter_mut() {
                peer_entry.peer_mtu = mtu;
            }
        }
    }

    // The test cases are based on the following graph, use
    // <https://mermaid.live> to visualize the graph.
    //
    // ```mermaid
    //     graph TD;
    // 1-ff00:0:120 -->|1->105| 1-ff00:0:130;
    // 1-ff00:0:120 -->|4->3| 1-ff00:0:121;
    // 1-ff00:0:120 -->|2->501| 2-ff00:0:220;
    // 1-ff00:0:120 -->|6->1| 1-ff00:0:110;
    // 1-ff00:0:120 -->|3->502| 2-ff00:0:220;
    // 1-ff00:0:120 -->|5->104| 1-ff00:0:111;
    // 2-ff00:0:222 -->|302->1| 2-ff00:0:221;
    // 2-ff00:0:222 -->|301->4| 2-ff00:0:211;
    // 1-ff00:0:121 -->|1->480,peer| 1-ff00:0:131;
    // 1-ff00:0:121 -->|4->100,peer| 1-ff00:0:111;
    // 1-ff00:0:121 -->|2->2| 1-ff00:0:122;
    // 1-ff00:0:110 -->|3->453| 2-ff00:0:210;
    // 1-ff00:0:110 -->|2->104| 1-ff00:0:130;
    // 1-ff00:0:112 -->|494->103| 1-ff00:0:111;
    // 1-ff00:0:112 -->|495->113| 1-ff00:0:130;
    // 1-ff00:0:122 -->|1->1,peer| 1-ff00:0:133;
    // 2-ff00:0:221 -->|3->1,peer| 2-ff00:0:211;
    // 2-ff00:0:221 -->|2->500| 2-ff00:0:220;
    // 2-ff00:0:212 -->|201->2| 2-ff00:0:211;
    // 2-ff00:0:212 -->|200->3| 2-ff00:0:211;
    // 1-ff00:0:130 -->|111->479| 1-ff00:0:131;
    // 1-ff00:0:130 -->|112->105| 1-ff00:0:111;
    // 2-ff00:0:220 -->|503->450| 2-ff00:0:210;
    // 2-ff00:0:211 -->|6->102,peer| 1-ff00:0:111;
    // 2-ff00:0:211 -->|7->451| 2-ff00:0:210;
    // 2-ff00:0:211 -->|5->101,peer| 1-ff00:0:111;
    // 2-ff00:0:211 -->|8->452| 2-ff00:0:210;
    // 1-ff00:0:131 -->|478->2| 1-ff00:0:132;
    // 1-ff00:0:133 -->|2->1| 1-ff00:0:132;
    // ```

    #[test_log::test]
    fn test_00_simple_up_core_down() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:111".parse().unwrap(),
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[5]).unwrap(),
            ],
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap()],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:131#479",
                "1-ff00:0:130#111",
                "1-ff00:0:130#105",
                "1-ff00:0:120#1",
                "1-ff00:0:120#5",
                "1-ff00:0:111#104",
            ])],
        });
    }

    #[test_log::test]
    fn test_01_simple_up_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:110".parse().unwrap(),
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
            ],
            cores: vec![g.beacon("1-ff00:0:110".parse().unwrap(), &[2]).unwrap()],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:131#479",
                "1-ff00:0:130#111",
                "1-ff00:0:130#104",
                "1-ff00:0:110#2",
            ])],
        });
    }

    #[test_log::test]
    fn test_02_simple_up_only() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:130".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
            ],
            expected_paths: vec![interfaces(&["1-ff00:0:131#479", "1-ff00:0:130#111"])],
        });
    }

    #[test_log::test]
    fn test_03_simple_core_down() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:130".parse().unwrap(),
            dst: "1-ff00:0:121".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap()],
            non_cores: vec![
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[4]).unwrap(),
            ],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:130#105",
                "1-ff00:0:120#1",
                "1-ff00:0:120#4",
                "1-ff00:0:121#3",
            ])],
        });
    }

    #[test_log::test]
    fn test_04_simple_down_only() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:130".parse().unwrap(),
            dst: "1-ff00:0:111".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // down segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[112]).unwrap(),
            ],
            expected_paths: vec![interfaces(&["1-ff00:0:130#112", "1-ff00:0:111#105"])],
        });
    }

    #[test_log::test]
    fn test_05_inverted_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:111".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:130".parse().unwrap(), &[105]).unwrap()],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[5]).unwrap(),
            ],
            // The behavior differs from the scionproto implementation. We do allow
            // inverted core segments and traverse them in the reverse direction setting cons_dir to
            // true.
            expected_paths: vec![interfaces(&[
                "1-ff00:0:131#479",
                "1-ff00:0:130#111",
                "1-ff00:0:130#105",
                "1-ff00:0:120#1",
                "1-ff00:0:120#5",
                "1-ff00:0:111#104",
            ])],
        });
    }

    #[test_log::test]
    fn test_06_simple_long_up_core_down() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "2-ff00:0:212".parse().unwrap(),
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
                // down segment
                g.beacon("2-ff00:0:210".parse().unwrap(), &[451, 2])
                    .unwrap(),
            ],
            cores: vec![
                g.beacon("2-ff00:0:210".parse().unwrap(), &[453, 2])
                    .unwrap(),
            ],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:132#2",
                "1-ff00:0:131#478",
                "1-ff00:0:131#479",
                "1-ff00:0:130#111",
                "1-ff00:0:130#104",
                "1-ff00:0:110#2",
                "1-ff00:0:110#3",
                "2-ff00:0:210#453",
                "2-ff00:0:210#451",
                "2-ff00:0:211#7",
                "2-ff00:0:211#2",
                "2-ff00:0:212#201",
            ])],
        });
    }

    #[test_log::test]
    fn test_07_missing_up() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "1-ff00:0:122".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[6, 2]).unwrap()],
            non_cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[4, 2]).unwrap()],
            expected_paths: vec![],
        });
    }

    #[test_log::test]
    fn test_08_missing_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "2-ff00:0:211".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
                // down segment
                g.beacon("2-ff00:0:210".parse().unwrap(), &[451]).unwrap(),
            ],
            expected_paths: vec![],
        });
    }

    #[test_log::test]
    fn test_09_missing_down() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "1-ff00:0:122".parse().unwrap(),
            cores: vec![
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
            ],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap(),
            ],
            expected_paths: vec![],
        });
    }

    #[test_log::test]
    fn test_10_simple_up_core_down_multiple_cores() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "1-ff00:0:112".parse().unwrap(),
            cores: vec![
                g.beacon("1-ff00:0:120".parse().unwrap(), &[6, 2]).unwrap(),
                g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap(),
            ],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[5, 103])
                    .unwrap(),
            ],
            expected_paths: vec![
                interfaces(&[
                    "1-ff00:0:132#2",
                    "1-ff00:0:131#478",
                    "1-ff00:0:131#479",
                    "1-ff00:0:130#111",
                    "1-ff00:0:130#105",
                    "1-ff00:0:120#1",
                    "1-ff00:0:120#5",
                    "1-ff00:0:111#104",
                    "1-ff00:0:111#103",
                    "1-ff00:0:112#494",
                ]),
                interfaces(&[
                    "1-ff00:0:132#2",
                    "1-ff00:0:131#478",
                    "1-ff00:0:131#479",
                    "1-ff00:0:130#111",
                    "1-ff00:0:130#104",
                    "1-ff00:0:110#2",
                    "1-ff00:0:110#1",
                    "1-ff00:0:120#6",
                    "1-ff00:0:120#5",
                    "1-ff00:0:111#104",
                    "1-ff00:0:111#103",
                    "1-ff00:0:112#494",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_11_shortcut_destination_on_path_going_up_vonly_hf_is_from_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:133".parse().unwrap(),
            dst: "1-ff00:0:131".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478, 1])
                    .unwrap(),
            ],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:133#2",
                "1-ff00:0:132#1",
                "1-ff00:0:132#2",
                "1-ff00:0:131#478",
            ])],
        });
    }

    #[test_log::test]
    fn test_12_shortcut_destination_on_path_going_up_vonly_hf_is_non_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:133".parse().unwrap(),
            dst: "1-ff00:0:132".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478, 1])
                    .unwrap(),
            ],
            expected_paths: vec![interfaces(&["1-ff00:0:133#2", "1-ff00:0:132#1"])],
        });
    }

    #[test_log::test]
    fn test_13_shortcut_destination_on_path_going_down_verify_hf_is_from_core() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:132".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // down segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
            ],
            expected_paths: vec![interfaces(&["1-ff00:0:131#478", "1-ff00:0:132#2"])],
        });
    }

    #[test_log::test]
    fn test_14_shortcut_common_upstream() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "2-ff00:0:212".parse().unwrap(),
            dst: "2-ff00:0:222".parse().unwrap(),
            cores: vec![],
            non_cores: vec![
                // up segment
                g.beacon("2-ff00:0:210".parse().unwrap(), &[452, 2])
                    .unwrap(),
                g.beacon("2-ff00:0:210".parse().unwrap(), &[452, 4])
                    .unwrap(),
            ],
            expected_paths: vec![interfaces(&[
                "2-ff00:0:212#201",
                "2-ff00:0:211#2",
                "2-ff00:0:211#4",
                "2-ff00:0:222#301",
            ])],
        });
    }

    #[test_log::test]
    fn test_15_go_through_peer() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "2-ff00:0:212".parse().unwrap(),
            dst: "2-ff00:0:222".parse().unwrap(),
            cores: vec![g.beacon("2-ff00:0:220".parse().unwrap(), &[503]).unwrap()],
            non_cores: vec![
                // up segment
                g.beacon("2-ff00:0:210".parse().unwrap(), &[452, 2])
                    .unwrap(),
                // down segment
                g.beacon("2-ff00:0:220".parse().unwrap(), &[500, 1])
                    .unwrap(),
            ],
            expected_paths: vec![
                interfaces(&[
                    "2-ff00:0:212#201",
                    "2-ff00:0:211#2",
                    "2-ff00:0:211#1",
                    "2-ff00:0:221#3",
                    "2-ff00:0:221#1",
                    "2-ff00:0:222#302",
                ]),
                interfaces(&[
                    "2-ff00:0:212#201",
                    "2-ff00:0:211#2",
                    "2-ff00:0:211#8",
                    "2-ff00:0:210#452",
                    "2-ff00:0:210#450",
                    "2-ff00:0:220#503",
                    "2-ff00:0:220#500",
                    "2-ff00:0:221#2",
                    "2-ff00:0:221#1",
                    "2-ff00:0:222#302",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_16_start_from_peer() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:122".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap()],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[4, 2]).unwrap(),
            ],
            expected_paths: vec![
                interfaces(&[
                    "1-ff00:0:131#480",
                    "1-ff00:0:121#1",
                    "1-ff00:0:121#2",
                    "1-ff00:0:122#2",
                ]),
                interfaces(&[
                    "1-ff00:0:131#479",
                    "1-ff00:0:130#111",
                    "1-ff00:0:130#105",
                    "1-ff00:0:120#1",
                    "1-ff00:0:120#4",
                    "1-ff00:0:121#3",
                    "1-ff00:0:121#2",
                    "1-ff00:0:122#2",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_17_start_and_end_on_peer() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:121".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap()],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[4]).unwrap(),
            ],
            expected_paths: vec![
                interfaces(&["1-ff00:0:131#480", "1-ff00:0:121#1"]),
                interfaces(&[
                    "1-ff00:0:131#479",
                    "1-ff00:0:130#111",
                    "1-ff00:0:130#105",
                    "1-ff00:0:120#1",
                    "1-ff00:0:120#4",
                    "1-ff00:0:121#3",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_18_only_end_on_peer() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:132".parse().unwrap(),
            dst: "1-ff00:0:121".parse().unwrap(),
            cores: vec![g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap()],
            non_cores: vec![
                // up segment
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111, 478])
                    .unwrap(),
                // down segment
                g.beacon("1-ff00:0:120".parse().unwrap(), &[4]).unwrap(),
            ],
            expected_paths: vec![
                interfaces(&[
                    "1-ff00:0:132#2",
                    "1-ff00:0:131#478",
                    "1-ff00:0:131#480",
                    "1-ff00:0:121#1",
                ]),
                interfaces(&[
                    "1-ff00:0:132#2",
                    "1-ff00:0:131#478",
                    "1-ff00:0:131#479",
                    "1-ff00:0:130#111",
                    "1-ff00:0:130#105",
                    "1-ff00:0:120#1",
                    "1-ff00:0:120#4",
                    "1-ff00:0:121#3",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_19_dont_use_core_shortcuts() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:110".parse().unwrap(),
            dst: "2-ff00:0:222".parse().unwrap(),
            cores: vec![
                g.beacon("2-ff00:0:210".parse().unwrap(), &[453]).unwrap(),
                g.beacon("2-ff00:0:220".parse().unwrap(), &[503, 453])
                    .unwrap(),
            ],
            non_cores: vec![
                // down segments
                g.beacon("2-ff00:0:210".parse().unwrap(), &[451, 4])
                    .unwrap(),
                g.beacon("2-ff00:0:220".parse().unwrap(), &[500, 1])
                    .unwrap(),
            ],
            expected_paths: vec![
                interfaces(&[
                    "1-ff00:0:110#3",
                    "2-ff00:0:210#453",
                    "2-ff00:0:210#451",
                    "2-ff00:0:211#7",
                    "2-ff00:0:211#4",
                    "2-ff00:0:222#301",
                ]),
                interfaces(&[
                    "1-ff00:0:110#3",
                    "2-ff00:0:210#453",
                    "2-ff00:0:210#450",
                    "2-ff00:0:220#503",
                    "2-ff00:0:220#500",
                    "2-ff00:0:221#2",
                    "2-ff00:0:221#1",
                    "2-ff00:0:222#302",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_20_core_only() {
        let g = default_graph().unwrap();
        run_test(TestCase {
            src: "1-ff00:0:130".parse().unwrap(),
            dst: "2-ff00:0:210".parse().unwrap(),
            cores: vec![
                g.beacon("2-ff00:0:210".parse().unwrap(), &[453, 2])
                    .unwrap(),
                g.beacon("2-ff00:0:210".parse().unwrap(), &[453, 1, 1])
                    .unwrap(),
                g.beacon("2-ff00:0:210".parse().unwrap(), &[450, 502, 6, 2])
                    .unwrap(),
            ],
            non_cores: vec![],
            expected_paths: vec![
                interfaces(&[
                    "1-ff00:0:130#104",
                    "1-ff00:0:110#2",
                    "1-ff00:0:110#3",
                    "2-ff00:0:210#453",
                ]),
                interfaces(&[
                    "1-ff00:0:130#105",
                    "1-ff00:0:120#1",
                    "1-ff00:0:120#6",
                    "1-ff00:0:110#1",
                    "1-ff00:0:110#3",
                    "2-ff00:0:210#453",
                ]),
                interfaces(&[
                    "1-ff00:0:130#104",
                    "1-ff00:0:110#2",
                    "1-ff00:0:110#1",
                    "1-ff00:0:120#6",
                    "1-ff00:0:120#3",
                    "2-ff00:0:220#502",
                    "2-ff00:0:220#503",
                    "2-ff00:0:210#450",
                ]),
            ],
        });
    }

    #[test_log::test]
    fn test_bad_peering() {
        let mut g = default_graph().unwrap();

        // Add a new peering link between AS 111 and AS 121
        g.add_link(
            "1-ff00:0:111".parse().unwrap(),
            4001,
            "1-ff00:0:121".parse().unwrap(),
            4002,
            true,
        )
        .unwrap();

        // Break the peering by deleting one interface
        g.delete_interface("1-ff00:0:121".parse().unwrap(), 4002)
            .unwrap();

        // Also delete the existing 111-121 peering interface (interface 100)
        g.delete_interface("1-ff00:0:111".parse().unwrap(), 100)
            .unwrap();

        run_test(TestCase {
            src: "1-ff00:0:112".parse().unwrap(),
            dst: "1-ff00:0:122".parse().unwrap(),
            non_cores: vec![
                // up segment: 130->111->112 (interfaces 112->105->103->494)
                g.beacon("1-ff00:0:130".parse().unwrap(), &[112, 103])
                    .unwrap(),
                // down segment: 120->121->122 (interfaces 4->3->2->2)
                g.beacon("1-ff00:0:120".parse().unwrap(), &[4, 2]).unwrap(),
            ],
            cores: vec![
                // 120->130 (interface 1->105)
                g.beacon("1-ff00:0:120".parse().unwrap(), &[1]).unwrap(),
            ],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:112#494",
                "1-ff00:0:111#103",
                "1-ff00:0:111#105",
                "1-ff00:0:130#112",
                "1-ff00:0:130#105",
                "1-ff00:0:120#1",
                "1-ff00:0:120#4",
                "1-ff00:0:121#3",
                "1-ff00:0:121#2",
                "1-ff00:0:122#2",
            ])],
        });
    }

    #[test_log::test]
    fn test_same_core_parent() {
        let g = default_graph().unwrap();

        run_test(TestCase {
            src: "1-ff00:0:131".parse().unwrap(),
            dst: "1-ff00:0:112".parse().unwrap(),
            non_cores: vec![
                // up segment 130->131 (interface 111->479)
                g.beacon("1-ff00:0:130".parse().unwrap(), &[111]).unwrap(),
                // down segment 130->112 (interface 113->495)
                g.beacon("1-ff00:0:130".parse().unwrap(), &[113]).unwrap(),
            ],
            cores: vec![],
            expected_paths: vec![interfaces(&[
                "1-ff00:0:131#479",
                "1-ff00:0:130#111",
                "1-ff00:0:130#113",
                "1-ff00:0:112#495",
            ])],
        });
    }

    // Create test segments that have MTU 1000 on all hops and links.
    // The segments form the following topology:
    //
    //   ┌───┐     ┌───┐
    //   │130|     │210|
    //   └─┬─┘     └─┬─┘
    //     │         │
    //   ┌─▼─┐     ┌─▼─┐
    //   │111|─ ─ ─┤211|
    //   └─┬─┘     └─┬─┘
    //     │         │
    //   ┌─▼─┐     ┌─▼─┐
    //   │112|     │212|
    //   └───┘     └───┘
    //
    // 130 and 210 are core ASes. The up segment is from 130 to 112.
    // The down segment is from 210 to 212.
    fn mtu_test_segments() -> (PathSegment, PathSegment) {
        let g = default_graph().unwrap();
        let mut up_segment = g
            .beacon("1-ff00:0:130".parse().unwrap(), &[112, 103])
            .unwrap();
        set_mtus(&mut up_segment, 1000);
        let mut down_segment = g
            .beacon("2-ff00:0:210".parse().unwrap(), &[451, 2])
            .unwrap();
        set_mtus(&mut down_segment, 1000);
        (up_segment, down_segment)
    }

    #[test_log::test]
    fn test_mtu_calculation_shortcut() {
        let (mut up, _) = mtu_test_segments();
        // Set AS MTU for 112 (index 2) to be higher than expected final MTU
        up.as_entries[2].mtu = 1005;
        up.as_entries[2].hop_entry.ingress_mtu = 1005;
        // The path MTU is determined by the final hop's (111) AS MTU.
        up.as_entries[1].mtu = 1002;

        let paths = combine(
            "1-ff00:0:112".parse().unwrap(),
            "1-ff00:0:111".parse().unwrap(),
            vec![],
            vec![up],
        );

        assert_eq!(paths.len(), 1, "should produce exactly one combined path");
        assert_eq!(
            paths[0].metadata.as_ref().unwrap().mtu,
            1002,
            "path MTU should be limited by the smallest segment MTU"
        );
    }

    #[test_log::test]
    fn test_mtu_calculation_shortcut_ingress() {
        let (mut up, _) = mtu_test_segments();
        // Set AS MTU for 112 (index 2) to be higher
        up.as_entries[2].mtu = 1005;
        // The path MTU is determined by the MTU of the link between 111 and 112.
        up.as_entries[2].hop_entry.ingress_mtu = 1002;
        up.as_entries[1].mtu = 1005;

        let paths = combine(
            "1-ff00:0:112".parse().unwrap(),
            "1-ff00:0:111".parse().unwrap(),
            vec![],
            vec![up],
        );

        assert_eq!(paths.len(), 1, "should produce exactly one combined path");
        assert_eq!(
            paths[0].metadata.as_ref().unwrap().mtu,
            1002,
            "path MTU should be limited by ingress link MTU"
        );
    }

    #[test_log::test]
    fn test_mtu_calculation_full_up_segment() {
        let (mut up, _) = mtu_test_segments();
        up.as_entries[2].mtu = 1005;
        up.as_entries[2].hop_entry.ingress_mtu = 1004;
        up.as_entries[1].mtu = 1003;
        up.as_entries[1].hop_entry.ingress_mtu = 1002;
        // The path MTU is determined by the final hop's (130) AS MTU.
        up.as_entries[0].mtu = 1001;

        let paths = combine(
            "1-ff00:0:112".parse().unwrap(),
            "1-ff00:0:130".parse().unwrap(),
            vec![],
            vec![up],
        );

        assert_eq!(paths.len(), 1, "should produce exactly one combined path");
        assert_eq!(
            paths[0].metadata.as_ref().unwrap().mtu,
            1001,
            "path MTU should be limited by the smallest AS MTU in the path"
        );
    }

    // Create test segments with one peer link removed between AS 111 and AS 211.
    // This is needed for the peer MTU tests to ensure only one path is returned per test case.
    fn mtu_test_segments_with_removed_peer_link() -> (PathSegment, PathSegment) {
        let mut g = default_graph().unwrap();
        // Remove one peer link between 211 and 111 so we only get one path per test case.
        g.remove_link(
            "1-ff00:0:111".parse().unwrap(),
            102,
            "2-ff00:0:211".parse().unwrap(),
            6,
        )
        .unwrap();

        let mut up = g
            .beacon("1-ff00:0:130".parse().unwrap(), &[112, 103])
            .unwrap();
        set_mtus(&mut up, 1000);
        let mut down = g
            .beacon("2-ff00:0:210".parse().unwrap(), &[451, 2])
            .unwrap();
        set_mtus(&mut down, 1000);
        (up, down)
    }

    #[test_log::test]
    fn test_mtu_calculation_peer_mtu() {
        let (mut up, mut down) = mtu_test_segments_with_removed_peer_link();

        up.as_entries[2].mtu = 1005;
        up.as_entries[2].hop_entry.ingress_mtu = 1005;
        up.as_entries[1].mtu = 1005;
        down.as_entries[1].mtu = 1005;

        // Path MTU is determined by the peer entry mtus.
        // Set the peer MTU on the up segment (AS 111) to 1002
        if let Some(peer_entry) = up.as_entries[1]
            .peer_entries
            .iter_mut()
            .find(|p| p.peer == "2-ff00:0:211".parse().unwrap())
        {
            peer_entry.peer_mtu = 1002;
        }
        // Set the peer MTU on the down segment (AS 211) to 1001 (this should be the limiting
        // factor)
        if let Some(peer_entry) = down.as_entries[1]
            .peer_entries
            .iter_mut()
            .find(|p| p.peer == "1-ff00:0:111".parse().unwrap())
        {
            peer_entry.peer_mtu = 1001;
        }

        down.as_entries[2].mtu = 1005;
        down.as_entries[2].hop_entry.ingress_mtu = 1005;

        let paths = combine(
            "1-ff00:0:112".parse().unwrap(),
            "2-ff00:0:212".parse().unwrap(),
            vec![],
            vec![up, down],
        );

        assert_eq!(paths.len(), 1, "should produce exactly one combined path");
        assert_eq!(
            paths[0].metadata.as_ref().unwrap().mtu,
            1001,
            "path MTU should be limited by the smallest peer link MTU"
        );
    }

    #[test_log::test]
    fn test_mtu_calculation_peer_mtu_down_segment() {
        let (mut up, mut down) = mtu_test_segments_with_removed_peer_link();
        up.as_entries[2].mtu = 1005;
        up.as_entries[2].hop_entry.ingress_mtu = 1005;
        up.as_entries[1].mtu = 1005;

        // Set peer MTUs to be higher than the limiting factor
        if let Some(peer_entry) = up.as_entries[1]
            .peer_entries
            .iter_mut()
            .find(|p| p.peer == "2-ff00:0:211".parse().unwrap())
        {
            peer_entry.peer_mtu = 1005;
        }
        if let Some(peer_entry) = down.as_entries[1]
            .peer_entries
            .iter_mut()
            .find(|p| p.peer == "1-ff00:0:111".parse().unwrap())
        {
            peer_entry.peer_mtu = 1005;
        }

        down.as_entries[1].mtu = 1005;
        down.as_entries[2].hop_entry.ingress_mtu = 1005;
        // The path MTU is determined by the final hop's (212) AS MTU.
        down.as_entries[2].mtu = 1002;

        let paths = combine(
            "1-ff00:0:112".parse().unwrap(),
            "2-ff00:0:212".parse().unwrap(),
            vec![],
            vec![up, down],
        );

        assert_eq!(paths.len(), 1, "should produce exactly one combined path");
        assert_eq!(
            paths[0].metadata.as_ref().unwrap().mtu,
            1002,
            "path MTU should be limited by the destination AS MTU in down segment"
        );
    }
}
