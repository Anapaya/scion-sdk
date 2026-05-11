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
//! SCION Network Testing Utilities

use std::collections::VecDeque;

use crate::network::scion::{
    segment::model::LinkSegment,
    topology::{DirectedScionLink, ScionAs, ScionGlobalInterfaceId, ScionLinkType, ScionTopology},
};

/// Parses a LinkSegment from a string representation.
pub fn parse_segment(s: &str, use_link_type: ScionLinkType) -> anyhow::Result<LinkSegment> {
    // Format:
    // 0-0#0 -> 1-1#1; 1-1#1 -> 1-2#2; 1-2#3 -> 1-3#4; 1-3#15 -> 1-4#16; 1-4#16 -> 0-0#0;
    use std::str::FromStr;

    use anyhow::bail;

    let mut hops = VecDeque::new();
    for entry in s.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = entry.split("->").map(str::trim).collect();
        if parts.len() != 2 {
            bail!("Invalid path entry: {}", entry);
        }

        let from = ScionGlobalInterfaceId::from_str(parts[0])?;
        let to = ScionGlobalInterfaceId::from_str(parts[1])?;

        hops.push_back(DirectedScionLink {
            from,
            to,
            link_type: use_link_type,
        });
    }

    Ok(LinkSegment {
        start_as: hops.front().unwrap().from.isd_as.into(),
        end_as: hops.back().unwrap().to.isd_as.into(),
        links: hops,
    })
}

/// Default test topology for tests
pub fn test_topology() -> anyhow::Result<ScionTopology> {
    // graph TD
    // subgraph ISD2
    //  direction BT
    //  subgraph CORE2
    //   direction LR
    //   2-1{{"2-1"}}
    //  end
    //  2-1
    //  2-2
    //  2-3
    //  2-21
    // end
    // subgraph ISD1
    //  direction BT
    //  subgraph CORE1
    //   direction LR
    //   1-1{{"1-1"}}
    //   1-11{{"1-11"}}
    //   1-21{{"1-21"}}
    //  end
    //  1-1
    //  1-2
    //  1-3
    //  1-4
    //  1-11
    //  1-12
    //  1-21
    // end
    // 1-2 -->|2 Up 1| 1-1
    // 1-1 ==>|5 Core 6| 1-11
    // 1-1 ==>|32 Core 17| 1-21
    // 1-3 -->|4 Up 3| 1-2
    // 1-2 -->|11 Up 12| 1-12
    // 1-4 -->|18 Up 17| 1-2
    // 1-3 -->|10 Up 9| 1-12
    // 1-4 -->|16 Up 15| 1-3
    // 1-3 -.->|53 Peer 22| 2-2
    // 1-4 -->|20 Up 19| 1-12
    // 1-12 -->|8 Up 7| 1-11
    // 1-11 ==>|15 Core 22| 1-21
    // 1-11 ==>|23 Core 1| 2-1
    // 1-21 ==>|23 Core 24| 2-1
    // 2-2 -->|3 Up 2| 2-1
    // 2-3 -->|5 Up 4| 2-2
    // 2-21 -->|2 Up 52| 2-2
    // 2-3 -->|6 Up 7| 2-21

    let mut topo = ScionTopology::new();

    topo.add_as(ScionAs::new_core("1-1".parse()?))?
        .add_as(ScionAs::new("1-2".parse()?))?
        .add_as(ScionAs::new("1-3".parse()?))?
        .add_as(ScionAs::new("1-4".parse()?))?
        .add_as(ScionAs::new_core("1-11".parse()?))?
        .add_as(ScionAs::new("1-12".parse()?))?
        .add_as(ScionAs::new_core("1-21".parse()?))?
        .add_as(ScionAs::new_core("2-1".parse()?))?
        .add_as(ScionAs::new("2-2".parse()?))?
        .add_as(ScionAs::new("2-3".parse()?))?
        .add_as(ScionAs::new("2-21".parse()?))?;

    // Core links
    topo.add_link("1-1#5 core 1-11#6".parse()?)?
        .add_link("1-1#32 core 1-21#17".parse()?)?
        .add_link("1-11#15 core 1-21#22".parse()?)?
        .add_link("1-21#23 core 2-1#24".parse()?)?
        .add_link("1-11#23 core 2-1#1".parse()?)?;

    // Single digit as links
    topo.add_link("1-1#1 down_to 1-2#2".parse()?)?
        .add_link("1-2#3 down_to 1-3#4".parse()?)?
        .add_link("1-3#15 down_to 1-4#16".parse()?)?
        .add_link("1-2#17 down_to 1-4#18".parse()?)?;

    // Double digit as links
    topo.add_link("1-11#7 down_to 1-12#8".parse()?)?
        .add_link("1-12#9 down_to 1-3#10".parse()?)?
        .add_link("1-12#19 down_to 1-4#20".parse()?)?
        .add_link("1-12#12 down_to 1-2#11 ".parse()?)?;

    // ISD2 links
    topo.add_link("2-1#2 down_to 2-2#3".parse()?)?
        .add_link("2-2#4 down_to 2-3#5".parse()?)?
        .add_link("2-3#6 up_to 2-21#7".parse()?)?
        .add_link("2-2#52 down_to 2-21#2".parse()?)?;

    // Peer links
    topo.add_link("1-3#53 peer 2-2#22".parse()?)?;

    Ok(topo)
}
