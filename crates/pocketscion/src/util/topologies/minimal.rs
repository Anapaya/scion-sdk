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

//! PocketSCION example topologies for testing.

use std::{collections::BTreeMap, num::NonZeroU16};

use chrono::Utc;

use crate::{
    network::scion::topology::{ScionAs, ScionLink, ScionLinkType, ScionTopologyBuilder},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::topologies::{IA132, IA212, IA222, PsSetup, UnderlayType},
};

/// Builds the [minimal_topology] definition (ASes and links only, no runtime).
fn minimal_topology_builder() -> ScionTopologyBuilder {
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(IA212))
        .unwrap()
        .add_as(ScionAs::new_core(IA132))
        .unwrap()
        .add_link(ScionLink::new(IA132, 1, ScionLinkType::Core, IA212, 3).unwrap())
        .unwrap();
    topo
}

/// Sets up a minimal PocketSCION topology with two [IA132] and [IA212] ASes and a single link
/// between them. As well as either a SNAP or a UDP underlay, depending on the `underlay` parameter.
#[doc = simple_mermaid::mermaid!("diagrams/minimal.mmd")]
pub async fn minimal_topology(underlay: UnderlayType) -> PsSetup {
    let mut pstate = PocketScionState::new(Utc::now());

    pstate.set_topology(minimal_topology_builder().build().unwrap());

    // Create Endhost API
    let eh132 = pstate.add_endhost_api(vec![IA132]);
    let eh212 = pstate.add_endhost_api(vec![IA212]);

    let endhost_apis = BTreeMap::from([(IA132, eh132), (IA212, eh212)]);

    match underlay {
        // Add SNAPs
        UnderlayType::Snap => {
            let _snap132 = pstate.add_snap(IA132).unwrap();
            let _snap212 = pstate.add_snap(IA212).unwrap();
        }
        // Add two routers for UDP underlay
        UnderlayType::Udp => {
            pstate.add_router(
                IA132,
                vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
                vec![],
                BTreeMap::new(),
            );
            pstate.add_router(
                IA212,
                vec![NonZeroU16::new(3).unwrap(), NonZeroU16::new(4).unwrap()],
                vec![],
                BTreeMap::new(),
            );
        }
    }

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate)
        .start()
        .await
        .expect("Failed to start PocketSCION");

    PsSetup {
        runtime: pocketscion,
        endhost_apis,
    }
}

/// Builds the [two_path_topology] definition (ASes and links only, no runtime).
fn two_path_topology_builder() -> ScionTopologyBuilder {
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(IA212))
        .unwrap()
        .add_as(ScionAs::new_core(IA132))
        .unwrap()
        .add_as(ScionAs::new_core(IA222))
        .unwrap()
        .add_link(ScionLink::new(IA132, 1, ScionLinkType::Core, IA212, 3).unwrap())
        .unwrap()
        .add_link(ScionLink::new(IA132, 2, ScionLinkType::Core, IA222, 1).unwrap())
        .unwrap()
        .add_link(ScionLink::new(IA212, 4, ScionLinkType::Core, IA222, 2).unwrap())
        .unwrap();
    topo
}

/// Sets up a PocketSCION topology with three ASes, [IA132], [IA212] and [IA222].
/// These ASes are connected in a triangle, with links between IA132-IA212, IA132-IA222 and
/// IA212-IA222. This gives [IA132] two distinct paths to [IA212]: the direct link, or the
/// detour via [IA222].
///
/// As well as either a SNAP or a UDP underlay, in both [IA132] and [IA212], depending on the
/// `underlay` parameter.
#[doc = simple_mermaid::mermaid!("diagrams/two_path.mmd")]
pub async fn two_path_topology(underlay: UnderlayType) -> PsSetup {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let mut pstate = PocketScionState::new(Utc::now());

    pstate.set_topology(two_path_topology_builder().build().unwrap());

    // Create Endhost API
    let eh132 = pstate.add_endhost_api(vec![IA132]);
    let eh212 = pstate.add_endhost_api(vec![IA212]);

    let endhost_apis = BTreeMap::from([(IA132, eh132), (IA212, eh212)]);

    match underlay {
        // Create two SNAPs with data planes
        UnderlayType::Snap => {
            let _snap132 = pstate.add_snap(IA132).unwrap();
            let _snap212 = pstate.add_snap(IA212).unwrap();
        }
        // Add two routers for UDP underlay
        UnderlayType::Udp => {
            pstate.add_router(
                IA132,
                vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
                vec![],
                BTreeMap::new(),
            );
            pstate.add_router(
                IA212,
                vec![NonZeroU16::new(3).unwrap(), NonZeroU16::new(4).unwrap()],
                vec![],
                BTreeMap::new(),
            );
        }
    }

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate)
        .start()
        .await
        .expect("Failed to start PocketSCION");

    PsSetup {
        runtime: pocketscion,
        endhost_apis,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{minimal_topology_builder, two_path_topology_builder};

    /// Path of the committed Mermaid diagram for the named topology.
    fn diagram_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/util/topologies/diagrams")
            .join(format!("{name}.mmd"))
    }

    /// Wraps the generated Mermaid body with a header marking the file as generated.
    fn generated(mermaid: &str) -> String {
        format!(
            "%% Generated from minimal.rs; do not edit by hand.\n\
             %% Regenerate with `UPDATE_TOPO_DIAGRAMS=1 cargo test -p pocketscion topology_diagrams`.\n\
             {mermaid}"
        )
    }

    /// Golden-file test: the committed `.mmd` diagrams must match what the topology definitions
    /// generate. Set `UPDATE_TOPO_DIAGRAMS=1` to (re)write them after an intentional change.
    #[test]
    fn topology_diagrams_up_to_date() {
        let cases = [
            ("minimal", minimal_topology_builder()),
            ("two_path", two_path_topology_builder()),
        ];
        let update = std::env::var_os("UPDATE_TOPO_DIAGRAMS").is_some();

        let mut stale = Vec::new();
        for (name, builder) in cases {
            let topology = builder.build().expect("building topology");
            let expected = generated(&topology.format_mermaid());
            let path = diagram_path(name);

            if update {
                fs::write(&path, &expected).expect("writing diagram");
            } else if fs::read_to_string(&path).unwrap_or_default() != expected {
                stale.push(name);
            }
        }

        assert!(
            stale.is_empty(),
            "topology diagram(s) {stale:?} are out of date; \
             rerun with UPDATE_TOPO_DIAGRAMS=1 to regenerate"
        );
    }
}
