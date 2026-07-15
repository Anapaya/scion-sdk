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

/// Sets up a minimal PocketSCION topology with two [IA132] and [IA212] ASes and a single link
/// between them. As well as either a SNAP or a UDP underlay, depending on the `underlay` parameter.
///
/// ```text
///   1-ff00:0:132  #1 ───────── #3  2-ff00:0:212
/// ```
pub async fn minimal_topology(underlay: UnderlayType) -> PsSetup {
    let mut pstate = PocketScionState::new(Utc::now());

    // Define the topology
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(IA212))
        .unwrap()
        .add_as(ScionAs::new_core(IA132))
        .unwrap()
        .add_link(ScionLink::new(IA132, 1, ScionLinkType::Core, IA212, 3).unwrap())
        .unwrap();

    pstate.set_topology(topo.build().unwrap());

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

/// Sets up a PocketSCION topology with three ASes, [IA132], [IA212] and [IA222].
/// These ASes are connected in a triangle, with links between IA132-IA212, IA132-IA222 and
/// IA212-IA222. This gives [IA132] two distinct paths to [IA212]: the direct link, or the
/// detour via [IA222].
///
/// As well as either a SNAP or a UDP underlay, in both [IA132] and [IA212], depending on the
/// `underlay` parameter.
///
/// ```text
///                     2-ff00:0:222
///                 #1 /            \ #2
///                   /              \
///             #2   /                \  #4
///   1-ff00:0:132  #1 ───────────── #3  2-ff00:0:212
/// ```
pub async fn two_path_topology(underlay: UnderlayType) -> PsSetup {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let mut pstate = PocketScionState::new(Utc::now());

    // Define the topology
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

    pstate.set_topology(topo.build().unwrap());

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
