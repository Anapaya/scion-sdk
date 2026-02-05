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

use std::{collections::BTreeMap, num::NonZeroU16, time::SystemTime};

use crate::{
    network::scion::topology::{ScionAs, ScionLink, ScionLinkType, ScionTopology},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
    topologies::{IA132, IA212, IA222, PocketScionHandle, UnderlayType},
};

/// PocketSCION topology with two ASes and a single link between them.
pub async fn minimal_topology(underlay: UnderlayType) -> PocketScionHandle {
    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    // Define the topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core(IA212))
        .unwrap()
        .add_as(ScionAs::new_core(IA132))
        .unwrap()
        .add_link(ScionLink::new(IA132, 1, ScionLinkType::Core, IA212, 3).unwrap())
        .unwrap();

    pstate.set_topology(topo);

    // Create Endhost API
    let _eh132 = pstate.add_endhost_api(vec![IA132]);
    let _eh212 = pstate.add_endhost_api(vec![IA212]);

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
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .expect("Failed to start PocketSCION");

    let api_client = pocketscion.api_client();

    PocketScionHandle::new(pocketscion, api_client)
}

/// PocketSCION topology with three ASes and two paths from [IA132] to [IA212].
pub async fn two_path_topology(underlay: UnderlayType) -> PocketScionHandle {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    // Define the topology
    let mut topo = ScionTopology::new();
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

    pstate.set_topology(topo);

    // Create Endhost API
    let _eh132 = pstate.add_endhost_api(vec![IA132]);
    let _eh212 = pstate.add_endhost_api(vec![IA212]);

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
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .expect("Failed to start PocketSCION");

    let api_client = pocketscion.api_client();

    PocketScionHandle::new(pocketscion, api_client)
}
