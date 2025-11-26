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

//! Integration tests for the SCION SDK components
//!
//! This crate contains integration tests that require multiple components
//! to work together, avoiding circular dependencies.

use std::{
    collections::BTreeMap,
    num::NonZeroU16,
    time::{Duration, SystemTime},
};

use pocketscion::{
    api::admin::api::EndhostApiResponseEntry,
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::{PocketScionRuntime, PocketScionRuntimeBuilder},
    state::{SharedPocketScionState, SnapId},
};
use rand::SeedableRng as _;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::IsdAsn;
use snap_dataplane::session::state::SessionManagerState;
use url::Url;

/// Underlay type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnderlayType {
    /// UDP underlay.
    Udp,
    /// SNAP underlay.
    Snap,
}

/// Test environment for PocketSCION integration tests.
pub struct PocketscionTestEnv {
    /// PocketSCION runtime.
    pub pocketscion: PocketScionRuntime,
    /// Endhost API entry for AS 1-ff00:0:132.
    pub eh_api132: EndhostApiResponseEntry,
    /// Endhost API entry for AS 2-ff00:0:212.
    pub eh_api212: EndhostApiResponseEntry,
    /// Snap ID for AS 1-ff00:0:132.
    pub snap132: SnapId,
    /// Snap ID for AS 2-ff00:0:212.
    pub snap212: SnapId,
}

/// Sets up PocketSCION with two SNAPs in different ASes for testing.
pub async fn minimal_pocketscion_setup(underlay: UnderlayType) -> PocketscionTestEnv {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let ia132: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let ia212: IsdAsn = "2-ff00:0:212".parse().unwrap();

    // Define the topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core(ia212))
        .unwrap()
        .add_as(ScionAs::new_core(ia132))
        .unwrap()
        .add_link("1-ff00:0:132#1 core 2-ff00:0:212#3".parse().unwrap())
        .unwrap();

    pstate.set_topology(topo);

    // Create Endhost API
    let eh132 = pstate.add_endhost_api(vec![ia132]);
    let eh212 = pstate.add_endhost_api(vec![ia212]);

    // Create two SNAPs with data planes
    let snap132 = pstate.add_snap();
    let snap212 = pstate.add_snap();
    match underlay {
        UnderlayType::Snap => {
            pstate.add_snap_data_plane(
                snap132,
                ia132,
                vec!["10.132.0.0/16".parse().unwrap()],
                ChaCha8Rng::seed_from_u64(1),
            );
            pstate.add_snap_data_plane(
                snap212,
                ia212,
                vec!["10.212.0.0/16".parse().unwrap()],
                ChaCha8Rng::seed_from_u64(42),
            );
        }
        UnderlayType::Udp => {
            pstate.add_router(
                ia132,
                vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
                vec![],
                BTreeMap::new(),
            );
            pstate.add_router(
                ia212,
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
    let mut endhost_apis = api_client.get_endhost_apis().await.unwrap();

    PocketscionTestEnv {
        pocketscion,
        eh_api132: endhost_apis.endhost_apis.remove(&eh132).unwrap(),
        eh_api212: endhost_apis.endhost_apis.remove(&eh212).unwrap(),
        snap132,
        snap212,
    }
}

/// Setup pocketscion with a single SNAP for testing. The SNAP uses a session manager with a short
/// session duration to test session renewal.
pub async fn single_snap_pocketscion_setup(
    session_validity: Duration,
) -> (PocketScionRuntime, Url) {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let isd_as: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let snap = pstate.add_snap_with_session_manager(SessionManagerState::new(session_validity));

    let _dp_id1 = pstate.add_snap_data_plane(
        snap,
        isd_as,
        vec!["10.132.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(1),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .expect("Failed to start PocketSCION");

    let snaps = pocketscion.api_client().get_snaps().await.unwrap();

    (
        pocketscion,
        snaps.snaps.get(&snap).unwrap().control_plane_api.clone(),
    )
}
