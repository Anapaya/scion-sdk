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

//! Simple end-to-end test for PocketScion utilizing a topology

use std::{str::FromStr, time::SystemTime};

use anyhow::{Context, Ok};
use ntest::timeout;
use pocketscion::{
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use scion_proto::address::IsdAsn;
use scion_stack::scionstack::ScionStackBuilder;
use snap_tokens::v0::dummy_snap_token;

#[tokio::test]
#[timeout(10_000)]
async fn should_send_receive_with_topology() -> anyhow::Result<()> {
    let server_ia = IsdAsn::from_str("1-3")?;
    let client_ia = IsdAsn::from_str("2-3")?;

    const MESSAGE_LEN: usize = 64;

    let mut state = SharedPocketScionState::new(SystemTime::now());

    //
    // Setup minimal topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core("1-1".parse()?))?
        .add_as(ScionAs::new_core("1-2".parse()?))?
        .add_as(ScionAs::new("1-3".parse()?))?
        .add_as(ScionAs::new_core("2-1".parse()?))?
        .add_as(ScionAs::new("2-2".parse()?))?
        .add_as(ScionAs::new("2-3".parse()?))?
        .add_link("1-1#1 core 1-2#2".parse()?)?
        .add_link("1-2#1 down_to 1-3#1".parse()?)?
        .add_link("1-1#2 down_to 1-3#2".parse()?)?
        .add_link("1-1#3 core 2-1#1".parse()?)?
        .add_link("2-1#2 down_to 2-2#1".parse()?)?
        .add_link("2-2#2 down_to 2-3#1".parse()?)?;

    state.set_topology(topo);

    //
    // Setup snaps
    let (server_snap_id, client_snap_id) = {
        let server_snap_id = state.add_snap(server_ia)?;
        let client_snap_id = state.add_snap(client_ia)?;

        (server_snap_id, client_snap_id)
    };

    //
    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state.into_state())
        .start()
        .await
        .context("starting runtime")?;

    let ps_api = ps_rt.api_client();

    //
    // Get the Assigned addresses for the snaps
    let all_snaps = ps_api.get_snaps().await.context("getting snaps")?;
    let client_control_plane_addr = all_snaps
        .snaps
        .get(&client_snap_id)
        .context("client snap not found")?
        .control_plane_api
        .clone();

    let server_control_plane_addr = all_snaps
        .snaps
        .get(&server_snap_id)
        .context("server snap not found")?
        .control_plane_api
        .clone();

    //
    // Setup server
    let server_stack = ScionStackBuilder::new(server_control_plane_addr)
        .with_auth_token(dummy_snap_token())
        .build()
        .await?;

    let server_socket = server_stack.bind(None).await?;
    let server_addr = server_socket.local_addr();

    //
    // Setup client
    let client_stack = ScionStackBuilder::new(client_control_plane_addr)
        .with_auth_token(dummy_snap_token())
        .build()
        .await?;

    let client_socket = client_stack.bind(None).await?;

    //
    // Actual Test
    let mut recv_buf = [0u8; MESSAGE_LEN];

    let random_message = rand::random::<[u8; MESSAGE_LEN]>();
    client_socket
        .send_to(&random_message, server_addr)
        .await
        .context("error client sending essage")?;

    let (_, client_addr) = server_socket
        .recv_from(&mut recv_buf)
        .await
        .context("error server receiving message")?;

    assert_eq!(recv_buf, random_message, "Message mismatch");

    let random_message = rand::random::<[u8; MESSAGE_LEN]>();
    server_socket
        .send_to(&random_message, client_addr)
        .await
        .context("error server echoing message")?;

    client_socket
        .recv_from(&mut recv_buf)
        .await
        .context("error client receiving echo")?;

    assert_eq!(recv_buf, random_message, "Message mismatch");

    Ok(())
}
