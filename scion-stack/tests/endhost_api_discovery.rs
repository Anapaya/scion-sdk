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

//! Simple end-to-end test with PocketScion checking Endhost API discovery

use std::{net::SocketAddr, str::FromStr, time::SystemTime};

use anyhow::{Context, Ok};
use ntest::timeout;
use pocketscion::{
    network::scion::util::test_helper::test_topology, runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use scion_proto::address::IsdAsn;
use scion_stack::{ea_source::StaticEndhostApiDiscovery, scionstack::ScionStackBuilder};
use snap_tokens::v0::dummy_snap_token;
use url::Url;

#[tokio::test]
#[timeout(10_000)]
async fn should_successfully_connect_with_endhost_api_discovery() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let server_ia = IsdAsn::from_str("1-1")?;
    let client_ia = IsdAsn::from_str("2-1")?;

    const MESSAGE_LEN: usize = 64;

    let mut state = SharedPocketScionState::new(SystemTime::now());

    let topo = test_topology().expect("creating test topology");
    state.set_topology(topo);

    // Setup snaps
    state.add_snap(server_ia)?;
    state.add_snap(client_ia)?;

    // Add Endhost APIs
    state.add_endhost_api(vec![server_ia]);
    state.add_endhost_api(vec![client_ia]);

    // Setup Discovery API
    let endhost_api_discovery_id = state.add_endhost_api_discovery_api();

    // Start PocketScion
    let ps = PocketScionRuntimeBuilder::new()
        .with_system_state(state.into_state())
        .start()
        .await
        .context("starting runtime")?;

    let ead_addr = ps
        .endhost_api_discovery_addr(endhost_api_discovery_id)
        .context("getting endhost api discovery address")?;

    let url = match ead_addr {
        SocketAddr::V4(addr) => {
            Url::parse(&format!("http://{}", addr))
                .expect("It is safe to format a SocketAddr as a URL")
        }
        SocketAddr::V6(addr) => {
            Url::parse(&format!("http://[{}]:{}", addr.ip(), addr.port()))
                .expect("It is safe to format a SocketAddr as a URL")
        }
    };

    // Setup server
    let server_stack = ScionStackBuilder::new()
        .with_endhost_api_discovery_source(StaticEndhostApiDiscovery::new(vec![url.clone()]))
        .with_auth_token(dummy_snap_token())
        .build()
        .await?;

    let server_socket = server_stack.bind(None).await?;
    let server_addr = server_socket.local_addr();

    // Setup client
    let client_stack = ScionStackBuilder::new()
        .with_endhost_api_discovery_source(StaticEndhostApiDiscovery::new(vec![url]))
        .with_auth_token(dummy_snap_token())
        .build()
        .await?;

    let client_socket = client_stack.bind(None).await?;

    // Actual Test
    let mut recv_buf = [0u8; MESSAGE_LEN];

    let random_message = rand::random::<[u8; MESSAGE_LEN]>();
    client_socket
        .send_to(&random_message, server_addr)
        .await
        .context("error client sending message")?;

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
