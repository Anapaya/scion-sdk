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

use std::time::Duration;

use anyhow::{Context, Ok};
use bytes::Bytes;
use chrono::Utc;
use ntest::timeout;
use pocketscion::{
    network::scion::topology::{ScionAs, ScionTopologyBuilder},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::addr_to_http_url,
};
use scion_proto::{
    address::{IsdAsn, SocketAddr},
    packet::{ByEndpoint, ScionPacketUdp, classify_scion_packet},
    scmp::{DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpMessage, ScmpMessageBase},
};
use scion_stack::{path::manager::traits::PathManager as _, scionstack::ScionStackBuilder};
use snap_tokens::v0::dummy_snap_token;
use test_log::test;
use url::Url;

#[test(tokio::test)]
#[timeout(10_000)]
async fn should_receive_scmp_messages() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let server_ia: IsdAsn = "1-1".parse().unwrap();

    let mut state = PocketScionState::new(Utc::now());

    //
    // Setup minimal topology
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(server_ia.into()))?
        .add_as(ScionAs::new_core("1-2".parse()?))?
        .add_link("1-1#1 core 1-2#1".parse()?)?;

    state.set_topology(topo.build()?);

    //
    // Setup snap
    let snap_id = state.add_snap(server_ia.into())?;
    let _eh_api_id = state.add_endhost_api(vec![server_ia.into()]);

    //
    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .start()
        .await
        .context("starting runtime")?;

    //
    // Get the Assigned addresses for the snaps
    let snap_cp_addr = ps_rt.snap_control_addr(snap_id).context("snap not found")?;
    let snap_cp_url: Url = addr_to_http_url(snap_cp_addr);

    //
    // Setup client
    let client_stack = ScionStackBuilder::new()
        .with_endhost_api(snap_cp_url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let client_raw = client_stack
        .bind_raw(None)
        .await
        .expect("bind raw SCION socket");

    let client_path_manager = client_stack.create_path_manager();

    //
    // Actual Test
    let (src, dst) = (
        client_raw.local_addr(),
        "[1-2,10.0.0.1]:12345".parse::<SocketAddr>().unwrap(),
    );
    let path = client_path_manager
        .path_wait(src.isd_asn(), dst.isd_asn(), Utc::now())
        .await
        .expect("error getting path");
    let random_message = Bytes::from_static(b"test message");
    let packet = ScionPacketUdp::new(
        ByEndpoint {
            source: src,
            destination: dst,
        },
        path.data_plane_path,
        random_message,
    )?;
    client_raw
        .send(packet.into())
        .await
        .context("error sending client message")?;

    let recv = tokio::time::timeout(Duration::from_secs(1), client_raw.recv())
        .await
        .context("timeout receiving client message")?
        .context("error receiving client message")?;

    let scmp = classify_scion_packet(recv)
        .expect("error classifying SCION packet")
        .try_into_scmp()
        .expect("error converting to SCMP packet")
        .message;

    assert!(scmp.is_error(), "Expected SCMP error message");
    assert!(
        matches!(
            scmp,
            ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable {
                code: DestinationUnreachableCode::AddressUnreachable,
                ..
            })
        ),
        "Expected Destination Unreachable with Address Unreachable code"
    );

    Ok(())
}
