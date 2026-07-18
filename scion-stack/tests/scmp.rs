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

use std::time::{Duration, SystemTime};

use anyhow::{Context, Ok};
use chrono::Utc;
use ntest::timeout;
use pocketscion::{
    network::scion::topology::{ScionAs, ScionTopologyBuilder},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::addr_to_http_url,
};
use scion_stack::{path::manager::traits::PathManager as _, stack::ScionStackBuilder};
use sciparse::{
    address::socket_addr::ScionSocketAddr,
    core::model::Model,
    dataplane_path::view::ScionDpPathViewExt,
    identifier::isd_asn::IsdAsn,
    packet::model::ScionUdpPacket,
    payload::scmp::{
        model::{ScmpDestinationUnreachable, ScmpMessage},
        types::ScmpDestinationUnreachableCode,
        view::ScmpMessageExt,
    },
};
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
    topo.add_as(ScionAs::new_core(server_ia))?
        .add_as(ScionAs::new_core("1-2".parse()?))?
        .add_link("1-1#1 core 1-2#1".parse()?)?;

    state.set_topology(topo.build()?);

    //
    // Setup snap
    let snap_id = state.add_snap(server_ia)?;
    let _eh_api_id = state.add_endhost_api(vec![server_ia]);

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
        "[1-2,10.0.0.1]:12345".parse::<ScionSocketAddr>().unwrap(),
    );
    let path = client_path_manager
        .path_wait(src.isd_asn(), dst.isd_asn(), SystemTime::now())
        .await
        .expect("error getting path");
    let random_message = b"test message".to_vec();
    let packet = ScionUdpPacket::new(src.into(), dst, path.dp_path().to_model(), random_message)
        .try_encode_to_owned_view()
        .expect("error encoding SCION packet")
        .into_raw();

    client_raw
        .send(&packet)
        .await
        .context("error sending client message")?;

    let recv = tokio::time::timeout(Duration::from_secs(1), client_raw.recv())
        .await
        .context("timeout receiving client message")?
        .context("error receiving client message")?;

    let scmp = recv
        .try_as_scmp()
        .expect("error converting to SCMP packet")
        .scmp()
        .message();

    assert!(scmp.is_error(), "Expected SCMP error message");
    assert!(
        matches!(
            scmp.to_model(),
            ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable {
                code: ScmpDestinationUnreachableCode::AddressUnreachable,
                ..
            })
        ),
        "Expected Destination Unreachable with Address Unreachable code"
    );

    Ok(())
}
