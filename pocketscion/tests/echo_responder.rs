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

//! Simple test verifying that the Daemon Service's CRPC endpoint can be reached.

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use anyhow::Context;
use chrono::Utc;
use ntest::timeout;
use pocketscion::{
    self,
    network::scion::{
        routing::ScionNetworkTime,
        topology::{ScionAs, ScionTopologyBuilder},
    },
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
};
use sciparse::{
    address::addr::ScionAddr,
    core::model::Model,
    dataplane_path::view::ScionDpPathViewExt,
    identifier::isd_asn::IsdAsn,
    packet::model::ScionScmpPacket,
    payload::scmp::{model::ScmpEchoRequest, view::ScmpMessageView},
};

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn echo_responder() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia2 = IsdAsn::from_str("1-2")?;
    // Setup minimal topology
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(ia1))?
        .add_as(ScionAs::new_core(ia2))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;

    state.set_topology(topo.build()?);

    // add ping responder
    let echo_resp_addr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    state.enable_global_scmp_echo_responder(echo_resp_addr.into());

    tracing::info!("Starting runtime");

    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .start()
        .await
        .context("error starting runtime")?;

    tracing::info!("Runtime started");

    let ns = ps_rt
        .bind_sim_network_stack(ia1, "1.2.3.4".parse()?, 1)
        .context("error binding sim network stack")?;

    let raw = ns.bind_raw();

    let path = ps_rt
        .paths(ia1, ia2, Utc::now())
        .context("error getting path")?
        .first()
        .cloned()
        .context("no path found")?;

    let mut pkt = ScionScmpPacket::new(
        raw.scion_addr(),
        ScionAddr::new(ia2, echo_resp_addr.into()),
        path.dp_path().to_model(),
        ScmpEchoRequest::new(0, 0, vec![0u8; 32]).into(),
    )
    .into_raw()
    .encode_to_owned_view()
    .context("error encoding packet")?;

    raw.try_send(&mut pkt, ScionNetworkTime::now())
        .context("error sending packet")?;

    let recv = raw.recv().await.context("error receiving packet")?;
    let scmp = recv.try_into_scmp().context("error parsing SCMP packet")?;
    let msg = scmp.scmp().message();
    let echo_reply = match msg {
        ScmpMessageView::EchoReply(reply) => reply,
        _ => anyhow::bail!("unexpected SCMP message type"),
    };

    tracing::info!("Received echo reply: {:?}", echo_reply);
    assert_eq!(echo_reply.data(), &[0u8; 32]);
    assert_eq!(echo_reply.identifier(), 0);
    assert_eq!(echo_reply.sequence_number(), 0);

    Ok(())
}
