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

//! Integration test for the network forwarder using the PocketSCION runtime.

use std::net::IpAddr;

use anyhow::Context;
use chrono::Utc;
use ntest::timeout;
use pocketscion::{
    network::scion::{
        routing::ScionNetworkTime,
        topology::{ScionAs, ScionTopologyBuilder},
    },
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
};
use scion_sdk_utils::rustls::select_ring_crypto_provider;
use sciparse::{
    address::{addr::ScionAddr, socket_addr::ScionSocketAddr},
    core::{convert::TryFromView, encode::WireEncode},
    dataplane_path::model::DpPath,
    identifier::isd_asn::IsdAsn,
    packet::model::{ScionRawPacket, ScionUdpPacket},
};
use tokio::time::{Duration, timeout as tokio_timeout};

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn network_forwarder_should_send_and_receive() -> anyhow::Result<()> {
    select_ring_crypto_provider();

    let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
    let sim_sock_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let sim_forwarder_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let queue_size = 8;

    let mut state = PocketScionState::new(Utc::now());
    let mut topology = ScionTopologyBuilder::new();

    topology.add_as(ScionAs::new_core(local_as))?;
    state.set_topology(topology.build()?);

    let external_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .context("bind external socket")?;

    let forward_addr = external_socket
        .local_addr()
        .context("external socket addr")?;

    state
        .add_network_forwarder(local_as, sim_forwarder_ip, queue_size, forward_addr)
        .context("add network forwarder")?;

    let runtime = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .start()
        .await
        .context("error starting runtime")?;

    let sim_stack = runtime
        .bind_sim_network_stack(local_as, sim_sock_ip, queue_size)
        .context("bind sender sim stack")?;

    let sim_socket = sim_stack.bind_udp(50000).context("bind sender udp")?;
    let forwarder_sock_addr = runtime
        .network_forwarder_addr(local_as, sim_forwarder_ip)
        .context("missing forwarder listen address")?;

    let forwarder_sock_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        forwarder_sock_addr.port(),
    );

    // Send packet from sim stack to external socket via network forwarder.
    let sim_payload = b"sim-to-real".to_vec();
    let sim_destination = ScionSocketAddr::new(local_as, sim_forwarder_ip.into(), 50000);
    sim_socket
        .try_send(
            sim_destination,
            DpPath::Empty,
            sim_payload,
            ScionNetworkTime::now(),
        )
        .context("send sim packet")?;

    let mut recv_buf = [0u8; 2048];
    let (size, addr) = tokio_timeout(
        Duration::from_secs(2),
        external_socket.recv_from(&mut recv_buf),
    )
    .await
    .context("timeout waiting for forwarder send")?
    .context("recv packet")?;

    let pkt_bytes = &recv_buf[..size];
    let (pkt, rest) =
        ScionRawPacket::try_from_slice(pkt_bytes).context("decode forwarded packet")?;
    debug_assert!(rest.is_empty(), "packet was not fully consumed");

    let dest = pkt.dst_scion_addr().context("bad destination")?;
    let src = pkt.src_scion_addr().context("bad source")?;

    assert_eq!(
        addr.port(),
        forwarder_sock_addr.port(),
        "external socket received from forwarder"
    );
    assert!(addr.ip().is_loopback(), "forwarder uses loopback ip");
    assert_eq!(
        dest,
        ScionAddr::new(local_as, forward_addr.ip().into()),
        "destination rewritten to forward addr"
    );
    assert_eq!(
        src,
        ScionAddr::new(local_as, sim_sock_ip.into()),
        "source preserved from sim sender"
    );

    // Send packet from external socket to sim stack via network forwarder.
    let real_payload = b"real-to-sim".to_vec();
    let real_packet = ScionUdpPacket::new(
        ScionSocketAddr::new(local_as, "10.0.0.9".parse::<IpAddr>()?.into(), 5555),
        ScionSocketAddr::new(local_as, sim_sock_ip.into(), 50000),
        DpPath::Empty,
        real_payload.clone(),
    )
    .into_raw()
    .try_encode_to_vec()
    .context("encode real packet")?;

    external_socket
        .send_to(&real_packet, forwarder_sock_addr)
        .await
        .context("send to forwarder")?;

    let recv = tokio_timeout(Duration::from_secs(2), sim_socket.recv())
        .await
        .context("timeout waiting for sim recv")?
        .context("recv sim packet")?;

    assert_eq!(recv.udp().payload(), &real_payload, "receiver got payload");
    assert_eq!(
        recv.src_socket_addr().context("bad source")?,
        ScionSocketAddr::new(local_as, sim_forwarder_ip.into(), 5555),
        "source rewritten to forwarder sim address"
    );

    Ok(())
}
