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

use std::{net::IpAddr, time::SystemTime};

use anyhow::Context;
use bytes::Bytes;
use ntest::timeout;
use pocketscion::{
    network::scion::{
        routing::ScionNetworkTime,
        topology::{ScionAs, ScionTopology},
    },
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
    path::DataPlanePath,
    wire_encoding::{WireDecode, WireEncodeVec},
};
use scion_sdk_utils::rustls::select_ring_crypto_provider;
use tokio::time::{Duration, timeout as tokio_timeout};

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn network_forwarder_should_send_and_receive() -> anyhow::Result<()> {
    select_ring_crypto_provider();

    let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
    let sim_sock_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let sim_forwarder_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let queue_size = 8;

    let mut state = SharedPocketScionState::new(SystemTime::now());
    let mut topology = ScionTopology::new();

    topology.add_as(ScionAs::new_core(local_as))?;
    state.set_topology(topology);

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
        .with_system_state(state.into_state())
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
    let sim_payload = Bytes::from_static(b"sim-to-real");
    let sim_destination = SocketAddr::new(ScionAddr::new(local_as, sim_forwarder_ip.into()), 50000);
    sim_socket
        .try_send(
            sim_destination,
            DataPlanePath::EmptyPath,
            sim_payload.clone(),
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

    let mut pkt_bytes = &recv_buf[..size];
    let pkt = ScionPacketRaw::decode(&mut pkt_bytes).context("decode forwarded packet")?;
    let dest = pkt
        .headers
        .address
        .destination()
        .context("missing destination")?;
    let src = pkt.headers.address.source().context("missing source")?;

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
    let real_payload = Bytes::from_static(b"real-to-sim");
    let real_packet = ScionPacketUdp::new(
        ByEndpoint {
            source: SocketAddr::new(
                ScionAddr::new(local_as, "10.0.0.9".parse::<IpAddr>()?.into()),
                5555,
            ),
            destination: SocketAddr::new(ScionAddr::new(local_as, sim_sock_ip.into()), 50000),
        },
        DataPlanePath::EmptyPath,
        real_payload.clone(),
    )
    .context("build real packet")?;

    external_socket
        .send_to(
            &real_packet.encode_to_bytes_vec().concat(),
            forwarder_sock_addr,
        )
        .await
        .context("send to forwarder")?;

    let recv = tokio_timeout(Duration::from_secs(2), sim_socket.recv())
        .await
        .context("timeout waiting for sim recv")?
        .context("recv sim packet")?;

    assert_eq!(recv.payload(), &real_payload, "receiver got payload");
    assert_eq!(
        recv.source().context("missing source")?,
        SocketAddr::new(ScionAddr::new(local_as, sim_forwarder_ip.into()), 5555),
        "source rewritten to forwarder sim address"
    );

    Ok(())
}
