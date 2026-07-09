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

//! Simple end-to-end test for PocketScion using an external AS, verifying that packets can be sent
//! and received correctly between the local AS and the external AS.

use std::{
    net::Ipv4Addr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, bail};
use chrono::Utc;
use ntest::timeout;
use pocketscion::{
    self,
    network::{
        local::receivers::Receiver,
        scion::{
            routing::ScionNetworkTime,
            topology::{ScionAs, ScionTopologyBuilder},
        },
    },
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
};
use sciparse::{
    address::addr::ScionAddr,
    core::{
        convert::{TryFromView, TryToModel},
        model::Model,
        view::View,
    },
    dataplane_path::{model::DpPath, view::ScionDpPathViewExt},
    identifier::isd_asn::IsdAsn,
    packet::{model::ScionRawPacket, view::ScionRawPacketView},
    payload::ProtocolNumber,
    util::test_builder::TestPathBuilder,
};
use tokio::{net::UdpSocket, task::yield_now, time::timeout};

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn external_as_should_work() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let external_as_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia1_key = [0; 16];
    let ia2 = IsdAsn::from_str("1-2")?;
    let addr1 = ScionAddr::new(ia1, Ipv4Addr::new(10, 0, 0, 1).into());
    let addr2 = ScionAddr::new(ia2, Ipv4Addr::new(20, 0, 0, 1).into());

    let network_time = ScionNetworkTime::now();
    // Setup minimal topology
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core("1-1".parse()?).with_forwarding_key(ia1_key))?
        .add_as(ScionAs::new_external_core("1-2".parse()?))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;

    // Path from ia1 to ia2
    let path1to2 = TestPathBuilder::new(addr1, addr2)
        .using_info_timestamp(network_time.inner())
        .with_hop_expiry(255)
        .using_forwarding_key(ia1_key)
        .core()
        .add_hop(0, 1)
        .add_hop(1, 2)
        .add_hop(2, 0)
        .build(network_time.inner())
        .path();

    state.set_topology(topo.build()?);

    // Setup external AS
    state.add_external_as(ia2)?;
    state.add_external_as_interface(ia2, 2, external_as_socket.local_addr()?)?;

    // Add network target to internal AS
    let network_target = Arc::new(MockNetworkTarget::new());
    state.add_wildcard_sim_receiver(ia1, network_target.clone())?;

    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .start()
        .await
        .context("error starting runtime")?;

    let ext_as_listen_addr = ps_rt
        .external_as_interface_addr(ia2, 2)
        .context("external AS interface address not found")?;

    tracing::info!("Runtime started");

    let recv_task = tokio::spawn({
        let socket = external_as_socket.clone();
        async move {
            let mut buf = [0u8; 1500];

            tracing::info!("External AS waiting for packet...");
            let (len, _) = socket.recv_from(&mut buf).await?;
            let (packet, rest) = ScionRawPacket::try_from_slice(&buf[..len])?;
            debug_assert!(rest.is_empty(), "packet was not fully consumed");

            Ok::<_, anyhow::Error>(packet)
        }
    });

    // Socket Needs to be waiting for packet before we dispatch, otherwise send would block and drop
    // the packet
    yield_now().await;

    // A packet sent to the external AS should be received by the external AS socket
    let mut packet = ScionRawPacket::new(
        addr1,
        addr2,
        path1to2.dp_path().to_model(),
        ProtocolNumber::Other(0),
        b"hello external AS".to_vec(),
    )
    .try_encode_to_owned_view()?;

    ps_rt.dispatch_packet(ia1, 0, network_time, &mut packet);

    let packet = timeout(std::time::Duration::from_secs(1), recv_task).await???;
    let payload: &[u8] = &packet.payload;

    assert_eq!(payload, b"hello external AS".as_slice());

    tracing::info!("External As Received packet");
    // Send a packet from the external AS to the local AS, should be received by the runtime and
    // dispatched to the correct AS

    // Reverse path, and advance by one hop since the external AS would have already processed the
    // first hop.
    let mut reversed_path = packet.header.path.clone();
    reversed_path.try_reverse()?;
    reversed_path = test_specific_advance_path_hop(reversed_path)?;

    let wait_task = tokio::spawn({
        let network_target = network_target.clone();
        async move {
            network_target.wait_for_packet().await;
            network_target
                .last_received_packet
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone()
        }
    });
    let response_packet = ScionRawPacket::new(
        addr2,
        addr1,
        reversed_path,
        ProtocolNumber::Other(0),
        b"hello local AS".to_vec(),
    )
    .try_encode_to_owned_view()?;

    external_as_socket
        .send_to(response_packet.as_slice(), ext_as_listen_addr)
        .await?;

    let received_packet = timeout(std::time::Duration::from_secs(1), wait_task).await??;

    assert_eq!(received_packet.payload, b"hello local AS".as_slice());

    Ok(())
}

struct MockNetworkTarget {
    last_received_packet: Mutex<Option<ScionRawPacket>>,
    notify: Arc<tokio::sync::Notify>,
}
impl MockNetworkTarget {
    fn new() -> Self {
        Self {
            last_received_packet: Mutex::new(None),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn wait_for_packet(&self) -> ScionRawPacket {
        self.notify.clone().notified_owned().await;
        let guard = self.last_received_packet.lock().unwrap();
        guard
            .as_ref()
            .expect("packet should be set when notified")
            .clone()
    }
}
impl Receiver for MockNetworkTarget {
    fn receive_packet(&self, packet: &ScionRawPacketView) {
        let mut guard = self.last_received_packet.lock().unwrap();
        *guard = Some(
            packet
                .try_to_model()
                .expect("failed to convert packet to model"),
        );
        self.notify.notify_waiters();
    }
}

// Advances the path by one hop in construction direction
//
// This function is not general and may only be used in this specific test
fn test_specific_advance_path_hop(path: DpPath) -> anyhow::Result<DpPath> {
    let DpPath::Standard(mut path) = path else {
        bail!("can only advance standard paths");
    };

    path.current_hop_field += 1;

    Ok(path.into())
}
