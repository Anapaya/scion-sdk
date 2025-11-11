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
//! Runtime tests for PocketSCION.

use std::{net::Ipv4Addr, sync::Arc, time::SystemTime};

use bytes::{BufMut, Bytes, BytesMut};
use pocketscion::{
    io_config::SharedPocketScionIoConfig, runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use scion_proto::{
    address::ScionAddr,
    packet,
    packet::{ByEndpoint, FlowId, ScionPacketRaw},
    path::{DataPlanePath, encoded::EncodedStandardPath},
    wire_encoding::{WireDecode, WireEncodeVec},
};
use scion_stack::snap_tunnel::{SessionRenewal, SnapTunnel};
use snap_control::client::{ControlPlaneApi, CrpcSnapControlClient};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;

#[test(tokio::test)]
async fn snap_tunnel_should_echo_packets() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());
    let io_config = SharedPocketScionIoConfig::new();

    let isd_as = "1-ff00:0:110".parse().unwrap();
    let tunnel_addr = "127.0.0.1:9000".parse().unwrap();

    let snap_id = pstate.add_snap();
    let dp_id = pstate.add_snap_data_plane(
        snap_id,
        isd_as,
        vec!["10.0.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(42),
    );
    let cp_api = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 9002));
    io_config.set_snap_control_addr(snap_id, cp_api);
    io_config.set_snap_data_plane_addr(dp_id, tunnel_addr);

    let mut pocketscion_runtime = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_io_config(io_config.into_state())
        .with_mgmt_listen_addr("127.0.0.1:9001".parse().expect("no fail"))
        .start()
        .await
        .expect("starting pocketscion");
    pocketscion_runtime
        .wait_for_ready()
        .await
        .expect("pocketscion ready");

    simple_echo().await;

    pocketscion_runtime.stop_and_join().await;
}

/// Builds a SCION packet with the given payload and source address.
fn build_scion_packet(source_addr: ScionAddr, dest_addr: ScionAddr, payload: &Bytes) -> Vec<u8> {
    let endpoints = ByEndpoint {
        source: source_addr,
        destination: dest_addr,
    };

    // Construct a simple one hop path:
    // https://docs.scion.org/en/latest/protocols/scion-header.html#path-type-onehoppath
    let mut path_raw = BytesMut::with_capacity(36);
    path_raw.put_u32(0x0000_2000);
    path_raw.put_slice(&[0_u8; 32]);
    let dp_path =
        DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap());

    let packet = ScionPacketRaw::new(
        endpoints,
        dp_path,
        payload.clone(),
        0,
        FlowId::new(0).unwrap(),
    )
    .unwrap();

    packet.encode_to_bytes_vec().concat()
}

/// Sends a SCION packet with the given payload on the SNAP tunnel and verifies
/// that the same payload is received.
async fn send_and_receive_echo(tun: &SnapTunnel, payload: Bytes) {
    let packet = build_scion_packet(
        tun.assigned_addresses()[0].into(),
        tun.assigned_addresses()[0].into(),
        &payload,
    );
    tun.sender().send_datagram(packet.clone().into()).unwrap();

    let rdata = tun.receiver().read_datagram().await.unwrap();

    // Check length before decoding as the bytes get consumed.
    assert!(packet.len() == rdata.len());
    let received_packet = packet::ScionPacketRaw::decode(&mut rdata.clone()).unwrap();
    assert!(received_packet.payload == payload);
    assert!(
        received_packet.headers.address.destination().unwrap()
            == tun.assigned_addresses()[0].into()
    );
}

async fn simple_echo() {
    let cp_api = url::Url::parse("http://127.0.0.1:9002").expect("parse URL");
    let mut client =
        CrpcSnapControlClient::new(&cp_api).expect("create SNAP control plane API client");
    client.use_token_source(Arc::new(dummy_snap_token()));

    let session_grants = client
        .create_data_plane_sessions()
        .await
        .expect("create SNAP data plane sessions");
    assert!(session_grants.len() == 1);
    let session_grant = session_grants
        .first()
        .expect("get first SNAP data plane session grant");

    let tun = SnapTunnel::new(
        session_grant,
        Arc::new(client),
        vec![],
        SessionRenewal::default(),
    )
    .await
    .unwrap();

    send_and_receive_echo(&tun, Bytes::from_static(b"my SCION packet")).await;
}
