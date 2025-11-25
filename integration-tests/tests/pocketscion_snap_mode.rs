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
//! Integration tests for PocketSCION in SNAP mode.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use bytes::{BufMut, Bytes, BytesMut};
use pocketscion::{
    authorization_server::{self, api::TokenRequest, fake_idp},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use quinn::{EndpointConfig, crypto::rustls::QuicClientConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rustls::ClientConfig;
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    packet::{self, ByEndpoint, ScionPacketUdp},
    path::{DataPlanePath, encoded::EncodedStandardPath},
    wire_encoding::{WireDecode, WireEncodeVec},
};
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use scion_stack::{
    quic::QuinnConn as _,
    scionstack::{ScionStackBuilder, UdpScionSocket, builder::SnapUnderlayConfig},
    snap_tunnel::{SessionRenewal, SnapTunnel},
};
use snap_control::client::{ControlPlaneApi, CrpcSnapControlClient};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use url::Url;

/// Builds a SCION packet with the given payload and source address.
fn build_scion_packet(source_addr: ScionAddr, dest_addr: ScionAddr, payload: &Bytes) -> Vec<u8> {
    let src_sock_addr = scion_proto::address::SocketAddr::new(source_addr, 1025);
    let dst_sock_addr = scion_proto::address::SocketAddr::new(dest_addr, 1025);
    let endpoints = ByEndpoint {
        source: src_sock_addr,
        destination: dst_sock_addr,
    };

    // Construct a simple one hop path:
    // https://docs.scion.org/en/latest/protocols/scion-header.html#path-type-onehoppath
    let mut path_raw = BytesMut::with_capacity(36);
    path_raw.put_u32(0x0000_2000);
    path_raw.put_slice(&[0_u8; 32]);
    let data_plane_path =
        DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap());

    let packet = ScionPacketUdp::new(endpoints, data_plane_path, payload.clone()).unwrap();

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
    let received_packet = packet::ScionPacketUdp::decode(&mut rdata.clone()).unwrap();
    assert!(received_packet.datagram.payload == payload);
    assert!(
        received_packet.headers.address.destination().unwrap()
            == tun.assigned_addresses()[0].into()
    );
}

// Test involving two clients in AS 110 sending packets to a server in AS 111.
// The server echoes the packets back. The clients connect via two different
// SNAP data planes in AS 110.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn multi_client_multi_snap() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let ia110: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let ia111: IsdAsn = "2-ff00:0:212".parse().unwrap();

    let snap_id1 = pstate.add_snap();
    let snap_id2 = pstate.add_snap();
    let _dp_id1_1 = pstate.add_snap_data_plane(
        snap_id1,
        ia110,
        vec!["10.110.0.0/24".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(1),
    );
    let _dp_id1_2 = pstate.add_snap_data_plane(
        snap_id1,
        ia110,
        vec!["10.110.1.0/24".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(2),
    );
    let _dp_id2_1 = pstate.add_snap_data_plane(
        snap_id2,
        ia111,
        vec!["10.111.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(42),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().expect("no fail"))
        .start()
        .await
        .expect("could not start runtime");

    let mgmt_client = pocketscion.api_client();
    let res = mgmt_client.get_snaps().await.expect("get snaps");
    assert_eq!(res.snaps.len(), 2);

    let snap1_cp_addr = res
        .snaps
        .get(&snap_id1)
        .expect("get snap1")
        .control_plane_api
        .clone();

    // stack1
    let stack1 = ScionStackBuilder::new(snap1_cp_addr.clone())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    // stack2
    let stack2 = ScionStackBuilder::new(snap1_cp_addr)
        .with_auth_token(dummy_snap_token())
        .with_snap_underlay_config(SnapUnderlayConfig::builder().with_snap_dp_index(1).build())
        .build()
        .await
        .unwrap();

    // snap2
    let snap2_cp_addr = res
        .snaps
        .get(&snap_id2)
        .expect("get snap2")
        .control_plane_api
        .clone();
    let server_stack = ScionStackBuilder::new(snap2_cp_addr)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    info!(
        "Server addr: {}, client1 addr: {}, client2 addr: {}",
        server_stack.local_addresses().first().unwrap(),
        stack1.local_addresses().first().unwrap(),
        stack2.local_addresses().first().unwrap()
    );
    let server_addr = SocketAddr::new(server_stack.local_addresses()[0].into(), 9007);
    let server_socket = server_stack.bind(Some(server_addr)).await.unwrap();
    let socket1 = stack1.bind(None).await.unwrap();
    let socket2 = stack2.bind(None).await.unwrap();

    let payload1 = Bytes::from_static(b"SCION payload from client 1");
    let payload2 = Bytes::from_static(b"SCION payload from client 2");

    let cancellation_token = CancellationToken::new();
    let server_cancellation_token = cancellation_token.clone();

    // server tunnel echoes packets back (reversed address headers)
    tokio::spawn(async move {
        tokio::select! {
            _ = server_cancellation_token.cancelled() => {}
            _ = async {
                loop {
                    let mut rdata = BytesMut::zeroed(1024);
                    let mut path_buffer = BytesMut::zeroed(1024);
                    let (received_len, sender_addr, path) = server_socket.recv_from_with_path(&mut rdata, &mut path_buffer).await.unwrap();
                    info!("Server received packet from {}", sender_addr);
                    let reversed_path = path.to_reversed().unwrap();
                    rdata.resize(received_len, 0);
                    server_socket.send_to_via(rdata.as_ref(), sender_addr, &reversed_path.to_slice_path()).await.unwrap();
                }
            } => {}
        }
    });

    socket1.send_to(&payload1, server_addr).await.unwrap();
    socket2.send_to(&payload2, server_addr).await.unwrap();

    // Check if received packet contains the same payload
    recv_and_check(&socket1, server_addr, &payload1).await;
    recv_and_check(&socket2, server_addr, &payload2).await;

    cancellation_token.cancel();
}

// Test involving two clients in AS 110 sending packets to a server in AS 111.
// The server echoes the packets back. The clients connect via two different
// SNAP data planes in AS 110.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn quic_on_quic() {
    info!("installing crypto provider");
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let ia110: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let ia111: IsdAsn = "2-ff00:0:212".parse().unwrap();

    let client_snap_id = pstate.add_snap();
    let server_snap_id = pstate.add_snap();
    let _dp_id1_1 = pstate.add_snap_data_plane(
        client_snap_id,
        ia110,
        vec!["10.10.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(1),
    );
    let _dp_id2_1 = pstate.add_snap_data_plane(
        server_snap_id,
        ia111,
        vec!["10.11.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(42),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().expect("no fail"))
        .start()
        .await
        .expect("could not start runtime");

    let mgmt_client = pocketscion.api_client();
    let res = mgmt_client.get_snaps().await.expect("get snaps");
    assert_eq!(res.snaps.len(), 2);

    let token_c1 = dummy_snap_token();
    let token_s = dummy_snap_token();

    // client stack
    let client_cp_addr = res
        .snaps
        .get(&client_snap_id)
        .expect("get client snap")
        .control_plane_api
        .clone();
    let client_stack = ScionStackBuilder::new(client_cp_addr)
        .with_auth_token(token_c1)
        .build()
        .await
        .unwrap();

    // server stack
    let server_cp_addr = res
        .snaps
        .get(&server_snap_id)
        .expect("get server snap")
        .control_plane_api
        .clone();
    let server_stack = ScionStackBuilder::new(server_cp_addr)
        .with_auth_token(token_s)
        .build()
        .await
        .unwrap();

    info!(
        "Server addr: {}, client addr: {}",
        server_stack.local_addresses().first().unwrap(),
        client_stack.local_addresses().first().unwrap()
    );
    let server_addr = SocketAddr::new(server_stack.local_addresses()[0].into(), 9007);

    let cancellation_token = CancellationToken::new();
    let server_cancellation_token = cancellation_token.clone();
    let reader_cancellation_token = cancellation_token.clone();

    let (cert_der, server_config) =
        scion_sdk_utils::test::generate_cert([42u8; 32], vec!["localhost".into()], vec![]);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client_crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    // Create a client endpoint.
    let mut client_endpoint = client_stack
        .quic_endpoint(None, EndpointConfig::default(), None, None)
        .await
        .unwrap();
    client_endpoint.set_default_client_config(client_config);

    let server_endpoint = server_stack
        .quic_endpoint(
            Some(server_addr),
            EndpointConfig::default(),
            Some(server_config),
            None,
        )
        .await
        .unwrap();

    let payload_size = 1100;

    let mut payload = BytesMut::from_iter(std::iter::repeat_n(b'X', payload_size));

    // server tunnel echoes packets back (reversed address headers)
    let server_handle = tokio::spawn(async move {
        let mut local_server_packets_missing = 0u64;
        let mut local_server_packets_received = 0u64;
        let mut local_server_packets_sent = 0u64;

        tokio::select! {
            _ = server_cancellation_token.cancelled() => {            }
            _ = async {
                let conn = server_endpoint.accept().await.unwrap().unwrap();
                let mut last_seen_seq = 0u64;
                loop {
                    let data = match conn.read_datagram().await {
                        Ok(data) => {
                            local_server_packets_received += 1;
                            data
                        }
                        Err(e) => {
                            error!("Server error reading datagram: {:?}", e);
                            break;
                        }
                    };
                    let incoming_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    if incoming_seq != last_seen_seq + 1 {
                        local_server_packets_missing += incoming_seq - last_seen_seq - 1;
                    }
                    last_seen_seq = incoming_seq;
                    match conn.send_datagram_wait(data).await {
                        Ok(_) => {
                            local_server_packets_sent += 1;
                        }
                        Err(e) => {
                            error!("Server error sending datagram: {:?}", e);
                            break;
                        }
                    }
                }
            } => {}
        }
        server_endpoint.wait_idle().await;
        (
            local_server_packets_sent,
            local_server_packets_received,
            local_server_packets_missing,
        )
    });

    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let start = Instant::now();

    let reader_conn = conn.clone();

    // receiver
    let receiver_handle = tokio::spawn(async move {
        let mut local_packets_received = 0u64;
        let mut local_packets_missing = 0u64;
        let mut last_seen_seq = 0u64;
        tokio::select! {
            _ = reader_cancellation_token.cancelled() => {            }
            _ = async {
                loop {
                    let data = match reader_conn.read_datagram().await {
                        Ok(data) => {
                            local_packets_received += 1;
                            data
                        }
                        Err(e) => {
                            error!("Client error reading datagram: {:?}", e);
                            break;
                        }
                    };
                    let incoming_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    if incoming_seq != last_seen_seq + 1 {
                        local_packets_missing += incoming_seq - last_seen_seq - 1;
                    }
                    last_seen_seq = incoming_seq;
                }
            } => {}
        }
        (local_packets_received, local_packets_missing)
    });

    let sender_cancellation_token = cancellation_token.clone();

    let sender_handle = tokio::spawn(async move {
        let mut local_packets_sent = 0u64;
        tokio::select! {
            _ = sender_cancellation_token.cancelled() => {            }
            _ = async {
                let mut last_sent = 1u64;
                loop{
                    payload[0..8].copy_from_slice(&last_sent.to_le_bytes());
                    last_sent += 1;
                    conn.send_datagram_wait(payload.clone().into()).await.unwrap();
                    local_packets_sent += 1;
                }
            } => {}
        }
        local_packets_sent
    });

    // wait for 2 seconds
    tokio::time::sleep(Duration::from_secs(2)).await;

    cancellation_token.cancel();

    // Wait for all handles to finish
    let (server_packets_sent, server_packets_received, server_packets_missing) =
        server_handle.await.unwrap();
    let (packets_received, packets_missing) = receiver_handle.await.unwrap();
    let packets_sent = sender_handle.await.unwrap();

    info!(
        "client sent {} packets in {} seconds -> {} mbps (one way)",
        packets_sent,
        start.elapsed().as_secs(),
        packets_sent as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0
    );
    info!(
        "echo server received {} packets in {} seconds -> {} mbps (one way), {} missing ({}%)",
        server_packets_received,
        start.elapsed().as_secs(),
        server_packets_received as f64 * payload_size as f64 / start.elapsed().as_secs() as f64
            * 8.0
            / 1024.0
            / 1024.0,
        server_packets_missing,
        server_packets_missing as f64 / server_packets_received as f64 * 100.0
    );
    info!(
        "echo server sent {} packets in {} seconds -> {} mbps (one way)",
        server_packets_sent,
        start.elapsed().as_secs(),
        server_packets_sent as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0
    );
    info!(
        "client received {} packets in {} seconds -> {} mbps (one way), {} missing ({}%)",
        packets_received,
        start.elapsed().as_secs(),
        packets_received as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0,
        packets_missing,
        packets_missing as f64 / packets_received as f64 * 100.0
    );

    assert!(packets_received > 0);

    // Drop the stacks before stopping pocketscion to close the tunnels.
    std::mem::drop(client_stack);
    std::mem::drop(server_stack);
}

async fn recv_and_check(
    socket: &UdpScionSocket,
    expected_sender_addr: SocketAddr,
    expected_payload: &[u8],
) {
    let mut rdata = BytesMut::zeroed(2048); // MAX_PAYLOAD_SIZE
    let (received_len, sender_addr) = socket.recv_from(&mut rdata).await.unwrap();
    rdata.resize(received_len, 0);
    assert_eq!(*expected_payload, rdata);
    assert_eq!(expected_sender_addr, sender_addr);
}

#[test(tokio::test)]
async fn with_auth_server() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (snap_token_private_pem, snap_token_public_pem) = insecure_const_ed25519_key_pair_pem();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());
    pstate.set_snap_token_public_pem(snap_token_public_pem);
    pstate.set_auth_server(snap_token_private_pem);

    let isd_as = "1-ff00:0:110".parse().unwrap();
    let snap_id = pstate.add_snap();
    let _ = pstate.add_snap_data_plane(
        snap_id,
        isd_as,
        vec!["10.0.0.0/16".parse().unwrap()],
        ChaCha8Rng::seed_from_u64(42),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().expect("no fail"))
        .start()
        .await
        .expect("could not start runtime");

    let mgmt_client = pocketscion.api_client();
    let res = mgmt_client.get_snaps().await.expect("get snaps");
    assert_eq!(res.snaps.len(), 1);

    // get the access token from the fake identity provider
    let access_token = fake_idp::oidc_id_token("fake user".to_string());

    let auth_server = mgmt_client
        .get_auth_server()
        .await
        .expect("get auth server");

    let auth_server_api: Url = format!("http://{}/", auth_server.addr).parse().unwrap();
    debug!("auth server api: {}", auth_server_api);
    let auth_client =
        authorization_server::client::ApiClient::new(&auth_server_api).expect("no fail");
    let token_exchange_req = TokenRequest::new(access_token);
    let snap_token_resp = auth_client
        .post_token(token_exchange_req)
        .await
        .expect("no fail");

    let snap_cp_addr = res
        .snaps
        .get(&snap_id)
        .expect("get snap")
        .control_plane_api
        .clone();
    let mut client =
        CrpcSnapControlClient::new(&snap_cp_addr).expect("creating SNAP cp API client");
    client.use_token_source(Arc::new(snap_token_resp.access_token));

    let session_grants = client
        .create_data_plane_sessions()
        .await
        .expect("creating SNAP data plane sessions");

    assert!(session_grants.len() == 1);
    let session_grant = session_grants
        .first()
        .expect("getting first SNAP data plane session grant");
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
