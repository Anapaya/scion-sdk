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

use bytes::{Bytes, BytesMut};
use pocketscion::{
    authorization_server::{self, api::TokenRequest, fake_idp},
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
};
use quinn::{EndpointConfig, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig;
use scion_proto::address::{IsdAsn, SocketAddr};
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use scion_stack::{
    quic::QuinnConn as _,
    scionstack::{ScionStackBuilder, UdpScionSocket},
};
use snap_tokens::snap_token::{dummy_snap_token, seeded_dummy_snap_token};
use test_log::test;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use url::Url;

// Test involving two clients in AS 110 sending packets to a server in AS 111.
// The server echoes the packets back. The clients connect via two different
// SNAP data planes in AS 110.
//
// XXX(scionstack-v2): rendezvous hashing for pocketscion missing
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn multi_client() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let ia110: IsdAsn = "1-ff00:0:132".parse().unwrap();
    let ia111: IsdAsn = "2-ff00:0:212".parse().unwrap();

    let snap_id1 = pstate.add_snap(ia110).unwrap();
    let snap_id2 = pstate.add_snap(ia111).unwrap();

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
        .with_auth_token(seeded_dummy_snap_token("client1".to_string()))
        .build()
        .await
        .unwrap();

    // stack2
    let stack2 = ScionStackBuilder::new(snap1_cp_addr)
        .with_auth_token(seeded_dummy_snap_token("client2".to_string()))
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

    let server_socket = server_stack.bind(None).await.unwrap();
    info!("binding first client socket");
    let socket1 = stack1.bind(None).await.unwrap();
    info!("bound first client socket, binding second client socket");
    let socket2 = stack2.bind(None).await.unwrap();
    info!("bound second client socket, binding server socket");
    let server_addr = server_socket.local_addr();
    info!(
        "Server addr: {}, client1 addr: {}, client2 addr: {}",
        server_addr,
        socket1.local_addr(),
        socket2.local_addr()
    );

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

    let client_snap_id = pstate.add_snap(ia110).unwrap();
    let server_snap_id = pstate.add_snap(ia111).unwrap();

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
    let client_addr = client_endpoint.local_scion_addr();

    let server_endpoint = server_stack
        .quic_endpoint(None, EndpointConfig::default(), Some(server_config), None)
        .await
        .unwrap();
    let server_addr = server_endpoint.local_scion_addr();

    info!("Server addr: {}, client addr: {}", server_addr, client_addr);

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
        (1f64 - server_packets_received as f64 / server_packets_missing as f64) * 100.0
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
        (1f64 - server_packets_received as f64 / server_packets_missing as f64) * 100.0
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

// Test creating the SCION stack with the SNAP token obtained from the auth server.
#[test(tokio::test)]
async fn with_auth_server() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (snap_token_private_pem, snap_token_public_pem) = insecure_const_ed25519_key_pair_pem();

    let mut pstate = SharedPocketScionState::new(SystemTime::now());
    pstate.set_snap_token_public_pem(snap_token_public_pem);
    pstate.set_auth_server(snap_token_private_pem);

    let isd_as = "1-ff00:0:110".parse().unwrap();
    let snap_id = pstate.add_snap(isd_as).unwrap();

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
    tracing::debug!("auth server api: {}", auth_server_api);
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
    let _client_stack = ScionStackBuilder::new(snap_cp_addr)
        .with_auth_token(snap_token_resp.access_token)
        .build()
        .await
        .unwrap();
}
