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

//! Integration tests with multiple clients in the same AS.

use bytes::{Bytes, BytesMut};
use pocketscion::topologies::{IA132, IA212, UnderlayType, minimal::minimal_topology};
use scion_proto::address::SocketAddr;
use scion_stack::scionstack::{ScionStackBuilder, UdpScionSocket};
use snap_tokens::v0::{dummy_snap_token, seeded_dummy_snap_token};
use test_log::test;
use tokio_util::sync::CancellationToken;

// Test involving two clients in AS 132 sending packets to a server in AS 212.
// The server echoes the packets back.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn multi_client() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let ps_handle = minimal_topology(UnderlayType::Snap).await;

    // stack1
    let ia132_eh_api = ps_handle.endhost_api(IA132).await.unwrap();
    let stack1 = ScionStackBuilder::new(ia132_eh_api.clone())
        .with_auth_token(seeded_dummy_snap_token("client1".to_string()))
        .build()
        .await
        .unwrap();

    // stack2
    let stack2 = ScionStackBuilder::new(ia132_eh_api.clone())
        .with_auth_token(seeded_dummy_snap_token("client2".to_string()))
        .build()
        .await
        .unwrap();

    // snap2
    let ia212_eh_api = ps_handle.endhost_api(IA212).await.unwrap();
    let server_stack = ScionStackBuilder::new(ia212_eh_api)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let server_socket = server_stack.bind(None).await.unwrap();
    tracing::info!("binding first client socket");
    let socket1 = stack1.bind(None).await.unwrap();
    tracing::info!("bound first client socket, binding second client socket");
    let socket2 = stack2.bind(None).await.unwrap();
    tracing::info!("bound second client socket, binding server socket");
    let server_addr = server_socket.local_addr();
    tracing::info!(
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
                    tracing::info!("Server received packet from {}", sender_addr);
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
