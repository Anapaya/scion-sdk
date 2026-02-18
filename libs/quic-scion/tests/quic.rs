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

//! QUIC client/server integration tests using pocket SCION.

mod common;

use pocketscion::topologies::{UnderlayType, minimal::minimal_topology};
use scion_sdk_quic_scion::quic::{client::QuicConnection, config::QuicConfig, server::QuicServer};
use test_log::test;

use crate::common::{generate_server_config, setup_sockets};

// Simple QUIC client/server ping-pong test.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn quic_ping_pong() {
    let topology = minimal_topology(UnderlayType::Snap).await;

    let (client_socket, server_socket) = setup_sockets(&topology)
        .await
        .expect("failed to create client/server sockets");

    //////////////////
    // Start the server

    let server_addr = server_socket.local_addr();
    let (server_config, _cert_file, _key_file) = generate_server_config();
    let mut server = QuicServer::new(server_socket.into(), server_config).unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(conn) = server.accept().await {
            let mut buf = [0u8; 1024];

            // Read ping
            loop {
                let stream_ids = conn.readable_streams().await;

                for stream_id in stream_ids {
                    tracing::info!(?stream_id, "Server stream is readable");
                    if let Ok((read, _fin)) = conn.stream_recv(stream_id, &mut buf).await {
                        tracing::info!(data=?&buf[..read], "Server received on stream");

                        if &buf[..read] == b"ping" {
                            // Write pong to same stream
                            conn.stream_send(stream_id, b"pong", true).await.unwrap();
                            return; // Done
                        }
                    }
                }
            }
        }
    });
    tracing::info!("Started server");

    //////////////////
    // Client

    tracing::info!("Start client connect to {:?}", server_addr);
    let client_config = QuicConfig::builder().verify_peer(false).build();

    let client_conn = QuicConnection::new(
        Some("localhost".to_string()),
        server_addr,
        client_socket.into(),
        client_config.to_quiche_config().unwrap(),
    )
    .await
    .expect("client connect");

    client_conn.wait_established().await;

    tracing::info!("Client connected, starting ping-pong");

    // Open stream and send ping
    let stream_id = 4;
    client_conn
        .stream_send(stream_id, b"ping", true)
        .await
        .unwrap();

    // Wait for pong
    tracing::info!("Client waiting for pong");
    let mut buf = [0u8; 1024];
    if let Ok((read, _fin)) = client_conn.stream_recv(stream_id, &mut buf).await
        && read > 0
    {
        assert_eq!(&buf[..read], b"pong");
    }

    // Close client gracefully
    {
        let mut quic = client_conn.conn.lock().await;
        quic.close(true, 0, b"done").ok();
    }

    server_task.await.unwrap();
}
