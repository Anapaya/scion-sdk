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
use scion_sdk_quic_scion::{
    h3::{client::H3Client, request::H3Request, server::H3Server},
    quic::{config::QuicConfig, server::QuicServer},
};
use test_log::test;

use crate::common::{generate_server_config, setup_sockets};

// Simple HTTP3 client/server ping-pong test.
#[test(tokio::test)]
#[ntest::timeout(5_000)]
async fn http3_ping_pong() {
    let topology = minimal_topology(UnderlayType::Snap).await;
    let (client_socket, server_socket) = setup_sockets(&topology)
        .await
        .expect("failed to create client/server sockets");

    //////////////////
    // Start the server

    let server_addr = server_socket.local_addr();
    let (server_config, _cert_file, _key_file) = generate_server_config();

    let quic_server = QuicServer::new(server_socket.into(), server_config).unwrap();
    let mut h3_server = H3Server::new(quic_server);

    let server_task = tokio::spawn(async move {
        if let Some(mut h3_conn) = h3_server.accept().await {
            tracing::info!("H3 server accepted connection");

            // handle request
            if let Some((req, mut responder)) = h3_conn.handle_request().await {
                tracing::info!(?req, "H3 server received request");
                assert_eq!(req.headers.method, http::Method::GET);
                assert_eq!(
                    req.headers.path,
                    http::uri::PathAndQuery::from_static("/ping")
                );

                // send pong response
                responder
                    .send_response(http::StatusCode::OK, b"pong")
                    .await
                    .unwrap();
            }
        }
    });
    tracing::info!("Started H3 server");

    //////////////////
    // Client

    let config = QuicConfig::builder().verify_peer(false).build();
    let client = H3Client::with_config(
        server_addr,
        client_socket.into(),
        Some("localhost".to_string()),
        config,
    )
    .await
    .expect("create h3 client");

    // Send request
    tracing::info!("Created h3 client, sending request");
    let req = H3Request::get("http://localhost/ping".parse().unwrap()).build();
    let resp = client.request(req).await.expect("send h3 request");
    assert_eq!(resp.status, http::StatusCode::OK);
    assert_eq!(resp.body, b"pong");

    server_task.await.unwrap();
}
