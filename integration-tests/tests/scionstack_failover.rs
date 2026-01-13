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
//! Integration tests for path failover functionality of the SCION stack.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use bytes::Bytes;
use integration_tests::{UnderlayType, minimal_pocketscion_setup};
use quinn::{EndpointConfig, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig;
use scion_proto::address::IsdAsn;
use scion_stack::{quic::QuinnConn as _, scionstack::ScionStackBuilder};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;
use tokio::{
    sync::Barrier,
    time::{sleep, timeout},
};
use tracing::info;

#[test(tokio::test)]
async fn should_failover_on_link_error() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;

    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    // Bind sender and receiver sockets
    let sender_socket = Arc::new(sender_stack.bind(None).await.unwrap());
    let sender_addr = sender_socket.local_addr();

    let receiver_socket = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    // Send packet from sender to receiver
    let test_data = Bytes::from("Hello, World!");
    let mut recv_buffer = [0u8; 1024];

    let failover_send_barrier = Arc::new(Barrier::new(2));

    // Start a task that receives on the sender_socket in order to process incoming SCMP errors.
    let sender_socket_clone = sender_socket.clone();
    let sender_recv_task = tokio::spawn(async move {
        let mut recv_buffer = [0u8; 1024];
        let (..) = sender_socket_clone
            .recv_from(&mut recv_buffer)
            .await
            .unwrap();
        panic!("Sender should not receive udp packets");
    });

    let sender_task = tokio::spawn({
        let failover_send_barrier = failover_send_barrier.clone();
        let test_data = test_data.clone();
        async move {
            // Send before failover
            sender_socket
                .send_to(test_data.as_ref(), receiver_addr)
                .await
                .unwrap_or_else(|_| {
                    panic!("error sending from {sender_addr:?} to {receiver_addr:?}")
                });

            // Await at the barrier to synchronize with the receiver
            failover_send_barrier.wait().await;

            // A single send should trigger the failover
            sender_socket
                .send_to(test_data.as_ref(), receiver_addr)
                .await
                .unwrap_or_else(|_| {
                    panic!("error sending from {sender_addr:?} to {receiver_addr:?}")
                });

            // Continue sending packets to ensure connectivity
            loop {
                sleep(Duration::from_millis(100)).await;
                sender_socket
                    .send_to(test_data.as_ref(), receiver_addr)
                    .await
                    .unwrap_or_else(|_| {
                        panic!("error sending from {sender_addr:?} to {receiver_addr:?}")
                    });
            }
        }
    });

    // Send and receive should work
    let mut path_buffer = vec![0u8; 1500];
    let (_, source, path) = receiver_socket
        .recv_from_with_path(&mut recv_buffer, &mut path_buffer)
        .await
        .unwrap();

    assert_eq!(
        source, sender_addr,
        "receiver should receive packets from the sender"
    );

    let egress = path
        .first_hop_egress_interface()
        .expect("path should have first hop egress interface");

    // Make direct link between ASes unavailable
    let client = test_env.pocketscion.api_client();
    client
        .set_link_state(egress.isd_asn, egress.id, false)
        .await
        .unwrap();

    // Notify sender task to start sending packets to trigger failover
    failover_send_barrier.wait().await;

    // Should now failover to the other link and we should be able to receive again
    let mut path_buffer = vec![0u8; 1500];
    let mut recv_buffer = [0u8; 1024];
    let (_size, _addr, new_path) = timeout(
        Duration::from_millis(500),
        receiver_socket.recv_from_with_path(&mut recv_buffer, &mut path_buffer),
    )
    .await
    .expect("should not time out waiting for packet after failover")
    .expect("should receive packet after failover");

    // Should not use the same path as before
    info!(old_path = ?path, new_path = ?new_path, "path changed?");
    assert_ne!(path, new_path, "should use a different path after failover");

    // Stop the sender tasks
    sender_task.abort();
    sender_recv_task.abort();
}

/// Verifies bidirectional communication over a QUIC connection.
/// Sends data from client to server and server to client concurrently, then receives on both
/// sides concurrently.
async fn verify_quic_bidirectional_communication(
    client_conn: &quinn::Connection,
    server_conn: &scion_stack::quic::ScionQuinnConn,
    test_data: Bytes,
    timeout_duration: Duration,
) -> anyhow::Result<()> {
    // Send from both sides concurrently
    let (client_send_result, server_send_result) = tokio::join!(
        client_conn.send_datagram_wait(test_data.clone()),
        server_conn.send_datagram_wait(test_data.clone())
    );

    client_send_result.context("failed to send data from client to server")?;
    server_send_result.context("failed to send data from server to client")?;

    // Receive on both sides concurrently
    let (server_recv_result, client_recv_result) = tokio::join!(
        timeout(timeout_duration, server_conn.read_datagram()),
        timeout(timeout_duration, client_conn.read_datagram())
    );

    let recv_data =
        server_recv_result.context("should not time out waiting for packet from client")??;
    let recv_response =
        client_recv_result.context("should not time out waiting for response from server")??;

    assert_eq!(
        recv_data.as_ref(),
        test_data.as_ref(),
        "server should receive data from client"
    );
    assert_eq!(
        recv_response.as_ref(),
        test_data.as_ref(),
        "client should receive data from server"
    );

    Ok(())
}

/// Test to verify that path failover works with QUIC connections.
///
/// 1. link b is down, so the connection from 132 to 212 is established via link a.
/// 2. set link b up and link a down to force the connection to use link b and c.
/// 3. verify that the connection is still established and data can be sent and received.
///
/// Topology overview:
///
///             1-ff00:0:132 (Core)
///               / \
///              /   \
///             /     \
///            /       \
///           /         \
///          /           \
///         /             \
///        /               \
///       /                 \
///      /                   \
///     / Link a: #1          \ Link b: #2
///    /   <-> #3              \   <-> #1
///   /                         \
///  /                           \
/// 2-ff00:0:212 (Core)   2-ff00:0:222 (Core)
///       |                       |
///       | Link c: #4 <-> #2     |
///       |                       |
///       +-----------------------+
#[test(tokio::test)]
async fn should_quic_failover_on_link_error() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;

    let client = test_env.pocketscion.api_client();
    let ia132: IsdAsn = "1-ff00:0:132".parse().unwrap();

    // Start with link b down to ensure the connection is established via a.
    client.set_link_state(ia132, 2, false).await.unwrap();

    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    // Generate self-signed certificate for QUIC
    let (cert_der, server_config) =
        scion_sdk_utils::test::generate_cert([42u8; 32], vec!["localhost".into()], vec![]);

    // Create server QUIC endpoint
    let server_endpoint = receiver_stack
        .quic_endpoint(None, EndpointConfig::default(), Some(server_config), None)
        .await
        .unwrap();
    let server_addr = server_endpoint.local_scion_addr();

    // Create client QUIC endpoint
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client_crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    let mut client_endpoint = sender_stack
        .quic_endpoint(None, EndpointConfig::default(), None, None)
        .await
        .unwrap();
    client_endpoint.set_default_client_config(client_config);

    // Accept connection on server side and establish client connection in parallel
    let (server_conn, conn) = tokio::join!(
        async { server_endpoint.accept().await.unwrap().unwrap() },
        async {
            client_endpoint
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .unwrap()
        }
    );

    info!(
        "QUIC connection established from {} to {}",
        client_endpoint.local_scion_addr(),
        server_addr
    );

    // Verify initial communication works with all links up
    let test_data = Bytes::from("Hello, QUIC!");
    verify_quic_bidirectional_communication(
        &conn,
        &server_conn,
        test_data,
        Duration::from_millis(100),
    )
    .await
    .expect("initial QUIC communication should work");

    // Now test failover: bring down the direct link a and bring up the indirect link b.
    // This forces the connection to use the indirect path via link b and c
    client.set_link_state(ia132, 2, true).await.unwrap();
    client.set_link_state(ia132, 1, false).await.unwrap();

    // Continue sending/receiving to verify communication still works after path change
    let test_data2 = Bytes::from("Hello after path change!");

    // Verify bidirectional communication still works after path change
    // Retry with very short timeouts to allow path manager to switch quickly
    for i in 0..200 {
        match verify_quic_bidirectional_communication(
            &conn,
            &server_conn,
            test_data2.clone(),
            Duration::from_millis(100),
        )
        .await
        {
            Ok(_) => break,
            Err(_) => {
                if i == 199 {
                    panic!(
                        "failed to verify QUIC communication after path change after 200 attempts"
                    );
                }
                // Retry immediately without sleep
            }
        }
    }
}
