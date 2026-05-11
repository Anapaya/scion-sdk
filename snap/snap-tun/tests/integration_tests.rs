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
//! Integration tests for the SnapTun library.

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ana_gotatun::{noise::rate_limiter::RateLimiter, packet::PacketBufPool, x25519};
use common::{
    mocks::{MockAuthorization, MockControlPlaneClient},
    server_harness::ServerHarness,
    test_helpers::{build_test_scion_packet, setup_test_environment},
};
use snap_tun::{
    client::{PACKET_BUF_POOL_SIZE, SnapTunEndpoint},
    server::SnapTunServer,
};

#[tokio::test]
async fn test_client_connect_and_echo() {
    let env = setup_test_environment().await;

    // Connect tunnel
    let tunnel = env
        .endpoint
        .connect_tunnel(
            env.server_static_identity,
            env.server_harness.socket_addr(),
            url::Url::parse("http://localhost:8080").unwrap(),
            env.mock_control_plane.clone(),
            env.client_socket.clone(),
            100,
            PacketBufPool::<PACKET_BUF_POOL_SIZE>::new(1024),
        )
        .await
        .expect("Failed to connect tunnel");

    // Assert tunnel has valid local address
    let local_addr = tunnel.local_addr();
    assert_ne!(
        local_addr.port(),
        0,
        "Local address should have non-zero port"
    );

    // Send test packet
    let test_payload = b"Hello, SNAP tunnel!";
    let mut test_packet = build_test_scion_packet(test_payload);
    let test_packet_clone = test_packet.buf_mut().clone();
    tunnel
        .send(test_packet)
        .await
        .expect("Failed to send packet");

    // Receive decrypted packet from server harness
    let (received_packet, source_addr) = env
        .server_harness
        .recv_from_tunnel(Duration::from_secs(2))
        .await
        .expect("Failed to receive packet from tunnel");

    assert_eq!(
        received_packet.as_ref(),
        test_packet_clone.as_ref(),
        "Received packet should match sent packet"
    );
    assert_eq!(
        source_addr, local_addr,
        "Source address should match tunnel local address"
    );

    // Echo packet back via server harness
    env.server_harness
        .send_to_tunnel(received_packet.clone(), local_addr);

    // Receive echo on client
    let echo_packet = tokio::time::timeout(Duration::from_secs(2), tunnel.recv())
        .await
        .expect("Timeout waiting for echo")
        .expect("Failed to receive echo");

    assert_eq!(
        echo_packet, test_packet_clone,
        "Echo packet should match original"
    );

    // Cleanup
    drop(tunnel);
    env.server_harness.stop().await;
}

#[test_log::test(tokio::test)]
async fn test_handshake_timeout_unregistered_identity() {
    // Create client and server keys using from() to avoid rand version conflicts
    let client_static_secret = x25519::StaticSecret::from([3u8; 32]);
    let server_static_secret = x25519::StaticSecret::from([4u8; 32]);
    let server_static_identity = x25519::PublicKey::from(&server_static_secret);

    // Create mock control plane that returns success (pretends registration worked)
    let mut mock_cp = MockControlPlaneClient::new();
    mock_cp
        .expect_register_identity()
        .returning(|_, _| Ok(None));
    let mock_cp = Arc::new(mock_cp);

    // Create MockAuthorization but DON'T authorize the client identity
    let mock_authz = Arc::new(MockAuthorization::new());
    // Intentionally NOT calling: mock_authz.authorize_for_duration(...)

    // Create and start server harness
    let rate_limiter = Arc::new(RateLimiter::new(&server_static_identity, 100));
    let server = SnapTunServer::new(server_static_secret, rate_limiter, mock_authz);

    let server_harness = Arc::new(
        ServerHarness::new(server, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("Failed to create server harness"),
    );

    // Spawn the server run task
    let harness_clone = server_harness.clone();
    let server_task = tokio::spawn(async move {
        harness_clone.run().await;
    });

    // Create endpoint with mock token source
    let token_source = Arc::new(
        scion_sdk_reqwest_connect_rpc::token_source::mock::MockTokenSource::new(
            "test-token".to_string(),
        ),
    );
    let endpoint = SnapTunEndpoint::new(token_source, client_static_secret);

    // Create client socket
    let client_socket = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind client socket"),
    );

    // The tunnel timeout is 90s, so we time out early.
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.connect_tunnel(
            server_static_identity,
            server_harness.socket_addr(),
            url::Url::parse("http://localhost:8080").unwrap(),
            mock_cp,
            client_socket,
            100,
            PacketBufPool::<PACKET_BUF_POOL_SIZE>::new(1024),
        ),
    )
    .await;

    assert!(result.is_err(), "Expected timeout error");

    // Cleanup
    server_harness.cancel_token().cancel();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_token_expiry_drops_tunnel() {
    let env = setup_test_environment().await;

    // Configure mock authorization with 1 second expiry
    let client_static_identity = x25519::PublicKey::from(&env.client_static_secret);
    env.mock_authz
        .revoke_identity(client_static_identity.as_bytes());
    env.mock_authz
        .authorize_for_duration(*client_static_identity.as_bytes(), Duration::from_secs(1));

    // Connect tunnel successfully
    let tunnel = env
        .endpoint
        .connect_tunnel(
            env.server_static_identity,
            env.server_harness.socket_addr(),
            url::Url::parse("http://localhost:8080").unwrap(),
            env.mock_control_plane.clone(),
            env.client_socket.clone(),
            100,
            PacketBufPool::<PACKET_BUF_POOL_SIZE>::new(1024),
        )
        .await
        .expect("Failed to connect tunnel");

    let _local_addr = tunnel.local_addr();
    let test_payload = b"Test packet";

    // Loop: continuously send packets and try to receive from tunnel
    let start = Instant::now();
    let (success_count, last_success) = tokio::time::timeout(Duration::from_secs(3), async {
        let mut success_count = 0;
        let mut last_success = Instant::now();
        loop {
            tunnel
                .send(build_test_scion_packet(test_payload))
                .await
                .expect("send queues");
            match env
                .server_harness
                .recv_from_tunnel(Duration::from_millis(100))
                .await
            {
                Some(_) => {
                    success_count += 1;
                    last_success = Instant::now();
                }
                None => {
                    // Check if enough time has passed since last success
                    if last_success.elapsed() > Duration::from_millis(500) {
                        // Authorization has expired - packets are being dropped
                        break (success_count, last_success);
                    }
                }
            }
        }
    })
    .await
    .expect("Test timed out");

    // Verify that we had some successful packets before authorization expired
    assert!(
        success_count > 0,
        "Should have had some successful packets before expiry"
    );
    assert!(
        last_success.duration_since(start) < Duration::from_secs(1),
        "Authorization should have expired after 1 second"
    );

    // Cleanup
    drop(tunnel);
    env.server_harness.stop().await;
}

#[tokio::test]
async fn test_client_reregisters_with_new_token() {
    // Setup environment with mockall control plane that counts calls
    let env = setup_test_environment().await;

    // Replace the mock control plane with one that counts calls
    let call_count = Arc::new(AtomicUsize::new(0));
    let count_clone = call_count.clone();
    let mut mock_cp = MockControlPlaneClient::new();
    mock_cp
        .expect_register_identity()
        .times(..)
        .returning(move |_, _| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        });
    let mock_cp = Arc::new(mock_cp);

    // Connect tunnel (may trigger registration if not done yet)
    let tunnel = env
        .endpoint
        .connect_tunnel(
            env.server_static_identity,
            env.server_harness.socket_addr(),
            url::Url::parse("http://localhost:8080").unwrap(),
            mock_cp.clone(),
            env.client_socket.clone(),
            100,
            PacketBufPool::<PACKET_BUF_POOL_SIZE>::new(1024),
        )
        .await
        .expect("Failed to connect tunnel");

    // Wait for at least one registration
    tokio::time::timeout(Duration::from_secs(2), async {
        if call_count.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    })
    .await
    .expect("Timeout waiting for initial registration");

    // Update token
    env.token_source.update_token("new-token".to_string());

    // Wait for re-registration using condition loop
    tokio::time::timeout(Duration::from_secs(2), async {
        if call_count.load(Ordering::SeqCst) >= 2 {
            return;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    })
    .await
    .expect("Timeout waiting for re-registration");

    // Send packet to verify tunnel still works after re-registration
    let test_payload = b"After re-registration";
    let mut test_packet = build_test_scion_packet(test_payload);
    let test_packet_clone = test_packet.buf_mut().clone();
    tunnel
        .send(test_packet)
        .await
        .expect("Failed to send packet");

    // Receive decrypted packet from server harness
    let (received_packet, _) = env
        .server_harness
        .recv_from_tunnel(Duration::from_secs(2))
        .await
        .expect("Failed to receive packet after re-registration");

    assert_eq!(
        received_packet, test_packet_clone,
        "Tunnel should still work after re-registration"
    );

    // Cleanup
    drop(tunnel);
    env.server_harness.stop().await;
}
