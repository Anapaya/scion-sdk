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

use std::{sync::Arc, time::Duration};

use ana_gotatun::{
    noise::rate_limiter::RateLimiter,
    packet::Packet,
    x25519::{self, PublicKey},
};
use bytes::BytesMut;
use scion_proto::{
    packet::{ByEndpoint, ScionPacketUdp},
    path::DataPlanePath,
    wire_encoding::WireEncodeVec,
};
use scion_sdk_reqwest_connect_rpc::token_source::mock::MockTokenSource;
use snap_tun::{client::SnapTunEndpoint, server::SnapTunServer};
use tokio::task::JoinHandle;

use super::{
    mocks::{MockAuthorization, MockControlPlaneClient},
    server_harness::ServerHarness,
};

/// Build a test SCION packet with the given payload
pub fn build_test_scion_packet(payload: &[u8]) -> Packet {
    let packet = ScionPacketUdp::new(
        ByEndpoint {
            source: "[1-ff00:0:100,10.0.0.1]:1234".parse().unwrap(),
            destination: "[1-ff00:0:101,10.0.0.2]:1235".parse().unwrap(),
        },
        DataPlanePath::EmptyPath,
        payload.to_owned().into(),
    )
    .unwrap();
    let mut buf = BytesMut::with_capacity(packet.required_capacity());
    buf.extend_from_slice(packet.encode_to_bytes_vec().concat().as_slice());
    Packet::from_bytes(buf)
}

/// Running server harness with task handle for cleanup
pub struct RunningServerHarness {
    harness: Arc<ServerHarness<MockAuthorization>>,
    task_handle: JoinHandle<()>,
}

impl RunningServerHarness {
    /// Stop the server harness and wait for completion
    pub async fn stop(self) {
        self.harness.cancel_token().cancel();
        let _ = self.task_handle.await;
    }

    /// Get the socket address
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.harness.socket_addr()
    }

    /// Send packet to tunnel
    pub fn send_to_tunnel(&self, packet: BytesMut, target_addr: std::net::SocketAddr) {
        self.harness.send_to_tunnel(packet, target_addr);
    }

    /// Receive packet from tunnel
    pub async fn recv_from_tunnel(
        &self,
        timeout: Duration,
    ) -> Option<(BytesMut, std::net::SocketAddr)> {
        self.harness.recv_from_tunnel(timeout).await
    }
}

/// Test environment with all necessary components
pub struct TestEnvironment {
    pub client_static_secret: x25519::StaticSecret,
    #[allow(dead_code)]
    pub server_static_secret: x25519::StaticSecret,
    pub server_static_identity: PublicKey,
    pub mock_control_plane: Arc<MockControlPlaneClient>,
    pub mock_authz: Arc<MockAuthorization>,
    pub server_harness: RunningServerHarness,
    pub client_socket: Arc<tokio::net::UdpSocket>,
    pub endpoint: SnapTunEndpoint,
    pub token_source: Arc<MockTokenSource>,
}

/// Setup a complete test environment with server harness and client endpoint
pub async fn setup_test_environment() -> TestEnvironment {
    // Generate test keys using from() to avoid rand version conflicts
    let client_static_secret = x25519::StaticSecret::from([1u8; 32]);
    let server_static_secret = x25519::StaticSecret::from([2u8; 32]);
    let server_public_key = x25519::PublicKey::from(&server_static_secret);
    let client_public_key = x25519::PublicKey::from(&client_static_secret);

    // Create mock control plane with default success behavior
    let mut mock_control_plane = MockControlPlaneClient::new();
    mock_control_plane
        .expect_register_identity()
        .returning(|_, _| Ok(None));
    let mock_control_plane = Arc::new(mock_control_plane);

    // Create mock authorization with long expiry (default authorization)
    let mock_authz = Arc::new(MockAuthorization::new());
    mock_authz.authorize_for_duration(*client_public_key.as_bytes(), Duration::from_secs(3600));

    // Create and start server harness
    let rate_limiter = Arc::new(RateLimiter::new(&server_public_key, 100));
    let server = SnapTunServer::new(
        server_static_secret.clone(),
        rate_limiter,
        mock_authz.clone(),
    );

    let harness = Arc::new(
        ServerHarness::new(server, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("Failed to create server harness"),
    );

    // Spawn the run task
    let harness_clone = harness.clone();
    let task_handle = tokio::spawn(async move {
        harness_clone.run().await;
    });

    let server_harness = RunningServerHarness {
        harness,
        task_handle,
    };

    // Create client socket
    let client_socket = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind client socket"),
    );

    // Create endpoint with mock token source
    let token_source = Arc::new(MockTokenSource::new("test-token".to_string()));
    let endpoint = SnapTunEndpoint::new(token_source.clone(), client_static_secret.clone());

    TestEnvironment {
        client_static_secret,
        server_static_secret,
        server_static_identity: server_public_key,
        mock_control_plane,
        mock_authz,
        server_harness,
        client_socket,
        endpoint,
        token_source,
    }
}
