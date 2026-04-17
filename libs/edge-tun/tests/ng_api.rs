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

//! Integration tests for the edge-tun ng Connect-RPC control plane API.
//!
//! These tests use in-memory mock SCION sockets to test the complete
//! client-server round-trip without requiring a real SCION network.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use ana_gotatun::x25519;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use scion_proto::address::{ScionAddr, SocketAddr as ScionSocketAddr};
use scion_sdk_edge_tun::ng::{
    api::{client::EdgeTunControlPlaneClient, server::EdgeTunControlPlaneCrpcApi},
    control_plane::{EdgeTunControlPlane, EdgeTunDataPlaneConfig},
    protobuf::anapaya::edgetun::v1::{
        AddressAssignRequest, AddressAssignResponse, GetDataPlaneConfigurationRequest,
        IpAddressRange,
    },
};
use scion_sdk_quic_scion::{
    quic::{config::QuicConfig, server::QuicServer},
    socket::{BoxedSocketError, GenericScionUdpSocket},
};
use scion_sdk_scion_connect_rpc::{
    Method,
    client::{ConnectRpcClient, CrpcClient},
};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

// ─── Mock SCION socket ──────────────────────────────────────────────────────────

struct MockDatagram {
    data: Vec<u8>,
    src: ScionSocketAddr,
    dst: ScionSocketAddr,
}

/// Simple in-memory mock SCION UDP socket backed by async channels.
struct MockScionSocket {
    recv_channel: Mutex<mpsc::Receiver<MockDatagram>>,
    send_channel: mpsc::Sender<MockDatagram>,
    local_addr: ScionSocketAddr,
}

impl MockScionSocket {
    /// Creates a pair of connected mock sockets.
    fn pair(
        queue_size: usize,
        addr_a: ScionSocketAddr,
        addr_b: ScionSocketAddr,
    ) -> (MockScionSocket, MockScionSocket) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(queue_size);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(queue_size);

        let socket_a = MockScionSocket {
            recv_channel: Mutex::new(a_to_b_rx),
            send_channel: b_to_a_tx,
            local_addr: addr_a,
        };
        let socket_b = MockScionSocket {
            recv_channel: Mutex::new(b_to_a_rx),
            send_channel: a_to_b_tx,
            local_addr: addr_b,
        };
        (socket_a, socket_b)
    }
}

#[async_trait::async_trait]
impl GenericScionUdpSocket for MockScionSocket {
    async fn send_to(
        &self,
        payload: &[u8],
        destination: ScionSocketAddr,
    ) -> Result<(), BoxedSocketError> {
        let datagram = MockDatagram {
            data: payload.to_vec(),
            src: self.local_addr,
            dst: destination,
        };
        self.send_channel
            .send(datagram)
            .await
            .map_err(|e| Box::new(e) as BoxedSocketError)
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketAddr), BoxedSocketError> {
        loop {
            let datagram = self.recv_channel.lock().await.recv().await.ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed",
                )) as BoxedSocketError
            })?;

            if datagram.dst != self.local_addr {
                continue;
            }

            let len = datagram.data.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram.data[..len]);
            return Ok((len, datagram.src));
        }
    }

    fn local_addr(&self) -> ScionSocketAddr {
        self.local_addr
    }
}

// ─── Test helpers ───────────────────────────────────────────────────────────────

/// Creates a socket pair for in-memory testing.
fn make_socket_pair() -> (MockScionSocket, MockScionSocket) {
    let ia1 = "1-1".parse().unwrap();
    let client_addr =
        ScionSocketAddr::new(ScionAddr::new(ia1, Ipv4Addr::new(10, 0, 0, 1).into()), 0);

    let ia2 = "1-2".parse().unwrap();
    let server_addr =
        ScionSocketAddr::new(ScionAddr::new(ia2, Ipv4Addr::new(10, 0, 0, 2).into()), 0);

    MockScionSocket::pair(1024, client_addr, server_addr)
}

/// Generates a `squiche::Config` for a QUIC server with a self-signed certificate.
fn make_server_quic_config() -> (squiche::Config, NamedTempFile, NamedTempFile) {
    let quic_config = QuicConfig::builder().verify_peer(false).build();
    let mut config = quic_config
        .to_quiche_config()
        .expect("QuicConfig::to_quiche_config");

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen cert gen");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let mut cert_file = NamedTempFile::new().expect("cert temp file");
    let mut key_file = NamedTempFile::new().expect("key temp file");

    use std::io::Write as _;
    cert_file
        .as_file_mut()
        .write_all(cert_pem.as_bytes())
        .expect("write cert");
    key_file
        .as_file_mut()
        .write_all(key_pem.as_bytes())
        .expect("write key");

    config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .expect("load cert");
    config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .expect("load key");

    (config, cert_file, key_file)
}

// ─── Fake control plane ─────────────────────────────────────────────────────────

struct FakeControlPlane {
    control_plane_addr: ScionSocketAddr,
    data_plane_addr: ScionSocketAddr,
    responder_key: x25519::PublicKey,
    assigned_addr: Option<IpAddr>,
    routes: Vec<IpNet>,
}

impl EdgeTunControlPlane for FakeControlPlane {
    fn get_data_plane_config(&self) -> EdgeTunDataPlaneConfig {
        EdgeTunDataPlaneConfig {
            control_plane_scion_sockaddr: self.control_plane_addr,
            data_plane_scion_sockaddr: self.data_plane_addr,
        }
    }

    fn register_edge_tun_identity(
        &self,
        _initiator_static_x25519: x25519::PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> (x25519::PublicKey, Option<[u8; 32]>) {
        (self.responder_key, psk_share)
    }

    fn assign_address(&self, _requested_address: Option<IpAddr>) -> Option<IpAddr> {
        self.assigned_addr
    }

    fn get_route_advertisement(&self, _identity: x25519::PublicKey) -> Vec<IpNet> {
        self.routes.clone()
    }
}

// ─── Setup helpers ──────────────────────────────────────────────────────────────

fn make_scion_addr(ia: &str, ip: impl Into<std::net::IpAddr>) -> ScionSocketAddr {
    use scion_proto::address::HostAddr;
    let ip: std::net::IpAddr = ip.into();
    ScionSocketAddr::new(
        ScionAddr::new(ia.parse().unwrap(), HostAddr::from(ip)),
        1234,
    )
}

/// Starts the API server and returns a cancellation token to stop it.
fn start_server(
    server_socket: MockScionSocket,
    control_plane: impl EdgeTunControlPlane + 'static,
) -> (CancellationToken, NamedTempFile, NamedTempFile) {
    let (server_config, cert_file, key_file) = make_server_quic_config();
    let quic_server =
        QuicServer::new(Arc::new(server_socket), server_config).expect("QuicServer::new");

    let api = Arc::new(EdgeTunControlPlaneCrpcApi::new(
        quic_server,
        Arc::new(control_plane),
    ));

    let token = CancellationToken::new();
    let token_clone = token.clone();
    tokio::spawn(async move {
        api.start_listening(token_clone).await;
    });
    // Return the temp files so they stay alive for the duration of the test.
    (token, cert_file, key_file)
}

/// Creates a client connected to the given server address.
async fn make_client(
    client_socket: MockScionSocket,
    server_addr: ScionSocketAddr,
) -> EdgeTunControlPlaneClient<CrpcClient> {
    let config = QuicConfig::builder().verify_peer(false).build();
    let crpc_client = CrpcClient::with_quic_config(
        server_addr,
        Arc::new(client_socket),
        Some("localhost".to_string()),
        None,
        config,
    )
    .await
    .expect("CrpcClient::new");
    EdgeTunControlPlaneClient::new(crpc_client)
}

/// Creates a raw CrpcClient (for tests needing direct proto access).
async fn make_raw_client(
    client_socket: MockScionSocket,
    server_addr: ScionSocketAddr,
) -> CrpcClient {
    let config = QuicConfig::builder().verify_peer(false).build();
    CrpcClient::with_quic_config(
        server_addr,
        Arc::new(client_socket),
        Some("localhost".to_string()),
        None,
        config,
    )
    .await
    .expect("CrpcClient::new")
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_get_data_plane_config() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let control_plane_addr = make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4));
    let data_plane_addr = make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5));

    let fake = FakeControlPlane {
        control_plane_addr,
        data_plane_addr,
        responder_key: x25519::PublicKey::from([1u8; 32]),
        assigned_addr: None,
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;
    let config = client
        .get_data_plane_config()
        .await
        .expect("get_data_plane_config");

    assert_eq!(config.control_plane_scion_sockaddr, control_plane_addr);
    assert_eq!(config.data_plane_scion_sockaddr, data_plane_addr);
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_register_edge_tun_identity_with_psk() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let responder_key = x25519::PublicKey::from([42u8; 32]);

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key,
        assigned_addr: None,
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;

    let initiator_key = x25519::PublicKey::from([7u8; 32]);
    let psk = Some([0xABu8; 32]);

    let (returned_key, returned_psk) = client
        .register_edge_tun_identity(initiator_key, psk)
        .await
        .expect("register_edge_tun_identity");

    assert_eq!(returned_key, responder_key);
    assert_eq!(returned_psk, psk);
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_register_edge_tun_identity_no_psk() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let responder_key = x25519::PublicKey::from([99u8; 32]);

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key,
        assigned_addr: None,
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;

    let initiator_key = x25519::PublicKey::from([3u8; 32]);
    let (returned_key, returned_psk) = client
        .register_edge_tun_identity(initiator_key, None)
        .await
        .expect("register_edge_tun_identity no psk");

    assert_eq!(returned_key, responder_key);
    assert_eq!(returned_psk, None);
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_assign_address_ipv4() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let assigned = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1));

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: Some(assigned),
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;
    let identity = x25519::PublicKey::from([5u8; 32]);

    let result = client
        .assign_address(identity, None)
        .await
        .expect("assign_address");

    assert_eq!(result, Some(assigned));
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_assign_address_ipv6() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let assigned = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: Some(assigned),
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;
    let identity = x25519::PublicKey::from([5u8; 32]);

    let result = client
        .assign_address(identity, None)
        .await
        .expect("assign_address ipv6");

    assert_eq!(result, Some(assigned));
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_assign_address_none() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: None,
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;
    let identity = x25519::PublicKey::from([5u8; 32]);

    let result = client
        .assign_address(identity, None)
        .await
        .expect("assign_address none");

    assert_eq!(result, None);
}

/// Tests that the server rejects a request containing more than one address.
#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_assign_address_multiple_requested_rejected() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    // Use the raw CrpcClient to send a request with 2 addresses — bypassing the
    // typed client which only allows at most one address.
    let raw_client = make_raw_client(client_socket, server_addr).await;

    let addr1 = IpAddressRange {
        version: 4,
        prefix_length: 32,
        address: vec![10, 0, 0, 1],
    };
    let addr2 = IpAddressRange {
        version: 4,
        prefix_length: 32,
        address: vec![10, 0, 0, 2],
    };

    let result = raw_client
        .unary_request::<AddressAssignRequest, AddressAssignResponse>(
            Method::POST,
            "https://localhost/anapaya.edgetun.v1/assign_addresses"
                .parse()
                .unwrap(),
            AddressAssignRequest {
                client_identity: vec![5u8; 32],
                requested_addresses: vec![addr1, addr2],
            },
        )
        .await;

    assert!(
        result.is_err(),
        "expected error for multiple-address request, got: {result:?}"
    );
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_get_route_advertisement() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let routes = vec![
        IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()),
        IpNet::V6(Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap()),
    ];

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: None,
        routes: routes.clone(),
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let client = make_client(client_socket, server_addr).await;
    let identity = x25519::PublicKey::from([8u8; 32]);

    let result = client
        .get_route_advertisement(identity)
        .await
        .expect("get_route_advertisement");

    assert_eq!(result, routes);
}

#[test_log::test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_unknown_path_returns_error() {
    let (client_socket, server_socket) = make_socket_pair();
    let server_addr = server_socket.local_addr();

    let fake = FakeControlPlane {
        control_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 4)),
        data_plane_addr: make_scion_addr("64-1:0:1", Ipv4Addr::new(1, 2, 3, 5)),
        responder_key: x25519::PublicKey::from([0u8; 32]),
        assigned_addr: None,
        routes: vec![],
    };

    let (_token, _cert, _key) = start_server(server_socket, fake);

    let raw_client = make_raw_client(client_socket, server_addr).await;

    let result = raw_client
        .unary_request::<GetDataPlaneConfigurationRequest, GetDataPlaneConfigurationRequest>(
            Method::POST,
            "https://localhost/anapaya.edgetun.v1/unknown_method"
                .parse()
                .unwrap(),
            GetDataPlaneConfigurationRequest {},
        )
        .await;

    assert!(result.is_err(), "expected error for unknown path");
}
