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
//! Integration tests for PocketSCION in router mode.

use std::{
    collections::BTreeMap,
    num::NonZeroU16,
    time::{Duration, SystemTime},
    vec,
};

use bytes::Bytes;
use ipnet::IpNet;
use pocketscion::{
    runtime::PocketScionRuntimeBuilder,
    state::SharedPocketScionState,
    topologies::{IA132, IA212, PocketScionHandle},
};
use scion_proto::{
    address::{ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketScmp, ScionPacketUdp},
    path::{DataPlanePath, EncodedStandardPath, HopField, InfoField, StandardPath},
    scmp::{ScmpEchoRequest, ScmpExternalInterfaceDown, ScmpMessage},
    wire_encoding::{WireDecode as _, WireEncodeVec as _},
};
use test_log::test;
use tokio::time::timeout;

// Test implementing a simple echo of an echo client and echo server using pocketscion in router
// mode, i.e., without SNAPs.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn echo() {
    let pocketscion = setup_pocketscion().await;

    let ia132_router_addr = pocketscion.router_addr(IA132).await.unwrap();

    // Bind sockets early to get allocated ports
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind server socket");

    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    tracing::info!(
        %client_addr,
        %server_addr,
        "Starting echo test"
    );

    // Spawn a task for the echo server.
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (len, src_addr) = server_socket
            .recv_from(&mut buf)
            .await
            .expect("Failed to receive packet");
        buf.truncate(len);

        let packet =
            ScionPacketUdp::decode(&mut buf.as_slice()).expect("Failed to decode SCION UDP packet");

        tracing::info!(
            "Server received packet from {}: {}",
            packet.source().unwrap(),
            String::from_utf8_lossy(packet.payload())
        );

        let response_payload = format!("Echo: {}", String::from_utf8_lossy(packet.payload()));
        let response_endp = ByEndpoint {
            source: packet.destination().unwrap(),
            destination: packet.source().unwrap(),
        };
        let response_path = packet
            .headers
            .path
            .to_reversed()
            .expect("Failed to reverse path");
        let response_pkt = ScionPacketUdp::new(
            response_endp,
            response_path.clone(),
            response_payload.into(),
        )
        .expect("Failed to create response packet");

        let resp_raw = response_pkt.encode_to_bytes_vec().concat();

        server_socket
            .send_to(&resp_raw, src_addr)
            .await
            .expect("Failed to send packet");
    });

    // Spawn a task for the client.
    let client_task = tokio::spawn(async move {
        // Construct a simple SCION UDP packet.
        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::from_std(IA132, client_addr),
                destination: SocketAddr::from_std(IA212, server_addr),
            },
            DataPlanePath::Standard(scion_path()),
            b"Hello SCION!".as_ref().into(),
        )
        .expect("Failed to create SCION packet");

        let pkt_raw = packet.encode_to_bytes_vec().concat();

        client_socket
            .send_to(&pkt_raw, ia132_router_addr)
            .await
            .expect("Failed to send packet");

        let mut recv_buf = vec![0u8; 2048];
        let (len, _) = client_socket
            .recv_from(&mut recv_buf)
            .await
            .expect("Failed to receive packet");
        recv_buf.truncate(len);

        let response_pkt = ScionPacketUdp::decode(&mut recv_buf.as_slice())
            .expect("Failed to decode response SCION UDP packet");

        tracing::info!(
            "Client received packet from {}: {}",
            response_pkt.source().unwrap(),
            String::from_utf8_lossy(response_pkt.payload())
        );

        assert_eq!(
            response_pkt.payload(),
            &Bytes::from(b"Echo: Hello SCION!".as_ref()),
            "Unexpected response payload"
        );
    });

    timeout(Duration::from_secs(5), async move {
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.expect("Server task panicked");
        client_result.expect("Client task panicked");
    })
    .await
    .expect("Echo test timed out");
}

// Test sending SCMP packets in router mode.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn send_scmp() {
    let pocketscion = setup_pocketscion().await;

    // Bind sockets early to get allocated ports
    let sender_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind sender socket");
    let receiver_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind receiver socket");

    let sender_addr = sender_socket.local_addr().unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    tracing::info!(
        %sender_addr,
        %receiver_addr,
        "Starting SCMP test"
    );

    // Spawn a task for the receiver.
    let receiver_task = tokio::spawn(async move {
        // Receive both SCMP packets
        for _ in 0..2 {
            let mut buf = vec![0u8; 2048];
            let (len, src_addr) = receiver_socket
                .recv_from(&mut buf)
                .await
                .expect("Failed to receive packet");
            buf.truncate(len);

            let packet = ScionPacketScmp::decode(&mut buf.as_slice())
                .expect("Failed to decode SCION SCMP packet");

            tracing::info!(
                "Receiver received SCMP packet from {}: {:?}",
                packet.headers.address.source().unwrap(),
                packet.message
            );

            // Send a simple acknowledgment back
            let response_payload = b"SCMP received";
            let response_pkt = ScionPacketUdp::new(
                ByEndpoint {
                    source: SocketAddr::new(
                        packet.headers.address.destination().unwrap(),
                        receiver_addr.port(),
                    ),
                    destination: SocketAddr::new(
                        packet.headers.address.source().unwrap(),
                        sender_addr.port(),
                    ),
                },
                packet
                    .headers
                    .path
                    .to_reversed()
                    .expect("Failed to reverse path"),
                response_payload.as_ref().into(),
            )
            .expect("Failed to create response packet");

            let resp_raw = response_pkt.encode_to_bytes_vec().concat();

            receiver_socket
                .send_to(&resp_raw, src_addr)
                .await
                .expect("Failed to send packet");
        }
    });

    // Spawn a task for the sender.
    let ia132_router_addr = pocketscion.router_addr(IA132).await.unwrap();
    let sender_task = tokio::spawn(async move {
        let dp_path = DataPlanePath::Standard(scion_path());

        // Send SCMP echo request with correct identifier (receiver's port)
        let echo_request = ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            receiver_addr.port(),
            1,
            Bytes::from_static(b"echo test data"),
        ));

        let echo_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: ScionAddr::new(IA132, sender_addr.ip().into()),
                destination: ScionAddr::new(IA212, receiver_addr.ip().into()),
            },
            dp_path.clone(),
            echo_request,
        )
        .expect("Failed to create SCMP echo packet");

        let echo_raw = echo_packet.encode_to_bytes_vec().concat();
        sender_socket
            .send_to(&echo_raw, ia132_router_addr)
            .await
            .expect("Failed to send SCMP echo packet");

        // Send SCMP external interface down with quoted UDP packet
        // Create a UDP packet that will be quoted in the SCMP error
        let quoted_udp = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::from_std(IA212, receiver_addr), // receiver as source
                destination: SocketAddr::from_std(IA132, sender_addr), // sender as destination
            },
            dp_path.clone(),
            Bytes::from_static(b"quoted payload"),
        )
        .expect("Failed to create quoted UDP packet");

        let interface_down = ScmpMessage::ExternalInterfaceDown(ScmpExternalInterfaceDown::new(
            IA132,
            42,
            quoted_udp.encode_to_bytes_vec().concat().into(),
        ));

        let interface_down_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: ScionAddr::new(IA132, sender_addr.ip().into()),
                destination: ScionAddr::new(IA212, receiver_addr.ip().into()),
            },
            dp_path,
            interface_down,
        )
        .expect("Failed to create SCMP interface down packet");

        let interface_down_raw = interface_down_packet.encode_to_bytes_vec().concat();
        sender_socket
            .send_to(&interface_down_raw, ia132_router_addr)
            .await
            .expect("Failed to send SCMP interface down packet");

        // Wait for acknowledgments
        for _ in 0..2 {
            let mut recv_buf = vec![0u8; 2048];
            let (len, _) = sender_socket
                .recv_from(&mut recv_buf)
                .await
                .expect("Failed to receive acknowledgment");
            recv_buf.truncate(len);

            let response_pkt = ScionPacketUdp::decode(&mut recv_buf.as_slice())
                .expect("Failed to decode response SCION UDP packet");

            tracing::info!(
                "Sender received acknowledgment from {}: {}",
                response_pkt.source().unwrap(),
                String::from_utf8_lossy(response_pkt.payload())
            );

            assert_eq!(
                response_pkt.payload(),
                &Bytes::from(b"SCMP received".as_ref()),
                "Unexpected acknowledgment payload"
            );
        }
    });

    timeout(Duration::from_secs(5), async move {
        let (receiver_result, sender_result) = tokio::join!(receiver_task, sender_task);
        receiver_result.expect("Receiver task panicked");
        sender_result.expect("Sender task panicked");
    })
    .await
    .expect("SCMP test timed out");
}

fn scion_path() -> EncodedStandardPath {
    let info = InfoField {
        cons_dir: true,
        ..Default::default()
    };
    let hop1 = HopField {
        cons_egress: 2,
        ..Default::default()
    };
    let hop2 = HopField {
        cons_ingress: 3,
        ..Default::default()
    };

    let mut path = StandardPath::new();
    path.add_segment(info, vec![hop1, hop2])
        .expect("Failed to add segment to SCION path");
    path.into()
}

// Test 1: SNAP interface forwarding
//
// Test that SCION packets are forwarded to the SNAP udp ip interface if it is configured.
//
// Topology:
//   ┌──────────────────────AS1 ────────────────┐
//   │ endhost_behind_snap                      │
//   │          │                               |
//   │          ↓                               |
//   │     snap_socket                          |
//   │    (127.0.0.1:...)                       |
//   │         ↕                                |
//   └─── router#1 ─────────────────────────┘
//             ↕
//        [core link]
//             ↕
//   ┌─── router#3 ─────────AS2 ───────────────┐
//   |         ↕                               |
//   │     remote_socket                       |
//   │     (127.0.0.1:...)                     │
//   └─────────────────────────────────────────┘
//
// Test sends two packets:
//   1. remote_socket → router#3 → router#1 → snap_socket (packet dest: 10.0.0.42:8080)
//   2. snap_socket → router#1 → router#3 → remote_socket (packet source: 10.0.0.42:8080)
//
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn snap_interface_forwarding() {
    // Bind sockets
    let snap_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind snap socket");
    let snap_addr = snap_socket.local_addr().unwrap();

    let remote_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind remote socket");
    let remote_addr = remote_socket.local_addr().unwrap();

    // Setup PocketSCION with SNAP interface
    let pocketscion =
        setup_pocketscion_router(vec![], BTreeMap::from([("dp-0".to_string(), snap_addr)])).await;

    // Router socket addresses
    let ia132_router_addr = pocketscion.router_addr(IA132).await.unwrap();
    let ia212_router_addr = pocketscion.router_addr(IA212).await.unwrap();

    // Hypothetical endhost behind the SNAP (packets to this address are forwarded to snap_socket)
    let endhost_behind_snap_addr = "10.0.0.42:8080".parse::<std::net::SocketAddr>().unwrap();
    let endhost_behind_snap_scion_addr = SocketAddr::from_std(IA132, endhost_behind_snap_addr);

    tracing::info!(
        %snap_addr,
        %remote_addr,
        %endhost_behind_snap_addr,
        "Starting SNAP interface forwarding test"
    );

    let remote_scion_addr = SocketAddr::from_std(IA212, remote_addr);
    let test_payload_1 = b"Test from remote to endhost behind SNAP";
    let test_payload_2 = b"Response from endhost behind SNAP to remote";

    // Spawn SNAP receiver task - snap_socket emulates the udp_ip interface of a SNAP
    let snap_task = tokio::spawn(async move {
        // Test Case 1a: Receive packet from remote destined for endhost behind SNAP
        let mut buf = vec![0u8; 2048];
        let (len, src_addr) = timeout(Duration::from_secs(3), snap_socket.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for packet at SNAP socket")
            .expect("Failed to receive at SNAP socket");
        buf.truncate(len);

        tracing::info!(%src_addr, "SNAP socket received packet");

        let packet = ScionPacketUdp::decode(&mut buf.as_slice())
            .expect("Failed to decode SCION UDP packet at SNAP socket");

        assert_eq!(
            packet.payload().as_ref(),
            test_payload_1,
            "SNAP socket received incorrect payload"
        );
        assert_eq!(
            packet.destination().unwrap(),
            endhost_behind_snap_scion_addr,
            "Packet destination should be the endhost behind SNAP"
        );

        tracing::info!("SNAP socket verified payload, now sending response");

        // Test Case 1b: SNAP Socket → remote
        let reversed_path = packet
            .headers
            .path
            .to_reversed()
            .expect("Failed to reverse path");

        let response_pkt = ScionPacketUdp::new(
            ByEndpoint {
                source: endhost_behind_snap_scion_addr,
                destination: packet.source().unwrap(),
            },
            reversed_path,
            test_payload_2.as_ref().into(),
        )
        .expect("Failed to create response packet");

        let response_raw = response_pkt.encode_to_bytes_vec().concat();
        snap_socket
            .send_to(&response_raw, ia132_router_addr)
            .await
            .expect("Failed to send from SNAP socket to router");

        tracing::info!("SNAP socket sent response");
    });

    // Test Case 1a: remote → endhost behind SNAP
    let packet_to_snap = ScionPacketUdp::new(
        ByEndpoint {
            source: remote_scion_addr,
            destination: endhost_behind_snap_scion_addr,
        },
        DataPlanePath::Standard(scion_path()),
        test_payload_1.as_ref().into(),
    )
    .expect("Failed to create packet to endhost behind SNAP");

    let pkt_raw = packet_to_snap.encode_to_bytes_vec().concat();
    remote_socket
        .send_to(&pkt_raw, ia212_router_addr)
        .await
        .expect("Failed to send from remote");
    tracing::info!("Remote sent packet to endhost behind SNAP");

    // Wait for SNAP task to complete
    snap_task.await.expect("SNAP task panicked");

    // Test Case 1b: Receive response from SNAP
    let mut recv_buf = vec![0u8; 2048];
    let (len, _) = timeout(
        Duration::from_secs(3),
        remote_socket.recv_from(&mut recv_buf),
    )
    .await
    .expect("Timeout waiting for response at remote")
    .expect("Failed to receive at remote socket");
    recv_buf.truncate(len);

    let response_pkt =
        ScionPacketUdp::decode(&mut recv_buf.as_slice()).expect("Failed to decode response packet");

    tracing::info!("Remote received response from endhost behind SNAP");

    assert_eq!(
        response_pkt.payload().as_ref(),
        test_payload_2,
        "Remote received incorrect payload from endhost behind SNAP"
    );
    assert_eq!(
        response_pkt.source().unwrap(),
        endhost_behind_snap_scion_addr,
        "Response source should be the endhost behind SNAP"
    );

    tracing::info!("SNAP interface forwarding test completed successfully");
}

// Test 2: Excluded networks
//
// Test that SCION packets are not forwarded to the SNAP udp ip interface if
// the destination is in the exclude list.
//
// Topology:
//   ┌ AS1 ─────────────────────────────────────────────┐
//   |                                                  |
//   │snap_socket (not used) excluded_socket            |
//   │ (127.0.0.1:...)       (127.0.0.1:...)            |
//   |       |                  ↑                       |
//   │       └─────────────┐    ↓                       |
//   └──────────────────── router#1 ────────────────────┘
//                              ↕
//                         [core link]
//                              ↕
//   ┌ AS2 ──────────────── router#3 ───────────────────┐
//   |                          ↕                       |
//   │                     remote_socket                |
//   │                     (127.0.0.1:...)              │
//   └──────────────────────────────────────────────────┘
//
// Config: router#1 has SNAP interface configured, but also has
//         exclude list: 127.0.0.1/32 (bypasses SNAP for local traffic)
//
// Test sends two packets:
//   1. remote_socket → router#3 → router#1 → excluded_socket (snap_socket does NOT receive)
//   2. excluded_socket → router#1 → router#3 → remote_socket
//
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn snap_excluded_networks() {
    // Bind sockets
    let snap_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind snap socket");
    let snap_addr = snap_socket.local_addr().unwrap();

    let excluded_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind excluded socket");
    let excluded_addr = excluded_socket.local_addr().unwrap();

    let remote_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind remote socket");
    let remote_addr = remote_socket.local_addr().unwrap();

    // Setup PocketSCION with SNAP interface and exclude list
    let pocketscion = setup_pocketscion_router(
        vec!["127.0.0.1/32".parse::<IpNet>().unwrap()],
        BTreeMap::from([("dp-0".to_string(), snap_addr)]),
    )
    .await;

    tracing::info!(
        %excluded_addr,
        %remote_addr,
        "Starting SNAP excluded networks test"
    );

    let excluded_scion_addr = SocketAddr::from_std(IA132, excluded_addr);
    let remote_scion_addr = SocketAddr::from_std(IA212, remote_addr);
    let test_payload_1 = b"Test from remote to excluded";
    let test_payload_2 = b"Response from excluded to remote";

    let ia132_router_addr = pocketscion.router_addr(IA132).await.unwrap();
    let ia212_router_addr = pocketscion.router_addr(IA212).await.unwrap();

    // Spawn excluded receiver task
    let excluded_task = tokio::spawn(async move {
        // Try to receive on snap_socket with timeout to verify it doesn't get the packet
        let snap_timeout_result = timeout(Duration::from_millis(200), async {
            let mut buf = vec![0u8; 2048];
            snap_socket.recv_from(&mut buf).await
        })
        .await;

        if snap_timeout_result.is_ok() {
            panic!("SNAP socket received packet but it should have been excluded");
        }
        tracing::info!("SNAP socket correctly did not receive packet (timeout as expected)");

        // Now receive on excluded socket
        let mut buf = vec![0u8; 2048];
        let (len, src_addr) = timeout(Duration::from_secs(3), excluded_socket.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for packet at excluded socket")
            .expect("Failed to receive at excluded socket");
        buf.truncate(len);

        tracing::info!("Excluded socket received packet from {}", src_addr);

        let packet = ScionPacketUdp::decode(&mut buf.as_slice())
            .expect("Failed to decode SCION UDP packet at excluded socket");

        assert_eq!(
            packet.payload().as_ref(),
            test_payload_1,
            "Excluded socket received incorrect payload"
        );

        tracing::info!("Excluded socket verified payload, now sending response");

        // Test Case 2b: Excluded Socket → remote
        let reversed_path = packet
            .headers
            .path
            .to_reversed()
            .expect("Failed to reverse path");

        let response_pkt = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::from_std(IA132, excluded_addr),
                destination: packet.source().unwrap(),
            },
            reversed_path,
            test_payload_2.as_ref().into(),
        )
        .expect("Failed to create response packet");

        let response_raw = response_pkt.encode_to_bytes_vec().concat();
        excluded_socket
            .send_to(&response_raw, ia132_router_addr)
            .await
            .expect("Failed to send from excluded socket to router");

        tracing::info!("Excluded socket sent response");
    });

    // Test Case 2a: remote → Excluded Socket
    let packet_to_excluded = ScionPacketUdp::new(
        ByEndpoint {
            source: remote_scion_addr,
            destination: excluded_scion_addr,
        },
        DataPlanePath::Standard(scion_path()),
        test_payload_1.as_ref().into(),
    )
    .expect("Failed to create packet to excluded");

    let pkt_raw = packet_to_excluded.encode_to_bytes_vec().concat();
    remote_socket
        .send_to(&pkt_raw, ia212_router_addr)
        .await
        .expect("Failed to send from remote");
    tracing::info!("Remote sent packet to excluded socket");

    // Wait for excluded task to complete
    excluded_task.await.expect("Excluded task panicked");

    // Test Case 2b: Receive response from excluded
    let mut recv_buf = vec![0u8; 2048];
    let (len, _) = timeout(
        Duration::from_secs(3),
        remote_socket.recv_from(&mut recv_buf),
    )
    .await
    .expect("Timeout waiting for response at remote")
    .expect("Failed to receive at remote socket");
    recv_buf.truncate(len);

    let response_pkt =
        ScionPacketUdp::decode(&mut recv_buf.as_slice()).expect("Failed to decode response packet");

    tracing::info!("Remote received response from excluded");

    assert_eq!(
        response_pkt.payload().as_ref(),
        test_payload_2,
        "Remote received incorrect payload from excluded"
    );

    tracing::info!("SNAP excluded networks test completed successfully");
}

async fn setup_pocketscion() -> PocketScionHandle {
    setup_pocketscion_router(vec![], BTreeMap::new()).await
}

async fn setup_pocketscion_router(
    snap_data_plane_excludes: Vec<IpNet>,
    snap_data_plane_interfaces: BTreeMap<String, std::net::SocketAddr>,
) -> PocketScionHandle {
    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let _router1 = pstate.add_router(
        IA132,
        vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
        snap_data_plane_excludes,
        snap_data_plane_interfaces,
    );
    let _router2 = pstate.add_router(
        IA212,
        vec![NonZeroU16::new(3).unwrap(), NonZeroU16::new(4).unwrap()],
        vec![],
        BTreeMap::new(),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .expect("Failed to start PocketScion runtime");

    let api_client = pocketscion.api_client();

    PocketScionHandle::new(pocketscion, api_client)
}
