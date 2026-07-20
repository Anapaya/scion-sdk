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

use std::{collections::BTreeMap, num::NonZeroU16, time::Duration, vec};

use chrono::Utc;
use ipnet::IpNet;
use pocketscion::{
    runtime::{PocketScionRuntime, builder::PocketScionRuntimeBuilder},
    state::PocketScionState,
    util::topologies::{IA132, IA212},
};
use sciparse::{
    address::{addr::ScionAddr, socket_addr::ScionSocketAddr},
    core::{convert::TryFromView, encode::WireEncode, model::Model, view::View},
    dataplane_path::view::ScionDpPathViewExt,
    packet::model::{ScionScmpPacket, ScionUdpPacket},
    payload::scmp::model::{ScmpEchoRequest, ScmpExternalInterfaceDown, ScmpMessage},
};
use test_log::test;
use tokio::time::timeout;

// Test implementing a simple echo of an echo client and echo server using pocketscion in router
// mode, i.e., without SNAPs.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn echo() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let pocketscion = setup_pocketscion().await;

    let ia132_router_addr = pocketscion.router_ia132_addr;

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

        let (packet, rest) =
            ScionUdpPacket::try_from_slice(&buf).expect("Failed to decode SCION UDP packet");
        debug_assert!(rest.is_empty(), "packet was not fully consumed");

        tracing::info!(
            "Server received packet from {}: {}",
            packet.src_scion_addr().unwrap(),
            String::from_utf8_lossy(&packet.payload.payload)
        );

        let response_payload =
            format!("Echo: {}", String::from_utf8_lossy(&packet.payload.payload));
        let response_path = packet
            .header
            .path
            .clone()
            .try_into_reversed()
            .expect("Failed to reverse path");

        let response_pkt = ScionUdpPacket::new(
            packet.dst_socket_addr().unwrap(),
            packet.src_socket_addr().unwrap(),
            response_path.clone(),
            response_payload.into(),
        );

        let pkt = response_pkt
            .into_raw()
            .try_encode_to_owned_view()
            .expect("Failed to encode response SCION UDP packet");
        debug_assert!(rest.is_empty(), "response packet was not fully consumed");

        server_socket
            .send_to(pkt.as_slice(), src_addr)
            .await
            .expect("Failed to send packet");
    });

    let dp_path = pocketscion
        .runtime
        .paths(IA132, IA212, Utc::now())
        .unwrap()
        .remove(0)
        .dp_path()
        .to_model();

    // Spawn a task for the client.
    let client_task = tokio::spawn(async move {
        // Construct a simple SCION UDP packet.
        let packet = ScionUdpPacket::new(
            ScionSocketAddr::new(IA132, client_addr.ip().into(), client_addr.port()),
            ScionSocketAddr::new(IA212, server_addr.ip().into(), server_addr.port()),
            dp_path,
            b"Hello SCION!".as_ref().into(),
        );

        let pkt_raw = packet
            .into_raw()
            .try_encode_to_owned_view()
            .expect("Failed to encode SCION UDP packet");

        client_socket
            .send_to(pkt_raw.as_slice(), ia132_router_addr)
            .await
            .expect("Failed to send packet");

        let mut recv_buf = vec![0u8; 2048];
        let (len, _) = client_socket
            .recv_from(&mut recv_buf)
            .await
            .expect("Failed to receive packet");
        recv_buf.truncate(len);

        let (pkt, rest) = ScionUdpPacket::try_from_slice(recv_buf.as_slice())
            .expect("Failed to decode response SCION UDP packet");

        debug_assert!(rest.is_empty(), "response packet was not fully consumed");

        tracing::info!(
            "Client received packet from {}: {}",
            pkt.src_socket_addr().unwrap(),
            String::from_utf8_lossy(pkt.payload.payload.as_ref())
        );

        assert_eq!(
            pkt.payload.payload, b"Echo: Hello SCION!",
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
    scion_sdk_utils::rustls::select_ring_crypto_provider();
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

            let (packet, rest) = ScionScmpPacket::try_from_slice(buf.as_slice())
                .expect("Failed to decode SCION SCMP packet");

            debug_assert!(rest.is_empty(), "packet was not fully consumed");

            tracing::info!(
                "Receiver received SCMP packet from {}: {:?}",
                packet.src_scion_addr().unwrap(),
                packet.payload
            );

            let src = packet
                .src_scion_addr()
                .expect("Failed to get source SCION address");
            let dst = packet
                .dst_scion_addr()
                .expect("Failed to get destination SCION address");

            // Send a simple acknowledgment back
            let response_payload = b"SCMP received";
            let response_pkt = ScionUdpPacket::new(
                ScionSocketAddr::new(dst.isd_asn(), dst.host(), receiver_addr.port()),
                ScionSocketAddr::new(src.isd_asn(), src.host(), sender_addr.port()),
                packet
                    .header
                    .path
                    .try_into_reversed()
                    .expect("Failed to reverse path"),
                response_payload.as_ref().into(),
            );

            let resp_raw = response_pkt
                .into_raw()
                .try_encode_to_owned_view()
                .expect("Failed to encode response SCION UDP packet");

            receiver_socket
                .send_to(resp_raw.as_slice(), src_addr)
                .await
                .expect("Failed to send packet");
        }
    });

    // Spawn a task for the sender.
    let ia132_router_addr = pocketscion.router_ia132_addr;
    let dp_path = pocketscion
        .runtime
        .paths(IA132, IA212, Utc::now())
        .unwrap()
        .remove(0)
        .dp_path()
        .to_model();

    let sender_task = tokio::spawn(async move {
        // Send SCMP echo request with correct identifier (receiver's port)
        let echo_request = ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            receiver_addr.port(),
            1,
            b"echo test data".to_vec(),
        ));

        let echo_packet = ScionScmpPacket::new(
            ScionAddr::new(IA132, sender_addr.ip().into()),
            ScionAddr::new(IA212, receiver_addr.ip().into()),
            dp_path.clone(),
            echo_request,
        );

        let echo_raw = echo_packet
            .into_raw()
            .try_encode_to_owned_view()
            .expect("Failed to encode SCMP echo packet");
        sender_socket
            .send_to(echo_raw.as_slice(), ia132_router_addr)
            .await
            .expect("Failed to send SCMP echo packet");

        // Send SCMP external interface down with quoted UDP packet
        // Create a UDP packet that will be quoted in the SCMP error
        let quoted_udp = ScionUdpPacket::new(
            ScionSocketAddr::new(IA212, receiver_addr.ip().into(), receiver_addr.port()), /* receiver as source */
            ScionSocketAddr::new(IA132, sender_addr.ip().into(), sender_addr.port()), /* sender as destination */
            dp_path.clone(),
            b"quoted payload".to_vec(),
        );

        let interface_down = ScmpMessage::ExternalInterfaceDown(ScmpExternalInterfaceDown::new(
            IA132,
            42,
            quoted_udp
                .try_encode_to_vec()
                .expect("Failed to encode quoted UDP packet"),
        ));

        let interface_down_packet = ScionScmpPacket::new(
            ScionAddr::new(IA132, sender_addr.ip().into()),
            ScionAddr::new(IA212, receiver_addr.ip().into()),
            dp_path,
            interface_down,
        );

        let interface_down_raw = interface_down_packet
            .into_raw()
            .try_encode_to_owned_view()
            .expect("Failed to encode SCMP interface down packet");

        sender_socket
            .send_to(interface_down_raw.as_slice(), ia132_router_addr)
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

            let (pkt, rest) = ScionUdpPacket::try_from_slice(recv_buf.as_slice())
                .expect("Failed to decode response SCION UDP packet");
            debug_assert!(rest.is_empty(), "response packet was not fully consumed");

            tracing::info!(
                "Sender received acknowledgment from {}: {}",
                pkt.src_socket_addr().unwrap(),
                String::from_utf8_lossy(&pkt.payload.payload)
            );

            assert_eq!(
                &pkt.payload.payload,
                b"SCMP received".as_ref(),
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
    scion_sdk_utils::rustls::select_ring_crypto_provider();
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
    let ia132_router_addr = pocketscion.router_ia132_addr;
    let ia212_router_addr = pocketscion.router_ia212_addr;

    // Hypothetical endhost behind the SNAP (packets to this address are forwarded to snap_socket)
    let endhost_behind_snap_addr = "10.0.0.42:8080".parse::<std::net::SocketAddr>().unwrap();
    let endhost_behind_snap_scion_addr = ScionSocketAddr::new(
        IA132,
        endhost_behind_snap_addr.ip().into(),
        endhost_behind_snap_addr.port(),
    );

    tracing::info!(
        %snap_addr,
        %remote_addr,
        %endhost_behind_snap_addr,
        "Starting SNAP interface forwarding test"
    );

    let remote_scion_addr =
        ScionSocketAddr::new(IA212, remote_addr.ip().into(), remote_addr.port());
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

        let (packet, rest) = ScionUdpPacket::try_from_slice(buf.as_slice())
            .expect("Failed to decode SCION UDP packet at SNAP socket");
        debug_assert!(rest.is_empty(), "response packet was not fully consumed");

        assert_eq!(
            &packet.payload.payload, test_payload_1,
            "SNAP socket received incorrect payload"
        );
        assert_eq!(
            packet
                .dst_socket_addr()
                .expect("Failed to get destination SCION socket address"),
            endhost_behind_snap_scion_addr,
            "Packet destination should be the endhost behind SNAP"
        );

        tracing::info!("SNAP socket verified payload, now sending response");

        // Test Case 1b: SNAP Socket → remote
        let reversed_path = packet
            .header
            .path
            .clone()
            .try_into_reversed()
            .expect("Failed to reverse path");

        let response_pkt = ScionUdpPacket::new(
            endhost_behind_snap_scion_addr,
            packet
                .src_socket_addr()
                .expect("Failed to get source SCION socket address"),
            reversed_path,
            test_payload_2.as_ref().into(),
        );

        let response_raw = response_pkt
            .try_encode_to_vec()
            .expect("Failed to encode response SCION UDP packet");

        snap_socket
            .send_to(&response_raw, ia132_router_addr)
            .await
            .expect("Failed to send from SNAP socket to router");

        tracing::info!("SNAP socket sent response");
    });

    let dp_path = pocketscion
        .runtime
        .paths(IA212, IA132, Utc::now())
        .unwrap()
        .remove(0)
        .dp_path()
        .to_model();

    // Test Case 1a: remote → endhost behind SNAP
    let packet_to_snap = ScionUdpPacket::new(
        remote_scion_addr,
        endhost_behind_snap_scion_addr,
        dp_path,
        test_payload_1.to_vec(),
    );

    let pkt_raw = packet_to_snap
        .try_encode_to_vec()
        .expect("Failed to encode SCION UDP packet");
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

    let (response_pkt, rest) = ScionUdpPacket::try_from_slice(recv_buf.as_slice())
        .expect("Failed to decode response packet");
    debug_assert!(rest.is_empty(), "response packet was not fully consumed");
    tracing::info!("Remote received response from endhost behind SNAP");

    assert_eq!(
        &response_pkt.payload.payload, test_payload_2,
        "Remote received incorrect payload from endhost behind SNAP"
    );
    assert_eq!(
        response_pkt
            .src_socket_addr()
            .expect("Failed to get source SCION socket address"),
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
    scion_sdk_utils::rustls::select_ring_crypto_provider();
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

    let excluded_scion_addr =
        ScionSocketAddr::new(IA132, excluded_addr.ip().into(), excluded_addr.port());
    let remote_scion_addr =
        ScionSocketAddr::new(IA212, remote_addr.ip().into(), remote_addr.port());
    let test_payload_1 = b"Test from remote to excluded";
    let test_payload_2 = b"Response from excluded to remote";

    let ia132_router_addr = pocketscion.router_ia132_addr;
    let ia212_router_addr = pocketscion.router_ia212_addr;

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

        let (packet, rest) = ScionUdpPacket::try_from_slice(buf.as_slice())
            .expect("Failed to decode SCION UDP packet at excluded socket");
        debug_assert!(rest.is_empty(), "packet was not fully consumed");

        assert_eq!(
            &packet.payload.payload, test_payload_1,
            "Excluded socket received incorrect payload"
        );

        tracing::info!("Excluded socket verified payload, now sending response");

        // Test Case 2b: Excluded Socket → remote
        let reversed_path = packet
            .header
            .path
            .clone()
            .try_into_reversed()
            .expect("Failed to reverse path");

        let response_pkt = ScionUdpPacket::new(
            ScionSocketAddr::new(IA132, excluded_addr.ip().into(), excluded_addr.port()),
            packet.src_socket_addr().unwrap(),
            reversed_path,
            test_payload_2.as_ref().into(),
        );

        let response_raw = response_pkt
            .try_encode_to_vec()
            .expect("Failed to encode response SCION UDP packet");

        excluded_socket
            .send_to(&response_raw, ia132_router_addr)
            .await
            .expect("Failed to send from excluded socket to router");

        tracing::info!("Excluded socket sent response");
    });

    let dp_path = pocketscion
        .runtime
        .paths(IA212, IA132, Utc::now())
        .unwrap()
        .remove(0)
        .dp_path()
        .to_model();

    // Test Case 2a: remote → Excluded Socket
    let packet_to_excluded = ScionUdpPacket::new(
        remote_scion_addr,
        excluded_scion_addr,
        dp_path,
        test_payload_1.as_ref().into(),
    );

    let pkt_raw = packet_to_excluded
        .try_encode_to_vec()
        .expect("Failed to encode SCION UDP packet");

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

    let (response_pkt, rest) = ScionUdpPacket::try_from_slice(recv_buf.as_slice())
        .expect("Failed to decode response packet");
    debug_assert!(rest.is_empty(), "response packet was not fully consumed");

    tracing::info!("Remote received response from excluded");

    assert_eq!(
        &response_pkt.payload.payload, test_payload_2,
        "Remote received incorrect payload from excluded"
    );

    tracing::info!("SNAP excluded networks test completed successfully");
}

async fn setup_pocketscion() -> PocketScionSetup {
    setup_pocketscion_router(vec![], BTreeMap::new()).await
}

struct PocketScionSetup {
    runtime: PocketScionRuntime,
    router_ia132_addr: std::net::SocketAddr,
    router_ia212_addr: std::net::SocketAddr,
}

async fn setup_pocketscion_router(
    snap_data_plane_excludes: Vec<IpNet>,
    snap_data_plane_interfaces: BTreeMap<String, std::net::SocketAddr>,
) -> PocketScionSetup {
    let mut pstate = PocketScionState::new(Utc::now());

    let router132 = pstate.add_router(
        IA132,
        vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
        snap_data_plane_excludes,
        snap_data_plane_interfaces,
    );
    let router212 = pstate.add_router(
        IA212,
        vec![NonZeroU16::new(3).unwrap(), NonZeroU16::new(4).unwrap()],
        vec![],
        BTreeMap::new(),
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate)
        .start()
        .await
        .expect("Failed to start PocketScion runtime");

    let ia132_router_addr = pocketscion.router_socket_addr(router132).unwrap();
    let ia212_router_addr = pocketscion.router_socket_addr(router212).unwrap();

    PocketScionSetup {
        runtime: pocketscion,
        router_ia132_addr: ia132_router_addr,
        router_ia212_addr: ia212_router_addr,
    }
}
