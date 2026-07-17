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
//! Integration tests for basic functionality of PocketSCION.

use std::{
    net::{self, IpAddr},
    time::Duration,
};

use bytes::Bytes;
use chrono::Utc;
use pocketscion::util::topologies::{
    IA132, IA212, PsSetup, UnderlayType, minimal::two_path_topology,
};
use scion_stack::{
    path::manager::traits::PathManager,
    stack::{ScionSocketBindError, ScionStackBuilder},
};
use sciparse::{
    address::{
        addr::ScionAddr, ip_addr::ScionIpAddr, ip_socket_addr::ScionSocketIpAddr,
        socket_addr::ScionSocketAddr,
    },
    core::{model::Model, view::View},
    dataplane_path::{model::DpPath, view::ScionDpPathViewExt},
    identifier::isd_asn::IsdAsn,
    packet::{
        model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
        view::ScionRawPacketView,
    },
    payload::{
        ProtocolNumber,
        scmp::{
            model::{ScmpEchoReply, ScmpMessage},
            view::ScmpMessageView,
        },
    },
};
use snap_tokens::v0::dummy_snap_token;
use test_log::test;
use tokio::net::UdpSocket;
use tracing::info;

const MS_100: Duration = Duration::from_millis(1000);

// Macro to assert that operation finishes within the given duration.
macro_rules! within_duration {
    ($duration:expr, $result:expr) => {
        tokio::time::timeout($duration, $result)
            .await
            .expect("operation timed out")
    };
}

#[test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_bind_two_sockets_send_receive_snap() {
    test_bind_two_sockets_send_receive_impl(two_path_topology(UnderlayType::Snap).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(5_000)]
async fn test_bind_two_sockets_send_receive_udp() {
    test_bind_two_sockets_send_receive_impl(two_path_topology(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_snap() {
    test_bind_with_specific_address_impl(two_path_topology(UnderlayType::Snap).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_udp() {
    test_bind_with_specific_address_impl(two_path_topology(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_snap() {
    test_bind_port_already_in_use_impl(two_path_topology(UnderlayType::Snap).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_udp() {
    test_bind_port_already_in_use_impl(two_path_topology(UnderlayType::Udp).await).await;
}

async fn test_bind_two_sockets_send_receive_impl(ps: PsSetup) {
    let sender_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    // Bind sender and receiver sockets
    let sender_socket = sender_stack.bind(None).await.unwrap();
    let sender_addr = sender_socket.local_addr();

    info!("sender socket bound to {sender_addr:?}");

    let receiver_socket = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    info!("receiver socket bound to {receiver_addr:?}");

    // Send packet from sender to receiver
    let test_data = Bytes::from("Hello, World!");
    let mut recv_buffer = [0u8; 1024];

    tokio::join!(
        async {
            let (len, source) = receiver_socket.recv_from(&mut recv_buffer).await.unwrap();
            assert_eq!(
                &recv_buffer[..len],
                test_data.as_ref(),
                "receiver should receive packets"
            );
            assert_eq!(
                source, sender_addr,
                "receiver should receive packets from the sender"
            );
        },
        async {
            sender_socket
                .send_to(test_data.as_ref(), receiver_addr)
                .await
                .unwrap_or_else(|e| {
                    panic!("error sending from {sender_addr:?} to {receiver_addr:?}: {e:?}");
                });
        },
    );
}

async fn test_bind_with_specific_address_impl(ps: PsSetup) {
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let scion_addr = ScionIpAddr::new(
        *stack.local_ases().first().unwrap(),
        "127.0.0.1".parse::<IpAddr>().unwrap(),
    );
    let port = {
        let bind_host = "127.0.0.1".parse().unwrap();
        let sock = UdpSocket::bind(net::SocketAddr::new(bind_host, 0))
            .await
            .unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock);
        port
    };
    let specific_addr = ScionSocketIpAddr::new(scion_addr.isd_asn(), scion_addr.ip(), port);
    let socket = stack.bind(Some(specific_addr)).await.unwrap();

    assert_eq!(socket.local_addr(), specific_addr);
}

async fn test_bind_port_already_in_use_impl(ps: PsSetup) {
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    // First bind should succeed
    let socket = stack.bind(None).await.unwrap();
    let addr = socket.local_addr();
    info!("First socket address: {addr:?}");

    // Second bind to same port should fail
    let result = stack.bind(Some(addr)).await;
    assert!(
        matches!(result, Err(ScionSocketBindError::PortAlreadyInUse(port)) if port == addr.port()),
        "expected PortAlreadyInUse({}) when binding to same port twice, got {result:?}",
        addr.port()
    );
    // Make sure the socket is only dropped now.
    info!("Socket is still around: {:?}", socket.local_addr());
    drop(socket);
}

/// Test that an SCMP socket receives SCMP messages.
async fn test_scmp_with_port_is_received_scmp_impl(ps: PsSetup) {
    let sender_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build sender SCION stack");

    let receiver_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build receiver SCION stack");

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_scmp(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    let echo_data = b"ping test data".to_vec();
    let sequence = 1u16;

    // Create an SCMP echo request
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_addr.isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();

    let echo_request = ScionScmpPacket::new(
        sender.local_addr().scion_addr(),
        receiver_addr.scion_addr(),
        path.dp_path().to_model(),
        ScmpEchoReply::new(receiver_addr.port(), sequence, echo_data.clone()).into(),
    )
    .try_encode_to_owned_view()
    .expect("should encode");

    tracing::info!(src = %sender.local_addr(), dst = %receiver_addr, "Sending echo reply");

    tokio::join!(
        async {
            // The test SCMP handler should receive the echo request
            match within_duration!(MS_100, receiver.recv_from()) {
                Ok((scmp_msg, src_addr)) => {
                    match scmp_msg.message() {
                        ScmpMessageView::EchoReply(rep) => {
                            assert_eq!(rep.identifier(), receiver_addr.port());
                            assert_eq!(rep.sequence_number(), sequence);
                            assert_eq!(rep.data(), echo_data);
                        }
                        _ => panic!("Expected echo reply, got: {:?}", scmp_msg),
                    }
                    assert_eq!(src_addr, sender.local_addr().scion_addr());
                }
                Err(e) => {
                    panic!("Error receiving echo reply: {e:?}");
                }
            }
        },
        async {
            within_duration!(MS_100, sender.send(echo_request.as_raw()))
                .expect("error sending echo reply");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_scmp_udp_impl() {
    test_scmp_with_port_is_received_scmp_impl(two_path_topology(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_scmp_snap_impl() {
    test_scmp_with_port_is_received_scmp_impl(two_path_topology(UnderlayType::Snap).await).await;
}

/// Test that a Raw socket receives SCMP messages.
async fn test_scmp_with_port_is_received_raw_impl(ps: PsSetup) {
    let sender_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build sender SCION stack");

    let receiver_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA212).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build receiver SCION stack");

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    let echo_data = b"ping test data".to_vec();
    let sequence = 1u16;

    // Create an SCMP echo reply
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_addr.isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let echo_reply = ScionScmpPacket::new(
        sender.local_addr().scion_addr(),
        receiver_addr.scion_addr(),
        path.dp_path().to_model(),
        ScmpMessage::EchoReply(ScmpEchoReply::new(
            receiver_addr.port(),
            sequence,
            echo_data.clone(),
        )),
    )
    .try_encode_to_owned_view()
    .expect("should encode");

    tracing::info!(src = %sender.local_addr(), dst = %receiver_addr, "Sending echo reply");

    tokio::join!(
        async {
            // The Raw socket should receive the echo request
            match within_duration!(MS_100, receiver.recv()) {
                Ok(raw) => {
                    let scmp_pkt = raw.try_into_scmp().expect("invalid scmp packet");
                    match scmp_pkt.scmp().message() {
                        ScmpMessageView::EchoReply(rep) => {
                            assert_eq!(rep.identifier(), receiver_addr.port());
                            assert_eq!(rep.sequence_number(), sequence);
                            assert_eq!(rep.data(), echo_data);
                        }
                        msg => panic!("Expected echo reply, got: {:?}", msg),
                    }
                }
                Err(e) => {
                    panic!("Error receiving echo reply: {e:?}");
                }
            }
        },
        async {
            within_duration!(MS_100, sender.send(echo_reply.as_raw()))
                .expect("error sending echo reply");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_raw_udp_impl() {
    test_scmp_with_port_is_received_raw_impl(two_path_topology(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_raw_snap_impl() {
    test_scmp_with_port_is_received_raw_impl(two_path_topology(UnderlayType::Snap).await).await;
}

/// Creates a raw SCION packet with unknown next_header (67) for local communication.
fn create_unknown_next_header_packet(
    source: ScionAddr,
    destination: ScionAddr,
    payload: Vec<u8>,
) -> ScionRawPacket {
    ScionRawPacket::new(
        source,
        destination,
        sciparse::dataplane_path::model::DpPath::Empty,
        ProtocolNumber::Other(67),
        payload,
    )
}

/// Sends a raw SCION packet directly to a SCION socket via tokio::UdpSocket.
async fn send_raw_packet_directly(
    packet: ScionRawPacket,
    target_socket_addr: ScionSocketIpAddr,
) -> Result<(), std::io::Error> {
    let target_addr = target_socket_addr.socket_addr();
    let sender_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let packet_bytes = packet.try_encode_to_owned_view().expect("failed to encode");

    sender_socket
        .send_to(packet_bytes.as_slice(), target_addr)
        .await?;
    Ok(())
}

/// Test that a UDP socket ignores packets with unknown next_header (67).
async fn test_udp_socket_ignores_unknown_next_header_impl() {
    let ps = two_path_topology(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = b"unknown next_header test".to_vec();
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_addr(),
        receiver_addr.scion_addr(),
        test_payload,
    );

    // Send the packet directly
    send_raw_packet_directly(packet, receiver_addr)
        .await
        .expect("Failed to send packet directly");

    // The UDP socket should NOT receive the packet (should timeout)
    let mut recv_buffer = [0u8; 1024];
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        receiver_socket.recv_from(&mut recv_buffer),
    )
    .await;
    assert!(
        result.is_err(),
        "UDP socket should ignore packets with unknown next_header, but received a packet"
    );
}

/// Test that an SCMP socket ignores packets with unknown next_header (67).
async fn test_scmp_socket_ignores_unknown_next_header_impl() {
    let ps = two_path_topology(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind_scmp(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = b"unknown next_header test".to_vec();
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_addr(),
        receiver_addr.scion_addr(),
        test_payload,
    );

    // Send the packet directly
    send_raw_packet_directly(packet, receiver_addr)
        .await
        .expect("Failed to send packet directly");

    // The SCMP socket should NOT receive the packet (should timeout)
    let result =
        tokio::time::timeout(Duration::from_millis(300), receiver_socket.recv_from()).await;
    assert!(
        result.is_err(),
        "SCMP socket should ignore packets with unknown next_header, but received a packet"
    );
}

/// Test that a RAW socket receives packets with unknown next_header (67).
async fn test_raw_socket_receives_unknown_next_header_impl() {
    let ps = two_path_topology(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = b"unknown next_header test".to_vec();
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_addr(),
        receiver_addr.scion_addr(),
        test_payload.clone(),
    );

    tokio::join!(
        async {
            // The RAW socket SHOULD receive the packet
            match within_duration!(MS_100, receiver_socket.recv()) {
                Ok(raw) => {
                    assert_eq!(
                        raw.payload(),
                        test_payload,
                        "RAW socket should receive the packet with unknown next_header"
                    );
                    assert_eq!(
                        raw.header().next_header(),
                        ProtocolNumber::Other(67),
                        "Received packet should have next_header=67"
                    );
                }
                Err(e) => {
                    panic!(
                        "RAW socket should receive packets with unknown next_header, but got error: {e:?}"
                    );
                }
            }
        },
        async {
            // Send the packet directly
            within_duration!(MS_100, send_raw_packet_directly(packet, receiver_addr))
                .expect("Failed to send packet directly");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_udp_socket_ignores_unknown_next_header() {
    test_udp_socket_ignores_unknown_next_header_impl().await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_socket_ignores_unknown_next_header() {
    test_scmp_socket_ignores_unknown_next_header_impl().await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_raw_socket_receives_unknown_next_header() {
    test_raw_socket_receives_unknown_next_header_impl().await;
}

/// Test that AS-local packets are correctly received or filtered.
///
/// Tests:
/// 1. Packet with correct ISD-AS → received
/// 2. Packet with ISD-AS 0-0 (wildcard/unset) → dropped
/// 3. Packet with wrong destination IP → dropped
/// 4. Packet with wrong destination port → dropped
async fn test_as_local_packets_impl(ps: PsSetup) {
    let sender_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build sender SCION stack");

    let receiver_stack = ScionStackBuilder::new()
        .with_endhost_api(ps.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build receiver SCION stack");

    let sender_raw = sender_stack.bind_raw(None).await.unwrap();
    let receiver_udp = receiver_stack.bind(None).await.unwrap();

    let sender_addr = sender_raw.local_addr();
    let receiver_addr = receiver_udp.local_addr();

    info!("Sender raw socket: {sender_addr:?}");
    info!("Receiver UDP socket: {receiver_addr:?}");

    let receiver_ip = receiver_addr.ip();

    // Helper to create a UDP-over-SCION packet as ScionPacketRaw.
    let local_packet = |dst: ScionSocketAddr, payload: &[u8]| -> Box<ScionRawPacketView> {
        ScionUdpPacket::new(sender_addr.into(), dst, DpPath::Empty, payload.to_vec())
            .try_encode_to_owned_view()
            .expect("should encode")
            .into()
    };

    let mut recv_buf = [0u8; 1024];

    // Test 1: Correct ISD-AS → should be received.
    {
        let payload = b"correct IA";
        let dst = ScionSocketAddr::new(IA132, receiver_ip.into(), receiver_addr.port());
        let pkt = local_packet(dst, payload);
        sender_raw.send(&pkt).await.unwrap();
        let (len, src) = within_duration!(MS_100, receiver_udp.recv_from(&mut recv_buf)).unwrap();
        assert_eq!(
            &recv_buf[..len],
            payload.as_slice(),
            "should receive packet with correct ISD-AS"
        );
        assert_eq!(src.isd_asn(), sender_addr.isd_asn());
    }

    // Test 2: ISD-AS 0-0 (wildcard/unset) → should be dropped.
    {
        let payload = b"wildcard IA";
        let dst = ScionSocketAddr::new(IsdAsn::WILDCARD, receiver_ip.into(), receiver_addr.port());
        let pkt = local_packet(dst, payload);
        let result = sender_raw.send(&pkt).await;
        assert!(
            result.is_err(),
            "sending packet with wildcard ISD-AS should fail",
        );
    }

    // Test 3: Wrong destination IP → should be dropped.
    {
        let wrong_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let dst = ScionSocketAddr::new(IA132, wrong_ip.into(), receiver_addr.port());
        let pkt = local_packet(dst, b"wrong ip");
        sender_raw.send(&pkt).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            receiver_udp.recv_from(&mut recv_buf),
        )
        .await;
        assert!(
            result.is_err(),
            "should not receive packet with wrong destination IP"
        );
    }

    // Test 4: Wrong destination port → should be dropped.
    {
        let wrong_port = receiver_addr.port().wrapping_add(1);
        let dst = ScionSocketAddr::new(
            receiver_addr.isd_asn(),
            receiver_addr.host().into(),
            wrong_port,
        );
        let pkt = local_packet(dst, b"wrong port");
        sender_raw.send(&pkt).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            receiver_udp.recv_from(&mut recv_buf),
        )
        .await;
        assert!(
            result.is_err(),
            "should not receive packet with wrong destination port"
        );
    }
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_as_local_packets() {
    test_as_local_packets_impl(two_path_topology(UnderlayType::Udp).await).await;
}
