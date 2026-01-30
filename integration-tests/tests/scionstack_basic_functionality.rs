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
use integration_tests::{PocketscionTestEnv, UnderlayType, minimal_pocketscion_setup};
use scion_proto::{
    address::{ScionAddr, SocketAddr},
    packet::{ByEndpoint, FlowId, ScionPacketRaw, ScionPacketScmp},
    path::DataPlanePath,
    scmp::{ScmpEchoReply, ScmpMessage},
    wire_encoding::WireEncodeVec,
};
use scion_stack::{
    path::manager::traits::PathManager,
    scionstack::{ScionSocketBindError, ScionStackBuilder},
};
use snap_tokens::snap_token::dummy_snap_token;
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
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_snap() {
    test_bind_two_sockets_send_receive_impl(minimal_pocketscion_setup(UnderlayType::Snap).await)
        .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_udp() {
    test_bind_two_sockets_send_receive_impl(minimal_pocketscion_setup(UnderlayType::Udp).await)
        .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_snap() {
    test_bind_with_specific_address_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_udp() {
    test_bind_with_specific_address_impl(UnderlayType::Udp).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_snap() {
    test_bind_port_already_in_use_impl(minimal_pocketscion_setup(UnderlayType::Snap).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_udp() {
    test_bind_port_already_in_use_impl(minimal_pocketscion_setup(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_snap() {
    test_quic_endpoint_creation_impl(minimal_pocketscion_setup(UnderlayType::Snap).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_udp() {
    test_quic_endpoint_creation_impl(minimal_pocketscion_setup(UnderlayType::Udp).await).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_endpoints_socket_already_in_use() {
    let first_endpoint = quinn::Endpoint::client(("0.0.0.0:0").parse().unwrap()).unwrap();
    let local_addr = first_endpoint.local_addr().unwrap();
    info!("Local address: {local_addr:?}");
    let second_endpoint = quinn::Endpoint::client(local_addr);
    assert!(
        second_endpoint.is_err(),
        "expected error but got {second_endpoint:?}"
    );
    info!("Local address again: {:?}", first_endpoint.local_addr());
}

async fn test_bind_two_sockets_send_receive_impl(test_env: PocketscionTestEnv) {
    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    // Bind sender and receiver sockets
    let sender_socket = sender_stack.bind(None).await.unwrap();
    let sender_addr = sender_socket.local_addr();

    let receiver_socket = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

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
                .unwrap_or_else(|_| {
                    panic!("error sending from {sender_addr:?} to {receiver_addr:?}")
                });
        },
    );
}

async fn test_bind_with_specific_address_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;

    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let scion_addr = ScionAddr::new(
        *stack.local_ases().first().unwrap(),
        "127.0.0.1".parse::<IpAddr>().unwrap().into(),
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
    let specific_addr = SocketAddr::new(scion_addr, port);
    let socket = stack.bind(Some(specific_addr)).await.unwrap();

    assert_eq!(socket.local_addr(), specific_addr);
}

async fn test_bind_port_already_in_use_impl(test_env: PocketscionTestEnv) {
    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
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

async fn test_quic_endpoint_creation_impl(test_env: PocketscionTestEnv) {
    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let endpoint = stack
        .quic_endpoint(None, quinn::EndpointConfig::default(), None, None)
        .await;

    assert!(endpoint.is_ok());
}

/// Test that an SCMP socket receives SCMP messages.
async fn test_scmp_with_port_is_received_scmp_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;
    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build sender SCION stack");

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build receiver SCION stack");

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_scmp(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    let echo_data = Bytes::from_static(b"ping test data");
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
    let echo_request = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_addr.scion_address(),
        },
        path.data_plane_path,
        ScmpMessage::EchoReply(ScmpEchoReply::new(
            receiver_addr.port(),
            sequence,
            echo_data.clone(),
        )),
    )
    .unwrap();

    tracing::info!(src = %sender.local_addr(), dst = %receiver_addr, "Sending echo reply");

    tokio::join!(
        async {
            // The test SCMP handler should receive the echo request
            match within_duration!(MS_100, receiver.recv_from()) {
                Ok((scmp_msg, src_addr)) => {
                    match scmp_msg {
                        ScmpMessage::EchoReply(rep) => {
                            assert_eq!(rep.identifier, receiver_addr.port());
                            assert_eq!(rep.sequence_number, sequence);
                            assert_eq!(rep.data, echo_data);
                        }
                        _ => panic!("Expected echo reply, got: {:?}", scmp_msg),
                    }
                    assert_eq!(src_addr, sender.local_addr().scion_address());
                }
                Err(e) => {
                    panic!("Error receiving echo reply: {e:?}");
                }
            }
        },
        async {
            within_duration!(MS_100, sender.send(echo_request.into()))
                .expect("error sending echo reply");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_scmp_udp_impl() {
    test_scmp_with_port_is_received_scmp_impl(UnderlayType::Udp).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_scmp_snap_impl() {
    test_scmp_with_port_is_received_scmp_impl(UnderlayType::Snap).await;
}

/// Test that a Raw socket receives SCMP messages.
async fn test_scmp_with_port_is_received_raw_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;
    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build sender SCION stack");

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build receiver SCION stack");

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    let echo_data = Bytes::from_static(b"ping test data");
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
    let echo_reply = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_addr.scion_address(),
        },
        path.data_plane_path,
        ScmpMessage::EchoReply(ScmpEchoReply::new(
            receiver_addr.port(),
            sequence,
            echo_data.clone(),
        )),
    )
    .unwrap();

    tracing::info!(src = %sender.local_addr(), dst = %receiver_addr, "Sending echo reply");

    tokio::join!(
        async {
            // The Raw socket should receive the echo request
            match within_duration!(MS_100, receiver.recv()) {
                Ok(raw) => {
                    let scmp_pkt: ScionPacketScmp = raw.try_into().expect("invalid scmp packet");
                    match scmp_pkt.message {
                        ScmpMessage::EchoReply(rep) => {
                            assert_eq!(rep.identifier, receiver_addr.port());
                            assert_eq!(rep.sequence_number, sequence);
                            assert_eq!(rep.data, echo_data);
                        }
                        _ => panic!("Expected echo reply, got: {:?}", scmp_pkt.message),
                    }
                }
                Err(e) => {
                    panic!("Error receiving echo reply: {e:?}");
                }
            }
        },
        async {
            within_duration!(MS_100, sender.send(echo_reply.into()))
                .expect("error sending echo reply");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_raw_udp_impl() {
    test_scmp_with_port_is_received_raw_impl(UnderlayType::Udp).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_with_port_is_received_raw_snap_impl() {
    test_scmp_with_port_is_received_raw_impl(UnderlayType::Snap).await;
}

/// Creates a raw SCION packet with unknown next_header (67) for local communication.
fn create_unknown_next_header_packet(
    source: ScionAddr,
    destination: ScionAddr,
    payload: Bytes,
) -> ScionPacketRaw {
    ScionPacketRaw::new(
        ByEndpoint {
            source,
            destination,
        },
        DataPlanePath::EmptyPath,
        payload,
        67, // Unknown next_header value
        FlowId::default(),
    )
    .expect("Failed to create raw SCION packet with unknown next_header")
}

/// Sends a raw SCION packet directly to a SCION socket via tokio::UdpSocket.
async fn send_raw_packet_directly(
    packet: ScionPacketRaw,
    target_socket_addr: SocketAddr,
) -> Result<(), std::io::Error> {
    let target_addr = target_socket_addr
        .local_address()
        .expect("Target socket must have a local address");

    let sender_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let packet_bytes = packet.encode_to_bytes_vec().concat();
    sender_socket.send_to(&packet_bytes, target_addr).await?;
    Ok(())
}

/// Test that a UDP socket ignores packets with unknown next_header (67).
async fn test_udp_socket_ignores_unknown_next_header_impl() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = Bytes::from_static(b"unknown next_header test");
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_address(),
        receiver_addr.scion_address(),
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
    let test_env = minimal_pocketscion_setup(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind_scmp(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = Bytes::from_static(b"unknown next_header test");
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_address(),
        receiver_addr.scion_address(),
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
    let test_env = minimal_pocketscion_setup(UnderlayType::Udp).await;
    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");

    let receiver_socket = stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    let test_payload = Bytes::from_static(b"unknown next_header test");
    let packet = create_unknown_next_header_packet(
        receiver_addr.scion_address(),
        receiver_addr.scion_address(),
        test_payload.clone(),
    );

    tokio::join!(
        async {
            // The RAW socket SHOULD receive the packet
            match within_duration!(MS_100, receiver_socket.recv()) {
                Ok(raw) => {
                    assert_eq!(
                        raw.payload, test_payload,
                        "RAW socket should receive the packet with unknown next_header"
                    );
                    assert_eq!(
                        raw.headers.common.next_header, 67,
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
