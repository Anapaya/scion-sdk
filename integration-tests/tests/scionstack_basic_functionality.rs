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
    future::Future,
    net::{self, IpAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use chrono::Utc;
use integration_tests::{
    PocketscionTestEnv, UnderlayType, minimal_pocketscion_setup, minimal_pocketscion_setup_v2,
};
use scion_proto::{
    address::{ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketScmp},
    scmp::{DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpEchoRequest, ScmpMessage},
};
use scion_stack::{
    path::manager::traits::PathManager,
    scionstack::{
        DEFAULT_RESERVED_TIME, NetworkError, ScionSocketBindError, ScionSocketSendError,
        ScionStackBuilder, ScmpHandler, builder::SnapUnderlayConfig,
    },
};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;
use tokio::{
    net::UdpSocket,
    sync::{
        Barrier,
        mpsc::{self, Sender},
    },
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
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

// Macro to assert that an operation does not finish within the given duration.
macro_rules! err_within_duration {
    ($duration:expr, $result:expr) => {
        assert!(
            tokio::time::timeout($duration, $result).await.is_err(),
            "operation did not time out within {:?}",
            $duration
        );
    };
}

// Helper struct for SCMP tests
struct TestScmpHandler {
    pub sender: Sender<ScionPacketScmp>,
}

impl ScmpHandler for TestScmpHandler {
    fn handle_packet(
        &self,
        packet: ScionPacketScmp,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move { self.sender.send(packet).await.unwrap() })
    }
}

impl TestScmpHandler {
    fn new(sender: Sender<ScionPacketScmp>) -> Self {
        Self { sender }
    }
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

async fn test_bind_two_sockets_send_receive_impl(test_env: PocketscionTestEnv, v2: bool) {
    let sender_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let receiver_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api212.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

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

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_snap() {
    test_bind_two_sockets_send_receive_impl(
        minimal_pocketscion_setup(UnderlayType::Snap).await,
        false,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_snap_v2() {
    test_bind_two_sockets_send_receive_impl(
        minimal_pocketscion_setup_v2(UnderlayType::Snap).await,
        true,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_udp() {
    test_bind_two_sockets_send_receive_impl(
        minimal_pocketscion_setup(UnderlayType::Udp).await,
        false,
    )
    .await;
}

async fn test_bind_with_specific_address_impl(underlay: UnderlayType, v2: bool) {
    let test_env = if v2 {
        minimal_pocketscion_setup_v2(underlay).await
    } else {
        minimal_pocketscion_setup(underlay).await
    };

    let mut builder =
        ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
    if v2 {
        builder = builder.with_use_v2();
    }
    let stack = builder.build().await.unwrap();

    let scion_addr = ScionAddr::new(
        *stack.local_ases().first().unwrap(),
        "10.132.0.1".parse::<IpAddr>().unwrap().into(),
    );
    let port = match underlay {
        UnderlayType::Snap => 8080,
        UnderlayType::Udp => {
            let bind_host = "10.132.0.1".parse().unwrap();
            let sock = UdpSocket::bind(net::SocketAddr::new(bind_host, 0))
                .await
                .unwrap();
            let port = sock.local_addr().unwrap().port();
            drop(sock);
            port
        }
    };
    let specific_addr = SocketAddr::new(scion_addr, port);
    let socket = stack.bind(Some(specific_addr)).await.unwrap();

    assert_eq!(socket.local_addr(), specific_addr);
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
#[ignore = "With the SCION stack v2 we can no longer return stacks local address before binding."]
async fn test_bind_with_specific_address_snap() {
    // On the snap underlay we can bind to any port without conflict.
    test_bind_with_specific_address_impl(UnderlayType::Snap, false).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
#[ignore = "With the SCION stack v2 we can no longer return stacks local address before binding."]
async fn test_bind_with_specific_address_snap_v2() {
    test_bind_with_specific_address_impl(UnderlayType::Snap, true).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
#[ignore = "With the SCION stack v2 we can no longer return stacks local address before binding."]
async fn test_bind_with_specific_address_udp() {
    test_bind_with_specific_address_impl(UnderlayType::Udp, false).await;
}

async fn test_bind_port_already_in_use_impl(test_env: PocketscionTestEnv, v2: bool) {
    let mut builder =
        ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
    if v2 {
        builder = builder.with_use_v2();
    }
    let stack = builder.build().await.unwrap();

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

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_snap() {
    test_bind_port_already_in_use_impl(minimal_pocketscion_setup(UnderlayType::Snap).await, false)
        .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_snap_v2() {
    test_bind_port_already_in_use_impl(
        minimal_pocketscion_setup_v2(UnderlayType::Snap).await,
        true,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_udp() {
    test_bind_port_already_in_use_impl(minimal_pocketscion_setup(UnderlayType::Udp).await, false)
        .await;
}

/// With the snap underlay ports are reserved for a fixed time.
/// With the udp underlay the reservation period is up to the operating system.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_port_reservation_timing_snap() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;

    let stack = Arc::new(
        ScionStackBuilder::new(test_env.eh_api132.url)
            .with_auth_token(dummy_snap_token())
            .build()
            .await
            .unwrap(),
    );
    info!("Stack local ASes: {:?}", stack.as_ref().local_ases());

    let initial_time = std::time::Instant::now();

    // Bind and immediately drop
    let addr = {
        let socket = stack
            .as_ref()
            .bind_with_time(None, initial_time)
            .await
            .unwrap();
        socket.local_addr()
    };

    // Immediate rebind should fail (port reserved)
    let bind_time = initial_time + Duration::from_secs(1);
    let result = stack.as_ref().bind_with_time(Some(addr), bind_time).await;
    assert!(
        matches!(result, Err(ScionSocketBindError::PortAlreadyInUse(port)) if port == addr.port()),
        "expected PortAlreadyInUse({}) when binding to reserved port, got {result:?}",
        addr.port()
    );

    // Bind with time after reservation timeout should succeed
    let socket = stack
        .as_ref()
        .bind_with_time(Some(addr), bind_time + DEFAULT_RESERVED_TIME)
        .await
        .unwrap();
    assert_eq!(socket.local_addr(), addr);
}

async fn test_quic_endpoint_creation_impl(test_env: PocketscionTestEnv, v2: bool) {
    let mut builder =
        ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
    if v2 {
        builder = builder.with_use_v2();
    }
    let stack = builder.build().await.unwrap();

    let endpoint = stack
        .quic_endpoint(None, quinn::EndpointConfig::default(), None, None)
        .await;

    assert!(endpoint.is_ok());
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_snap() {
    test_quic_endpoint_creation_impl(minimal_pocketscion_setup(UnderlayType::Snap).await, false)
        .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_snap_v2() {
    test_quic_endpoint_creation_impl(minimal_pocketscion_setup_v2(UnderlayType::Snap).await, true)
        .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_udp() {
    test_quic_endpoint_creation_impl(minimal_pocketscion_setup(UnderlayType::Udp).await, false)
        .await;
}

/// Test that if a UDP socket and Raw socket bind to the same socket address,
/// udp packets are delivered to the UDP socket and other packets are delivered to the Raw socket.
async fn test_udp_packet_dispatch_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;
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

    let sender = sender_stack.bind(None).await.unwrap();

    let udp0 = receiver_stack.bind(None).await.unwrap();
    let udp1 = receiver_stack
        .bind(Some(SocketAddr::new(udp0.local_addr().scion_address(), 0)))
        .await
        .unwrap();

    let raw0 = receiver_stack
        .bind_raw(Some(udp0.local_addr()))
        .await
        .unwrap();
    let raw1 = receiver_stack
        .bind_raw(Some(udp1.local_addr()))
        .await
        .unwrap();

    let test_data = Bytes::from("Hello, World!");

    tokio::join!(
        async {
            let mut recv_buffer = [0u8; 1024];
            let (len, source) = within_duration!(MS_100, udp0.recv_from(&mut recv_buffer)).unwrap();
            assert_eq!(&recv_buffer[..len], test_data.as_ref());
            assert_eq!(source, sender.local_addr());
        },
        async {
            let result: Result<ScionPacketRaw, _> = within_duration!(MS_100, raw0.recv());
            match result {
                Ok(packet) => {
                    let destination = packet.headers.address.source().unwrap();
                    assert_eq!(sender.local_addr().scion_address(), destination);
                }
                Err(e) => {
                    panic!("Error receiving packet: {e:?}");
                }
            }
        },
        async {
            let mut recv_buffer = [0u8; 1024];
            err_within_duration!(MS_100, udp1.recv_from(&mut recv_buffer));
        },
        async {
            err_within_duration!(MS_100, raw1.recv());
        },
        async {
            sender
                .send_to(test_data.as_ref(), udp0.local_addr())
                .await
                .unwrap();
            info!("sent packet to udp0");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_udp_packet_dispatch_snap() {
    test_udp_packet_dispatch_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_udp_packet_dispatch_udp() {
    test_udp_packet_dispatch_impl(UnderlayType::Udp).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_packet_dispatch_with_port_snap() {
    test_scmp_packet_dispatch_with_port_snap_impl(false).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
#[ignore = "XXX(uniquefine): This test needs to be fixed when SCMP handling is implemented for v2."]
async fn test_scmp_packet_dispatch_with_port_snap_v2() {
    test_scmp_packet_dispatch_with_port_snap_impl(true).await;
}

async fn test_scmp_packet_dispatch_with_port_snap_impl(v2: bool) {
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;
    let sender_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let (tx, mut rx) = mpsc::channel(1);

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .with_snap_underlay_config(
            SnapUnderlayConfig::builder()
                .with_default_scmp_handler(Box::new(move |_| {
                    Arc::new(TestScmpHandler::new(tx.clone()))
                }))
                .build(),
        )
        .build()
        .await
        .unwrap();

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let path_manager = sender_stack.create_path_manager();

    let udp_receiver = receiver_stack.bind(None).await.unwrap();
    let raw_receiver = receiver_stack
        .bind_raw(Some(udp_receiver.local_addr()))
        .await
        .unwrap();

    // Create an SCMP echo request towards the receiver sockets.
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            udp_receiver.local_addr().isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let echo_request = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: udp_receiver.local_addr().scion_address(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            // Use the identifier for the receiver port.
            udp_receiver.local_addr().port(),
            1,
            Bytes::from_static(b"echo test"),
        )),
    )
    .unwrap();

    tokio::join!(
        async {
            // Raw receiver should get the SCMP packet
            let packet =
                within_duration!(MS_100, raw_receiver.recv()).expect("error receiving scmp packet");
            let scmp_packet: ScionPacketScmp = packet.try_into().expect("invalid scmp packet");

            match scmp_packet.message {
                ScmpMessage::EchoRequest(req) => {
                    assert_eq!(req.identifier, udp_receiver.local_addr().port());
                    assert_eq!(req.sequence_number, 1);
                    assert_eq!(req.data, Bytes::from_static(b"echo test"));
                }
                _ => panic!("Expected echo request, got: {:?}", scmp_packet.message),
            }
        },
        async {
            // Default SCMP handler should receive the echo request
            let packet = within_duration!(MS_100, rx.recv()).expect("error receiving echo request");

            match packet.message {
                ScmpMessage::EchoRequest(reply) => {
                    assert_eq!(reply.identifier, udp_receiver.local_addr().port());
                    assert_eq!(reply.sequence_number, 1);
                    assert_eq!(reply.data, Bytes::from_static(b"echo test"));
                }
                _ => panic!("Expected echo request, got: {:?}", packet.message),
            }
        },
        async {
            err_within_duration!(MS_100, udp_receiver.recv_from(&mut [0u8; 1024]));
        },
        async {
            within_duration!(MS_100, sender.send(echo_request.into()))
                .expect("error sending echo request");
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_packet_dispatch_with_port_udp() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Udp).await;
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

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let path_manager = sender_stack.create_path_manager();

    let udp_receiver = receiver_stack.bind(None).await.unwrap();
    let raw_receiver = receiver_stack
        .bind_raw(Some(udp_receiver.local_addr()))
        .await
        .unwrap();

    // Create an SCMP echo request towards the receiver sockets.
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            udp_receiver.local_addr().isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let echo_request = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: udp_receiver.local_addr().scion_address(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            // Use the identifier for the receiver port.
            udp_receiver.local_addr().port(),
            1,
            Bytes::from_static(b"echo test"),
        )),
    )
    .unwrap();

    tokio::join!(
        async {
            // Raw receiver should get the SCMP packet
            let packet =
                within_duration!(MS_100, raw_receiver.recv()).expect("error receiving scmp packet");
            let scmp_packet: ScionPacketScmp = packet.try_into().expect("invalid scmp packet");

            match scmp_packet.message {
                ScmpMessage::EchoRequest(req) => {
                    assert_eq!(req.identifier, udp_receiver.local_addr().port());
                    assert_eq!(req.sequence_number, 1);
                    assert_eq!(req.data, Bytes::from_static(b"echo test"));
                }
                _ => panic!("Expected echo request, got: {:?}", scmp_packet.message),
            }
        },
        async {
            err_within_duration!(MS_100, udp_receiver.recv_from(&mut [0u8; 1024]));
        },
        async {
            within_duration!(MS_100, sender.send(echo_request.into()))
                .expect("error sending echo request");
        },
    );
}

/// XXX(uniquefine): With the SCION stack v2 we can no longer dispatch SCMP packets without a port.
#[ignore]
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_packet_dispatch_without_port_snap() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;
    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let (tx, mut scmp_handler_receiver) = mpsc::channel(1);
    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .with_snap_underlay_config(
            SnapUnderlayConfig::builder()
                .with_default_scmp_handler(Box::new(move |_| {
                    Arc::new(TestScmpHandler::new(tx.clone()))
                }))
                .build(),
        )
        .build()
        .await
        .unwrap();

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    // Create an SCMP error message (destination unreachable) which doesn't have a port
    // This should only be dispatched to the default SCMP handler
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_ases()[0],
            Utc::now(),
        )
        .await
        .unwrap();

    let offending_payload = build_minimal_udp_datagram(
        sender.local_addr().port(), // source port
        1025,                       // destination port (0 or any test port)
        b"offending packet data",
    );

    let error_message = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_addr.scion_address(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            offending_payload.clone(),
        )),
    )
    .unwrap();

    tokio::join!(
        async {
            err_within_duration!(MS_100, receiver.recv());
        },
        async {
            // The default SCMP handler should receive the error message
            let packet = within_duration!(MS_100, scmp_handler_receiver.recv())
                .expect("error receiving scmp packet");

            match packet.message {
                ScmpMessage::DestinationUnreachable(error) => {
                    assert_eq!(error.code, DestinationUnreachableCode::AddressUnreachable);
                    assert_eq!(error.get_offending_packet(), offending_payload);
                }
                _ => {
                    panic!(
                        "Expected destination unreachable scmp packet, got: {:?}",
                        packet.message
                    )
                }
            }
        },
        async {
            sender.send(error_message.into()).await.unwrap();
        },
    );
}

// Added helper for minimal UDP datagram.
fn build_minimal_udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Bytes {
    use bytes::{BufMut, BytesMut};
    let total_len = 8 + payload.len();
    let mut buf = BytesMut::with_capacity(total_len);
    buf.put_u16(src_port);
    buf.put_u16(dst_port);
    buf.put_u16(total_len as u16);
    buf.put_u16(0); // checksum placeholder
    buf.put_slice(payload);
    buf.freeze()
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_packet_dispatch_without_port_udp() {
    let test_env = minimal_pocketscion_setup(UnderlayType::Udp).await;
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

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    // Create an SCMP error message (destination unreachable) which doesn't have a port
    // This should only be dispatched to the default SCMP handler
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_ases()[0],
            Utc::now(),
        )
        .await
        .unwrap();
    let error_message = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_addr.scion_address(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet data"),
        )),
    )
    .unwrap();

    // None of the receivers should receive the error message
    tokio::join!(
        async {
            err_within_duration!(MS_100, receiver.recv());
        },
        async {
            sender.send(error_message.into()).await.unwrap();
        },
    );
}

/// With the snap underlay echo requests are replied to by the SCION stack.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_scmp_echo_is_replied_snap() {
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

    let sender = sender_stack.bind_raw(None).await.unwrap();
    let receiver = receiver_stack.bind_raw(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let path_manager = sender_stack.create_path_manager();

    let echo_data = Bytes::from_static(b"ping test data");
    let identifier = sender.local_addr().port();
    let sequence = 1u16;

    // Create an SCMP echo request
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_ases()[0],
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
        ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            identifier,
            sequence,
            echo_data.clone(),
        )),
    )
    .unwrap();

    tokio::join!(
        async {
            // The test SCMP handler should receive the echo request
            match within_duration!(MS_100, sender.recv()) {
                Ok(packet) => {
                    let scmp_packet: ScionPacketScmp =
                        packet.try_into().expect("invalid scmp packet");
                    match scmp_packet.message {
                        ScmpMessage::EchoReply(rep) => {
                            assert_eq!(rep.identifier, identifier);
                            assert_eq!(rep.sequence_number, sequence);
                            assert_eq!(rep.data, echo_data);
                        }
                        _ => panic!("Expected echo reply, got: {:?}", scmp_packet.message),
                    }
                }
                Err(e) => {
                    panic!("Error receiving echo reply: {e:?}");
                }
            }
        },
        async {
            within_duration!(MS_100, sender.send(echo_request.into()))
                .expect("error sending echo request");
        },
    );
}

fn test_packet(i: u32) -> Bytes {
    Bytes::from(format!("test {i}").as_bytes().to_owned())
}
fn test_packet_index(bytes: &[u8]) -> Option<u32> {
    str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
}

async fn should_snaptun_sender_reconnects_snap_impl(test_env: PocketscionTestEnv, v2: bool) {
    let sender_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let receiver_stack = ScionStackBuilder::new(test_env.eh_api212.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let sender = Arc::new(sender_stack.bind(None).await.unwrap());
    let receiver = Arc::new(receiver_stack.bind(None).await.unwrap());

    // 1. close the sender's snaptun connection on the server (pocketscion).
    // 2. send packets and wait for the sender's snaptun connection to recover.
    // 2 a) We expect all errors to be ConnectionClosed.
    // 2 b) We expect the sender to eventually recover and successfully send packets.

    let delete_address = if v2 {
        // delete connection using the full socket address.
        sender.local_addr().local_address().unwrap()
    } else {
        // delete connection using the ip only.
        sender
            .local_addr()
            .local_address()
            .map(|a| net::SocketAddr::new(a.ip(), 0))
            .unwrap()
    };

    let client = test_env.pocketscion.api_client();
    client
        .delete_snap_connection(test_env.snap132, delete_address)
        .await
        .unwrap();

    let cancel_sender = CancellationToken::new();
    let sender_addr = sender.local_addr();
    let receiver_addr = receiver.local_addr();
    tokio::join!(
        {
            let sender = sender.clone();
            let cancel_sender = cancel_sender.clone();
            async move {
                assert!(
                    cancel_sender
                        .run_until_cancelled(async move {
                            let mut index = 0;
                            loop {
                                match &sender
                                    .send_to(test_packet(index).as_ref(), receiver_addr)
                                    .await
                                {
                                    Ok(_) => {
                                        index += 1;
                                    }
                                    Err(e) => {
                                        assert!(
                                            matches!(
                                                e,
                                                ScionSocketSendError::NetworkUnreachable(
                                                    NetworkError::DestinationUnreachable(_)
                                                )
                                            ),
                                            "expected NetworkUnreachable, got {e:?}"
                                        );
                                    }
                                }
                                sleep(Duration::from_millis(200)).await;
                            }
                        })
                        .await
                        .is_none(),
                    "sender should eventually recover and be able to send packets",
                )
            }
        },
        {
            let receiver = receiver.clone();
            async move {
                let mut recv_buffer = [0u8; 1024];
                let (n_read, source) =
                    within_duration!(Duration::from_secs(3), receiver.recv_from(&mut recv_buffer))
                        .unwrap();
                assert!(
                    test_packet_index(&recv_buffer[..n_read]).is_some(),
                    "receiver should receive packets"
                );
                assert_eq!(
                    source, sender_addr,
                    "receiver should receive packets from the sender"
                );
                cancel_sender.cancel();
            }
        },
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_sender_reconnects_snap() {
    should_snaptun_sender_reconnects_snap_impl(
        minimal_pocketscion_setup(UnderlayType::Snap).await,
        false,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_sender_reconnects_snap_v2() {
    should_snaptun_sender_reconnects_snap_impl(
        minimal_pocketscion_setup_v2(UnderlayType::Snap).await,
        true,
    )
    .await;
}

async fn should_snaptun_receiver_reconnects_snap_impl(test_env: PocketscionTestEnv, v2: bool) {
    let sender_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let receiver_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api212.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let sender = Arc::new(sender_stack.bind(None).await.unwrap());
    let receiver = Arc::new(receiver_stack.bind(None).await.unwrap());

    // 1. Start to receive
    // 2. Close the receiver's snaptun connection on the server (pocketscion).
    // 3. Send packets towards the receiver and wait for the receiver's snaptun connection to
    //    recover.

    let sender_addr = sender.local_addr();
    let receiver_addr = receiver.local_addr();

    // Start a receive on the receiver.
    let receive_join_handle = tokio::spawn(async move {
        let mut recv_buffer = [0u8; 1024];
        let (n_read, source) = receiver.recv_from(&mut recv_buffer).await.unwrap();
        assert!(
            test_packet_index(&recv_buffer[..n_read]).is_some(),
            "receiver should receive packets"
        );
        assert_eq!(
            source, sender_addr,
            "receiver should receive packets from the sender"
        );
    });

    let delete_address = if v2 {
        // delete connection using the full socket address.
        receiver_addr.local_address().unwrap()
    } else {
        // delete connection using the ip only.
        receiver_addr
            .local_address()
            .map(|a| net::SocketAddr::new(a.ip(), 0))
            .unwrap()
    };

    // Close the receiver connection.
    let client = test_env.pocketscion.api_client();
    client
        .delete_snap_connection(test_env.snap212, delete_address)
        .await
        .unwrap();

    let sender_join_handle = tokio::spawn(async move {
        let mut index = 0;
        loop {
            sender
                .send_to(test_packet(index).as_ref(), receiver_addr)
                .await
                .unwrap();
            index += 1;
            sleep(Duration::from_millis(200)).await;
        }
    });

    // Wait 3 seconds for a successful receive.
    within_duration!(Duration::from_secs(3), receive_join_handle).unwrap();
    sender_join_handle.abort();
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_receiver_reconnects_snap() {
    should_snaptun_receiver_reconnects_snap_impl(
        minimal_pocketscion_setup(UnderlayType::Snap).await,
        false,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_receiver_reconnects_snap_v2() {
    should_snaptun_receiver_reconnects_snap_impl(
        minimal_pocketscion_setup_v2(UnderlayType::Snap).await,
        true,
    )
    .await;
}

async fn should_snaptun_reconnects_bind_socket_snap_impl(test_env: PocketscionTestEnv, v2: bool) {
    let sender_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api132.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };

    let receiver_stack = {
        let mut builder =
            ScionStackBuilder::new(test_env.eh_api212.url).with_auth_token(dummy_snap_token());
        if v2 {
            builder = builder.with_use_v2();
        }
        builder.build().await.unwrap()
    };
    let receiver = Arc::new(receiver_stack.bind(None).await.unwrap());

    let initial_sender = sender_stack.bind(None).await.unwrap();
    let sender_addr: scion_proto::address::EndhostAddr = initial_sender
        .local_addr()
        .scion_address()
        .try_into()
        .expect("local address is an endhost address");

    // Address to delete the connection on the server.
    let delete_address = if v2 {
        // delete connection using the full socket address.
        initial_sender.local_addr().local_address().unwrap()
    } else {
        // delete connection using the ip only.
        initial_sender
            .local_addr()
            .local_address()
            .map(|a| net::SocketAddr::new(a.ip(), 0))
            .unwrap()
    };

    drop(initial_sender);

    // 1. Create a SCION stack
    // 2. Close the sender's snaptun connection on the server (pocketscion).
    // 3. Bind a socket to the stack, no error.
    // 4. Wait for the socket send function to succeed.

    let client = test_env.pocketscion.api_client();
    client
        .delete_snap_connection(test_env.snap132, delete_address)
        .await
        .unwrap();

    let sender = Arc::new(sender_stack.bind(None).await.unwrap());
    assert_eq!(
        sender_addr,
        sender
            .local_addr()
            .scion_address()
            .try_into()
            .expect("local address is an endhost address"),
        "Expected the socket to be bound to the same address as the stack, got {sender:?}"
    );

    let sender_addr = sender.local_addr();
    let receiver_addr = receiver.local_addr();

    // Start a receive on the receiver.
    let receive_join_handle = tokio::spawn(async move {
        let mut recv_buffer = [0u8; 1024];
        let (n_read, source) = receiver.recv_from(&mut recv_buffer).await.unwrap();
        assert!(
            test_packet_index(&recv_buffer[..n_read]).is_some(),
            "receiver should receive packets"
        );
        assert_eq!(
            source, sender_addr,
            "receiver should receive packets from the sender"
        );
    });

    let sender_join_handle = tokio::spawn(async move {
        let mut index = 0;
        loop {
            match sender
                .send_to(test_packet(index).as_ref(), receiver_addr)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    assert!(
                        matches!(
                            e,
                            ScionSocketSendError::NetworkUnreachable(
                                NetworkError::DestinationUnreachable(_)
                            )
                        ),
                        "expected NetworkUnreachable, got {e:?}"
                    );
                }
            }
            index += 1;
            sleep(Duration::from_millis(200)).await;
        }
    });

    // Wait 3 seconds for a successful receive.
    within_duration!(Duration::from_secs(3), receive_join_handle).unwrap();
    sender_join_handle.abort();
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_reconnects_bind_socket_snap() {
    should_snaptun_reconnects_bind_socket_snap_impl(
        minimal_pocketscion_setup(UnderlayType::Snap).await,
        false,
    )
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn should_snaptun_reconnects_bind_socket_snap_v2() {
    should_snaptun_reconnects_bind_socket_snap_impl(
        minimal_pocketscion_setup_v2(UnderlayType::Snap).await,
        true,
    )
    .await;
}

#[tokio::test]
#[ignore = "Requires (#26946): currently failing as pathmanager does not receive SCMP errors to mark paths as down"]
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
    let sender_socket = sender_stack.bind(None).await.unwrap();
    let sender_addr = sender_socket.local_addr();

    let receiver_socket = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver_socket.local_addr();

    // Send packet from sender to receiver
    let test_data = Bytes::from("Hello, World!");
    let mut recv_buffer = [0u8; 1024];

    let failover_send_barrier = Arc::new(Barrier::new(2));

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
    assert_ne!(path, new_path, "should use a different path after failover");

    // Stop the sender task
    sender_task.abort();
}
