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

use std::{future::Future, net, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use chrono::Utc;
use integration_tests::{UnderlayType, minimal_pocketscion_setup};
use scion_proto::{
    address::SocketAddr,
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketScmp},
    scmp::{DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpEchoRequest, ScmpMessage},
};
use scion_stack::{
    path::manager::PathManager,
    scionstack::{
        DEFAULT_RESERVED_TIME, ScionSocketBindError, ScionStackBuilder, ScmpHandler,
        builder::SnapUnderlayConfig,
    },
};
use snap_tokens::snap_token::dummy_snap_token;
use test_log::test;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, Sender},
};
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

async fn test_bind_two_sockets_send_receive_impl(underlay: UnderlayType) {
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
            assert_eq!(&recv_buffer[..len], test_data.as_ref());
            assert_eq!(source, sender_addr);
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
    test_bind_two_sockets_send_receive_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_two_sockets_send_receive_udp() {
    test_bind_two_sockets_send_receive_impl(UnderlayType::Udp).await;
}

async fn test_bind_with_specific_address_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;

    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let local_address = *stack.local_addresses().first().unwrap();
    let port = match underlay {
        UnderlayType::Snap => 8080,
        UnderlayType::Udp => {
            let sock = UdpSocket::bind(net::SocketAddr::new(local_address.local_address(), 0))
                .await
                .unwrap();
            let port = sock.local_addr().unwrap().port();
            drop(sock);
            port
        }
    };
    let specific_addr = SocketAddr::new(local_address.into(), port);
    let socket = stack.bind(Some(specific_addr)).await.unwrap();

    assert_eq!(socket.local_addr(), specific_addr);
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_snap() {
    // On the snap underlay we can bind to any port without conflict.
    test_bind_with_specific_address_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_with_specific_address_udp() {
    test_bind_with_specific_address_impl(UnderlayType::Udp).await;
}

async fn test_bind_port_already_in_use_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;

    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let local_addresses = stack.local_addresses();
    let addr = SocketAddr::new(local_addresses[0].into(), 8080);

    // First bind should succeed
    let _socket1 = stack.bind(Some(addr)).await.unwrap();

    // Second bind to same port should fail
    let result = stack.bind(Some(addr)).await;
    assert!(
        matches!(result, Err(ScionSocketBindError::PortAlreadyInUse(port)) if port == addr.port()),
        "expected PortAlreadyInUse({}) when binding to same port twice, got {result:?}",
        addr.port()
    );
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_snap() {
    test_bind_port_already_in_use_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_bind_port_already_in_use_udp() {
    test_bind_port_already_in_use_impl(UnderlayType::Udp).await;
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

    let local_addresses = stack.local_addresses();
    let addr = SocketAddr::new(local_addresses[0].into(), 8080);

    let initial_time = std::time::Instant::now();

    // Bind and immediately drop
    {
        let _socket = stack
            .as_ref()
            .bind_with_time(Some(addr), initial_time)
            .await
            .unwrap();
    }

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

async fn test_quic_endpoint_creation_impl(underlay: UnderlayType) {
    let test_env = minimal_pocketscion_setup(underlay).await;

    let stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let endpoint = stack
        .quic_endpoint(None, quinn::EndpointConfig::default(), None, None)
        .await;

    assert!(endpoint.is_ok());
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_snap() {
    test_quic_endpoint_creation_impl(UnderlayType::Snap).await;
}

#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn test_quic_endpoint_creation_udp() {
    test_quic_endpoint_creation_impl(UnderlayType::Udp).await;
}

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
    let test_env = minimal_pocketscion_setup(UnderlayType::Snap).await;
    let sender_stack = ScionStackBuilder::new(test_env.eh_api132.url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

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
    let path_manager = sender_stack.create_path_manager();

    // Create an SCMP error message (destination unreachable) which doesn't have a port
    // This should only be dispatched to the default SCMP handler
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_addresses()[0].isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let error_message = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_stack.local_addresses()[0].into(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet data"),
        )),
    )
    .unwrap();

    let raw_receiver = receiver_stack.bind_raw(None).await.unwrap();

    tokio::join!(
        async {
            err_within_duration!(MS_100, raw_receiver.recv());
        },
        async {
            // The default SCMP handler should receive the error message
            let packet = within_duration!(MS_100, scmp_handler_receiver.recv())
                .expect("error receiving scmp packet");

            match packet.message {
                ScmpMessage::DestinationUnreachable(error) => {
                    assert_eq!(error.code, DestinationUnreachableCode::AddressUnreachable);
                    assert_eq!(
                        error.get_offending_packet(),
                        Bytes::from_static(b"offending packet data")
                    );
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
    let path_manager = sender_stack.create_path_manager();

    // Create an SCMP error message (destination unreachable) which doesn't have a port
    // This should only be dispatched to the default SCMP handler
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_addresses()[0].isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let error_message = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_stack.local_addresses()[0].into(),
        },
        path.data_plane_path.clone(),
        ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet data"),
        )),
    )
    .unwrap();

    let raw_receiver = receiver_stack.bind_raw(None).await.unwrap();

    // None of the receivers should receive the error message
    tokio::join!(
        async {
            err_within_duration!(MS_100, raw_receiver.recv());
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
    let path_manager = sender_stack.create_path_manager();

    let echo_data = Bytes::from_static(b"ping test data");
    let identifier = sender.local_addr().port();
    let sequence = 1u16;

    // Create an SCMP echo request
    let path = path_manager
        .path_wait(
            sender.local_addr().isd_asn(),
            receiver_stack.local_addresses()[0].isd_asn(),
            Utc::now(),
        )
        .await
        .unwrap();
    let echo_request = ScionPacketScmp::new(
        ByEndpoint {
            source: sender.local_addr().scion_address(),
            destination: receiver_stack.local_addresses()[0].into(),
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
