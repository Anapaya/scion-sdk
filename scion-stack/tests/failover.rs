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

use bytes::Bytes;
use pocketscion::util::topologies::{IA132, IA212, UnderlayType, minimal::two_path_topology};
use scion_stack::scionstack::ScionStackBuilder;
use snap_tokens::v0::dummy_snap_token;
use test_log::test;
use tokio::{
    sync::Barrier,
    time::{sleep, timeout},
};
use tracing::info;

#[test(tokio::test)]
#[ntest::timeout(5_000)]
async fn should_failover_on_link_error() {
    let ps_handle = two_path_topology(UnderlayType::Snap).await;

    let sender_stack = ScionStackBuilder::new()
        .with_endhost_api(ps_handle.endhost_api(IA132).unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let receiver_stack = ScionStackBuilder::new()
        .with_endhost_api(ps_handle.endhost_api(IA212).unwrap())
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
        .first_egress_interface()
        .expect("path should have first hop egress interface");

    // Make direct link between ASes unavailable
    ps_handle
        .runtime
        .set_link_state(egress.isd_asn, egress.id, false)
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
