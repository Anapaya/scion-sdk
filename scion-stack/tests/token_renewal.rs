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
//! Integration tests for SNAP token renewal in PocketSCION.

use std::time::Duration;

use bytes::Bytes;
use pocketscion::topologies::{IA132, IA212, UnderlayType, minimal::minimal_topology};
use scion_sdk_reqwest_connect_rpc::token_source::mock::MockTokenSource;
use scion_stack::scionstack::{ScionStackBuilder, builder::SnapUnderlayConfig};
use snap_tokens::v0::{dummy_snap_token, dummy_snap_token_with_validity};
use test_log::test;

/// Test that after the token expires, packets are dropped.
#[test(tokio::test)]
async fn token_expiry_causes_send_failure() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let ps_handle = minimal_topology(UnderlayType::Snap).await;

    // Token expires in 1 second
    let start_time = std::time::Instant::now();
    let mock_token_source = MockTokenSource::new(dummy_snap_token_with_validity(1));

    let sender_stack = ScionStackBuilder::new(ps_handle.endhost_api(IA132).await.unwrap())
        .with_auth_token_source(mock_token_source)
        .with_snap_underlay_config(SnapUnderlayConfig::builder().build())
        .build()
        .await
        .unwrap();

    let receiver_stack = ScionStackBuilder::new(ps_handle.endhost_api(IA212).await.unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let sender = sender_stack.bind(None).await.unwrap();
    let receiver = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let test_data = Bytes::from("Hello, World!");

    let mut iteration = 0;
    let mut recv_buffer = [0u8; 1024];

    // Loop until send/receive fails (expected after ~1s)
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            iteration += 1;
            tracing::debug!("Iteration {}: Attempting send/receive", iteration,);

            // Try to send and receive with timeout
            let (send_result, recv_result) = tokio::join!(
                sender.send_to(&test_data, receiver_addr),
                tokio::time::timeout(
                    Duration::from_millis(200),
                    receiver.recv_from(&mut recv_buffer)
                )
            );

            match (send_result, recv_result) {
                (_, Err(_)) => {
                    tracing::debug!(
                        "Packet dropped after {}ms",
                        start_time.elapsed().as_millis()
                    );
                    break;
                }
                (Err(send_err), _) => {
                    panic!("Unexpected send error: {:?}", send_err);
                }
                (_, Ok(Err(recv_err))) => {
                    panic!("Unexpected receive error: {:?}", recv_err);
                }
                _ => {
                    tracing::debug!("Packet {} succeeded", iteration);
                }
            };
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
}

/// Tests that an updated token with longer expiration time extends the session.
#[test(tokio::test)]
async fn updated_token_extends_session() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let ps_handle = minimal_topology(UnderlayType::Snap).await;

    // Initial token expires in 1 second
    let start_time = std::time::Instant::now();
    let mock_token_source = MockTokenSource::new(dummy_snap_token_with_validity(1));

    let sender_stack = ScionStackBuilder::new(ps_handle.endhost_api(IA132).await.unwrap())
        .with_auth_token_source(mock_token_source.clone())
        .with_snap_underlay_config(SnapUnderlayConfig::builder().build())
        .build()
        .await
        .unwrap();

    let receiver_stack = ScionStackBuilder::new(ps_handle.endhost_api(IA212).await.unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .unwrap();

    let sender = sender_stack.bind(None).await.unwrap();
    let receiver = receiver_stack.bind(None).await.unwrap();
    let receiver_addr = receiver.local_addr();
    let test_data = Bytes::from("Hello, World!");

    // Immediately update token to 2 seconds validity
    mock_token_source.update_token(dummy_snap_token_with_validity(2));
    tracing::info!("Updated token from 1s to 2s validity");

    let mut iteration = 0;
    let mut recv_buffer = [0u8; 1024];

    // Continue sending until failure
    let elapsed_at_failure = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            iteration += 1;
            tracing::info!(
                "Iteration {}: Attempting send/receive at {}ms",
                iteration,
                start_time.elapsed().as_millis()
            );

            let (send_result, recv_result) = tokio::join!(
                sender.send_to(&test_data, receiver_addr),
                tokio::time::timeout(
                    Duration::from_millis(500),
                    receiver.recv_from(&mut recv_buffer)
                )
            );

            match (send_result, recv_result) {
                (_, Err(_)) => {
                    tracing::info!(
                        "Packet dropped after {}ms",
                        start_time.elapsed().as_millis()
                    );
                    break start_time.elapsed();
                }
                (Err(send_err), _) => {
                    panic!("Unexpected send error: {:?}", send_err);
                }
                (_, Ok(Err(recv_err))) => {
                    panic!("Unexpected receive error: {:?}", recv_err);
                }
                _ => {
                    tracing::debug!("Packet {} succeeded", iteration);
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();

    // Make sure the sending lasted longer than the initial token validity
    assert!(
        (elapsed_at_failure - Duration::from_millis(500)) >= Duration::from_secs(1),
        "Session lasted {}ms, must be > 1000ms to prove token update worked",
        elapsed_at_failure.as_millis()
    );

    tracing::info!(
        "✓ Session lasted {}ms, which is > 1000ms initial token validity",
        elapsed_at_failure.as_millis()
    );

    tracing::info!("Test completed successfully");
}
