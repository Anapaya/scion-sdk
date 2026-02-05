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

//! Integration tests for a QUIC connection using the SCION stack as transport.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use pocketscion::topologies::{IA132, IA212, UnderlayType, minimal::minimal_topology};
use quinn::{EndpointConfig, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig;
use scion_stack::{quic::QuinnConn as _, scionstack::ScionStackBuilder};
use snap_tokens::v0::dummy_snap_token;
use test_log::test;
use tokio_util::sync::CancellationToken;

// Tests a quinn QUIC connection using the SCION stack as transport. The server simply echoes back
// any datagram it receives.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn quinn_echo() {
    tracing::info!("installing crypto provider");
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let ps_handle = minimal_topology(UnderlayType::Snap).await;

    let token_c1 = dummy_snap_token();
    let token_s = dummy_snap_token();

    // client stack
    let ia132_eh_api = ps_handle.endhost_api(IA132).await.unwrap();
    let client_stack = ScionStackBuilder::new(ia132_eh_api)
        .with_auth_token(token_c1)
        .build()
        .await
        .unwrap();

    // server stack
    let ia212_eh_api = ps_handle.endhost_api(IA212).await.unwrap();
    let server_stack = ScionStackBuilder::new(ia212_eh_api)
        .with_auth_token(token_s)
        .build()
        .await
        .unwrap();

    let cancellation_token = CancellationToken::new();
    let server_cancellation_token = cancellation_token.clone();
    let reader_cancellation_token = cancellation_token.clone();

    let (cert_der, server_config) =
        scion_sdk_utils::test::generate_cert([42u8; 32], vec!["localhost".into()], vec![]);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client_crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

    // Create a client endpoint.
    let mut client_endpoint = client_stack
        .quic_endpoint(None, EndpointConfig::default(), None, None)
        .await
        .unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client_addr = client_endpoint.local_scion_addr();

    let server_endpoint = server_stack
        .quic_endpoint(None, EndpointConfig::default(), Some(server_config), None)
        .await
        .unwrap();
    let server_addr = server_endpoint.local_scion_addr();

    tracing::info!("Server addr: {}, client addr: {}", server_addr, client_addr);

    let payload_size = 1100;

    let mut payload = BytesMut::from_iter(std::iter::repeat_n(b'X', payload_size));

    // server tunnel echoes packets back (reversed address headers)
    let server_handle = tokio::spawn(async move {
        let mut local_server_packets_missing = 0u64;
        let mut local_server_packets_received = 0u64;
        let mut local_server_packets_sent = 0u64;

        tokio::select! {
            _ = server_cancellation_token.cancelled() => {            }
            _ = async {
                let conn = server_endpoint.accept().await.unwrap().unwrap();
                let mut last_seen_seq = 0u64;
                loop {
                    let data = match conn.read_datagram().await {
                        Ok(data) => {
                            local_server_packets_received += 1;
                            data
                        }
                        Err(e) => {
                            tracing::error!("Server error reading datagram: {:?}", e);
                            break;
                        }
                    };
                    let incoming_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    if incoming_seq != last_seen_seq + 1 {
                        local_server_packets_missing += incoming_seq - last_seen_seq - 1;
                    }
                    last_seen_seq = incoming_seq;
                    match conn.send_datagram_wait(data).await {
                        Ok(_) => {
                            local_server_packets_sent += 1;
                        }
                        Err(e) => {
                            tracing::error!("Server error sending datagram: {:?}", e);
                            break;
                        }
                    }
                }
            } => {}
        }
        server_endpoint.wait_idle().await;
        (
            local_server_packets_sent,
            local_server_packets_received,
            local_server_packets_missing,
        )
    });

    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let start = Instant::now();

    let reader_conn = conn.clone();

    // receiver
    let receiver_handle = tokio::spawn(async move {
        let mut local_packets_received = 0u64;
        let mut local_packets_missing = 0u64;
        let mut last_seen_seq = 0u64;
        tokio::select! {
            _ = reader_cancellation_token.cancelled() => {            }
            _ = async {
                loop {
                    let data = match reader_conn.read_datagram().await {
                        Ok(data) => {
                            local_packets_received += 1;
                            data
                        }
                        Err(e) => {
                            tracing::error!("Client error reading datagram: {:?}", e);
                            break;
                        }
                    };
                    let incoming_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
                    if incoming_seq != last_seen_seq + 1 {
                        local_packets_missing += incoming_seq - last_seen_seq - 1;
                    }
                    last_seen_seq = incoming_seq;
                }
            } => {}
        }
        (local_packets_received, local_packets_missing)
    });

    let sender_cancellation_token = cancellation_token.clone();

    let sender_handle = tokio::spawn(async move {
        let mut local_packets_sent = 0u64;
        tokio::select! {
            _ = sender_cancellation_token.cancelled() => {            }
            _ = async {
                let mut last_sent = 1u64;
                loop{
                    payload[0..8].copy_from_slice(&last_sent.to_le_bytes());
                    last_sent += 1;
                    conn.send_datagram_wait(payload.clone().into()).await.unwrap();
                    local_packets_sent += 1;
                }
            } => {}
        }
        local_packets_sent
    });

    // wait for 2 seconds
    tokio::time::sleep(Duration::from_secs(2)).await;

    cancellation_token.cancel();

    // Wait for all handles to finish
    let (server_packets_sent, server_packets_received, server_packets_missing) =
        server_handle.await.unwrap();
    let (packets_received, packets_missing) = receiver_handle.await.unwrap();
    let packets_sent = sender_handle.await.unwrap();

    tracing::info!(
        "client sent {} packets in {} seconds -> {} mbps (one way)",
        packets_sent,
        start.elapsed().as_secs(),
        packets_sent as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0
    );
    tracing::info!(
        "echo server received {} packets in {} seconds -> {} mbps (one way), {} missing ({}%)",
        server_packets_received,
        start.elapsed().as_secs(),
        server_packets_received as f64 * payload_size as f64 / start.elapsed().as_secs() as f64
            * 8.0
            / 1024.0
            / 1024.0,
        server_packets_missing,
        (1f64 - server_packets_received as f64 / server_packets_missing as f64) * 100.0
    );
    tracing::info!(
        "echo server sent {} packets in {} seconds -> {} mbps (one way)",
        server_packets_sent,
        start.elapsed().as_secs(),
        server_packets_sent as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0
    );
    tracing::info!(
        "client received {} packets in {} seconds -> {} mbps (one way), {} missing ({}%)",
        packets_received,
        start.elapsed().as_secs(),
        packets_received as f64 * payload_size as f64 / start.elapsed().as_secs() as f64 * 8.0
            / 1024.0
            / 1024.0,
        packets_missing,
        (1f64 - server_packets_received as f64 / server_packets_missing as f64) * 100.0
    );

    assert!(packets_received > 0);

    // Drop the stacks before stopping pocketscion to close the tunnels.
    std::mem::drop(client_stack);
    std::mem::drop(server_stack);
}
