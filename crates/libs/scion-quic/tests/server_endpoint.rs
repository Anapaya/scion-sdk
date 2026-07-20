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

//! tests for the quic server endpoint

/// common
#[allow(unused)]
pub mod common;

use std::time::Duration;

use common::{
    IncomingPerPeerLimitGate, PassAll, TestClient, TestServer, connect_test_client,
    connect_test_client_with_config, generate_server_config_with_idle_timeout,
};
use scion_quic::quic::config::QuicConfig;
use tokio_quiche::quic::{ConnectionShutdownBehaviour, QuicCommand};

/// Number of concurrent connections exercised by the multi-connection tests.
const NUM_CONNECTIONS: usize = 32;

/// A `tokio-quiche` client can complete a QUIC handshake against the
/// squiche-based server endpoint, and the endpoint reports the connection as
/// established.
#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn client_can_connect() {
    let mut server = TestServer::spawn(PassAll).await;

    // Drives the QUIC handshake to completion against the squiche server. The
    // client must be kept alive for the duration of the test, otherwise the
    // connection is torn down.
    let _client = connect_test_client(server.local_addr)
        .await
        .expect("client failed to connect");

    // The server observes the established connection via the driver's
    // `established_conn` callback. The overall `#[ntest::timeout]` bounds how
    // long we wait here (and for the connect above).
    let _handle = server
        .next_established()
        .await
        .expect("endpoint driver stopped before reporting a connection");
}

/// The server closes each connection as soon as it is established; every client
/// must eventually observe its connection being closed.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn server_immediately_closes_connections() {
    let mut server = TestServer::spawn(PassAll).await;

    let mut client_closed = Vec::with_capacity(NUM_CONNECTIONS);
    for _ in 0..NUM_CONNECTIONS {
        let client = connect_test_client(server.local_addr)
            .await
            .expect("client failed to connect");

        // Watch (in the background) for the client to observe the closure.
        client_closed.push(tokio::spawn(wait_until_client_closed(client)));

        // Server side: as soon as the connection is established, close it and
        // wake its driver so the CONNECTION_CLOSE is flushed to the client.
        let handle = server
            .next_established()
            .await
            .expect("endpoint driver stopped before reporting a connection");
        {
            let mut conn = handle.lock();
            let _ = conn.inner.close(false, 0x0, b"server closing");
        }
        handle.notify();
    }

    // Every client must eventually see its connection closed.
    for closed in client_closed {
        closed.await.expect("client task panicked");
    }

    // Once all clients are closed the server endpoint must deregister all
    // connections, returning the routed-source-CIDs gauge to zero.
    while server.registered_count() != 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.registered_count(), 0);
}

/// After the connections are established, the client closes them; every
/// server-side handle must eventually report the connection as closed.
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn client_closes_connections() {
    let mut server = TestServer::spawn(PassAll).await;

    // Establish all connections, keeping both the client handles and the
    // server-side connection handles alive.
    let mut clients = Vec::with_capacity(NUM_CONNECTIONS);
    let mut handles = Vec::with_capacity(NUM_CONNECTIONS);
    for _ in 0..NUM_CONNECTIONS {
        let client = connect_test_client(server.local_addr)
            .await
            .expect("client failed to connect");
        let handle = server
            .next_established()
            .await
            .expect("endpoint driver stopped before reporting a connection");
        clients.push(client);
        handles.push(handle);
    }

    // Close every connection from the client side.
    for client in &clients {
        client
            .controller
            .cmd_sender()
            .send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
                send_application_close: true,
                error_code: 0,
                reason: Vec::new(),
            }))
            .expect("failed to submit close command to the client driver");
    }

    // Every server-side handle must eventually report the connection as closed.
    for handle in &handles {
        while !handle.lock().inner.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // Once all connections are closed the endpoint must deregister them all.
    while server.registered_count() != 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.registered_count(), 0);
}

/// Extends [`client_closes_connections`]: after the first round of connections
/// is fully closed and drained, a second identical round is opened and closed.
/// This exercises that the endpoint driver's [`FuturesUnordered`] continues to
/// work correctly once it has been fully emptied and then repopulated.
#[test_log::test(tokio::test)]
#[ntest::timeout(60_000)]
async fn client_closes_connections_after_full_drain() {
    let mut server = TestServer::spawn(PassAll).await;

    for _ in 0..2 {
        // Establish all connections.
        let mut clients = Vec::with_capacity(NUM_CONNECTIONS);
        let mut handles = Vec::with_capacity(NUM_CONNECTIONS);
        for _ in 0..NUM_CONNECTIONS {
            let client = connect_test_client(server.local_addr)
                .await
                .expect("client failed to connect");
            let handle = server
                .next_established()
                .await
                .expect("endpoint driver stopped before reporting a connection");
            clients.push(client);
            handles.push(handle);
        }

        // Close all connections from the client side.
        for client in &clients {
            client
                .controller
                .cmd_sender()
                .send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
                    send_application_close: true,
                    error_code: 0,
                    reason: Vec::new(),
                }))
                .expect("failed to submit close command to the client driver");
        }

        // Wait for all server-side connections to close.
        for handle in &handles {
            while !handle.lock().inner.is_closed() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        // Confirm the endpoint has deregistered all connections.
        while server.registered_count() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(server.registered_count(), 0);
    }
}

/// Drains the client's HTTP/3 event stream until it ends, which happens once
/// the QUIC connection is closed and the driver task terminates.
async fn wait_until_client_closed(mut client: TestClient) {
    while client
        .controller
        .event_receiver_mut()
        .recv()
        .await
        .is_some()
    {}
}

/// An extension of [`client_closes_connections`] where the channel drops
/// packets so that the first three observed client connections stall at
/// different stages of the handshake:
///
/// * 1st observed connection: only its first Initial reaches the server (the retry-token Initial is
///   dropped), so the server never starts establishing it;
/// * 2nd: the retry token reaches the server (the connection starts establishing) but the handshake
///   never completes, so the server has to time it out;
/// * 3rd: the connection is established, but all subsequent packets are dropped, so the client's
///   close never arrives and the server must time the connection out.
///
/// All remaining connections are unrestricted and are closed by the client.
// Only run on Linux: this test relies on real-time idle-timeout cleanup and is
// flaky on Windows, where UDP packet loss and timer jitter *seem* to make the
// partial handshakes resolve unreliably.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "flaky on Windows; relies on real-time idle-timeout cleanup"
)]
#[test_log::test(tokio::test)]
#[ntest::timeout(30_000)]
async fn client_closes_connections_with_partial_handshakes() {
    // This test depends on real-time idle-timeout cleanup of the half-open and
    // isolated connections, so it needs more headroom than the connect-only
    // tests; match the budget the other multi-connection tests here use (30s).
    //
    // Use a small, dedicated connection count rather than the shared
    // `NUM_CONNECTIONS` (32): the partial-handshake behavior only needs the 3
    // restricted connections plus a few unrestricted ones, and fewer concurrent
    // handshakes mean far less contention and UDP-buffer loss on the single
    // shared server socket under load.
    const NUM_CONNECTIONS: usize = 8;

    // Short idle timeout so the half-open (2nd) and isolated-but-established
    // (3rd) connections time out quickly.
    let idle_timeout = Duration::from_secs(2);
    let (config, cert, key) = generate_server_config_with_idle_timeout(idle_timeout);
    let gate = IncomingPerPeerLimitGate::new([1, 2, 3]);
    let mut server = TestServer::spawn_with_config(gate, config, (cert, key)).await;

    // Launch all client connections in the background: the rate-limited ones
    // never finish their handshake, so we must not await connect inline.
    let mut client_tasks = Vec::with_capacity(NUM_CONNECTIONS);
    for _ in 0..NUM_CONNECTIONS {
        let server_addr = server.local_addr;
        client_tasks.push(tokio::spawn(async move {
            // Mirror the server's short idle timeout so a stalled client gives
            // up instead of lingering.
            let config = QuicConfig::builder()
                .verify_peer(false)
                .idle_timeout(idle_timeout)
                .build();
            let Ok(client) = connect_test_client_with_config(server_addr, &config).await else {
                return;
            };
            // Close from the client side. For the rate-limited "third"
            // connection this close is dropped, so the server times it out.
            let _ = client
                .controller
                .cmd_sender()
                .send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
                    send_application_close: true,
                    error_code: 0,
                    reason: Vec::new(),
                }));
            wait_until_client_closed(client).await;
        }));
    }

    // (2) The first two observed connections never establish on the server, so
    // we observe exactly two fewer established connections than were launched.
    let expected_established = NUM_CONNECTIONS - 2;
    let mut handles = Vec::with_capacity(expected_established);
    for _ in 0..expected_established {
        handles.push(
            server
                .next_established()
                .await
                .expect("endpoint driver stopped before reporting a connection"),
        );
    }

    // ... and no further connection establishes.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), server.next_established())
            .await
            .is_err(),
        "more connections established than expected"
    );

    // (1) The establishing gauge eventually returns to 0 once the half-open
    // (2nd) connection is timed out and removed.
    while server.establishing_count() != 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // (2) Every established connection eventually reaches the closed state
    // (the unrestricted ones via the client's close, the isolated one via the
    // server's idle timeout).
    for handle in &handles {
        while !handle.lock().inner.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // (3) Once closed, the driver must deregister all established connections.
    while server.registered_count() != 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.registered_count(), 0);
}
