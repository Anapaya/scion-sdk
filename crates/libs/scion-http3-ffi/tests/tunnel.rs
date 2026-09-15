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

//! Integration tests for [`Tunnel`], against the echo tunnel of the test server.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use scion_h3_test_server::{Options, TestServer};
use scion_http3_ffi::{
    CancelHandle, ClientConfig, DnsOverride, HttpRequest, ScionHttp3Client, ScionHttp3Error,
    TrustAnchors, Tunnel, default_client_config,
};
use test_log::test;

/// A request timeout nothing is waiting for.
const NEVER_MS: u64 = 600_000;

/// How long an ended call may take to come back. A coarse bound.
const END_DEADLINE: Duration = Duration::from_secs(20);

/// How long anything this test waits for may take.
const WAIT_DEADLINE: Duration = Duration::from_secs(30);

/// How often a wait re-reads what it is waiting for.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Long enough for a call to be in flight short enough not to matter.
const IN_FLIGHT: Duration = Duration::from_millis(100);

async fn test_server() -> TestServer {
    TestServer::start(Options::default())
        .await
        .expect("starting the test server")
}

/// The authorities the server refuses or resets, which the certificate does not name.
const INVALID_HOSTS: [&str; 3] = ["status-502.invalid", "status-404.invalid", "reset.invalid"];

/// A client that trusts the server's certificate and resolves `localhost` to the server.
fn client(server: &TestServer) -> Arc<ScionHttp3Client> {
    client_with_trust(
        server,
        TrustAnchors::Pem {
            pem: server.ca_pem().as_bytes().to_vec(),
        },
        &["localhost"],
    )
}

/// A client that verifies nothing and resolves the `.invalid` authorities to the server.
fn insecure_client(server: &TestServer) -> Arc<ScionHttp3Client> {
    client_with_trust(server, TrustAnchors::InsecureNoVerify, &INVALID_HOSTS)
}

/// The topology serves no TSAR records, so every host a test uses is an override.
fn client_with_trust(
    server: &TestServer,
    trust: TrustAnchors,
    hosts: &[&str],
) -> Arc<ScionHttp3Client> {
    ScionHttp3Client::new(ClientConfig {
        auth_token: Some(server.auth_token()),
        trust,
        dns_overrides: hosts
            .iter()
            .map(|host| {
                DnsOverride {
                    host: host.to_string(),
                    addresses: vec![server.target()],
                }
            })
            .collect(),
        request_timeout_ms: NEVER_MS,
        ..default_client_config(server.endhost_api_url().to_string())
    })
    .expect("building a client")
}

/// The authority for `host` on the server's port.
fn authority(server: &TestServer, host: &str) -> String {
    format!("{host}:{}", server.port())
}

async fn open(client: &ScionHttp3Client, server: &TestServer) -> Arc<Tunnel> {
    client
        .connect(authority(server, "localhost"))
        .await
        .expect("opening a tunnel")
}

/// A `GET /hello`, resolved through the `localhost` override.
fn hello(server: &TestServer) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        url: server.url("/hello"),
        headers: vec![],
        body: None,
        request_timeout_ms: Some(NEVER_MS),
        max_response_body_bytes: None,
    }
}

/// Serves `/hello` and asserts it worked, which shows the connection is still usable.
async fn assert_hello_works(client: &ScionHttp3Client, server: &TestServer) {
    let response = client.execute(hello(server)).await.expect("GET /hello");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"world");
}

/// Waits until `condition` holds, and fails the test if it never does.
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT_DEADLINE;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Reads until `len` bytes have arrived. A read returns at most one frame, so one call is not
/// enough for a payload the transport split.
async fn read_exactly(tunnel: &Tunnel, len: usize) -> Vec<u8> {
    let mut collected = Vec::with_capacity(len);
    while collected.len() < len {
        let chunk = tunnel
            .read(u32::try_from(len - collected.len()).unwrap())
            .await
            .expect("reading from the tunnel");
        assert!(
            !chunk.is_empty(),
            "the stream ended after {} bytes",
            collected.len()
        );
        collected.extend_from_slice(&chunk);
    }
    collected
}

async fn echo_round_trip(tunnel: &Tunnel, payload: &[u8]) {
    tunnel.write(payload.to_vec()).await.expect("writing");
    assert_eq!(read_exactly(tunnel, payload.len()).await, payload);
}

fn assert_client_closed<T: std::fmt::Debug>(result: Result<T, ScionHttp3Error>) {
    match result {
        Err(ScionHttp3Error::Closed { retryable, .. }) => {
            assert!(!retryable, "a closed client was reported as worth retrying");
        }
        other => panic!("a call on a tunnel of a closed client ended as {other:?}"),
    }
}

fn assert_tunnel_closed<T: std::fmt::Debug>(result: Result<T, ScionHttp3Error>) {
    match result {
        Err(ScionHttp3Error::TunnelClosed { retryable, .. }) => {
            assert!(!retryable, "a closed tunnel was reported as worth retrying");
        }
        other => panic!("a call on a closed tunnel ended as {other:?}"),
    }
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_tunnel_carries_bytes_both_ways() {
    let server = test_server().await;
    let client = client(&server);
    let started = server.counters().tunnels_started();
    let bytes = server.counters().tunnel_bytes();

    let tunnel = open(&client, &server).await;
    for round in 0..3u32 {
        echo_round_trip(&tunnel, format!("chunk-{round}").as_bytes()).await;
    }

    assert_eq!(server.counters().tunnels_started(), started + 1);
    assert_eq!(server.counters().tunnel_bytes(), bytes + 3 * 7);
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn shutdown_write_ends_the_stream_at_both_ends() {
    let server = test_server().await;
    let client = client(&server);
    let resets = server.counters().tunnels_reset();

    let tunnel = open(&client, &server).await;
    echo_round_trip(&tunnel, b"before the end").await;

    tunnel
        .shutdown_write()
        .await
        .expect("shutting the write direction down");
    assert!(
        tunnel
            .read(16)
            .await
            .expect("reading at the end")
            .is_empty()
    );
    assert!(
        tunnel
            .read(16)
            .await
            .expect("reading at the end again")
            .is_empty()
    );
    tunnel.shutdown_write().await.expect("shutting down twice");
    assert_tunnel_closed(tunnel.write(b"too late".to_vec()).await);

    drop(tunnel);
    tokio::time::sleep(IN_FLIGHT).await;
    assert_eq!(
        server.counters().tunnels_reset(),
        resets,
        "a tunnel that ended cleanly was counted as reset"
    );
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn reads_and_writes_run_at_the_same_time() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    let (read, write) = tokio::join!(tunnel.read(16), async {
        tokio::time::sleep(IN_FLIGHT).await;
        tunnel.write(b"late".to_vec()).await
    });

    write.expect("writing while a read is pending");
    assert_eq!(read.expect("the pending read"), b"late");
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn read_returns_at_most_max_bytes() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    tunnel.write(vec![b'x'; 100]).await.expect("writing");
    let first = tunnel.read(10).await.expect("reading ten bytes");
    assert!(
        (1..=10).contains(&first.len()),
        "read(10) returned {} bytes",
        first.len()
    );
    assert_eq!(
        read_exactly(&tunnel, 100 - first.len()).await.len(),
        100 - first.len()
    );

    assert!(
        matches!(
            tunnel.read(0).await,
            Err(ScionHttp3Error::InvalidRequest { .. })
        ),
        "a read of zero bytes was accepted"
    );
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn abort_ends_a_pending_read_and_resets_the_stream() {
    let server = test_server().await;
    let client = client(&server);
    let resets = server.counters().tunnels_reset();
    let tunnel = open(&client, &server).await;

    let pending = {
        let tunnel = tunnel.clone();
        tokio::spawn(async move { tunnel.read(16).await })
    };
    tokio::time::sleep(IN_FLIGHT).await;
    tunnel.abort();

    let result = tokio::time::timeout(END_DEADLINE, pending)
        .await
        .expect("the pending read never came back")
        .expect("the reading task panicked");
    assert_tunnel_closed(result);
    wait_until("the reset to reach the server", || {
        server.counters().tunnels_reset() > resets
    })
    .await;
    assert_hello_works(&client, &server).await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn abort_is_idempotent_and_final() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    tunnel.abort();
    tunnel.abort();

    assert_tunnel_closed(tunnel.read(16).await);
    assert_tunnel_closed(tunnel.write(b"x".to_vec()).await);
    assert_tunnel_closed(tunnel.shutdown_write().await);
    assert_hello_works(&client, &server).await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn dropping_the_tunnel_resets_the_stream() {
    let server = test_server().await;
    let client = client(&server);
    let resets = server.counters().tunnels_reset();

    let tunnel = open(&client, &server).await;
    echo_round_trip(&tunnel, b"in use").await;
    drop(tunnel);

    wait_until("the reset to reach the server", || {
        server.counters().tunnels_reset() > resets
    })
    .await;
    assert_hello_works(&client, &server).await;
}

/// What a cancelled Kotlin coroutine does to a read: the future is dropped, the task is aborted on
/// a worker, and the half it held is released again.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn dropping_a_pending_read_leaves_the_tunnel_usable() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    tokio::time::timeout(IN_FLIGHT, tunnel.read(16))
        .await
        .expect_err("a read with nothing to read returned");

    echo_round_trip(&tunnel, b"still open").await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn client_shutdown_closes_an_open_tunnel() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    let pending = {
        let tunnel = tunnel.clone();
        tokio::spawn(async move { tunnel.read(16).await })
    };
    tokio::time::sleep(IN_FLIGHT).await;
    client.shutdown().await;

    let result = tokio::time::timeout(END_DEADLINE, pending)
        .await
        .expect("the pending read never came back")
        .expect("the reading task panicked");
    assert_client_closed(result);
    assert_client_closed(tunnel.write(b"after shutdown".to_vec()).await);
}

/// A tunnel that outlives the client that opened it.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn dropping_the_client_closes_an_open_tunnel() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;
    echo_round_trip(&tunnel, b"before the drop").await;

    let pending = {
        let tunnel = tunnel.clone();
        tokio::spawn(async move { tunnel.read(16).await })
    };
    tokio::time::sleep(IN_FLIGHT).await;
    drop(client);

    let result = tokio::time::timeout(END_DEADLINE, pending)
        .await
        .expect("the pending read never came back")
        .expect("the reading task panicked");
    assert_client_closed(result);
    assert_client_closed(tunnel.write(b"after the drop".to_vec()).await);
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_refused_tunnel_reports_its_status() {
    let server = test_server().await;
    let client = insecure_client(&server);
    let started = server.counters().tunnels_started();

    let result = client
        .connect(authority(&server, "status-502.invalid"))
        .await;
    assert!(
        matches!(
            result,
            Err(ScionHttp3Error::TunnelRefused {
                status: 502,
                retryable: true,
                ..
            })
        ),
        "a 502 ended as {result:?}"
    );

    let result = client
        .connect(authority(&server, "status-404.invalid"))
        .await;
    assert!(
        matches!(
            result,
            Err(ScionHttp3Error::TunnelRefused {
                status: 404,
                retryable: false,
                ..
            })
        ),
        "a 404 ended as {result:?}"
    );
    assert_eq!(server.counters().tunnels_started(), started);
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_peer_reset_reports_tunnel_reset() {
    let server = test_server().await;
    let client = insecure_client(&server);
    let resets = server.counters().tunnels_reset();

    let tunnel = client
        .connect(authority(&server, "reset.invalid"))
        .await
        .expect("opening the tunnel the server resets");
    tunnel
        .write(b"first".to_vec())
        .await
        .expect("writing the first chunk");

    // The first chunk may arrive before the reset does.
    let mut reads = 0;
    let error = loop {
        match tunnel.read(16).await {
            Ok(chunk) => {
                assert!(!chunk.is_empty(), "the stream ended instead of being reset");
                reads += 1;
                assert!(reads <= 2, "the server kept echoing instead of resetting");
            }
            Err(error) => break error,
        }
    };
    assert!(
        matches!(
            error,
            ScionHttp3Error::TunnelReset {
                retryable: true,
                ..
            }
        ),
        "a peer reset ended as {error:?}"
    );

    // The peer stopped the write direction as well, which is the same reset from the caller's
    // point of view.
    let error = tunnel
        .write(b"after the reset".to_vec())
        .await
        .expect_err("a write to a reset tunnel succeeded");
    assert!(
        matches!(
            error,
            ScionHttp3Error::TunnelReset {
                retryable: true,
                ..
            }
        ),
        "a write to a reset tunnel ended as {error:?}"
    );
    // A shutdown cannot succeed either and it still ends the write direction.
    tunnel
        .shutdown_write()
        .await
        .expect_err("a shutdown of a reset tunnel succeeded");
    assert_tunnel_closed(tunnel.write(b"after the shutdown".to_vec()).await);
    wait_until("the server to count its own reset", || {
        server.counters().tunnels_reset() > resets
    })
    .await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_malformed_authority_is_rejected() {
    let server = test_server().await;
    let client = client(&server);

    for authority in ["localhost", "", "user@localhost:4443", "localhost:0"] {
        let result = client.connect(authority.to_string()).await;
        assert!(
            matches!(result, Err(ScionHttp3Error::InvalidRequest { .. })),
            "{authority:?} ended as {result:?}"
        );
    }
}

/// A DNS override with nothing in it is a configuration error, reported when the client is built.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn an_empty_dns_override_is_rejected() {
    let server = test_server().await;

    let result = ScionHttp3Client::new(ClientConfig {
        dns_overrides: vec![DnsOverride {
            host: "localhost".to_string(),
            addresses: vec![],
        }],
        ..default_client_config(server.endhost_api_url().to_string())
    });

    assert!(
        matches!(result, Err(ScionHttp3Error::InvalidRequest { .. })),
        "an empty override was accepted"
    );
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn connect_after_shutdown_reports_closed() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    client.shutdown().await;

    let result = client.connect(authority(&server, "localhost")).await;
    assert!(
        matches!(result, Err(ScionHttp3Error::Closed { .. })),
        "a connect on a shut-down client ended as {result:?}"
    );
}

/// The property that justifies the cancellable exports: a cancelled read costs nothing but the
/// read, where a dropped one may cost a frame.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_cancelled_read_leaves_the_tunnel_usable() {
    let server = test_server().await;
    let client = client(&server);
    let tunnel = open(&client, &server).await;

    let handle = CancelHandle::new();
    let pending = {
        let (tunnel, handle) = (tunnel.clone(), handle.clone());
        tokio::spawn(async move { tunnel.read_cancellable(16, handle).await })
    };
    tokio::time::sleep(IN_FLIGHT).await;
    handle.cancel();

    let result = tokio::time::timeout(END_DEADLINE, pending)
        .await
        .expect("the cancelled read never came back")
        .expect("the reading task panicked");
    assert!(
        matches!(result, Err(ScionHttp3Error::Cancelled { .. })),
        "a cancelled read ended as {result:?}"
    );
    echo_round_trip(&tunnel, b"still open").await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_handle_that_already_fired_opens_no_tunnel() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;
    let started = server.counters().tunnels_started();

    let handle = CancelHandle::new();
    handle.cancel();
    let result = client
        .connect_cancellable(authority(&server, "localhost"), handle)
        .await;

    assert!(
        matches!(result, Err(ScionHttp3Error::Cancelled { .. })),
        "a connect whose handle had fired ended as {result:?}"
    );
    assert_hello_works(&client, &server).await;
    assert_eq!(server.counters().tunnels_started(), started);
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_handle_that_never_fires_delivers_the_bytes() {
    let server = test_server().await;
    let client = client(&server);

    let tunnel = client
        .connect_cancellable(authority(&server, "localhost"), CancelHandle::new())
        .await
        .expect("opening a tunnel");
    tunnel
        .write_cancellable(b"cancellable".to_vec(), CancelHandle::new())
        .await
        .expect("writing");
    let echoed = tunnel
        .read_cancellable(16, CancelHandle::new())
        .await
        .expect("reading");

    assert_eq!(echoed, b"cancellable");
}
