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

//! Integration tests for[`CancelHandle`].

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use scion_h3_test_server::{Options, TestServer};
use scion_http3_ffi::{
    CancelHandle, ClientConfig, HttpRequest, HttpResponse, ScionHttp3Client, ScionHttp3Error,
    TrustAnchors, default_client_config,
};
use test_log::test;

/// A response nothing is waiting for, for a request that must not answer on its own.
const NEVER_MS: u64 = 600_000;

/// How long a cancelled request may take to come back.
///
/// A coarse bound rather than a measurement: a working cancellation returns in milliseconds, and
/// what this catches is one that returns never. Anything tighter would fail on a loaded machine
/// without telling a reader anything it could act on.
const CANCEL_DEADLINE: Duration = Duration::from_secs(20);

/// How long anything this test waits for may take.
const WAIT_DEADLINE: Duration = Duration::from_secs(30);

/// How often a wait re-reads what it is waiting for.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

async fn test_server() -> TestServer {
    TestServer::start(Options::default())
        .await
        .expect("starting the test server")
}

/// A client for the topology: its endhost API, its development token, and its certificate trusted.
fn client(server: &TestServer) -> Arc<ScionHttp3Client> {
    ScionHttp3Client::new(ClientConfig {
        auth_token: Some(server.auth_token()),
        trust: TrustAnchors::Pem {
            pem: server.ca_pem().as_bytes().to_vec(),
        },
        ..default_client_config(server.endhost_api_url().to_string())
    })
    .expect("building a client")
}

/// A request body big enough that the server is still taking it when the cancellation lands.
///
/// The server records a request only once it has the whole body, so a count that stays put is what
/// proves the upload was cut off.
const UPLOAD_BODY_BYTES: usize = 2 * 1024 * 1024;

/// How long the server waits between reads of an upload it is meant to hold open.
const UPLOAD_READ_INTERVAL_MS: u64 = 50;

/// A request for `path`, addressed rather than resolved: the topology serves no TSAR records, so
/// the address comes from the request and the port from the URL.
fn request(server: &TestServer, path: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        url: server.url(path),
        headers: vec![],
        body: None,
        targets: vec![server.target()],
        // Long enough that no deadline can be mistaken for a cancellation: a request that ends
        // because it timed out reports `Timeout`, and every assertion below names what it wants.
        request_timeout_ms: Some(NEVER_MS),
        max_response_body_bytes: None,
    }
}

/// Waits until `condition` holds, and fails the test if it never does.
///
/// Polling rather than sleeping for a fixed time, so that a loaded machine is slow here instead of
/// red.
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT_DEADLINE;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Asserts that a call ended as a cancellation rather than as a failure or a response.
fn assert_cancelled(result: Result<HttpResponse, ScionHttp3Error>) {
    match result {
        Err(ScionHttp3Error::Cancelled { retryable, .. }) => {
            assert!(!retryable, "a cancellation was reported as worth retrying");
        }
        other => panic!("a cancelled request ended as {other:?}"),
    }
}

/// Serves `/hello` and asserts it worked, which is how every test shows the connection is usable.
async fn assert_hello_works(client: &ScionHttp3Client, server: &TestServer) {
    let served = server.counters().requests("/hello");
    let response = client
        .execute(request(server, "/hello"))
        .await
        .expect("GET /hello");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"world");
    assert_eq!(
        server.counters().requests("/hello"),
        served + 1,
        "the response did not come from the server"
    );
}

/// Cancelling before the response head arrives: the request is stopped while the server is still
/// thinking about it, and the connection carries the next request.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn cancelling_before_the_response_head_leaves_the_connection_usable() {
    let server = test_server().await;
    let client = client(&server);
    // First, so that what follows is about a request rather than about building connectivity.
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let call = client.execute_cancellable(
        request(&server, &format!("/slow?ms={NEVER_MS}")),
        handle.clone(),
    );
    let cancel = async {
        // Once the server has the request, so that the cancellation reaches a request in flight
        // rather than one that has not been sent.
        wait_until("the request to reach the server", || {
            server.counters().started("/slow") > 0
        })
        .await;
        handle.cancel();
    };

    let (result, ()) = tokio::time::timeout(CANCEL_DEADLINE, async { tokio::join!(call, cancel) })
        .await
        .expect("the cancelled request never came back");

    assert_cancelled(result);
    assert_hello_works(&client, &server).await;
}

/// Cancelling mid-body, which is the case the whole export exists for: the reset has to reach the
/// server, and it has to cost the connection nothing.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn cancelling_mid_body_resets_the_stream_on_the_wire() {
    let tag = "mid-body";
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let call = client.execute_cancellable(
        request(&server, &format!("/endless-body?tag={tag}")),
        handle.clone(),
    );
    let cancel = async {
        // Several chunks in, so the cancellation lands in the body rather than around it.
        wait_until("the server to start sending the body", || {
            server.counters().endless_chunks(tag) >= 3
        })
        .await;
        // The control for the assertion after the cancellation: a request that is still running
        // must not set it, or it would say nothing about the reset.
        assert_eq!(
            server.counters().endless_released(tag),
            0,
            "the server released the body before anything was cancelled"
        );
        handle.cancel();
    };

    let (result, ()) = tokio::time::timeout(CANCEL_DEADLINE, async { tokio::join!(call, cancel) })
        .await
        .expect("the cancelled request never came back");

    assert_cancelled(result);
    // The endless body is released for one reason, which its counter documents: the transport
    // refused a chunk because the stream was reset. So this is the reset, observed from the far
    // end, rather than a client that merely stopped reading.
    wait_until("the reset to reach the server", || {
        server.counters().endless_released(tag) > 0
    })
    .await;
    // One stream was reset, not the connection.
    assert_hello_works(&client, &server).await;
}

/// A handle that never fires must change nothing: the cancellable export has to be the ordinary
/// path for a binding that uses it, not a special case for cancelled requests.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_handle_that_never_fires_delivers_the_response() {
    let server = test_server().await;
    let client = client(&server);

    let response = client
        .execute_cancellable(request(&server, "/hello"), CancelHandle::new())
        .await
        .expect("GET /hello");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"world");
}

/// Firing a handle after its request finished is what a facade does when its task is cancelled a
/// moment too late. It has to be a no-op rather than a failure of the next request.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn cancelling_after_the_request_finished_does_nothing() {
    let server = test_server().await;
    let client = client(&server);

    let handle = CancelHandle::new();
    let response = client
        .execute_cancellable(request(&server, "/hello"), handle.clone())
        .await
        .expect("GET /hello");
    assert_eq!(response.body, b"world");

    handle.cancel();

    assert_hello_works(&client, &server).await;
}

/// A handle that fired before the call has to stop the request before it is sent. Otherwise a
/// facade whose task was cancelled while it was preparing the request would still pay for one.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_handle_that_already_fired_sends_nothing() {
    let server = test_server().await;
    let client = client(&server);
    // So that a request would certainly reach the server if one were sent.
    assert_hello_works(&client, &server).await;
    let started = server.counters().started("/hello");

    let handle = CancelHandle::new();
    handle.cancel();
    let result = client
        .execute_cancellable(request(&server, "/hello"), handle)
        .await;

    assert_cancelled(result);
    assert_eq!(
        server.counters().started("/hello"),
        started,
        "a request whose handle had already fired still reached the server"
    );
    assert_hello_works(&client, &server).await;
}

/// Firing twice is what a caller that cancels defensively does. The second one must not turn a
/// cancelled request into anything else, and must not disturb the connection.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn cancelling_twice_ends_the_request_once() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let call = client.execute_cancellable(
        request(&server, &format!("/slow?ms={NEVER_MS}")),
        handle.clone(),
    );
    let cancel = async {
        wait_until("the request to reach the server", || {
            server.counters().started("/slow") > 0
        })
        .await;
        handle.cancel();
        handle.cancel();
    };

    let (result, ()) = tokio::time::timeout(CANCEL_DEADLINE, async { tokio::join!(call, cancel) })
        .await
        .expect("the cancelled request never came back");

    assert_cancelled(result);
    assert_hello_works(&client, &server).await;
}

/// Cancelling while the request body is going out, which the mid-body test does not cover: that one
/// cancels a response being received, and an upload has to end the same way.
///
/// The connection recovering is the part worth the size of the body here. Until the fix in
/// `Http3Client::request`, the body pump outlived the dropped request future and left the stream
/// and its share of the connection window spent for good, so every later request to that origin
/// failed until `reset` rebuilt connectivity.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn cancelling_while_the_request_body_is_sent_ends_the_upload() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let upload = HttpRequest {
        method: "POST".to_string(),
        body: Some(vec![b'x'; UPLOAD_BODY_BYTES]),
        ..request(
            &server,
            &format!("/echo?read-interval-ms={UPLOAD_READ_INTERVAL_MS}"),
        )
    };
    let call = client.execute_cancellable(upload, handle.clone());
    let cancel = async {
        wait_until("the upload to reach the server", || {
            server.counters().uploaded_bytes("/echo") > 0
        })
        .await;
        handle.cancel();
    };

    let (result, ()) = tokio::time::timeout(CANCEL_DEADLINE, async { tokio::join!(call, cancel) })
        .await
        .expect("the cancelled upload never came back");

    assert_cancelled(result);
    wait_until("the server to see the upload cut off", || {
        server.counters().uploads_truncated("/echo") > 0
    })
    .await;
    assert_hello_works(&client, &server).await;
}

/// Which of the two rejections a caller gets when both apply. The request is converted before the
/// handle is read, so a caller who got the request wrong is told that, and is not left thinking a
/// cancellation is why nothing happened.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_malformed_request_is_reported_even_though_the_handle_has_fired() {
    let server = test_server().await;
    let client = client(&server);

    let handle = CancelHandle::new();
    handle.cancel();
    let malformed = HttpRequest {
        url: "not a url".to_string(),
        ..request(&server, "/hello")
    };
    let result = client.execute_cancellable(malformed, handle).await;

    assert!(
        matches!(result, Err(ScionHttp3Error::InvalidRequest { .. })),
        "a malformed request reported {result:?}"
    );
}

/// One handle serves one request, which the documentation says and nothing enforces. This pins what
/// sharing one actually does, so that a facade author reads it here rather than discovering it.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_shared_handle_cancels_every_request_that_holds_it() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let first = client.execute_cancellable(
        request(&server, &format!("/slow?ms={NEVER_MS}")),
        handle.clone(),
    );
    let second = client.execute_cancellable(
        request(&server, &format!("/slow?ms={NEVER_MS}")),
        handle.clone(),
    );
    let cancel = async {
        wait_until("both requests to reach the server", || {
            server.counters().started("/slow") >= 2
        })
        .await;
        handle.cancel();
    };

    let (first, second, ()) = tokio::time::timeout(CANCEL_DEADLINE, async {
        tokio::join!(first, second, cancel)
    })
    .await
    .expect("the cancelled requests never came back");

    assert_cancelled(first);
    assert_cancelled(second);
    assert_hello_works(&client, &server).await;
}

/// A caller that stops holding its handle has said nothing about the request. This is what makes
/// the handle safe to forget, and it is the difference between a cancellation token and a guard
/// that cancels when it is dropped.
#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn a_handle_dropped_without_firing_lets_the_request_finish() {
    let server = test_server().await;
    let client = client(&server);
    assert_hello_works(&client, &server).await;

    let handle = CancelHandle::new();
    let call = client.execute_cancellable(request(&server, "/slow?ms=300"), handle.clone());
    drop(handle);

    let response = call.await.expect("GET /slow");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"eventually");
}
