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

//! Every exported future, polled the way UniFFI polls it.
//!
//! UniFFI drives an exported future from a foreign thread, which has no ambient Tokio runtime.
//! Awaiting anything that needs one there panics with "there is no reactor running", and the panic
//! surfaces at the boundary as an internal error with no obvious cause. That failure cannot happen
//! in an ordinary `#[tokio::test]`, because those threads do have a runtime, so it would otherwise
//! be found by whoever ran a foreign test suite next.
//!
//! These tests reproduce the foreign side's conditions instead: a bare `std::thread` and a
//! futures executor. They are about where the work runs, not about what it returns, so they use
//! an endhost API that is not there and assert only that the call reports rather than panics.

use std::thread;

use scion_http3_ffi::{ClientConfig, HttpRequest, ScionHttp3Client, default_client_config};

/// An endhost API on a port nothing listens on, so the request fails quickly and locally.
const UNREACHABLE_ENDHOST_API: &str = "http://127.0.0.1:1";

fn config() -> ClientConfig {
    ClientConfig {
        // Long enough not to fire before the connection is refused, short enough that a machine
        // which somehow does not refuse it fails the test rather than hanging the suite.
        connect_timeout_ms: 2_000,
        request_timeout_ms: 5_000,
        ..default_client_config(UNREACHABLE_ENDHOST_API.to_string())
    }
}

fn request() -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        url: "https://example.invalid/hello".to_string(),
        headers: vec![],
        body: None,
        targets: vec![],
        request_timeout_ms: None,
        max_response_body_bytes: None,
    }
}

/// Runs `work` on a thread that knows nothing about Tokio, which is the only kind of thread the
/// exported futures are ever polled from.
fn on_a_foreign_thread<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::spawn(work)
        .join()
        .expect("the exported future panicked when polled without a runtime")
}

#[test]
fn execute_is_pollable_without_a_runtime() {
    let result = on_a_foreign_thread(|| {
        let client = ScionHttp3Client::new(config()).expect("building a client");
        futures::executor::block_on(client.execute(request()))
    });
    // Which failure it is belongs to the error-mapping tests; here it only has to be one.
    assert!(
        result.is_err(),
        "the request reached a server that is not there"
    );
}

#[test]
fn warm_up_is_pollable_without_a_runtime() {
    let result = on_a_foreign_thread(|| {
        let client = ScionHttp3Client::new(config()).expect("building a client");
        futures::executor::block_on(client.warm_up("https://example.invalid/".to_string()))
    });
    assert!(
        result.is_err(),
        "connectivity was built without an endhost API"
    );
}

#[test]
fn shutdown_is_pollable_without_a_runtime() {
    on_a_foreign_thread(|| {
        let client = ScionHttp3Client::new(config()).expect("building a client");
        futures::executor::block_on(client.shutdown());
        // Idempotent, and still not needing a runtime the second time.
        futures::executor::block_on(client.shutdown());
    });
}

/// The synchronous exports are called from foreign threads too, and `reset` in particular is
/// called from a platform network-change callback rather than from an asynchronous call.
#[test]
fn reset_and_construction_need_no_runtime() {
    on_a_foreign_thread(|| {
        let client = ScionHttp3Client::new(config()).expect("building a client");
        client.reset();
    });
}

/// Dropping the client hands its shutdown to the runtime, and needs none of its own.
#[test]
fn dropping_the_client_needs_no_runtime() {
    on_a_foreign_thread(|| {
        let client = ScionHttp3Client::new(config()).expect("building a client");
        drop(client);
    });
}
