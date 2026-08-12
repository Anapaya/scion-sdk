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

//! End-to-end tests against a PocketSCION topology: a URL and a built
//! [`Client`] are all a request needs.

mod common;

use std::{sync::Arc, time::Duration};

use scion_http3::{Client, Error, Request, TimeoutPhase};
use scion_stack::resolver::txt::ScionTxtDnsResolver;
use test_log::test;

use crate::common::{SERVER_NAME, e2e_setup};

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_get_post_over_dns_resolution() {
    let setup = e2e_setup().await;

    // The DNS path: the URL's host resolves to the server's SCION address
    // (via a resolver override, standing in for real TSAR TXT records).
    let resolver = ScionTxtDnsResolver::new()
        .expect("system resolver")
        .with_override(SERVER_NAME, vec![setup.server_ip()]);
    let config = setup.client_config().with_resolver(Arc::new(resolver));
    let client = Client::new(config);

    let response = client.get(setup.url("/hello")).await.expect("GET /hello");
    assert!(response.is_success());
    let (body, _trailers) = response.text(Some(1024)).await.expect("collecting body");
    assert_eq!(body, "world");

    let response = client
        .post(setup.url("/echo"), "ping over SCION")
        .await
        .expect("POST /echo");
    let (body, _trailers) = response.text(Some(1024)).await.expect("collecting body");
    assert_eq!(body, "ping over SCION");

    client.close().await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_target_override_bypasses_resolution() {
    let setup = e2e_setup().await;
    let client = Client::new(setup.client_config());

    // No DNS involved: the request carries the resolved address, the URL
    // still provides host (SNI, certificate identity) and port.
    let request = Request::get(setup.url("/hello"))
        .target(setup.server_ip())
        .build()
        .expect("building request");
    let response = client.request(request).await.expect("GET /hello");
    let (body, _trailers) = response.text(Some(1024)).await.expect("collecting body");
    assert_eq!(body, "world");

    client.close().await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_per_request_timeout() {
    let setup = e2e_setup().await;
    let resolver = ScionTxtDnsResolver::new()
        .expect("system resolver")
        .with_override(SERVER_NAME, vec![setup.server_ip()]);
    let client = Client::new(setup.client_config().with_resolver(Arc::new(resolver)));

    // Warm up so the timing below covers the request, not the stack build.
    client.warm_up(setup.url("/")).await.expect("warming up");

    let request = Request::get(setup.url("/slow"))
        .target(setup.server_ip())
        .request_timeout(Duration::from_millis(300))
        .build()
        .expect("building request");
    let err = client.request(request).await.expect_err("must time out");
    assert!(
        matches!(
            err,
            Error::Timeout {
                phase: TimeoutPhase::Request,
                ..
            }
        ),
        "{err}"
    );
    assert!(err.is_retryable());

    client.close().await;
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_body_size_limit() {
    let setup = e2e_setup().await;
    let client = Client::new(setup.client_config());

    let request = Request::get(setup.url("/hello"))
        .target(setup.server_ip())
        .build()
        .expect("building request");
    let response = client.request(request).await.expect("GET /hello");
    let err = response
        .bytes(Some(2))
        .await
        .expect_err("body exceeds the limit");
    assert!(matches!(err, Error::BodyTooLarge { limit: 2 }), "{err}");

    client.close().await;
}
