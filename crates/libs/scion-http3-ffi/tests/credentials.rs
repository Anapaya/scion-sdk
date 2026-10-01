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

//! The rules that decide which credential a client is built with.
//!
//! The exchange of an Anapaya AA API key needs an AA to answer, which no fixture here provides;
//! the scion-http3 example covers that end to end.

use std::sync::Arc;

use scion_h3_test_server::{Options, TestServer};
use scion_http3_ffi::{
    ApiKeyAuth, ClientConfig, DnsOverride, ScionHttp3Client, ScionHttp3Error, TrustAnchors,
    default_client_config,
};
use test_log::test;

async fn test_server() -> TestServer {
    TestServer::start(Options::default())
        .await
        .expect("starting the test server")
}

fn api_key(key: &str) -> ApiKeyAuth {
    ApiKeyAuth {
        key: key.to_string(),
        aa_url: "http://127.0.0.1:1".to_string(),
        device_id: "ffi-test".to_string(),
        allow_insecure_http: true,
    }
}

fn config(server: &TestServer) -> ClientConfig {
    ClientConfig {
        trust: TrustAnchors::Pem {
            pem: server.ca_pem().as_bytes().to_vec(),
        },
        dns_overrides: vec![DnsOverride {
            host: "localhost".to_string(),
            addresses: vec![server.target()],
        }],
        ..default_client_config(server.endhost_api_url().to_string())
    }
}

fn client(server: &TestServer, key: &str) -> Arc<ScionHttp3Client> {
    ScionHttp3Client::new(ClientConfig {
        api_key: Some(api_key(key)),
        ..config(server)
    })
    .expect("building a client")
}

#[test(tokio::test)]
async fn set_auth_token_is_refused_on_a_client_that_renews_its_own() {
    let server = test_server().await;
    let client = client(&server, "a-key");

    let error = client
        .set_auth_token(server.auth_token())
        .expect_err("the client renews its own token");
    assert!(matches!(error, ScionHttp3Error::InvalidRequest { .. }));

    client.shutdown().await;
}

#[test(tokio::test)]
async fn a_key_and_a_token_together_fail_construction() {
    let server = test_server().await;

    let Err(error) = ScionHttp3Client::new(ClientConfig {
        auth_token: Some(server.auth_token()),
        api_key: Some(api_key("a-key")),
        ..config(&server)
    }) else {
        panic!("two credentials are not a configuration");
    };
    assert!(matches!(error, ScionHttp3Error::InvalidRequest { .. }));
}
