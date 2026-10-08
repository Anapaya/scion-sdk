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

//! A server of the user that opens its own SCION socket in AS 2-ff00:0:212.

use std::{collections::HashMap, io::Write, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use ktor_scion_testing::topology::{Options, Topology};
use pocketscion::util::topologies::UnderlayType;
use scion_http3::{
    Client, Config,
    scion_quic::{quic::config::QuicConfig, socket::GenericScionUdpSocket},
    scion_stack::ScionStackBuilder,
};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

const MAX_BODY: usize = 1024;

#[tokio::test(flavor = "multi_thread")]
async fn a_server_of_the_user_gets_requests_over_scion() {
    let topology = Topology::start(Options {
        underlay: UnderlayType::Udp,
        gateway_backends: HashMap::new(),
    })
    .await
    .expect("the topology starts");

    // Attach the server.
    let stack = ScionStackBuilder::new()
        .with_endhost_api(topology.server_endhost_api_url().parse().unwrap())
        .with_auth_token(topology.auth_token())
        .build()
        .await
        .expect("the server stack attaches");
    let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(stack.bind(None).await.unwrap());
    let bound = socket.local_addr();
    assert_eq!(bound.host().to_string(), topology.target());

    // Configure QUIC with a self-signed identity.
    let identity = rcgen::generate_simple_self_signed(vec!["api.test".to_owned()]).unwrap();
    let cert = temp_file(identity.cert.pem().as_bytes());
    let key = temp_file(identity.signing_key.serialize_pem().as_bytes());
    let mut quic = QuicConfig::builder().verify_peer(false).build();
    quic.application_protos = vec![b"h3".to_vec()];
    let mut quic = quic.to_quiche_config().unwrap();
    quic.load_cert_chain_from_pem_file(cert.path().to_str().unwrap())
        .unwrap();
    quic.load_priv_key_from_pem_file(key.path().to_str().unwrap())
        .unwrap();

    // Serve the user API.
    let shutdown = CancellationToken::new();
    let router = Router::new().route("/hello", get(|| async { "from the user" }));
    tokio::spawn(
        scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
            socket,
            router,
            quic,
            shutdown.clone(),
        ),
    );

    // Request it over SCION.
    let client = Client::new(
        Config::new(topology.endhost_api_url().parse().unwrap())
            .with_auth_token(topology.auth_token())
            .with_dns_override("api.test", vec![topology.target().parse().unwrap()])
            .with_quic_config(QuicConfig::builder().verify_peer(false).build())
            .with_request_timeout(Duration::from_secs(20)),
    );
    let response = client
        .get(format!("https://api.test:{}/hello", bound.port()))
        .await
        .expect("the request reaches the server of the user");
    let (body, _trailers) = response.text(Some(MAX_BODY)).await.unwrap();
    assert_eq!(body, "from the user");

    // Stop the server.
    shutdown.cancel();
    drop(stack);

    fn temp_file(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }
}
