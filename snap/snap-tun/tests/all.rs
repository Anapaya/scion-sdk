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
//! SNAP tunnel test suite.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_matches::assert_matches;
use bytes::Bytes;
use ipnet::IpNet;
use quinn::{Endpoint, TransportConfig, crypto::rustls::QuicClientConfig, rustls};
use rustls::ClientConfig;
use scion_proto::address::{Asn, EndhostAddr, Isd, IsdAsn};
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_token_validator::validator::{Token, TokenValidator, TokenValidatorError};
use serde::{Deserialize, Serialize};
use snap_tun::{
    AddressAllocation, AddressAllocationError, AddressAllocationId, AddressAllocator,
    client::{
        AutoSessionRenewal, ClientBuilder, Control, DEFAULT_RENEWAL_WAIT_THRESHOLD, Receiver,
        Sender,
    },
    metrics::Metrics,
    server::ControlError,
};
use tokio::task::JoinSet;

const DESIRED_IPV4_ADDR: EndhostAddr = EndhostAddr::new(
    IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
);
const DESIRED_IPV6_ADDR: EndhostAddr = EndhostAddr::new(
    IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
);

/// Test address assignments by checking that sent packets are echoed back.
#[test_log::test(tokio::test)]
pub async fn assign_address_and_retrieve_echoed_packet() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (quic_client, quic_srv) = quic_endpoint_pair();
    let srv_addr = quic_srv.local_addr().expect("no fail");
    let srv = prepare_snaptun_server(MagicAuthorizer::default());

    let mut js = JoinSet::<()>::new();
    js.spawn(run_server(quic_srv, srv));

    let desired_addresses = vec![DESIRED_IPV6_ADDR];
    let (tx, rx, _ctrl) =
        prepare_snaptun_client(quic_client, srv_addr, desired_addresses.clone()).await;

    let n_packets = 64u16;
    js.spawn(async move {
        for i in 0..n_packets {
            let p = gen_packet(i, n_packets);
            tx.send_datagram(p).expect("no fail");
            // give the builder some time to consume the packets
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
    for i in 0..n_packets {
        let p = rx.read_datagram().await.expect("no fail");
        assert_eq!(gen_packet(i, n_packets), p);
    }
}

/// Test session enforcement by using a short token validity.
#[test_log::test(tokio::test)]
pub async fn session_enforcement() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (quic_client, quic_srv) = quic_endpoint_pair();
    let srv_addr = quic_srv.local_addr().expect("no fail");
    let srv = prepare_snaptun_server(MagicAuthorizer::new(1));

    // accept connections but only wait for the control stream to close due to session expiry
    let join_handle = tokio::spawn(async move {
        let incoming = quic_srv.accept().await.expect("no fail");
        let conn = incoming.await.expect("no fail");
        let (_tx, _rx, ctrl) = srv.accept_with_timeout(conn).await.expect("no fail");

        let res = ctrl.await;
        assert_matches!(res, Err(ControlError::SessionExpired));
    });

    let desired_addresses = vec![DESIRED_IPV4_ADDR];
    let (_tx, _rx, _ctrl) = prepare_snaptun_client(quic_client, srv_addr, desired_addresses).await;

    // Wait for the session to expire
    join_handle.await.expect("no fail");
}

/// Test manual session renewal.
#[test_log::test(tokio::test)]
pub async fn session_renewal() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (quic_client, quic_srv) = quic_endpoint_pair();
    let srv_addr = quic_srv.local_addr().expect("no fail");
    let srv = prepare_snaptun_server(MagicAuthorizer::default());

    let mut js = JoinSet::<()>::new();
    js.spawn(run_server(quic_srv, srv));

    let desired_addresses = vec![DESIRED_IPV4_ADDR];
    let (_tx, _rx, mut ctrl) =
        prepare_snaptun_client(quic_client, srv_addr, desired_addresses.clone()).await;
    let validity_before = ctrl.session_expiry();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let res = ctrl.renew_session().await;
    assert!(res.is_ok(), "Session renewal should succeed: {res:?}");

    let validity_after = ctrl.session_expiry();
    assert!(
        validity_after > validity_before,
        "Session expiry must be extended {:?} > {:?}",
        chrono::DateTime::<chrono::Utc>::from(validity_after),
        chrono::DateTime::<chrono::Utc>::from(validity_before)
    );
}

/// Test automatic session renewal.
#[test_log::test(tokio::test)]
pub async fn auto_session_renewal() {
    scion_sdk_utils::test::install_rustls_crypto_provider();

    let (quic_client, quic_srv) = quic_endpoint_pair();
    let srv_addr = quic_srv.local_addr().expect("no fail");
    let srv = prepare_snaptun_server(MagicAuthorizer::new(3));

    let mut js = JoinSet::<()>::new();
    js.spawn(run_server(quic_srv, srv));

    let desired_addresses = vec![DESIRED_IPV6_ADDR];
    let c = quic_client
        .connect(srv_addr, "localhost")
        .expect("no fail")
        .await
        .expect("no_fail");

    let (_tx, _rx, ctrl) = ClientBuilder::new(MAGIC_TOKEN)
        .with_desired_addresses(desired_addresses.clone())
        .with_auto_session_renewal(AutoSessionRenewal::new(
            DEFAULT_RENEWAL_WAIT_THRESHOLD,
            Arc::new(move || Box::pin(async move { Ok(MAGIC_TOKEN.to_string()) })),
        ))
        .connect(c)
        .await
        .expect("no fail");
    assert_eq!(ctrl.assigned_addresses(), desired_addresses);

    // Given the token is only valid for 3 seconds, sleeping for 2 seconds ensures a session
    // renewal.
    tokio::time::sleep(Duration::from_secs(2)).await;
}

fn prepare_snaptun_server(validator: MagicAuthorizer) -> snap_tun::server::Server<DummyToken> {
    let allocator = Arc::new(EchoingAllocator);

    snap_tun::server::Server::new(
        allocator,
        Arc::new(validator),
        Metrics::new(&MetricsRegistry::new()),
    )
}

async fn prepare_snaptun_client(
    quic_client: Endpoint,
    srv_addr: SocketAddr,
    desired_addresses: Vec<EndhostAddr>,
) -> (Sender, Receiver, Control) {
    let c = quic_client
        .connect(srv_addr, "localhost")
        .expect("no fail")
        .await
        .expect("no_fail");

    let (tx, rx, ctrl) = ClientBuilder::new(MAGIC_TOKEN)
        .with_desired_addresses(desired_addresses.clone())
        .connect(c)
        .await
        .expect("no fail");

    assert_eq!(ctrl.assigned_addresses(), desired_addresses);

    (tx, rx, ctrl)
}

async fn run_server(ep: Endpoint, srv: snap_tun::server::Server<DummyToken>) {
    let mut js = JoinSet::<()>::new();
    while let Some(c) = ep.accept().await {
        let c = c.await.expect("no fail");
        let (tx, rx, ctrl) = srv.accept_with_timeout(c).await.expect("no fail");

        js.spawn(async move {
            match ctrl.await {
                Ok(_) => {
                    tracing::info!("Session control stream closed gracefully");
                }
                Err(e) => {
                    tracing::warn!("Session control stream closed with error: {}", e);
                }
            }
        });
        js.spawn(async move {
            loop {
                // Receive a packet and echo it back
                let packet = rx.receive().await.expect("no fail");
                tx.send_wait(packet).await.expect("no fail");
            }
        });
    }
}

fn quic_endpoint_pair() -> (quinn::Endpoint, quinn::Endpoint) {
    let (_cert, config) = scion_sdk_utils::test::generate_cert(
        [42u8; 32],
        vec!["localhost".into()],
        vec![b"snaptun".to_vec()],
    );
    let sock_addr = "127.0.0.1:0".parse().expect("no fail");
    let server_ep = quinn::Endpoint::server(config, sock_addr).expect("no fail");

    let mut client_ep = quinn::Endpoint::client(sock_addr).expect("no fail");
    client_ep.set_default_client_config(client_config());

    (client_ep, server_ep)
}

fn client_config() -> quinn::ClientConfig {
    let (cert_der, _config) = scion_sdk_utils::test::generate_cert(
        [42u8; 32],
        vec!["localhost".into()],
        vec![b"snaptun".to_vec()],
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"snaptun".into()];
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(None);

    let transport_config_arc = Arc::new(transport_config);
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config_arc);
    client_config
}

fn gen_packet(idx: u16, total: u16) -> Bytes {
    Bytes::from(format!("Packet {}/{}", idx + 1, total))
}

/// A simple address allocator that assigns constant IP addresses.
struct EchoingAllocator;

impl AddressAllocator<DummyToken> for EchoingAllocator {
    fn put_on_hold(&self, _id: AddressAllocationId) -> bool {
        true
    }

    fn deallocate(&self, _id: AddressAllocationId) -> bool {
        true
    }

    fn allocate(
        &self,
        isd_as: IsdAsn,
        prefix: IpNet,
        claims: DummyToken,
    ) -> Result<AddressAllocation, AddressAllocationError> {
        Ok(AddressAllocation {
            id: AddressAllocationId {
                registry_id: 0,
                alloc_id: claims.id(),
            },
            address: EndhostAddr::new(isd_as, prefix.addr()),
        })
    }
}

/// A simple dummy token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DummyToken {
    /// The expiration time of the JWT, represented as a Unix timestamp.
    pub exp: u64,
}

impl Token for DummyToken {
    fn id(&self) -> String {
        "dummy_token".to_string()
    }
    fn exp_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.exp)
    }
    fn required_claims() -> Vec<&'static str> {
        vec!["exp"]
    }
}

const MAGIC_TOKEN: &str = "ANAPAYA";

/// A simple token validator that accepts the token "ANAPAYA".
struct MagicAuthorizer {
    // Seconds for which the token is valid. This is relevant for testing the session management.
    token_validity: u64,
}

impl Default for MagicAuthorizer {
    fn default() -> Self {
        Self { token_validity: 60 }
    }
}

impl MagicAuthorizer {
    pub fn new(token_validity: u64) -> Self {
        Self { token_validity }
    }
}

impl TokenValidator<DummyToken> for MagicAuthorizer {
    fn validate(
        &self,
        now: std::time::SystemTime,
        token: &str,
    ) -> Result<DummyToken, TokenValidatorError> {
        match token {
            MAGIC_TOKEN => {
                Ok(DummyToken {
                    exp: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                        + self.token_validity,
                })
            }
            _ => Err(TokenValidatorError::TokenExpired(std::time::UNIX_EPOCH)),
        }
    }
}
