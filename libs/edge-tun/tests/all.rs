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
//! Edge tun integration tests

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anapaya_quinn::{Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};
use assert_matches::assert_matches;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustls::ClientConfig;
use scion_sdk_edge_tun::{
    address_allocation::{AddressAllocation, AddressAllocationError, AddressAllocator, AllocId},
    client::{ClientBuilder, Control, Incoming, Outgoing},
    metrics::EdgeTunMetrics,
    server::{ControlError, SendPacketError, Server as EtServer},
    test_util::gen_ip_packet,
};
use scion_sdk_observability::metrics::registry::MetricsRegistry;
use scion_sdk_token_validator::validator::{Token, TokenValidator, TokenValidatorError};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

const ASSIGNED_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);
const ASSIGNED_IPV6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn assign_address_and_retrieve_echoed_packet() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut js = JoinSet::<()>::new();

    let (client, server) = quic_endpoint_pair();
    let srv_addr = server.local_addr().expect("no fail");
    let ets = prepare_edgetun_server(MagicAuthorizer::default());
    js.spawn(run_server(server, ets));

    let (mut rx, mut tx, _ctrl) = prepare_edge_tun_client(&client, srv_addr).await;

    let n_packets = 64u32;
    js.spawn(async move {
        for i in 0..n_packets {
            let p = gen_ip_packet(i, 2000).into();
            tx.send_wait(p).await.expect("no fail");
            // give the builder some time to consume the packets
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
    for i in 0..n_packets {
        let p = rx.receive().await.expect("no fail");
        assert_eq!(gen_ip_packet(i, 2000), p);
    }
}

#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn session_enforcement() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let (client, server) = quic_endpoint_pair();
    let srv_addr = server.local_addr().expect("no fail");
    let ets = prepare_edgetun_server(MagicAuthorizer::new(1));

    // accept connections but only wait for the control stream to close due to session expiry
    let join_handle = tokio::spawn(async move {
        let incoming = server.accept().await.expect("no fail");
        let conn = incoming.await.expect("no fail");
        let (_tx, _rx, ctrl) = ets.accept_with_timeout(conn).await.expect("no fail");

        let res = ctrl.await;
        assert_matches!(res, Err(ControlError::SessionExpired));
    });

    let (_rx, _tx, _ctrl) = prepare_edge_tun_client(&client, srv_addr).await;

    // Wait for the session to expire
    join_handle.await.expect("no fail");
}

#[test_log::test(tokio::test)]
#[ntest::timeout(10_000)]
async fn session_renewal() {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let (client, server) = quic_endpoint_pair();
    let srv_addr = server.local_addr().expect("no fail");
    let ets = prepare_edgetun_server(MagicAuthorizer::default());

    let mut js = JoinSet::<()>::new();
    js.spawn(run_server(server, ets));

    let (_rx, _tx, mut ctrl) = prepare_edge_tun_client(&client, srv_addr).await;
    let validity_before = ctrl.session_expiry();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let res = ctrl.renew_session(MAGIC_TOKEN).await;
    assert!(res.is_ok(), "Session renewal should succeed: {res:?}");

    let validity_after = ctrl.session_expiry();
    assert!(
        validity_after > validity_before,
        "Session expiry must be extended {:?} > {:?}",
        chrono::DateTime::<chrono::Utc>::from(validity_after),
        chrono::DateTime::<chrono::Utc>::from(validity_before)
    );
}

fn prepare_edgetun_server(validator: MagicAuthorizer) -> EtServer<DummyToken> {
    let allocator = Arc::new(ConstantAllocator);

    let defrag_queues = 8;
    EtServer::new(
        Arc::new(validator),
        allocator,
        get_test_routes(),
        100,
        defrag_queues,
        EdgeTunMetrics::new(&MetricsRegistry::new()),
    )
}

async fn prepare_edge_tun_client(
    client: &anapaya_quinn::Endpoint,
    srv_addr: SocketAddr,
) -> (Incoming, Outgoing, Control) {
    let c = client
        .connect(srv_addr, "localhost")
        .expect("no fail")
        .await
        .expect("no_fail");

    let (incoming, outgoing, ctrl) = ClientBuilder::default()
        // an mtu that has been proven to work on my machine. ;-)
        .with_initial_mtu(1350)
        .with_initial_auth_token(MAGIC_TOKEN)
        .connect(c)
        .await
        .expect("no fail");

    assert_eq!(
        ctrl.assigned_addresses(),
        vec![IpAddr::from(ASSIGNED_IPV4_ADDR),]
    );

    let mut advertised_routes = ctrl.advertised_routes();
    advertised_routes.sort();
    assert_eq!(advertised_routes, get_test_routes());

    (incoming, outgoing, ctrl)
}

fn get_test_routes() -> Vec<IpNet> {
    let ipv4_net_addr = "192.168.2.0".parse().expect("no fail");
    let ipv6_net_addr = "fd00::".parse().expect("no fail");
    let mut res = vec![
        Ipv4Net::new(ipv4_net_addr, 24).expect("no fail").into(),
        Ipv6Net::new(ipv6_net_addr, 64).expect("no fail").into(),
    ];
    res.sort();
    res
}

async fn run_server<T>(ep: Endpoint, ets: EtServer<T>)
where
    T: for<'de> Deserialize<'de> + Token,
{
    let mut js = JoinSet::<()>::new();
    while let Some(c) = ep.accept().await {
        let c = c.await.expect("no fail");
        let (mut rx, mut tx, ctrl) = ets.accept_with_timeout(c).await.expect("no fail");

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
                let packet = rx.receive().await.expect("no fail");
                match tx.send_wait(packet).await {
                    Ok(_) => {}
                    Err(SendPacketError::NewAssignedAddress((outgoing, p))) => {
                        tracing::info!("Assigned addresses changed, update sender");
                        // If assigned addresses changed, update the sender and resend the packet.
                        tx = *outgoing;
                        tx.send_wait(p)
                            .await
                            .expect("re-send due to address change must succeed");
                    }
                    Err(e) => {
                        unreachable!("Failed to send packet: {e}");
                    }
                }
            }
        });
    }
}

fn quic_endpoint_pair() -> (anapaya_quinn::Endpoint, anapaya_quinn::Endpoint) {
    let (_cert, config) = scion_sdk_utils::test::generate_cert(
        [42u8; 32],
        vec!["localhost".into()],
        vec![b"edgetun".to_vec()],
    );
    let sock_addr = "127.0.0.1:0".parse().expect("no fail");
    let server_ep = anapaya_quinn::Endpoint::server(config, sock_addr).expect("no fail");

    let mut client_ep = anapaya_quinn::Endpoint::client(sock_addr).expect("no fail");
    client_ep.set_default_client_config(client_config());

    (client_ep, server_ep)
}

fn client_config() -> anapaya_quinn::ClientConfig {
    let (cert_der, _config) = scion_sdk_utils::test::generate_cert(
        [42u8; 32],
        vec!["localhost".into()],
        vec![b"edgetun".to_vec()],
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"edgetun".into()];
    let transport_config = TransportConfig::default();

    let transport_config_arc = Arc::new(transport_config);
    let mut client_config = anapaya_quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    client_config.transport_config(transport_config_arc);
    client_config
}

/// A simple address allocator that assigns constant IP addresses.
struct ConstantAllocator;

impl AddressAllocator<DummyToken> for ConstantAllocator {
    fn allocate(
        &self,
        prefix: IpNet,
        claims: DummyToken,
    ) -> Result<scion_sdk_edge_tun::address_allocation::AddressAllocation, AddressAllocationError>
    {
        let assigned_ip_net = match prefix {
            IpNet::V4(_) => IpNet::V4(Ipv4Net::new(ASSIGNED_IPV4_ADDR, 32).unwrap()),
            IpNet::V6(_) => IpNet::V6(Ipv6Net::new(ASSIGNED_IPV6_ADDR, 128).unwrap()),
        };
        Ok(AddressAllocation {
            id: AllocId(claims.id()),
            address: assigned_ip_net.addr(),
        })
    }

    fn put_on_hold(&self, _id: scion_sdk_edge_tun::address_allocation::AllocId) -> bool {
        true
    }

    fn deallocate(&self, _id: scion_sdk_edge_tun::address_allocation::AllocId) -> bool {
        true
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
