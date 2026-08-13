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
//! Integration tests for TXT-based SCION DNS resolution.

use std::{net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};

use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, NameServerConfigGroup, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::{
        rr::{
            Name, RData, Record,
            rdata::{SOA, TXT},
        },
        runtime::TokioRuntimeProvider,
        xfer::Protocol,
    },
};
use hickory_server::{
    ServerFuture,
    authority::{Catalog, ZoneType},
    proto::rr::LowerName,
    store::in_memory::InMemoryAuthority,
};
use scion_stack::resolver::{ResolveError, ScionDnsResolver, txt::ScionTxtDnsResolver};
use sciparse::address::ip_addr::ScionIpAddr;
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const ORIGIN: &str = "example.com.";

/// A DNS server authoritative for [`ORIGIN`], together with a resolver pointed at it.
struct TestDns {
    resolver: ScionTxtDnsResolver,
    shutdown: CancellationToken,
    server: Option<JoinHandle<()>>,
}

impl TestDns {
    /// Serves `records` from the [`ORIGIN`] zone. The zone always carries an SOA, so a name with no
    /// TXT records gets an authoritative negative answer rather than a referral.
    async fn start(records: Vec<Record>) -> Self {
        let origin = name(ORIGIN);
        let mut zone = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);
        let serial = 1;

        let soa = SOA::new(
            name("ns.example.com."),
            name("hostmaster.example.com."),
            serial,
            3600,
            600,
            86_400,
            60,
        );
        zone.upsert_mut(
            Record::from_rdata(origin.clone(), 60, RData::SOA(soa)),
            serial,
        );
        for record in records {
            zone.upsert_mut(record, serial);
        }

        let mut catalog = Catalog::new();
        catalog.upsert(LowerName::new(&origin), vec![Arc::new(zone)]);

        let mut server = ServerFuture::new(catalog);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
        let server_addr = socket.local_addr().expect("local addr");
        server.register_socket(socket);

        let shutdown = server.shutdown_token().clone();
        let task = tokio::spawn(async move {
            let _ = server.block_until_done().await;
        });

        let mut name_servers = NameServerConfigGroup::new();
        name_servers.push(NameServerConfig::new(server_addr, Protocol::Udp));
        let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
        let mut builder = Resolver::builder_with_config(
            resolver_config,
            TokioConnectionProvider::new(TokioRuntimeProvider::new()),
        );
        // One short attempt, so the test that shuts the server down does not wait out the default
        // retry schedule.
        let options = builder.options_mut();
        options.timeout = Duration::from_secs(1);
        options.attempts = 1;

        Self {
            resolver: ScionTxtDnsResolver::from_builder(builder).expect("resolver build"),
            shutdown,
            server: Some(task),
        }
    }

    /// Stops the server and waits for it to release its socket, so that later lookups fail.
    async fn stop(&mut self) {
        self.shutdown.cancel();
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
    }
}

fn name(value: &str) -> Name {
    Name::from_str(value).expect("valid name")
}

fn txt_record(owner: &str, value: &str) -> Record {
    Record::from_rdata(
        name(owner),
        60,
        RData::TXT(TXT::new(vec![value.to_string()])),
    )
}

#[tokio::test]
async fn resolves_txt_records_from_local_server() {
    let scion_addr_ipv4 =
        ScionIpAddr::from_str("19-ff00:0:110,192.0.2.1").expect("invalid scion addr");
    let scion_addr_ipv6 =
        ScionIpAddr::from_str("19-ff00:0:110,2001:db8::1").expect("invalid scion addr");
    let mut dns = TestDns::start(vec![txt_record(
        ORIGIN,
        &format!("scion=v1;[{scion_addr_ipv4}],[{scion_addr_ipv6}]"),
    )])
    .await;

    let addresses = dns.resolver.resolve(ORIGIN).await.expect("resolver lookup");

    assert_eq!(addresses, vec![scion_addr_ipv4, scion_addr_ipv6]);

    dns.stop().await;
}

#[tokio::test]
async fn name_without_txt_records_is_not_transient() {
    let owner = "no-txt.example.com.";
    let mut dns = TestDns::start(vec![Record::from_rdata(
        name(owner),
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
    )])
    .await;

    let err = dns
        .resolver
        .resolve(owner)
        .await
        .expect_err("no TXT records");

    assert_eq!(
        err,
        ResolveError::NoValidEntries {
            domain: owner.to_string(),
            invalid_entries: Vec::new(),
        }
    );
    assert!(!err.is_transient());

    dns.stop().await;
}

#[tokio::test]
async fn nonexistent_name_is_not_transient() {
    let mut dns = TestDns::start(Vec::new()).await;

    let err = dns
        .resolver
        .resolve("missing.example.com.")
        .await
        .expect_err("name does not exist");

    assert_eq!(
        err,
        ResolveError::NoValidEntries {
            domain: "missing.example.com.".to_string(),
            invalid_entries: Vec::new(),
        }
    );
    assert!(!err.is_transient());

    dns.stop().await;
}

#[tokio::test]
async fn non_tsar_txt_records_are_not_transient() {
    let owner = "spf.example.com.";
    let mut dns = TestDns::start(vec![txt_record(owner, "v=spf1 -all")]).await;

    let err = dns
        .resolver
        .resolve(owner)
        .await
        .expect_err("no TSAR entries");

    // The record carries no `scion=v1;` prefix, so it is skipped rather than reported as invalid.
    assert_eq!(
        err,
        ResolveError::NoValidEntries {
            domain: owner.to_string(),
            invalid_entries: Vec::new(),
        }
    );
    assert!(!err.is_transient());

    dns.stop().await;
}

#[tokio::test]
async fn unreachable_server_is_transient() {
    let mut dns = TestDns::start(Vec::new()).await;
    dns.stop().await;

    let err = dns
        .resolver
        .resolve("unreachable.example.com.")
        .await
        .expect_err("server is gone");

    assert!(matches!(err, ResolveError::DnsLookup(_)), "{err:?}");
    assert!(err.is_transient());
}
