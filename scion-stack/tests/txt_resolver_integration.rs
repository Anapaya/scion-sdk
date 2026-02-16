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

use std::{str::FromStr, sync::Arc};

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
use scion_proto::address::ScionAddr;
use scion_stack::resolver::{ScionDnsResolver, txt::ScionTxtDnsResolver};
use tokio::net::UdpSocket;

#[tokio::test]
async fn resolves_txt_records_from_local_server() {
    let origin = Name::from_str("example.com.").expect("valid origin");
    let mut zone = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);
    let serial = 1;

    let soa = SOA::new(
        Name::from_str("ns.example.com.").expect("valid mname"),
        Name::from_str("hostmaster.example.com.").expect("valid rname"),
        serial,
        3600,
        600,
        86_400,
        60,
    );
    let soa_record = Record::from_rdata(origin.clone(), 60, RData::SOA(soa));
    zone.upsert_mut(soa_record, serial);

    let scion_addr_ipv4 =
        ScionAddr::from_str("19-ff00:0:110,192.0.2.1").expect("invalid scion addr");
    let scion_addr_ipv6 =
        ScionAddr::from_str("19-ff00:0:110,2001:db8::1").expect("invalid scion addr");
    let txt_record = Record::from_rdata(
        origin.clone(),
        60,
        RData::TXT(TXT::new(vec![format!(
            "scion=v1;[{}],[{}]",
            scion_addr_ipv4.to_string(),
            scion_addr_ipv6.to_string()
        )])),
    );
    zone.upsert_mut(txt_record, serial);

    let mut catalog = Catalog::new();
    catalog.upsert(LowerName::new(&origin), vec![Arc::new(zone)]);

    let mut server = ServerFuture::new(catalog);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
    let server_addr = socket.local_addr().expect("local addr");
    server.register_socket(socket);

    let shutdown = server.shutdown_token().clone();
    let server_task = tokio::spawn(async move { server.block_until_done().await });

    let mut name_servers = NameServerConfigGroup::new();
    name_servers.push(NameServerConfig::new(server_addr, Protocol::Udp));
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
    let builder = Resolver::builder_with_config(
        resolver_config,
        TokioConnectionProvider::new(TokioRuntimeProvider::new()),
    );
    let resolver = ScionTxtDnsResolver::from_builder(builder).expect("resolver build");

    let addresses = resolver
        .resolve("example.com.")
        .await
        .expect("resolver lookup");
    assert_eq!(addresses.len(), 2);
    assert_eq!(addresses[0], scion_addr_ipv4);
    assert_eq!(addresses[1], scion_addr_ipv6);

    shutdown.cancel();
    let _ = server_task.await;
}
