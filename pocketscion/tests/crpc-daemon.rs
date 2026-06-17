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

//! Simple test verifying that the Daemon Service's CRPC endpoint can be reached.

use std::{str::FromStr, sync::Arc};

use anyhow::Context;
use chrono::Utc;
use http::Method;
use ntest::timeout;
use pocketscion::{
    self,
    comp::daemon::{
        DaemonServiceState,
        model::{PATH_AS, SERVICE_PREFIX},
    },
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::{addr_to_http_url, path_providers::ManualPathProvider},
};
use scion_proto::{address::IsdAsn, path::DataPlanePath};
use scion_protobuf::daemon::v1::{AsRequest, AsResponse};
use scion_sdk_quic_scion::quic::config::QuicConfig;
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient};
use sciparse::address::socket_addr::ScionSocketAddr;

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn daemon_crpc_lookup() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia2 = IsdAsn::from_str("1-2")?;

    // Setup minimal topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core(ia1))?
        .add_as(ScionAs::new_core(ia2))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;

    state.set_topology(topo);

    // Add daemon service for 1-2

    let ds_addr = "1.2.3.4:12345".parse()?;

    let mut ds = DaemonServiceState::new();
    ds.set_virtual_addr(ds_addr);
    state.add_daemon_service(ia2, ds)?;

    tracing::info!("Starting runtime");
    // Start PocketScion
    let ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .start()
        .await
        .context("error starting runtime")?;

    tracing::info!("Runtime started");

    // Create CRPC client in 1-2
    let ns_stack = ps_rt.bind_sim_network_stack(ia2, "192.0.0.1".parse()?, 10)?;
    let ns_socket = ns_stack
        .bind_udp(12344)?
        .into_path_aware(ManualPathProvider::default());

    let quic_config = QuicConfig {
        // Peer validation is disabled in general
        verify_peer: false,
        ca_certs_directory: None,
        ..Default::default()
    };

    // Set the path to be used in the packet
    ns_socket.path_provider.set_path(DataPlanePath::EmptyPath);

    let client = CrpcClient::with_quic_config(
        ScionSocketAddr::new(ia2.into(), ds_addr.ip().into(), ds_addr.port()),
        Arc::new(ns_socket),
        None,
        None,
        quic_config,
    )
    .await?;

    tracing::info!("CRPC client connected");
    let mut url = addr_to_http_url(ds_addr);

    url.set_path(&format!("{}{}", SERVICE_PREFIX, PATH_AS));

    let rsp: AsResponse = client
        .unary_request(Method::POST, url.clone(), &AsRequest { isd_as: ia2.into() })
        .await?;

    tracing::info!("CRPC request successful: {:?}", rsp);

    assert_eq!(
        rsp.isd_as,
        ia2.to_u64(),
        "CRPC response ISD-AS does not match expected value"
    );
    assert!(
        rsp.core,
        "CRPC response core status does not match expected value"
    );

    Ok(())
}
