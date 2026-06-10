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

//! Simple test verifying that the Control Service's CRPC endpoint can be reached and returns
//! expected results.

use std::{str::FromStr, sync::Arc};

use anyhow::Context;
use chrono::Utc;
use http::Method;
use ntest::timeout;
use pocketscion::{
    self,
    comp::control_service::{ControlServiceState, ManualPathProvider},
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::addr_to_http_url,
};
use scion_proto::{address::IsdAsn, path::DataPlanePath};
use scion_protobuf::control_plane::v1::{SegmentsRequest, SegmentsResponse};
use scion_sdk_quic_scion::quic::config::QuicConfig;
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient};
use sciparse::address::socket_addr::ScionSocketAddr;

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn control_service_crpc_lookup() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia1_key = [0; 16];
    let ia2 = IsdAsn::from_str("1-2")?;

    // Setup minimal topology
    let mut topo = ScionTopology::new();
    topo.add_as(ScionAs::new_core("1-1".parse()?).with_forwarding_key(ia1_key))?
        .add_as(ScionAs::new_core("1-2".parse()?))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;

    state.set_topology(topo);

    // Add control service for 1-2

    let control_service_addr = "1.2.3.4:12345".parse()?;

    let mut cs = ControlServiceState::new();
    cs.set_virtual_addr(control_service_addr);
    state.add_control_service(ia2, cs)?;

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
    let remote = control_service_addr;

    let client = CrpcClient::with_quic_config(
        ScionSocketAddr::new(ia2.into(), remote.ip().into(), remote.port()),
        Arc::new(ns_socket),
        None,
        None,
        quic_config,
    )
    .await?;

    tracing::info!("CRPC client connected to Control Service");
    let mut url = addr_to_http_url(remote);

    const SERVICE_PATH: &str = "/proto.control_plane.v1.SegmentLookupService";
    const ENDPOINT_PATH: &str = "/Segments";
    url.set_path(&format!("{}{}", SERVICE_PATH, ENDPOINT_PATH));

    let rsp: SegmentsResponse = client
        .unary_request(
            Method::POST,
            url.clone(),
            &SegmentsRequest {
                src_isd_as: ia2.0,
                dst_isd_as: ia1.0,
            },
        )
        .await?;

    assert_eq!(
        rsp.segments
            .get(&scion_protobuf::control_plane::v1::SegmentType::Core.into())
            .unwrap()
            .segments
            .len(),
        1
    );
    Ok(())
}
