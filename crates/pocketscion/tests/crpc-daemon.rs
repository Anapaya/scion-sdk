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

use std::str::FromStr;

use anyhow::Context;
use buffa::Message as _;
use chrono::Utc;
use http::Method;
use ntest::timeout;
use pocketscion::{
    self,
    comp::daemon::{
        DaemonServiceState,
        model::{PATH_AS, SERVICE_PREFIX},
    },
    network::scion::topology::{ScionAs, ScionTopologyBuilder},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::addr_to_http_url,
};
use scion_protobuf::proto::daemon::v1::{ASRequest, ASResponse};
use sciparse::identifier::isd_asn::IsdAsn;

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn daemon_crpc_request() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia2 = IsdAsn::from_str("1-2")?;

    // Setup minimal topology
    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(ia1))?
        .add_as(ScionAs::new_core(ia2))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;

    state.set_topology(topo.build()?);

    // Add daemon service for 1-2

    let io_config = pocketscion::io_config::IoConfig::default();
    let ds = DaemonServiceState::new();
    state.add_daemon_service(ia2, ds)?;

    tracing::info!("Starting runtime");
    // Start PocketScion
    let _ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .with_io_config(io_config.clone())
        .start()
        .await
        .context("error starting runtime")?;

    let ds_addr = io_config
        .daemon_service_addr(ia2)
        .context("Daemon service address not found")?;

    tracing::info!("Runtime started");

    let reqwest = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge() // Since we aren't using TLS, we need to tell reqwest to use HTTP/2 without any negotiation
        .build()
        .context("Failed to build reqwest client")?;

    let mut url = addr_to_http_url(ds_addr);

    url.set_path(format!("/{SERVICE_PREFIX}{PATH_AS}").as_str());

    let body = ASRequest {
        isd_as: ia2.to_u64(),
    }
    .encode_to_vec();

    let response = reqwest
        .request(Method::POST, url)
        .body(body)
        .header("Content-Type", "application/proto")
        .send()
        .await
        .context("Failed to perform AS lookup with reqwest")?;

    if !response.status().is_success() {
        let status = response.status();
        let response_raw = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        anyhow::bail!("AS lookup request failed with status {status}: {response_raw}");
    } else {
        let body = response.bytes().await?;
        let as_response = ASResponse::decode_from_slice(&body)?;
        assert_eq!(as_response.isd_as, ia2.to_u64());
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn daemon_grpc_request() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();
    let mut state = PocketScionState::new(Utc::now());

    let ia1 = IsdAsn::from_str("1-1")?;
    let ia2 = IsdAsn::from_str("1-2")?;

    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(ia1))?
        .add_as(ScionAs::new_core(ia2))?
        .add_link("1-1#1 core 1-2#2".parse()?)?;
    state.set_topology(topo.build()?);

    let io_config = pocketscion::io_config::IoConfig::default();
    state.add_daemon_service(ia2, DaemonServiceState::new())?;

    let _ps_rt = PocketScionRuntimeBuilder::new()
        .with_system_state(state)
        .with_io_config(io_config.clone())
        .start()
        .await
        .context("error starting runtime")?;

    let ds_addr = io_config
        .daemon_service_addr(ia2)
        .context("Daemon service address not found")?;

    let reqwest = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .context("Failed to build reqwest client")?;

    let mut url = addr_to_http_url(ds_addr);
    url.set_path(format!("/{SERVICE_PREFIX}{PATH_AS}").as_str());

    let response = reqwest
        .request(Method::POST, url)
        .body(grpc_frame(
            &ASRequest {
                isd_as: ia2.to_u64(),
            }
            .encode_to_vec(),
        ))
        .header("Content-Type", "application/grpc")
        .header("TE", "trailers")
        .send()
        .await
        .context("Failed to perform AS lookup over gRPC")?;

    // gRPC always answers 200 and puts the status in the trailers.
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc+proto"),
    );

    let body = response.bytes().await?;
    let as_response = ASResponse::decode_from_slice(&grpc_unframe(&body)?)?;
    assert_eq!(as_response.isd_as, ia2.to_u64());

    Ok(())
}

/// Wraps a message in the gRPC envelope: a compression flag, then a big-endian length.
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(5 + message.len());
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

/// Strips the gRPC envelope from a unary response.
fn grpc_unframe(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let length = u32::from_be_bytes(
        body.get(1..5)
            .context("gRPC response is shorter than its envelope")?
            .try_into()?,
    ) as usize;
    Ok(body
        .get(5..5 + length)
        .context("gRPC response is shorter than its envelope declares")?
        .to_vec())
}
