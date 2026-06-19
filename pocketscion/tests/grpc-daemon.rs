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
    util::addr_to_http_url,
};
use scion_proto::address::IsdAsn;
use scion_protobuf::daemon::v1::{AsRequest, AsResponse};

#[test_log::test(tokio::test)]
#[timeout(10_000)]
async fn daemon_grpc_request() -> anyhow::Result<()> {
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

    let grpc_body = Grpc(AsRequest {
        isd_as: ia2.to_u64(),
    })
    .encode()?;

    let response = reqwest
        .request(Method::POST, url)
        .body(grpc_body)
        .header("Content-Type", "application/grpc")
        .header("TE", "trailers")
        .header("grpc-accept-encoding", "identity")
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
        let as_response: AsResponse = Grpc::<AsResponse>::decode(&body)?;
        assert_eq!(as_response.isd_as, ia2.to_u64());
    }

    Ok(())
}

/// Handles gRPC length-prefixed message framing (5-byte prefix:
/// 1-byte compression flag + 4-byte big-endian length).
struct Grpc<B: prost::Message + Default + Sized + 'static>(B);

impl<B: prost::Message + Default + Sized + 'static> Grpc<B> {
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let protobuf = self.0.encode_to_vec();
        let mut buf = Vec::with_capacity(5 + protobuf.len());
        buf.push(0); // compression flag: uncompressed
        buf.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        buf.extend_from_slice(&protobuf);
        Ok(buf)
    }

    fn decode<M: prost::Message + Default>(bytes: &[u8]) -> anyhow::Result<M> {
        if bytes.len() < 5 {
            anyhow::bail!("gRPC response too short");
        }
        if bytes[0] != 0 {
            anyhow::bail!("compressed gRPC response not supported");
        }
        let len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        if bytes.len() < 5 + len {
            anyhow::bail!("truncated gRPC response");
        }
        Ok(M::decode(&bytes[5..5 + len])?)
    }
}
