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

//! CRPC Client for the Control Service to send requests to the control service in the External
//! AS through the network simulator

use std::time::Duration;

use anyhow::{Context, bail};
use scion_proto::{address::IsdAsn, path::DataPlanePath};
use scion_protobuf::control_plane::v1::{BeaconRequest, BeaconResponse};
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient};
use url::Url;

use crate::{
    comp::{control_service::CertificateTempDir, sim_network_stack::NetSimStack},
    network::scion::trust_store::StoreCertificateDer,
    util::{addr_to_http_url, crpc::client::PsCrpcClient, path_providers::ManualPathProvider},
};

/// Control Service CRPC client that can be used to send requests to the control service in the
/// External AS through the network simulator
pub struct ControlServiceCrpcClient {
    client: CrpcClient,
    base_url: Url,
}
impl ControlServiceCrpcClient {
    pub async fn connect(
        timeout: Duration,
        network_stack: &NetSimStack,
        dst_ia: IsdAsn,
        dst_addr: std::net::SocketAddr,
        path: DataPlanePath,
        cert_chain: &[StoreCertificateDer],
        cert_temp_dir: &CertificateTempDir,
    ) -> anyhow::Result<ControlServiceCrpcClient> {
        // Create cert chain file for destination AS
        let _ = cert_temp_dir
            .get_or_create_cert_file(cert_chain)
            .context("Failed to get certificate path for destination ISD-AS")?;

        let path_provider = ManualPathProvider::default();
        path_provider.set_path(path);

        let client = PsCrpcClient::connect(
            timeout,
            network_stack,
            dst_ia,
            dst_addr,
            path_provider,
            cert_chain,
            cert_temp_dir,
        )
        .await
        .context("Failed to create CRPC client")?;

        Ok(Self {
            client,
            base_url: addr_to_http_url(dst_addr),
        })
    }

    /// Sends a beacon request to the control service in the External AS through the network
    pub async fn beacon_request(
        &self,
        timeout: Duration,
        beacon_req: &BeaconRequest,
    ) -> anyhow::Result<BeaconResponse> {
        const BEACON_SERVICE_PATH: &str = "/proto.control_plane.v1.SegmentCreationService/Beacon";

        let mut url = self.base_url.clone();
        url.set_path(BEACON_SERVICE_PATH);

        let req = self.client.unary_request::<BeaconRequest, BeaconResponse>(
            http::Method::POST,
            url,
            beacon_req,
        );

        match tokio::time::timeout(timeout, req).await {
            Ok(Ok(res)) => Ok(res),
            Ok(Err(e)) => bail!("Failed to send beacon request through CRPC client: {e}"),
            Err(_) => bail!("Timed out while sending beacon request through CRPC client"),
        }
    }
}
