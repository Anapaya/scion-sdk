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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use scion_proto::{address::IsdAsn, path::DataPlanePath};
use scion_protobuf::control_plane::v1::{BeaconRequest, BeaconResponse};
use scion_sdk_quic_scion::{
    h3::server::{H3Server, H3ServerConnection},
    quic::{config::QuicConfig, server::QuicServer},
    reexport::squiche::{self, h3::NameValue},
    socket::GenericScionUdpSocket,
};
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient};
use sciparse::address::socket_addr::ScionSocketAddr;
use url::Url;

use crate::{
    comp::{
        control_service::CertificateTempDir,
        sim_network_stack::{NetSimPathProvider, NetSimStack},
    },
    network::scion::trust_store::StoreCertificateDer,
    util::addr_to_http_url,
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

        let quic_config = QuicConfig {
            // Peer validation is disabled in general
            verify_peer: false,
            ca_certs_directory: Some(
                cert_temp_dir
                    .temp_dir
                    .path()
                    .to_str()
                    .context("Failed to convert certificate temp directory path to string")?
                    .to_owned(),
            ),
            ..Default::default()
        };

        let socket = network_stack
            .bind_udp(0)
            .context("Failed to bind UDP socket for CRPC client")?
            .into_path_aware(ManualPathProvider::default());

        // Set the path to be used in the packet
        socket.path_provider.set_path(path);

        let socket = Arc::new(socket);

        let client_fut = CrpcClient::with_quic_config(
            ScionSocketAddr::new(dst_ia.into(), dst_addr.ip().into(), dst_addr.port()),
            socket,
            None, // XXX: Peer validation is disabled
            None,
            quic_config,
        );

        let client = match tokio::time::timeout(timeout, client_fut).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => bail!("Failed to create CRPC client: {e}"),
            Err(_) => bail!("Timed out while creating CRPC client"),
        };

        let url = addr_to_http_url(dst_addr);

        Ok(Self {
            client,
            base_url: url,
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

/// A simple implementation of a path provider for the network simulator that allows manually
/// setting the path to be returned.
#[derive(Debug, Default)]
pub struct ManualPathProvider {
    /// The path to be returned by this path provider. Wrapped in a Mutex to allow mutation.
    pub path: Mutex<Option<DataPlanePath>>,
}

impl ManualPathProvider {
    /// Sets the path to be returned by this path provider.
    pub fn set_path(&self, path: DataPlanePath) {
        self.path.lock().unwrap().replace(path);
    }
}

impl NetSimPathProvider for ManualPathProvider {
    fn get_path(
        &self,
        _src_as: IsdAsn,
        _dst_as: IsdAsn,
    ) -> Option<scion_proto::path::DataPlanePath> {
        self.path.lock().unwrap().clone()
    }
}

#[derive(Debug, Default)]
pub struct MirroringPathProvider {
    /// Maps (src AS, dst AS) to the path to be used for packets from src AS to dst AS
    pub paths: Mutex<HashMap<(IsdAsn, IsdAsn), DataPlanePath>>,
}

impl MirroringPathProvider {
    /// Sets the path to be returned for packets from src AS to dst AS.
    ///
    /// This path may be overridden when the path provider is informed of a path from src AS to dst
    /// AS through `inform_path`.
    #[allow(dead_code)]
    pub fn set_path(&self, src_as: IsdAsn, dst_as: IsdAsn, path: DataPlanePath) {
        self.paths.lock().unwrap().insert((src_as, dst_as), path);
    }
}

impl NetSimPathProvider for MirroringPathProvider {
    fn inform_path(&self, src_as: IsdAsn, dst_as: IsdAsn, path: &DataPlanePath) {
        let mut reversed_path = path.clone();
        let Ok(_) = reversed_path.reverse() else {
            tracing::debug!(src_as = %src_as, dst_as = %dst_as, "Failed to reverse path, not setting path for MirroringPathProvider");
            return;
        };
        self.paths
            .lock()
            .unwrap()
            .insert((dst_as, src_as), reversed_path.clone());
    }

    fn get_path(&self, src_as: IsdAsn, dst_as: IsdAsn) -> Option<DataPlanePath> {
        self.paths.lock().unwrap().get(&(src_as, dst_as)).cloned()
    }
}

/// Axum-based HTTP/3 server using a GenericScionUdpSocket
pub struct AxumH3Server;

impl AxumH3Server {
    /// Serves the given Axum app over HTTP/3 using the provided socket. This function will run
    /// until the server is stopped (e.g., by dropping the socket or shutting down the runtime
    pub async fn serve(
        sock: Arc<dyn GenericScionUdpSocket>,
        app: axum::Router,
        quic_config: squiche::Config,
    ) -> anyhow::Result<()> {
        let quic_server = QuicServer::new(sock, quic_config)?;

        let mut h3_server = H3Server::new(quic_server);

        while let Some(conn) = h3_server.accept().await {
            tracing::debug!("Accepted new H3 connection");
            // Dispatch a task to handle the connection
            let app_clone = app.clone();
            tokio::spawn(async move {
                match Self::handle_client_connection(conn, app_clone).await {
                    Ok(_) => tracing::debug!("Client connection closed gracefully"),
                    Err(e) => tracing::error!(?e, "Client connection closed with error"),
                }
            });
        }

        tracing::info!("Stopping CRPC server");

        Ok(())
    }

    /// Handles a single client connection, processing incoming requests and sending responses using
    /// the provided Axum app. This function will run until the connection is closed.
    async fn handle_client_connection(
        mut conn: H3ServerConnection,
        app: axum::Router,
    ) -> anyhow::Result<()> {
        while let Some((req, responder)) = conn.handle_request().await {
            let id = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis();
            tracing::debug!(?req, id, "CRPC server received request");
            // Handle Requests concurrently
            tokio::spawn({
                let app = app.clone();
                async move {
                    match Self::handle_request(app, req, responder, id).await {
                        Ok(_) => {}
                        Err(e) => tracing::error!(?e, id, "Error handling request"),
                    }
                }
            });
        }

        Ok(())
    }

    async fn handle_request(
        app: axum::Router,
        req: scion_sdk_quic_scion::h3::request::H3Request,
        mut responder: scion_sdk_quic_scion::h3::server::H3ResponseSender,
        id: u128,
    ) -> Result<(), anyhow::Error> {
        tracing::debug!(id, "CRPC server handling request");
        let mut axum_request_builder = http::request::Builder::new()
            .method(req.headers.method)
            .uri(format!(
                "{}://{}{}",
                req.headers.scheme, req.headers.authority, req.headers.path
            ));

        for header in req.headers.headers.iter() {
            axum_request_builder = axum_request_builder.header(header.name(), header.value());
        }

        let body = match req.body {
            Some(body) => axum::body::Body::from(Bytes::from_owner(body)),
            None => axum::body::Body::empty(),
        };

        let axum_request = axum_request_builder
            .body(body)
            .context("Failed to build HTTP request from H3 request")?;
        let res = tower::ServiceExt::oneshot(app, axum_request).await?;

        tracing::debug!(status = res.status().as_u16(), req_at = ?id, "CRPC server generated response");

        let (parts, body) = res.into_parts();
        let body_stream = std::pin::pin!(body.into_data_stream());

        tracing::debug!(
            status = parts.status.as_u16(),
            id,
            "CRPC server sending response"
        );

        match responder
            .send_streaming_response(parts.status, &parts.headers, body_stream)
            .await
        {
            Ok(_) => {}
            Err(e) => tracing::error!(?e, "Failed to send response to client"),
        }

        Ok(())
    }
}
