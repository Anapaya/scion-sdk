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

//! HTTP/3 implementations for PocketSCION

pub mod client {
    //! CRPC client helper for PocketSCION.

    use std::{sync::Arc, time::Duration};

    use anyhow::{Context, bail};
    use scion_proto::address::IsdAsn;
    use scion_sdk_quic_scion::quic::config::QuicConfig;
    use scion_sdk_scion_connect_rpc::client::CrpcClient;
    use sciparse::address::socket_addr::ScionSocketAddr;

    use crate::{
        comp::sim_network_stack::{NetSimPathProvider, NetSimStack},
        network::scion::trust_store::StoreCertificateDer,
        util::cert_tmp_dir::CertificateTempDir,
    };

    /// Helper to create a CRPC client working within the network simulator
    pub struct PsCrpcClient;
    impl PsCrpcClient {
        /// Connects to a CRPC server at the given destination ISD-AS and socket address, using the
        /// provided network stack, path provider, and certificate chain.
        pub async fn connect(
            timeout: Duration,
            network_stack: &NetSimStack,
            dst_ia: IsdAsn,
            dst_addr: std::net::SocketAddr,
            path_provider: impl NetSimPathProvider,
            cert_chain: &[StoreCertificateDer],
            cert_temp_dir: &CertificateTempDir,
        ) -> anyhow::Result<CrpcClient> {
            // Create cert chain file for destination AS
            let _ = cert_temp_dir
                .get_or_create_cert_file(cert_chain)
                .context("Failed to get certificate path for destination ISD-AS")?;

            let quic_config = QuicConfig {
                // Peer validation is disabled in general
                verify_peer: false,
                ca_certs_directory: Some(
                    cert_temp_dir
                        .temp_dir_path()
                        .to_str()
                        .context("Failed to convert certificate temp directory path to string")?
                        .to_owned(),
                ),
                ..Default::default()
            };

            let socket = network_stack
                .bind_udp(0)
                .context("Failed to bind UDP socket for CRPC client")?
                .into_path_aware(path_provider);

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

            Ok(client)
        }
    }
}

pub mod server {
    //! HTTP/3 server implementation for PocketSCION. This allows serving an Axum app over HTTP/3
    //! using the NetSimStack
    use std::{sync::Arc, time::SystemTime};

    use anyhow::Context;
    use bytes::Bytes;
    use scion_sdk_quic_scion::{
        h3::server::{H3Server, H3ServerConnection},
        quic::server::QuicServer,
        reexport::squiche::{self, h3::NameValue},
        socket::GenericScionUdpSocket,
    };

    /// Axum-based HTTP/3 server using a GenericScionUdpSocket
    pub struct AxumH3Server;

    impl AxumH3Server {
        /// Serves the given Axum app over HTTP/3 using the provided socket. This function will run
        /// until the server is stopped (e.g., by dropping the socket or shutting down the runtime)
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

            tracing::info!("Stopping H3 server");

            Ok(())
        }

        /// Handles a single client connection, processing incoming requests and sending responses
        /// using the provided Axum app. This function will run until the connection is
        /// closed.
        async fn handle_client_connection(
            mut conn: H3ServerConnection,
            app: axum::Router,
        ) -> anyhow::Result<()> {
            while let Some((req, responder)) = conn.handle_request().await {
                let id = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_millis();
                tracing::debug!(?req, id, "H3 server received request");
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
            tracing::debug!(id, "H3 server handling request");
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
}
