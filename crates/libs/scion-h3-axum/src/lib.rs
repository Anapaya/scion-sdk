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

//! # SCION HTTP/3 Axum Server
//!
//! [ScionH3AxumServer] allows serving an Axum application over SCION/Http3 using a
//! [GenericScionUdpSocket].

use std::{convert::Infallible, sync::Arc};

use axum::http;
use scion_quic::{
    h3::server::{H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    quic::{
        connection::ConnectionHandle,
        server_endpoint::{Metrics, QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    reexport::squiche::{self},
    socket::{GenericScionUdpSocket, SocketError},
};
use tokio_util::sync::CancellationToken;

/// Axum-based HTTP/3 server using a GenericScionUdpSocket
pub struct ScionH3AxumServer;

impl ScionH3AxumServer {
    /// Serves the given Axum app over HTTP/3 using the provided socket.
    ///
    /// This function will return when the server is stopped or encounters an error.
    ///
    /// ### Parameters
    /// * `sock`: An `Arc` to a `GenericScionUdpSocket` that will be used to listen for incoming
    ///   connections.
    /// * `app`: The Axum application to serve over HTTP/3.
    /// * `quic_config`: The QUIC configuration to use for the server.
    pub async fn serve(
        sock: Arc<dyn GenericScionUdpSocket>,
        app: axum::Router,
        quic_config: squiche::Config,
    ) -> Result<(), Box<dyn SocketError>> {
        let cancel_token = CancellationToken::new();
        Self::serve_with_graceful_shutdown(sock, app, quic_config, cancel_token).await
    }

    /// Serves the given Axum app over HTTP/3 using the provided socket.
    ///
    /// This function will return when the server is stopped or encounters an error.
    /// The `cancel_token` can be used to stop the server gracefully.
    ///
    /// ### Parameters
    /// * `sock`: An `Arc` to a `GenericScionUdpSocket` that will be used to listen for incoming
    ///   connections.
    /// * `app`: The Axum application to serve over HTTP/3.
    /// * `quic_config`: The QUIC configuration to use for the server.
    /// * `cancel_token`: A `CancellationToken` that can be used to stop the server gracefully.
    pub async fn serve_with_graceful_shutdown(
        sock: Arc<dyn GenericScionUdpSocket>,
        app: axum::Router,
        quic_config: squiche::Config,
        cancel_token: CancellationToken,
    ) -> Result<(), Box<dyn SocketError>> {
        let addr = sock.local_addr();
        let metrics = Metrics::new_without_registry();
        let ep = QuicScionServerEndpoint::new([0u8; 32], quic_config, addr, metrics);
        let driver = QuicScionEndpointDriver::with_config(
            ep,
            sock,
            |_: ConnectionHandle<Http3Server<AxumH3Service>>| {},
            Http3ServerConfig::new(AxumH3Service { app: app.clone() }),
        );

        driver.run(cancel_token).await
    }
}

struct AxumH3Service {
    app: axum::Router,
}

impl HttpService for AxumH3Service {
    type Body = H3RequestBody;
    type ResponseBody = axum::body::Body;

    async fn call(&self, req: http::Request<Self::Body>) -> http::Response<Self::ResponseBody> {
        // Pinning the type to Infallible
        let res: Result<http::Response<axum::body::Body>, Infallible> =
            tower::ServiceExt::oneshot(self.app.clone(), req).await;
        res.expect("Infallible")
    }
}
