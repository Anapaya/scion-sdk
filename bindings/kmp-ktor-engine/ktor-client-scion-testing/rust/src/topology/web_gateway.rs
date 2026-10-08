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

//! The `CONNECT` tunnels. The server plays the WebGateway that
//! `ScionWebGateway` in the engine points at.
//!
//! | Authority | Serves |
//! | --- | --- |
//! | a key of the backend map | The tunnel, connected to that backend over TCP |
//! | `https.invalid:<port>` | TLS with the server certificate, then HTTP/1.1 with the test API |
//! | `http.invalid:<port>` | HTTP/1.1 with the test API, without TLS |
//! | `status-<code>.invalid:<port>` | That status and no tunnel |
//!
//! A backend key is `host` or `host:port`, as in the PathGuard WebGateway. A
//! key with a port matches only that port, and it wins over a key without a
//! port. Any other request that reaches the fallback gets a 404.

use std::{collections::HashMap, convert::Infallible, io, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::Request,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures::{SinkExt, TryStreamExt};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    sync::PollSender,
};

/// The `CONNECT` host that serves HTTP/1.1 inside the tunnel.
pub const HTTP1_HOST: &str = "http.invalid";

/// The `CONNECT` host that serves TLS, and HTTP/1.1 inside it.
pub const TLS_HOST: &str = "https.invalid";

/// Answers `CONNECT` requests as the module doc describes.
pub struct WebGateway {
    /// What runs inside a test API tunnel.
    router: Router,
    /// The identity of the `https.invalid` tunnel.
    tls: Arc<rustls::ServerConfig>,
    /// `host` or `host:port`, in lowercase, to the backend.
    backends: HashMap<String, SocketAddr>,
}

impl WebGateway {
    pub fn new(
        router: Router,
        tls: Arc<rustls::ServerConfig>,
        backends: &HashMap<String, SocketAddr>,
    ) -> Self {
        let backends = backends
            .iter()
            .map(|(key, target)| (key.to_ascii_lowercase(), *target))
            .collect();
        WebGateway {
            router,
            tls,
            backends,
        }
    }

    /// The response to `request`, which reached the fallback of the router.
    pub async fn answer(&self, request: Request) -> Response {
        if request.method() != Method::CONNECT {
            return StatusCode::NOT_FOUND.into_response();
        }

        // Read the target host.
        let Some(authority) = request.uri().authority().cloned() else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let host = authority.host().to_ascii_lowercase();

        if let Some(target) = self.backend(&host, authority.port_u16()) {
            let response = match TcpStream::connect(target).await {
                Ok(backend) => splice(request.into_body(), backend),
                Err(error) => {
                    tracing::debug!(%error, %target, "cannot reach a gateway backend");
                    StatusCode::BAD_GATEWAY.into_response()
                }
            };
            return response;
        }

        // Serve the test API.
        if host == HTTP1_HOST || host == TLS_HOST {
            return self.serve(request.into_body(), host == TLS_HOST);
        }

        // Answer with the status in the name.
        let status = host
            .strip_prefix("status-")
            .and_then(|rest| rest.strip_suffix(".invalid"))
            .and_then(|code| code.parse().ok())
            .and_then(|code| StatusCode::from_u16(code).ok());
        return status.unwrap_or(StatusCode::NOT_FOUND).into_response();

        /// Connects the tunnel whose request body is `inbound` to `backend`.
        fn splice(inbound: Body, mut backend: TcpStream) -> Response {
            let (mut io, response) = tunnel(inbound);
            tokio::spawn(async move {
                if let Err(error) = tokio::io::copy_bidirectional(&mut io, &mut backend).await {
                    tracing::debug!(%error, "a tunnel to a gateway backend ended");
                }
            });

            response
        }
    }

    fn backend(&self, host: &str, port: Option<u16>) -> Option<SocketAddr> {
        port.and_then(|port| self.backends.get(&format!("{host}:{port}")))
            .or_else(|| self.backends.get(host))
            .copied()
    }

    /// Serves one HTTP/1.1 connection with the test API over the tunnel whose
    /// request body is `inbound`.
    fn serve(&self, inbound: Body, with_tls: bool) -> Response {
        // Serve the tunnel in a task.
        let (io, response) = tunnel(inbound);
        let router = self.router.clone();
        let tls = self.tls.clone();
        tokio::spawn(async move {
            let served = if with_tls {
                match TlsAcceptor::from(tls).accept(io).await {
                    Ok(io) => serve_http1(io, router).await,
                    Err(error) => Err(error.into()),
                }
            } else {
                serve_http1(io, router).await
            };

            // Log the end.
            if let Err(error) = served {
                tracing::debug!(%error, "an HTTP/1.1 connection inside a tunnel ended");
            }
        });

        return response;

        async fn serve_http1<I>(
            io: I,
            router: Router,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
        where
            I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(io), TowerToHyperService::new(router))
                .await?;
            Ok(())
        }
    }
}

/// The two ends of a tunnel: a byte stream for the server side, and the
/// response whose body carries what the server side writes.
///
/// The tunnel opens only after the server returns the response. So the user
/// of the byte stream runs in its own task. The tunnel ends when the client
/// ends it or drops the response body.
fn tunnel(
    inbound: Body,
) -> (
    impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Response,
) {
    let (tx, mut rx) = mpsc::channel::<Bytes>(16);
    let reader = StreamReader::new(inbound.into_data_stream().map_err(io::Error::other));
    let writer = SinkWriter::new(CopyToBytes::new(
        PollSender::new(tx).sink_map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe)),
    ));
    let outbound = futures::stream::poll_fn(move |cx| {
        rx.poll_recv(cx).map(|chunk| chunk.map(Ok::<_, Infallible>))
    });

    (
        tokio::io::join(reader, writer),
        Response::new(Body::from_stream(outbound)),
    )
}
