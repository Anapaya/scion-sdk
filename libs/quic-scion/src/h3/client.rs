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

//! The HTTP/3-over-SCION client.
//!
//! [`Http3Client`] is the entry point: a cheap-to-construct handle that lazily
//! establishes a connection on the first
//! [`request`](Http3Client::request) and transparently
//! re-establishes it if it breaks (**lazy reconnect**).
//! [`request`](Http3Client::request) sends the request headers
//! and returns a [`RequestBodyWriter`] the caller drives to stream the request
//! body, plus a [`ResponseFut`] that resolves to an `http::Response` whose body
//! is a streaming [`H3ResponseBody`] once the response head arrives.
//!
//! HTTP/3 places no ordering between the request and response bodies, the caller
//! must drive the two concurrently (typically by sending the body from a spawned
//! task while awaiting/reading the response).
//!
//! This is the client counterpart of
//! [`Http3Server`](crate::h3::server::Http3Server), built on the same
//! [`QuicScionApplication`](crate::app::QuicScionApplication) /
//! [`ConnectionHandle`] machinery. The per-connection internals are private
//! submodules: the driver engine (`app`) that routes responses, the connection
//! bootstrap and its ingress loop (`connect`), and an open request stream with
//! its two halves (`stream`). Only the types above are part of
//! the API.
//!
//! The legacy client lives under
//! [`deprecated`](crate::h3::deprecated::client::H3Client).

mod app;
mod connect;
mod error;
mod stream;

use std::sync::Arc;

use sciparse::address::socket_addr::ScionSocketAddr;
use tokio::sync::Mutex;

use self::{app::Http3ClientApp, connect::connect};
pub use self::{
    error::{EstablishError, RequestError},
    stream::{H3DuplexStream, H3ResponseBody, RequestBodyWriter, ResponseFut},
};
pub use crate::h3::common::H3Error;
use crate::{
    quic::{config::QuicConfig, connection::ConnectionHandle},
    socket::GenericScionUdpSocket,
};

/// An HTTP/3-over-SCION client with lazy reconnect.
///
/// Cheap to construct (it does not connect eagerly); the first request — or the
/// first after a connection breaks — establishes a connection. Concurrent
/// first-use is serialized so at most one connection is established. In-flight
/// requests on a connection that breaks are faulted (not retried or migrated).
pub struct Http3Client {
    remote: ScionSocketAddr,
    socket: Arc<dyn GenericScionUdpSocket>,
    server_name: Option<String>,
    config: QuicConfig,
    /// The current connection, if any. The async mutex serializes establishment
    /// so concurrent first-use opens only one connection.
    current: Mutex<Option<ConnectionHandle<Http3ClientApp>>>,
}

impl Http3Client {
    /// Creates a client for `remote` using the default [`QuicConfig`].
    ///
    /// No connection is established until the first request.
    pub fn new(
        remote: ScionSocketAddr,
        socket: Arc<dyn GenericScionUdpSocket>,
        server_name: Option<String>,
    ) -> Self {
        Self::with_config(remote, socket, server_name, QuicConfig::default())
    }

    /// Like [`Http3Client::new`], but with a custom [`QuicConfig`].
    pub fn with_config(
        remote: ScionSocketAddr,
        socket: Arc<dyn GenericScionUdpSocket>,
        server_name: Option<String>,
        config: QuicConfig,
    ) -> Self {
        Self {
            remote,
            socket,
            server_name,
            config,
            current: Mutex::new(None),
        }
    }

    /// Issues a request with a caller-driven streaming body.
    ///
    /// Returns once the request headers are on the wire (without a FIN), yielding
    /// a [`ResponseFut`] that resolves to the response when the head arrives and a
    /// [`RequestBodyWriter`] that streams the request body.
    ///
    /// HTTP/3 places no ordering between the request and response bodies, so the
    /// two **must be driven concurrently**.
    /// The usual pattern is to drive the body from a spawned task while
    /// awaiting and reading the response:
    ///
    /// ```ignore
    /// let (response, mut writer) = client.request(req).await?;
    /// tokio::spawn(async move {
    ///     writer.write_chunk(chunk).await?;
    ///     writer.finish().await
    /// });
    /// let response = response.await?;
    /// ```
    ///
    /// Dropping `writer` before [`finish`](RequestBodyWriter::finish) resets the
    /// request's write side without disturbing the response (read) side.
    pub async fn request(
        &self,
        req: http::Request<()>,
    ) -> Result<(ResponseFut, RequestBodyWriter), RequestError> {
        let handle = self.get_connection().await?;
        stream::initiate_request(&handle, req)
    }

    /// Returns the current connection, establishing (or re-establishing) one if
    /// none exists or the current one is closed.
    ///
    /// The async mutex serializes concurrent first-use so only one connection is
    /// established.
    async fn get_connection(&self) -> Result<ConnectionHandle<Http3ClientApp>, EstablishError> {
        let mut guard = self.current.lock().await;

        if let Some(handle) = guard.as_ref() {
            let closed = handle.lock().inner.is_closed();
            if !closed {
                return Ok(handle.clone());
            }
        }

        let quiche_config = self
            .config
            .to_quiche_config()
            .map_err(EstablishError::Quic)?;
        let handle = connect(
            self.remote,
            self.socket.clone(),
            self.server_name.clone(),
            quiche_config,
        )
        .await?;
        *guard = Some(handle.clone());
        Ok(handle)
    }

    /// Test-only introspection: the number of per-stream bookkeeping entries the
    /// current connection still holds (the shared read/write `streams` map plus
    /// the client-only `response_heads` routing map). Returns `0` when no
    /// connection is established.
    ///
    /// Used by tests to assert that cleanly completed requests and tunnels
    /// release their per-stream state instead of leaking it for the life of the
    /// connection.
    #[doc(hidden)]
    pub async fn tracked_stream_state(&self) -> usize {
        let guard = self.current.lock().await;
        let Some(handle) = guard.as_ref() else {
            return 0;
        };
        let conn = handle.lock();
        conn.app.streams.len() + conn.app.response_heads.len()
    }
}
