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
//! establishes a connection on the first request and transparently
//! re-establishes it if it breaks (**lazy reconnect**).
//! [`close`](Http3Client::close) ends it explicitly, faulting everything in
//! flight without waiting for a timeout and marking the client closed.
//!
//! There are two ways to issue a request:
//! - [`request`](Http3Client::request) to send a request body on a background task and await the
//!   response.
//! - [`request_with_writer`](Http3Client::request_with_writer) allowing custom streaming of the
//!   request body. It returns a [`RequestBodyWriter`] the caller drives to stream the request body,
//!   plus a [`ResponseFut`] that resolves to an `http::Response` whose body is a streaming
//!   [`H3ResponseBody`].
//!
//! HTTP/3 places no ordering between the request and response bodies; both entry
//! points make the two progress concurrently ([`request`](Http3Client::request)
//! on a spawned task, [`request_with_writer`](Http3Client::request_with_writer) under caller
//! control).
//!
//! This is the client counterpart of
//! [`Http3Server`](crate::h3::server::Http3Server), built on the same
//! [`QuicScionApplication`](crate::app::QuicScionApplication) /
//! [`ConnectionHandle`] machinery. The per-connection internals are private
//! submodules: the driver engine (`app`) that routes responses, the connection
//! bootstrap and its ingress loop (`connect`), and an open request stream with
//! its two halves (`stream`). Only the types above are part of
//! the API.

mod app;
mod connect;
mod error;
mod stream;

use std::sync::Arc;

use bytes::Buf;
use http_body::Body;
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use self::{
    app::{Http3ClientApp, close_connection},
    connect::connect,
};
pub use self::{
    error::{EstablishError, RequestError, UploadError},
    stream::{
        CollectError, CollectToStringError, H3DuplexStream, H3ResponseBody, RequestBodyWriter,
        ResponseFut,
    },
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
///
/// [`close`](Self::close) is the explicit counterpart: it tears the connection
/// down at once and marks the client closed for good. Lazy reconnect applies
/// only to connections that *broke*, never to a client that was closed.
///
/// Dropping the client tears the connection down too, so a client that goes out
/// of scope does not leave one running until the idle timeout. `close` is the
/// version you can await and observe: it faults in-flight work with a
/// distinguishable error, and returns once the close is queued.
pub struct Http3Client {
    remote: ScionSocketIpAddr,
    socket: Arc<dyn GenericScionUdpSocket>,
    server_name: Option<String>,
    config: QuicConfig,
    /// The current connection, if any. The async mutex serializes establishment
    /// so concurrent first-use opens only one connection.
    current: Mutex<Option<ConnectionHandle<Http3ClientApp>>>,
    /// Cancelled by [`Self::close`] and by dropping the client.
    closed: CancellationToken,
}

impl Drop for Http3Client {
    fn drop(&mut self) {
        // The connection is driven by its own task, which holds the only other
        // reference; canelling the token is what tells it to close and exit.
        self.closed.cancel();
    }
}

impl Http3Client {
    /// Creates a client for `remote` using the default [`QuicConfig`].
    ///
    /// No connection is established until the first request.
    pub fn new(
        remote: ScionSocketIpAddr,
        socket: Arc<dyn GenericScionUdpSocket>,
        server_name: Option<String>,
    ) -> Self {
        Self::with_config(remote, socket, server_name, QuicConfig::default())
    }

    /// Like [`Http3Client::new`], but with a custom [`QuicConfig`].
    pub fn with_config(
        remote: ScionSocketIpAddr,
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
            closed: CancellationToken::new(),
        }
    }

    /// The remote this client is pinned to.
    ///
    /// A client targets one address for its whole life. Reconnects go back to
    /// the same remote, so callers that rank or cache candidates can key off
    /// this instead of carrying the address alongside the client.
    pub fn remote(&self) -> ScionSocketIpAddr {
        self.remote
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
    /// let (response, mut writer) = client.request_with_writer(req).await?;
    /// tokio::spawn(async move {
    ///     writer.write_chunk(chunk).await?;
    ///     writer.finish().await
    /// });
    /// let response = response.await?;
    /// ```
    ///
    /// Dropping `writer` before [`finish`](RequestBodyWriter::finish) resets the
    /// request's write side without disturbing the response (read) side.
    pub async fn request_with_writer(
        &self,
        req: http::Request<()>,
    ) -> Result<(ResponseFut, RequestBodyWriter), RequestError> {
        let handle = self.get_connection().await?;
        let (parts, ()) = req.into_parts();

        stream::initiate_request(&handle, parts)
    }

    /// Issues a request, returning its response.
    ///
    /// The request body is an [`http_body::Body`] that is streamed to the server on a background
    /// task, concurrently with the response.
    ///
    /// The response is returned once the response head arrives. The response body is a streaming
    /// [`H3ResponseBody`] that can be read from it as it arrives.
    ///
    /// For more complex use cases, requiring precise control over writing the body, use
    /// [`request_with_writer`](Self::request_with_writer).
    pub async fn request<B>(
        &self,
        req: http::Request<B>,
    ) -> Result<http::Response<H3ResponseBody>, RequestError>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let handle = self.get_connection().await?;
        let (parts, body) = req.into_parts();
        let (response, writer) = stream::initiate_request(&handle, parts)?;

        // Drive the request body on a background task, concurrently with the response.
        tokio::spawn(async move {
            if let Err(e) = pump_request_body(body, writer).await {
                tracing::debug!(?e, "request body upload failed")
            }
        });

        response.await
    }

    /// Eagerly establishes the connection if none is currently up.
    ///
    /// Connections are normally established lazily on the first
    /// [`request`](Http3Client::request); this warms one up ahead of time so
    /// establishment failures surface here instead of on the first request. It
    /// is a no-op when a live connection already exists.
    pub async fn connect(&self) -> Result<(), EstablishError> {
        self.get_connection().await?;
        Ok(())
    }

    /// Closes the client and tears down its connection.
    ///
    /// Initiates a QUIC application close and faults everything in flight at
    /// once: pending requests fail with [`RequestError::LocallyClosed`],
    /// streaming bodies and `CONNECT` tunnels with
    /// [`H3Error::ConnectionClosed`], and a caller blocked establishing the
    /// connection with [`EstablishError::Closed`]. None of it waits on the QUIC
    /// idle timeout.
    ///
    /// Idempotent, and safe to call concurrently with requests.
    ///
    /// A closed client stays closed: later requests fail with
    /// [`EstablishError::Closed`] instead of reconnecting. This is the one
    /// difference from the lazy reconnect that covers connections which broke on
    /// their own.
    ///
    /// Returns once CONNECTION_CLOSE is queued, not once it is on the wire:
    /// the connection's driver flushes it, so the socket must stay alive
    /// afterwards for the peer to learn of the close promptly rather than by its
    /// own idle timeout.
    pub async fn close(&self) {
        // Cancel first: requests then fail immediately, and an establishment in
        // flight is cut loose before we contend for the mutex it holds.
        self.closed.cancel();
        // Release the connection state with the handle; the driver holds its own
        // until it has flushed the close and exited.
        if let Some(handle) = self.current.lock().await.take() {
            close_connection(&handle);
        }
    }

    /// Whether [`close`](Self::close) has been called on this client.
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Returns the current connection, establishing (or re-establishing) one if
    /// none exists or the current one is closed.
    ///
    /// The async mutex serializes concurrent first-use so only one connection is
    /// established.
    async fn get_connection(&self) -> Result<ConnectionHandle<Http3ClientApp>, EstablishError> {
        // Fast path: don't queue behind an establishment we already know we will
        // not use.
        if self.is_closed() {
            return Err(EstablishError::Closed);
        }
        let mut guard = self.current.lock().await;
        // `close()` may have landed while we waited for the mutex, which is exactly what happens
        // when it interrupts the establishment the previous holder was running.
        if self.is_closed() {
            return Err(EstablishError::Closed);
        }

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
        let connect = connect(
            self.remote,
            self.socket.clone(),
            self.server_name.clone(),
            quiche_config,
            self.config.handshake_timeout,
            self.closed.clone(),
        );
        // Whichever arm wins, the connection is accounted for: the bootstrap task
        // holds the same token and closes whatever it managed to establish.
        let handle = tokio::select! {
            res = connect => res?,
            _ = self.closed.cancelled() => return Err(EstablishError::Closed),
        };
        if self.is_closed() {
            return Err(EstablishError::Closed);
        }
        *guard = Some(handle.clone());
        Ok(handle)
    }

    /// Test-only introspection: the number of per-stream bookkeeping entries the
    /// current connection still holds (the shared read/write `streams` map plus
    /// the client-only `response_heads` routing map). Returns `0` when no
    /// connection is established, which includes every closed client — after
    /// [`close`](Self::close) this says nothing about how the streams were
    /// released.
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

/// Streams `body` into `writer` and finishes the request when the body ends.
async fn pump_request_body<B>(body: B, mut writer: RequestBodyWriter) -> Result<(), UploadError>
where
    B: Body,
    B::Error: Send + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut body = std::pin::pin!(body);
    let mut trailers: Option<http::HeaderMap> = None;

    while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        let frame = frame.map_err(|e| UploadError::Body(e.into()))?;
        match frame.into_data() {
            Ok(mut data) => {
                let chunk = data.copy_to_bytes(data.remaining());
                writer.write_chunk(chunk).await.map_err(UploadError::Send)?;
            }
            // A non-data frame is the trailing header section (a well-formed body
            // yields nothing after it).
            Err(frame) => {
                if let Ok(t) = frame.into_trailers() {
                    trailers = Some(t);
                }
            }
        }
    }

    match trailers {
        Some(trailers) => {
            writer
                .write_trailers(trailers)
                .await
                .map_err(UploadError::Send)?
        }
        None => writer.finish().await.map_err(UploadError::Send)?,
    }
    Ok(())
}
