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
//! is a streaming [`H3ResponseBody`] once the response head arrives. Because
//! HTTP/3 places no ordering between the request and response bodies, the caller
//! must drive the two concurrently (typically by sending the body from a spawned
//! task while awaiting/reading the response). A bidirectional exchange such as a
//! `CONNECT` tunnel is just a request whose [`RequestBodyWriter`] and
//! [`H3ResponseBody`] are the two directions; [`H3DuplexStream`] adapts that pair
//! into an `AsyncRead + AsyncWrite` byte stream (e.g. for TCP forward proxying
//! with `tokio::io::copy_bidirectional`). Read/establishment failures surface as
//! [`H3Error`], [`EstablishError`], and [`RequestError`].
//!
//! This is the client counterpart of
//! [`Http3Server`](crate::h3::server::Http3Server), built on the same
//! [`QuicScionApplication`](crate::app::QuicScionApplication) /
//! [`ConnectionHandle`] machinery. The
//! per-connection internals — the application that routes responses, the
//! connection bootstrap, the socket ingress loop, and the streaming body
//! adapters — are private submodules; only the types above are part of the API.
//!
//! The legacy client lives under
//! [`deprecated`](crate::h3::deprecated::client::H3Client).

mod app;
mod body;
mod connect;
mod duplex;
mod error;
mod ingress;
mod writer;

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub use body::H3ResponseBody;
pub use duplex::H3DuplexStream;
pub use error::{EstablishError, RequestError};
use sciparse::address::socket_addr::ScionSocketAddr;
use squiche::h3::Header;
use tokio::sync::Mutex;
pub use writer::RequestBodyWriter;

use self::{
    app::{
        Http3ClientApp, ReadGuard, ResponseHead, StreamRef, WriteGuard, poll_head, register_stream,
    },
    connect::connect,
};
pub use crate::h3::common::H3Error;
use crate::{
    quic::{
        config::QuicConfig,
        connection::{ConnectionHandle, QuicScionConn, WeakConnectionHandle},
    },
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
        let (parts, ()) = req.into_parts();
        let headers = request_headers(&parts);

        let stream_id = send_request(&handle, &headers, false)?;
        handle.notify();
        let stream_ref = StreamRef::new(handle.downgrade(), stream_id);

        let response = ResponseFut::new(ReadGuard::new(stream_ref.clone()));
        let writer = RequestBodyWriter::new(WriteGuard::new(stream_ref));
        Ok((response, writer))
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

/// Sends the request head on a fresh stream, registering per-stream state, and
/// returns the allocated stream id.
fn send_request(
    handle: &ConnectionHandle<Http3ClientApp>,
    headers: &[Header],
    fin: bool,
) -> Result<u64, RequestError> {
    let mut guard = handle.lock();
    let QuicScionConn { inner, app, .. } = &mut *guard;
    let Some(h3) = app.h3.as_mut() else {
        return Err(RequestError::ConnectionClosed);
    };
    match h3.send_request(inner, headers, fin) {
        Ok(stream_id) => {
            register_stream(app, stream_id);
            Ok(stream_id)
        }
        Err(squiche::h3::Error::StreamBlocked) => Err(RequestError::StreamBlocked),
        Err(err) => Err(RequestError::H3(err)),
    }
}

/// Builds the HTTP/3 request header list (pseudo-headers plus regular headers).
///
/// `CONNECT` uses authority-form (`:method` + `:authority`, no `:scheme`/`:path`);
/// every other method gets `:method`/`:scheme`/`:authority`/`:path`.
fn request_headers(parts: &http::request::Parts) -> Vec<Header> {
    let mut headers = vec![Header::new(b":method", parts.method.as_str().as_bytes())];

    if parts.method == http::Method::CONNECT {
        if let Some(authority) = parts.uri.authority() {
            headers.push(Header::new(b":authority", authority.as_str().as_bytes()));
        }
    } else {
        let scheme = parts.uri.scheme_str().unwrap_or("https");
        headers.push(Header::new(b":scheme", scheme.as_bytes()));
        if let Some(authority) = parts.uri.authority() {
            headers.push(Header::new(b":authority", authority.as_str().as_bytes()));
        }
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        headers.push(Header::new(b":path", path.as_bytes()));
    }

    for (name, value) in parts.headers.iter() {
        headers.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    headers
}

/// Assembles an `http::Response` from a routed head and the streaming body.
fn head_into_response(head: ResponseHead, body: H3ResponseBody) -> http::Response<H3ResponseBody> {
    let mut response = http::Response::builder()
        .status(head.status)
        .body(body)
        .expect("status is valid");
    *response.headers_mut() = head.headers;
    response
}

/// A future resolving to the response of a request issued via
/// [`Http3Client::request`].
///
/// It resolves once the response head has arrived, yielding an `http::Response`
/// whose body is the streaming [`H3ResponseBody`]. It owns the stream's read-side
/// guard: dropped before the head arrives it stops the read side; on success the
/// guard is handed to the response body, which continues to own it.
pub struct ResponseFut {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    /// The read-side guard, taken when the head arrives and moved into the
    /// response body. `None` once the future has resolved.
    read_guard: Option<ReadGuard>,
}

impl ResponseFut {
    fn new(read_guard: ReadGuard) -> Self {
        Self {
            handle: read_guard.handle(),
            stream_id: read_guard.stream_id(),
            read_guard: Some(read_guard),
        }
    }
}

impl Future for ResponseFut {
    type Output = Result<http::Response<H3ResponseBody>, RequestError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match poll_head(&this.handle, this.stream_id, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(head)) => {
                let guard = this
                    .read_guard
                    .take()
                    .expect("ResponseFut polled after completion");
                Poll::Ready(Ok(head_into_response(head, H3ResponseBody::new(guard))))
            }
            Poll::Ready(Err(err)) => {
                // The read side is already gone (reset or connection close); mark
                // the guard done so its drop does not signal STOP_SENDING on a
                // dead stream.
                if let Some(guard) = this.read_guard.as_mut() {
                    guard.mark_done();
                }
                Poll::Ready(Err(err))
            }
        }
    }
}
