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

//! An HTTP/3 server [`QuicScionApplication`] driving an [`HttpService`].
//!
//! [`Http3Server`] is constructed once per QUIC connection by the connection
//! driver. On every driver iteration its [`QuicScionApplication::update`] drains
//! HTTP/3 events in lockstep with the connection:
//!
//! * A new request (a leading `Headers` event) is turned into an `http::Request` with a streaming
//!   [`H3RequestBody`] and dispatched to the service via a spawned task. The request body is
//!   **not** materialized before dispatch, so streaming methods such as `CONNECT` are supported.
//! * The spawned task awaits `S::call(..)` and then streams the response back to the peer, locking
//!   the (shared, single) connection mutex to write each chunk via `send_response`/`send_body`.
//!
//! Request body frames are read directly from the connection via
//! `recv_body` inside [`H3RequestBody::poll_frame`]; flow control is therefore
//! provided entirely by the QUIC stream window (no intermediate buffer).

use std::{
    collections::HashMap,
    future::poll_fn,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use futures::FutureExt;
use http_body::{Body, Frame};
use squiche::h3::NameValue;

use crate::{
    app::{QuicScionApplication, Wakeups},
    http::HttpService,
    quic::connection::{ConnectionHandle, QuicScionConn, WeakConnectionHandle},
};

/// HTTP/3 internal error code, used when resetting a stream on a body error.
const H3_INTERNAL_ERROR: u64 = 0x0102;

/// An HTTP/3 server application running an [`HttpService`] over a single
/// QUIC/SCION connection.
pub struct Http3Server<S: HttpService> {
    /// `None` until/unless the HTTP/3 layer is successfully set up (e.g. the
    /// ALPN must be `h3`).
    h3: Option<squiche::h3::Connection>,
    service: Arc<S>,
    self_handle: Option<WeakConnectionHandle<Http3Server<S>>>,
    streams: HashMap<u64, StreamState>,
    draining: bool,
}

impl<S> QuicScionApplication for Http3Server<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    type Config = Http3ServerConfig<S>;

    fn on_established(conn: &mut squiche::Connection, config: &Self::Config) -> Self {
        let mut app = Http3Server {
            h3: None,
            service: config.service.clone(),
            self_handle: None,
            streams: HashMap::new(),
            draining: false,
        };

        if conn.application_proto() != b"h3" {
            tracing::warn!(
                alpn = ?conn.application_proto(),
                "connection ALPN is not h3; closing"
            );
            let _ = conn.close(true, H3_INTERNAL_ERROR, b"expected h3 alpn");
            return app;
        }

        match squiche::h3::Config::new()
            .and_then(|h3_config| squiche::h3::Connection::with_transport(conn, &h3_config))
        {
            Ok(h3) => app.h3 = Some(h3),
            Err(err) => {
                tracing::warn!(?err, "failed to create h3 connection; closing");
                let _ = conn.close(true, H3_INTERNAL_ERROR, b"h3 init failed");
            }
        }
        app
    }

    fn bind(&mut self, handle: &ConnectionHandle<Self>) {
        self.self_handle = Some(handle.downgrade());
    }

    fn update(&mut self, conn: &mut squiche::Connection, wakeups: &mut Wakeups) {
        let Http3Server {
            h3,
            service,
            self_handle,
            streams,
            draining,
        } = self;
        let Some(h3) = h3.as_mut() else {
            return;
        };

        // (1) Drain HTTP/3 events, advancing per-stream state machines.
        loop {
            match h3.poll(conn) {
                Ok((stream_id, squiche::h3::Event::Headers { list, more_frames })) => {
                    if streams.contains_key(&stream_id) {
                        // A trailing header section (the leading one created the
                        // stream entry at dispatch time).
                        let st = streams.entry(stream_id).or_default();
                        st.read.state = ReadState::Trailers(headers_to_map(&list));
                        if let Some(w) = st.read.waker.take() {
                            wakeups.schedule(w);
                        }
                    } else if let Some(reader_handle) = self_handle.clone() {
                        dispatch_request::<S>(
                            stream_id,
                            list,
                            more_frames,
                            service,
                            reader_handle,
                            streams,
                        );
                    }
                }
                Ok((stream_id, squiche::h3::Event::Data)) => {
                    if let Some(st) = streams.get_mut(&stream_id)
                        && let Some(w) = st.read.waker.take()
                    {
                        wakeups.schedule(w);
                    }
                }
                Ok((stream_id, squiche::h3::Event::Finished)) => {
                    if let Some(st) = streams.get_mut(&stream_id) {
                        if matches!(st.read.state, ReadState::Streaming) {
                            st.read.state = ReadState::Eof;
                        }
                        if let Some(w) = st.read.waker.take() {
                            wakeups.schedule(w);
                        }
                    }
                }
                Ok((stream_id, squiche::h3::Event::Reset(code))) => {
                    if let Some(st) = streams.get_mut(&stream_id) {
                        st.read.state = ReadState::Reset(code);
                        if let Some(w) = st.read.waker.take() {
                            wakeups.schedule(w);
                        }
                        if let Some(w) = st.write_waker.take() {
                            wakeups.schedule(w);
                        }
                    }
                }
                Ok((_, squiche::h3::Event::GoAway)) => {
                    *draining = true;
                }
                Ok((_, squiche::h3::Event::PriorityUpdate)) => {}
                Err(squiche::h3::Error::Done) => break,
                Err(err) => {
                    tracing::warn!(?err, "error polling h3 connection");
                    break;
                }
            }
        }

        // (2) Wake response writers whose streams have regained capacity.
        for stream_id in conn.writable() {
            if let Some(st) = streams.get_mut(&stream_id)
                && let Some(w) = st.write_waker.take()
            {
                wakeups.schedule(w);
            }
        }
    }

    fn on_closed(&mut self, wakeups: &mut Wakeups) {
        for st in self.streams.values_mut() {
            st.read.state = ReadState::Reset(0);
            if let Some(w) = st.read.waker.take() {
                wakeups.schedule(w);
            }
            if let Some(w) = st.write_waker.take() {
                wakeups.schedule(w);
            }
        }
    }
}

/// Configuration for an [`Http3Server`]: the service shared across all
/// connections of an endpoint.
pub struct Http3ServerConfig<S> {
    service: Arc<S>,
}

impl<S> Http3ServerConfig<S> {
    /// Creates a config that serves requests with `service`.
    pub fn new(service: S) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    /// Creates a config from an already-shared `service`.
    pub fn from_shared(service: Arc<S>) -> Self {
        Self { service }
    }
}

/// The streaming body of an incoming HTTP/3 request.
///
/// Body data is read directly from the QUIC connection on each
/// [`Body::poll_frame`], so backpressure is provided by the QUIC stream's flow
/// control window. This is the body type a service must use:
/// `impl HttpService<Body = H3RequestBody>`.
pub struct H3RequestBody {
    reader: Arc<dyn StreamReader>,
    stream_id: u64,
}

impl Body for H3RequestBody {
    type Data = Bytes;
    type Error = H3Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.reader.poll_read(self.stream_id, cx)
    }
}

/// An error observed while reading an HTTP/3 request body.
#[derive(Debug)]
pub enum H3Error {
    /// The peer reset the stream with the given HTTP/3 error code.
    Reset(u64),
    /// The underlying QUIC connection was closed.
    ConnectionClosed,
    /// An HTTP/3 protocol error occurred.
    H3(squiche::h3::Error),
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Reset(code) => write!(f, "stream reset by peer (code {code:#x})"),
            H3Error::ConnectionClosed => write!(f, "connection closed"),
            H3Error::H3(err) => write!(f, "h3 error: {err}"),
        }
    }
}

impl std::error::Error for H3Error {}

/// Builds an `http::Request` for a new stream and spawns the service call.
fn dispatch_request<S>(
    stream_id: u64,
    list: Vec<squiche::h3::Header>,
    more_frames: bool,
    service: &Arc<S>,
    reader_handle: WeakConnectionHandle<Http3Server<S>>,
    streams: &mut HashMap<u64, StreamState>,
) where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    let reader: Arc<dyn StreamReader> = Arc::new(ConnReader {
        handle: reader_handle.clone(),
    });
    let body = H3RequestBody { reader, stream_id };

    let Some(request) = build_request(&list, body) else {
        tracing::warn!(stream_id, "failed to build request from headers; ignoring");
        return;
    };

    // Register the stream. A header-only request (no body) is immediately at
    // EOF on the read side.
    let mut state = StreamState::default();
    if !more_frames {
        state.read.state = ReadState::Eof;
    }
    streams.insert(stream_id, state);

    let service = service.clone();
    tokio::spawn(async move {
        // `cleanup` tears the stream down (reset + drop the bookkeeping) when
        // this task ends for *any* reason — normal completion, a panic in the
        // response body, or cancellation. Without it, a panic would leak the
        // stream entry and stall the peer (no response, no reset).
        let mut cleanup = StreamCleanup {
            handle: reader_handle.clone(),
            stream_id,
            done_cleanly: false,
        };

        // Isolate a panicking handler: convert the panic into a `500` rather
        // than letting it unwind the task (which would only reset the stream
        // and give the peer no status). Panics from the *response body* happen
        // later in `serve_response` and are not catchable here; they fall
        // through to `cleanup`, which resets the stream.
        match AssertUnwindSafe(service.call(request)).catch_unwind().await {
            Ok(response) => {
                cleanup.done_cleanly =
                    serve_response::<S>(reader_handle, stream_id, response).await;
            }
            Err(_panic) => {
                tracing::error!(stream_id, "h3 service handler panicked; replying 500");
                cleanup.done_cleanly = send_error_response::<S>(&reader_handle, stream_id).await;
            }
        }
    });
}

/// Streams a service response back to the peer on `stream_id`.
///
/// Returns `true` if the response finished cleanly (a FIN was sent), or `false`
/// if it was aborted partway through (the caller should reset the stream).
async fn serve_response<S>(
    handle: WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    response: http::Response<S::ResponseBody>,
) -> bool
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    let (parts, body) = response.into_parts();
    let headers = response_headers(&parts);
    if let Err(err) = send_headers(&handle, stream_id, headers).await {
        tracing::debug!(?err, stream_id, "failed to send response headers");
        return false;
    }

    let mut body = std::pin::pin!(body);
    let mut trailers_sent = false;
    loop {
        match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            Some(Ok(frame)) => {
                match frame.into_data() {
                    Ok(mut data) => {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if let Err(err) = send_data(&handle, stream_id, bytes, false).await {
                            tracing::debug!(?err, stream_id, "failed to send response body");
                            return false;
                        }
                    }
                    Err(non_data) => {
                        // A trailing header section terminates the response: it
                        // carries the FIN, so it must be the last frame sent.
                        // Other (unknown) frame kinds are ignored.
                        if let Ok(map) = non_data.into_trailers() {
                            let trailers = header_map_to_h3(&map);
                            if !trailers.is_empty() {
                                if let Err(err) = send_trailers(&handle, stream_id, trailers).await
                                {
                                    tracing::debug!(
                                        ?err,
                                        stream_id,
                                        "failed to send response trailers"
                                    );
                                    return false;
                                }
                                trailers_sent = true;
                                break;
                            }
                        }
                    }
                }
            }
            Some(Err(_err)) => {
                tracing::debug!(stream_id, "response body errored before completion");
                return false;
            }
            None => break,
        }
    }

    if trailers_sent {
        // The trailing header section already finished the stream with a FIN.
        true
    } else {
        // Finish the stream with an empty, FIN-bearing body frame.
        send_data(&handle, stream_id, Bytes::new(), true)
            .await
            .is_ok()
    }
}

/// Sends the response head, retrying while the stream is blocked.
async fn send_headers<S>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    headers: Vec<squiche::h3::Header>,
) -> Result<(), H3Error>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    poll_fn(|cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        if app.h3.is_none() {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        }
        match app
            .h3
            .as_mut()
            .unwrap()
            .send_response(inner, stream_id, &headers, false)
        {
            Ok(()) => {
                drop(guard);
                handle.notify();
                Poll::Ready(Ok(()))
            }
            Err(squiche::h3::Error::StreamBlocked) => {
                app.streams.entry(stream_id).or_default().write_waker = Some(cx.waker().clone());
                drop(guard);
                handle.notify();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(H3Error::H3(err))),
        }
    })
    .await
}

/// Sends `bytes` (and optionally a FIN) on `stream_id`, retrying across stream
/// capacity blocks.
async fn send_data<S>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    mut bytes: Bytes,
    fin: bool,
) -> Result<(), H3Error>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    poll_fn(move |cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        if app.h3.is_none() {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        }

        loop {
            if bytes.is_empty() && !fin {
                drop(guard);
                handle.notify();
                return Poll::Ready(Ok(()));
            }
            match app
                .h3
                .as_mut()
                .unwrap()
                .send_body(inner, stream_id, bytes.as_ref(), fin)
            {
                Ok(written) => {
                    bytes.advance(written);
                    if bytes.is_empty() {
                        // All data (and the FIN, if any) was accepted.
                        drop(guard);
                        handle.notify();
                        return Poll::Ready(Ok(()));
                    }
                    // Partial write; loop to send the remainder.
                }
                Err(squiche::h3::Error::Done) | Err(squiche::h3::Error::StreamBlocked) => {
                    app.streams.entry(stream_id).or_default().write_waker =
                        Some(cx.waker().clone());
                    drop(guard);
                    handle.notify();
                    return Poll::Pending;
                }
                Err(err) => return Poll::Ready(Err(H3Error::H3(err))),
            }
        }
    })
    .await
}

/// Sends a trailing header section (closing the stream with a FIN), retrying
/// while the stream is blocked.
async fn send_trailers<S>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    trailers: Vec<squiche::h3::Header>,
) -> Result<(), H3Error>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    poll_fn(|cx| {
        let Some(handle) = handle.upgrade() else {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        if app.h3.is_none() {
            return Poll::Ready(Err(H3Error::ConnectionClosed));
        }
        match app
            .h3
            .as_mut()
            .unwrap()
            .send_additional_headers(inner, stream_id, &trailers, true, true)
        {
            Ok(()) => {
                drop(guard);
                handle.notify();
                Poll::Ready(Ok(()))
            }
            Err(squiche::h3::Error::StreamBlocked) => {
                app.streams.entry(stream_id).or_default().write_waker = Some(cx.waker().clone());
                drop(guard);
                handle.notify();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(H3Error::H3(err))),
        }
    })
    .await
}

/// Sends a bodyless `500` response (head + FIN) on `stream_id`, used when the
/// service handler panics before producing a response.
///
/// Returns `true` if the `500` was delivered cleanly (FIN sent), or `false`
/// otherwise (the stream's cleanup will then reset it).
async fn send_error_response<S>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
) -> bool
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    let headers = vec![squiche::h3::Header::new(b":status", b"500")];
    if let Err(err) = send_headers(handle, stream_id, headers).await {
        tracing::debug!(?err, stream_id, "failed to send 500 response headers");
        return false;
    }
    send_data(handle, stream_id, Bytes::new(), true)
        .await
        .is_ok()
}

/// A guard that tears the stream down when the request task ends, regardless of
/// how: normal completion, a panic, or cancellation. This ensures the QUIC
/// stream is always reset/finished and the per-stream bookkeeping is always
/// released, so a panicking handler can neither leak streams nor stall the peer.
///
/// `done_cleanly` records whether the response finished with a FIN (write side
/// left intact) or must be reset; it is updated by the task before it returns.
struct StreamCleanup<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    handle: WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    done_cleanly: bool,
}

impl<S> Drop for StreamCleanup<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    fn drop(&mut self) {
        finish_stream::<S>(&self.handle, self.stream_id, self.done_cleanly);
    }
}

/// Tears down a stream once its response task has finished.
///
/// Closes the read side (a no-op if it already finished; otherwise it discards
/// any unread request body and signals `STOP_SENDING`), resets the write side
/// when the response was aborted, and drops the per-stream bookkeeping. This
/// lets quiche collect the stream and prevents per-stream state from
/// accumulating over the life of a connection.
///
/// A response that finished cleanly already sent a FIN, so its write side must
/// *not* be reset; only aborted responses reset it.
///
/// Uses the poison-recovering lock because it runs from [`StreamCleanup`]'s
/// `Drop`, where a second panic (on a poisoned lock) would abort the process
/// during unwinding.
fn finish_stream<S>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    response_done_cleanly: bool,
) where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    let Some(handle) = handle.upgrade() else {
        return;
    };
    let mut guard = handle.lock_recovering();
    let QuicScionConn { inner, app, .. } = &mut *guard;

    let _ = inner.stream_shutdown(stream_id, squiche::Shutdown::Read, 0);
    if !response_done_cleanly {
        let _ = inner.stream_shutdown(stream_id, squiche::Shutdown::Write, H3_INTERNAL_ERROR);
    }
    app.streams.remove(&stream_id);

    drop(guard);
    handle.notify();
}

/// Converts an HTTP/3 header list into an `http::HeaderMap`, skipping
/// pseudo-headers.
fn headers_to_map(list: &[squiche::h3::Header]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for header in list {
        let name = header.name();
        if name.starts_with(b":") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name),
            http::HeaderValue::from_bytes(header.value()),
        ) {
            map.append(name, value);
        }
    }
    map
}

/// Builds the HTTP/3 response header list (`:status` plus regular headers).
fn response_headers(parts: &http::response::Parts) -> Vec<squiche::h3::Header> {
    let mut headers = vec![squiche::h3::Header::new(
        b":status",
        parts.status.as_str().as_bytes(),
    )];
    for (name, value) in parts.headers.iter() {
        headers.push(squiche::h3::Header::new(
            name.as_str().as_bytes(),
            value.as_bytes(),
        ));
    }
    headers
}

/// Converts an `http::HeaderMap` into an HTTP/3 header list, skipping any
/// pseudo-headers (a trailing header section must not contain them).
fn header_map_to_h3(map: &http::HeaderMap) -> Vec<squiche::h3::Header> {
    map.iter()
        .filter(|(name, _)| !name.as_str().starts_with(':'))
        .map(|(name, value)| squiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
}

/// Builds an `http::Request` from a received header list and the streaming
/// request body.
fn build_request(
    list: &[squiche::h3::Header],
    body: H3RequestBody,
) -> Option<http::Request<H3RequestBody>> {
    let mut method: Option<http::Method> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut path: Option<Vec<u8>> = None;
    let mut scheme: Option<Vec<u8>> = None;
    let mut headers = http::HeaderMap::new();

    for header in list {
        match header.name() {
            b":method" => method = http::Method::from_bytes(header.value()).ok(),
            b":authority" => authority = Some(header.value().to_vec()),
            b":path" => path = Some(header.value().to_vec()),
            b":scheme" => scheme = Some(header.value().to_vec()),
            name if name.starts_with(b":") => {}
            name => {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(name),
                    http::HeaderValue::from_bytes(header.value()),
                ) {
                    headers.append(name, value);
                }
            }
        }
    }

    let method = method?;

    let uri = if method == http::Method::CONNECT {
        // CONNECT uses the authority-form request target.
        let authority = authority.as_deref()?;
        let authority = http::uri::Authority::try_from(authority).ok()?;
        let mut parts = http::uri::Parts::default();
        parts.authority = Some(authority);
        http::Uri::from_parts(parts).ok()?
    } else {
        let scheme = scheme.as_deref().unwrap_or(b"https");
        let authority = authority.as_deref().unwrap_or(b"");
        let path = path.as_deref().unwrap_or(b"/");
        let mut raw = Vec::with_capacity(scheme.len() + 3 + authority.len() + path.len());
        raw.extend_from_slice(scheme);
        raw.extend_from_slice(b"://");
        raw.extend_from_slice(authority);
        raw.extend_from_slice(path);
        http::Uri::try_from(raw).ok()?
    };

    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .ok()?;
    *request.headers_mut() = headers;
    Some(request)
}

/// Type-erased access to a connection for reading request bodies.
///
/// This erases the service type `S` from [`H3RequestBody`], so a service only
/// needs to name `H3RequestBody` (and not `H3RequestBody<Self>`) as its request
/// body type.
trait StreamReader: Send + Sync {
    /// Polls the request body for `stream_id`, reading directly from the
    /// connection via `recv_body`.
    fn poll_read(
        &self,
        stream_id: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, H3Error>>>;
}

/// A [`StreamReader`] backed by a weak handle to an [`Http3Server`] connection.
struct ConnReader<S: HttpService> {
    handle: WeakConnectionHandle<Http3Server<S>>,
}

impl<S> StreamReader for ConnReader<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
{
    fn poll_read(
        &self,
        stream_id: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, H3Error>>> {
        let Some(handle) = self.handle.upgrade() else {
            return Poll::Ready(None);
        };
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        if app.h3.is_none() {
            return Poll::Ready(None);
        }

        let mut buf = [0u8; 16 * 1024];
        match app
            .h3
            .as_mut()
            .unwrap()
            .recv_body(inner, stream_id, &mut buf)
        {
            Ok(n) => {
                let bytes = Bytes::copy_from_slice(&buf[..n]);
                drop(guard);
                // Reading frees flow-control window; nudge the driver so it can
                // flush any resulting transport frames.
                handle.notify();
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Err(squiche::h3::Error::Done) => {
                let st = app.streams.entry(stream_id).or_default();
                match std::mem::replace(&mut st.read.state, ReadState::Streaming) {
                    ReadState::Streaming => {
                        st.read.waker = Some(cx.waker().clone());
                        drop(guard);
                        // Ask the driver to poll() for the next event (it may
                        // already be buffered behind the bytes we just drained).
                        handle.notify();
                        Poll::Pending
                    }
                    ReadState::Trailers(trailers) => {
                        st.read.state = ReadState::Eof;
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    }
                    ReadState::Eof => {
                        st.read.state = ReadState::Eof;
                        Poll::Ready(None)
                    }
                    ReadState::Reset(code) => {
                        st.read.state = ReadState::Reset(code);
                        Poll::Ready(Some(Err(H3Error::Reset(code))))
                    }
                }
            }
            Err(err) => Poll::Ready(Some(Err(H3Error::H3(err)))),
        }
    }
}

#[derive(Default)]
struct StreamState {
    read: ReadHalf,
    /// Waker of the task currently writing the response (blocked on capacity).
    write_waker: Option<Waker>,
}

#[derive(Default)]
struct ReadHalf {
    state: ReadState,
    /// Waker of the task currently reading the request body.
    waker: Option<Waker>,
}

/// Per-stream read state, advanced by the driver's `update` loop and consumed
/// by [`H3RequestBody::poll_frame`].
#[derive(Default)]
enum ReadState {
    /// More request-body data may still arrive.
    #[default]
    Streaming,
    /// A trailing header section was received and is ready to be yielded.
    Trailers(http::HeaderMap),
    /// The request body has ended (FIN received).
    Eof,
    /// The stream was reset by the peer with the given code.
    Reset(u64),
}
