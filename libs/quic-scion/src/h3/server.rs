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
//!   the (shared, single) connection mutex to write each chunk.
//!
//! The read-side body machinery, the write-side frame helpers, and the
//! per-stream state are shared with the client and live in
//! `crate::h3::common`; this module holds only the server-specific glue
//! (request dispatch, response assembly, panic isolation).

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::FutureExt;
use http_body::{Body, Frame};
use squiche::h3::{Header, NameValue};

pub use crate::h3::common::H3Error;
use crate::{
    app::{QuicScionApplication, Wakeups},
    h3::common::{
        H3_INTERNAL_ERROR, H3App, ReadState, StreamState,
        headers::headers_to_map,
        read::{ConnReader, StreamReader, on_data, on_finished, on_reset, wake_writable},
        write::{pump_body, send_data, send_headers},
    },
    quic::connection::{ConnectionHandle, QuicScionConn, WeakConnectionHandle},
};

/// The request handler an [`Http3Server`] runs: it receives an `http::Request`
/// and resolves to an `http::Response`.
///
/// The request body type must be [`H3RequestBody`] (the server's streaming
/// body); the response body is any [`Body`].
pub trait HttpService {
    /// The request body type. Must be [`H3RequestBody`].
    type Body: Body;
    /// The response body type.
    type ResponseBody: Body;

    /// Calls the service with `req`, resolving to the response to send back.
    fn call(
        &self,
        req: http::Request<Self::Body>,
    ) -> impl std::future::Future<Output = http::Response<Self::ResponseBody>> + Send;
}

/// An HTTP/3 server application running an [`HttpService`] over a single
/// QUIC/SCION connection.
pub struct Http3Server<S: HttpService> {
    /// `None` until/unless the HTTP/3 layer is successfully set up (e.g. the
    /// ALPN must be `h3`).
    h3: Option<squiche::h3::Connection>,
    service: Arc<S>,
    self_handle: Option<WeakConnectionHandle<Http3Server<S>>>,
    streams: HashMap<u64, StreamState>,
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
                        st.read_state = ReadState::Trailers(headers_to_map(&list));
                        if let Some(w) = st.read_waker.take() {
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
                Ok((stream_id, squiche::h3::Event::Data)) => on_data(streams, stream_id, wakeups),
                Ok((stream_id, squiche::h3::Event::Finished)) => {
                    on_finished(streams, stream_id, wakeups)
                }
                Ok((stream_id, squiche::h3::Event::Reset(code))) => {
                    on_reset(streams, stream_id, code, wakeups)
                }
                // A peer GOAWAY (a client winding down / capping push IDs) needs
                // no action: we keep serving in-flight requests and let the
                // client close the connection when it is done.
                Ok((_, squiche::h3::Event::GoAway)) => {}
                Ok((_, squiche::h3::Event::PriorityUpdate)) => {}
                Err(squiche::h3::Error::Done) => break,
                Err(err) => {
                    tracing::warn!(?err, "error polling h3 connection");
                    break;
                }
            }
        }

        // (2) Wake response writers whose streams have regained capacity.
        wake_writable(conn, streams, wakeups);
    }

    fn on_closed(&mut self, wakeups: &mut Wakeups) {
        for st in self.streams.values_mut() {
            st.read_state = ReadState::Reset(0);
            if let Some(w) = st.read_waker.take() {
                wakeups.schedule(w);
            }
            if let Some(w) = st.write_waker.take() {
                wakeups.schedule(w);
            }
        }
    }
}

impl<S> H3App for Http3Server<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    fn h3_streams(
        &mut self,
    ) -> (
        Option<&mut squiche::h3::Connection>,
        &mut HashMap<u64, StreamState>,
    ) {
        (self.h3.as_mut(), &mut self.streams)
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
        tracing::warn!(
            stream_id,
            "failed to build request from headers; resetting stream"
        );
        // The stream was never registered, so no per-stream state to drop; reset
        // it so the peer is informed instead of hanging until the idle timeout.
        shutdown_stream(&reader_handle, stream_id, true);
        return;
    };

    // Register the stream. A header-only request (no body) is immediately at
    // EOF on the read side.
    let mut state = StreamState::default();
    if !more_frames {
        state.read_state = ReadState::Eof;
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
    // The head is sent; stream the body (DATA/trailers/FIN) via the shared pump.
    pump_body(&handle, stream_id, body).await
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
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    let headers = vec![Header::new(b":status", b"500")];
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
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    handle: WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    done_cleanly: bool,
}

impl<S> Drop for StreamCleanup<S>
where
    S: HttpService<Body = H3RequestBody> + Send + Sync + 'static,
    S::ResponseBody: Send + 'static,
    <S::ResponseBody as Body>::Data: Send,
    <S::ResponseBody as Body>::Error: Send,
{
    fn drop(&mut self) {
        // A response that finished cleanly already sent a FIN, so its write side
        // must *not* be reset; only aborted responses reset it.
        shutdown_stream(&self.handle, self.stream_id, !self.done_cleanly);
    }
}

/// Tears a request stream down and drops its per-stream bookkeeping.
///
/// Closes the read side (a no-op if it already finished; otherwise it discards
/// any unread body and signals `STOP_SENDING`). When `reset_write` is set, also
/// resets the write side — used when the request was aborted partway or the
/// service handler panicked. A response that finished cleanly already sent a
/// FIN, so its write side must *not* be reset.
///
/// Removes the stream's entry from the server's stream map so quiche can collect
/// it and per-stream state does not accumulate over the connection's life. Uses
/// the poison-recovering lock because it typically runs from a `Drop` guard,
/// where a second panic (on a poisoned lock) would abort the process during
/// unwinding.
fn shutdown_stream<S: HttpService>(
    handle: &WeakConnectionHandle<Http3Server<S>>,
    stream_id: u64,
    reset_write: bool,
) {
    let Some(handle) = handle.upgrade() else {
        return;
    };
    let mut guard = handle.lock_recovering();
    let QuicScionConn { inner, app, .. } = &mut *guard;

    let _ = inner.stream_shutdown(stream_id, squiche::Shutdown::Read, 0);
    if reset_write {
        let _ = inner.stream_shutdown(stream_id, squiche::Shutdown::Write, H3_INTERNAL_ERROR);
    }
    app.streams.remove(&stream_id);

    drop(guard);
    handle.notify();
}

/// Builds the HTTP/3 response header list (`:status` plus regular headers).
fn response_headers(parts: &http::response::Parts) -> Vec<Header> {
    let mut headers = vec![Header::new(b":status", parts.status.as_str().as_bytes())];
    for (name, value) in parts.headers.iter() {
        headers.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    headers
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
