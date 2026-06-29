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

//! The per-connection HTTP/3 client application and its event routing.
//!
//! [`Http3ClientApp`] is the client analog of
//! [`Http3Server`](crate::h3::server::Http3Server): a
//! [`QuicScionApplication`] driven in lockstep by the connection driver. The
//! roles invert relative to the server — the client *initiates* requests
//! out-of-band through the [`ConnectionHandle`] (from the
//! [`Http3Client`](super::Http3Client) facade), and the leading inbound
//! `Headers` event is the **response head**, routed by stream id to the waiting
//! response future (`ResponseFut`).
//!
//! The read-side state (`Data`/`Finished`/`Reset`) and the `writable()` waker
//! logic are shared with the server via `crate::h3::common`; this module adds
//! the client-only response-head routing kept in a separate `response_heads` map (so the
//! shared per-stream `StreamState` stays identical on both sides).

use std::{
    collections::HashMap,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use squiche::h3::NameValue;

use crate::{
    app::{QuicScionApplication, Wakeups},
    h3::{
        client::error::RequestError,
        common::{
            H3_INTERNAL_ERROR, H3_REQUEST_CANCELLED, H3App, ReadState, StreamState,
            headers::headers_to_map,
            read::{on_data, on_finished, on_reset, wake_writable},
        },
    },
    quic::connection::{ConnectionHandle, QuicScionConn, WeakConnectionHandle},
};

/// An HTTP/3 client application running over a single QUIC/SCION connection.
///
/// Constructed once per connection by the `connect()` bootstrap (via
/// [`QuicScionApplication::on_established`]) and stepped by the connection
/// driver.
pub struct Http3ClientApp {
    /// `None` until/unless the HTTP/3 layer is successfully set up (the ALPN
    /// must be `h3`).
    pub(crate) h3: Option<squiche::h3::Connection>,
    pub(crate) self_handle: Option<WeakConnectionHandle<Http3ClientApp>>,
    /// Shared per-stream read/write state.
    pub(crate) streams: HashMap<u64, StreamState>,
    /// Client-only response-head routing, keyed by stream id.
    pub(crate) response_heads: HashMap<u64, ResponseHeadSlot>,
}

impl QuicScionApplication for Http3ClientApp {
    type Config = ();

    fn on_established(conn: &mut squiche::Connection, _config: &Self::Config) -> Self {
        let mut app = Http3ClientApp {
            h3: None,
            self_handle: None,
            streams: HashMap::new(),
            response_heads: HashMap::new(),
        };

        if conn.application_proto() != b"h3" {
            tracing::warn!(
                alpn = ?conn.application_proto(),
                "client connection ALPN is not h3; closing"
            );
            let _ = conn.close(true, H3_INTERNAL_ERROR, b"expected h3 alpn");
            return app;
        }

        match squiche::h3::Config::new()
            .and_then(|h3_config| squiche::h3::Connection::with_transport(conn, &h3_config))
        {
            Ok(h3) => app.h3 = Some(h3),
            Err(err) => {
                tracing::warn!(?err, "failed to create client h3 connection; closing");
                let _ = conn.close(true, H3_INTERNAL_ERROR, b"h3 init failed");
            }
        }
        app
    }

    fn bind(&mut self, handle: &ConnectionHandle<Self>) {
        self.self_handle = Some(handle.downgrade());
    }

    fn update(&mut self, conn: &mut squiche::Connection, wakeups: &mut Wakeups) {
        let Http3ClientApp {
            h3,
            streams,
            response_heads,
            ..
        } = self;
        let Some(h3) = h3.as_mut() else {
            return;
        };

        // (1) Drain HTTP/3 events, advancing per-stream state machines.
        loop {
            match h3.poll(conn) {
                Ok((stream_id, squiche::h3::Event::Headers { list, .. })) => {
                    match response_heads.get_mut(&stream_id) {
                        // The leading header section is the response head: route
                        // it to the waiting request future.
                        Some(slot) if matches!(slot.state, ResponseHeadState::Waiting) => {
                            match parse_response_head(&list) {
                                Some(head) => slot.state = ResponseHeadState::Arrived(head),
                                None => {
                                    if let Some(st) = streams.get_mut(&stream_id) {
                                        st.read_state = ReadState::Reset(H3_INTERNAL_ERROR);
                                    }
                                }
                            }
                            if let Some(w) = slot.waker.take() {
                                wakeups.schedule(w);
                            }
                        }
                        // A trailing header section after the head: surfaced as
                        // body trailers (identical to the server).
                        Some(_) => {
                            if let Some(st) = streams.get_mut(&stream_id) {
                                st.read_state = ReadState::Trailers(headers_to_map(&list));
                                if let Some(w) = st.read_waker.take() {
                                    wakeups.schedule(w);
                                }
                            }
                        }
                        // An event for a stream we never opened (or already tore
                        // down); nothing to route it to.
                        None => {}
                    }
                }
                Ok((stream_id, squiche::h3::Event::Data)) => on_data(streams, stream_id, wakeups),
                Ok((stream_id, squiche::h3::Event::Finished)) => {
                    on_finished(streams, stream_id, wakeups)
                }
                Ok((stream_id, squiche::h3::Event::Reset(code))) => {
                    on_reset(streams, stream_id, code, wakeups);
                    // A reset before the head wakes the pending request future so
                    // it can fail instead of hanging.
                    if let Some(slot) = response_heads.get_mut(&stream_id)
                        && let Some(w) = slot.waker.take()
                    {
                        wakeups.schedule(w);
                    }
                }
                Ok((_, squiche::h3::Event::GoAway)) => {}
                Ok((_, squiche::h3::Event::PriorityUpdate)) => {}
                Err(squiche::h3::Error::Done) => break,
                Err(err) => {
                    tracing::warn!(?err, "error polling client h3 connection");
                    break;
                }
            }
        }

        // (2) Wake request-body / tunnel writers whose streams regained capacity.
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
        for slot in self.response_heads.values_mut() {
            if let Some(w) = slot.waker.take() {
                wakeups.schedule(w);
            }
        }
    }
}

impl H3App for Http3ClientApp {
    fn h3_streams(
        &mut self,
    ) -> (
        Option<&mut squiche::h3::Connection>,
        &mut HashMap<u64, StreamState>,
    ) {
        (self.h3.as_mut(), &mut self.streams)
    }
}

/// The response-head routing slot for a client-opened stream.
#[derive(Default)]
pub(crate) struct ResponseHeadSlot {
    pub(crate) state: ResponseHeadState,
    /// Waker of the `ResponseFut` awaiting the response head.
    pub(crate) waker: Option<Waker>,
}

/// The state of a response head as it is routed to the waiting request future.
#[derive(Default)]
pub(crate) enum ResponseHeadState {
    /// The request future is waiting for the response head.
    #[default]
    Waiting,
    /// The response head arrived and has not yet been taken by the future.
    Arrived(ResponseHead),
    /// The response head has been delivered to the future.
    Done,
}

/// A parsed HTTP/3 response head.
pub(crate) struct ResponseHead {
    pub(crate) status: http::StatusCode,
    pub(crate) headers: http::HeaderMap,
}

/// Registers a freshly-opened request stream's read/write and head-routing state.
pub(crate) fn register_stream(app: &mut Http3ClientApp, stream_id: u64) {
    app.streams.insert(stream_id, StreamState::default());
    app.response_heads
        .insert(stream_id, ResponseHeadSlot::default());
}

/// Parses a response header list into a [`ResponseHead`] (status plus regular
/// headers). Returns `None` if there is no valid `:status` pseudo-header.
fn parse_response_head(list: &[squiche::h3::Header]) -> Option<ResponseHead> {
    let mut status = None;
    let mut headers = http::HeaderMap::new();
    for header in list {
        match header.name() {
            b":status" => {
                status = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|value| value.parse::<u16>().ok())
                    .and_then(|code| http::StatusCode::from_u16(code).ok());
            }
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
    Some(ResponseHead {
        status: status?,
        headers,
    })
}

/// Shuts down the *read* side of `stream_id`: discards any unread body and, if
/// the read side has not already finished, signals `STOP_SENDING`. Touches only
/// the QUIC stream, not the per-stream bookkeeping maps (those are released by
/// [`StreamRef`] once the last reference drops).
fn shutdown_read(handle: &WeakConnectionHandle<Http3ClientApp>, stream_id: u64) {
    let Some(handle) = handle.upgrade() else {
        return;
    };
    let mut guard = handle.lock_recovering();
    let _ = guard
        .inner
        .stream_shutdown(stream_id, squiche::Shutdown::Read, 0);
    drop(guard);
    handle.notify();
}

/// Resets the *write* side of `stream_id` with `H3_REQUEST_CANCELLED`, aborting
/// an unfinished request body. Touches only the QUIC stream, not the per-stream
/// bookkeeping maps.
fn shutdown_write(handle: &WeakConnectionHandle<Http3ClientApp>, stream_id: u64) {
    let Some(handle) = handle.upgrade() else {
        return;
    };
    let mut guard = handle.lock_recovering();
    let _ = guard
        .inner
        .stream_shutdown(stream_id, squiche::Shutdown::Write, H3_REQUEST_CANCELLED);
    drop(guard);
    handle.notify();
}

/// Shared lifetime token for one client stream, cloned into every handle that
/// references the stream — its read half ([`ReadGuard`], carried by the response
/// future and then [`H3ResponseBody`](super::H3ResponseBody)) and its write half
/// ([`WriteGuard`], carried by the request-body sender). When the **last** clone
/// drops, the per-stream bookkeeping — the shared `streams` entry plus the
/// client-only `response_heads` entry — is released.
///
/// Directional teardown (read `STOP_SENDING`, write `RESET_STREAM`) is performed
/// by the guards as each half drops; this token only collects the map entries,
/// and only once both halves are gone, so neither half can strand the other's
/// wakers.
pub(crate) struct StreamRef {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
}

impl StreamRef {
    pub(crate) fn new(handle: WeakConnectionHandle<Http3ClientApp>, stream_id: u64) -> Arc<Self> {
        Arc::new(Self { handle, stream_id })
    }
}

impl Drop for StreamRef {
    fn drop(&mut self) {
        let Some(handle) = self.handle.upgrade() else {
            return;
        };
        let mut guard = handle.lock_recovering();
        guard.app.streams.remove(&self.stream_id);
        guard.app.response_heads.remove(&self.stream_id);
    }
}

/// The read-side lifetime guard for a client stream. While held it keeps the
/// shared [`StreamRef`] alive; dropped before the read side has finished cleanly
/// (EOF, trailers, or an error already observed) it signals `STOP_SENDING`.
pub(crate) struct ReadGuard {
    stream_ref: Arc<StreamRef>,
    done: bool,
}

impl ReadGuard {
    pub(crate) fn new(stream_ref: Arc<StreamRef>) -> Self {
        Self {
            stream_ref,
            done: false,
        }
    }

    /// A weak handle to the owning connection.
    pub(crate) fn handle(&self) -> WeakConnectionHandle<Http3ClientApp> {
        self.stream_ref.handle.clone()
    }

    /// The stream this guard governs.
    pub(crate) fn stream_id(&self) -> u64 {
        self.stream_ref.stream_id
    }

    /// Whether the read side has reached a terminal state.
    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Marks the read side finished cleanly, suppressing `STOP_SENDING` on drop.
    pub(crate) fn mark_done(&mut self) {
        self.done = true;
    }
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        if !self.done {
            shutdown_read(&self.stream_ref.handle, self.stream_ref.stream_id);
        }
    }
}

/// The write-side lifetime guard for a client stream. While held it keeps the
/// shared [`StreamRef`] alive; dropped before the request body finished with a
/// FIN it resets the write side with `H3_REQUEST_CANCELLED`.
pub(crate) struct WriteGuard {
    stream_ref: Arc<StreamRef>,
    done: bool,
}

impl WriteGuard {
    pub(crate) fn new(stream_ref: Arc<StreamRef>) -> Self {
        Self {
            stream_ref,
            done: false,
        }
    }

    /// A weak handle to the owning connection.
    pub(crate) fn handle(&self) -> WeakConnectionHandle<Http3ClientApp> {
        self.stream_ref.handle.clone()
    }

    /// The stream this guard governs.
    pub(crate) fn stream_id(&self) -> u64 {
        self.stream_ref.stream_id
    }

    /// Marks the write side finished (a FIN was sent), suppressing the reset on
    /// drop.
    pub(crate) fn mark_done(&mut self) {
        self.done = true;
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if !self.done {
            shutdown_write(&self.stream_ref.handle, self.stream_ref.stream_id);
        }
    }
}

/// Polls the response-head slot for `stream_id`, registering a waker when the
/// head has not yet arrived. Drives the request [`ResponseFut`](super::ResponseFut);
/// it performs no stream teardown of its own (the caller's guard owns the read
/// side).
pub(crate) fn poll_head(
    handle: &WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    cx: &mut Context<'_>,
) -> Poll<Result<ResponseHead, RequestError>> {
    let Some(handle) = handle.upgrade() else {
        return Poll::Ready(Err(RequestError::ConnectionClosed));
    };
    let mut guard = handle.lock();
    let QuicScionConn { app, .. } = &mut *guard;
    let Http3ClientApp {
        response_heads,
        streams,
        ..
    } = app;
    let Some(slot) = response_heads.get_mut(&stream_id) else {
        return Poll::Ready(Err(RequestError::ConnectionClosed));
    };

    match slot.state {
        ResponseHeadState::Arrived(_) => {
            let ResponseHeadState::Arrived(head) =
                std::mem::replace(&mut slot.state, ResponseHeadState::Done)
            else {
                unreachable!("just matched Arrived")
            };
            Poll::Ready(Ok(head))
        }
        ResponseHeadState::Waiting => {
            // A reset (or connection close, which sets `Reset(0)`) before the
            // head means the request faulted.
            match streams.get(&stream_id) {
                Some(st) => {
                    if let ReadState::Reset(code) = st.read_state {
                        return Poll::Ready(Err(if code == 0 {
                            RequestError::ConnectionClosed
                        } else {
                            RequestError::Reset(code)
                        }));
                    }
                }
                None => {
                    return Poll::Ready(Err(RequestError::ConnectionClosed));
                }
            }
            slot.waker = Some(cx.waker().clone());
            Poll::Pending
        }
        ResponseHeadState::Done => {
            // Polled again after the head was already delivered.
            Poll::Ready(Err(RequestError::ConnectionClosed))
        }
    }
}
