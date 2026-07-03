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
//! response future.
//!
//! The read-side state (`Data`/`Finished`/`Reset`) and the `writable()` waker
//! logic are shared with the server via `crate::h3::common`; this module adds
//! the client-only response-head routing kept in a separate `response_heads` map
//! (so the shared per-stream `StreamState` stays identical on both sides).
//!
//! This module is the *driver-side engine* only: it advances per-stream state as
//! events arrive. The stream-facing API driven from the futures side lives in the
//! stream module.

use std::{collections::HashMap, task::Waker};

use squiche::h3::NameValue;

use crate::{
    app::{QuicScionApplication, Wakeups},
    h3::common::{
        H3_INTERNAL_ERROR, H3App, ReadState, StreamState,
        headers::headers_to_map,
        read::{on_data, on_finished, on_reset, wake_writable},
    },
    quic::connection::{ConnectionHandle, WeakConnectionHandle},
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
