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

//! The shared read-side machinery: the per-`poll_frame` connection read, a
//! type-erased reader handle, and the per-event read-state advances used by both
//! applications' `update` loops.

use std::{
    collections::HashMap,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::Frame;

use crate::{
    app::Wakeups,
    h3::common::{H3App, H3Error, ReadState, StreamState},
    quic::connection::{QuicScionConn, WeakConnectionHandle},
};

/// Size of the scratch buffer used per `recv_body` call.
const READ_CHUNK: usize = 16 * 1024;

/// Reads one body frame for `stream_id`, advancing the per-stream read state and
/// registering a waker when no data is ready.
///
/// Body data is read directly from the connection via `recv_body`, so
/// backpressure is the QUIC stream's flow-control window (no intermediate
/// buffer). This is the single read step shared by the server's request body,
/// the client's response body, and the client's `CONNECT` tunnel reader.
pub(crate) fn poll_read_frame<A: H3App>(
    handle: &WeakConnectionHandle<A>,
    stream_id: u64,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Bytes>, H3Error>>> {
    let Some(handle) = handle.upgrade() else {
        return Poll::Ready(None);
    };
    let mut guard = handle.lock();
    let QuicScionConn { inner, app, .. } = &mut *guard;
    let (h3, streams) = app.h3_streams();
    let Some(h3) = h3 else {
        return Poll::Ready(None);
    };

    let mut buf = [0u8; READ_CHUNK];
    match h3.recv_body(inner, stream_id, &mut buf) {
        Ok(n) => {
            let bytes = Bytes::copy_from_slice(&buf[..n]);
            drop(guard);
            // Reading frees flow-control window; nudge the driver so it can flush
            // any resulting transport frames.
            handle.notify();
            Poll::Ready(Some(Ok(Frame::data(bytes))))
        }
        Err(squiche::h3::Error::Done) => {
            // No body bytes available right now; the read state says whether that
            // is temporary or terminal. Only the trailers arm mutates the state
            // (it hands the header map over, after which the body is at EOF).
            let st = streams.entry(stream_id).or_default();
            match &mut st.read_state {
                ReadState::Streaming => {
                    st.read_waker = Some(cx.waker().clone());
                    drop(guard);
                    // Ask the driver to poll() for the next event (it may already
                    // be buffered behind the bytes we just drained).
                    handle.notify();
                    Poll::Pending
                }
                ReadState::Trailers(_) => {
                    let ReadState::Trailers(trailers) =
                        std::mem::replace(&mut st.read_state, ReadState::Eof)
                    else {
                        unreachable!("just matched Trailers")
                    };
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                ReadState::Eof => Poll::Ready(None),
                ReadState::Reset(code) => Poll::Ready(Some(Err(H3Error::Reset(*code)))),
            }
        }
        Err(err) => Poll::Ready(Some(Err(H3Error::H3(err)))),
    }
}

/// Type-erased access to a connection for reading a body.
///
/// This lets a streaming body name a concrete, non-generic type (e.g. the
/// server's `H3RequestBody`) instead of leaking the application type parameter.
pub(crate) trait StreamReader: Send + Sync {
    /// Polls the body for `stream_id`, reading directly from the connection.
    fn poll_read(
        &self,
        stream_id: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, H3Error>>>;
}

/// A [`StreamReader`] backed by a weak handle to an HTTP/3 connection.
pub(crate) struct ConnReader<A: H3App> {
    pub(crate) handle: WeakConnectionHandle<A>,
}

impl<A: H3App + 'static + Send> StreamReader for ConnReader<A> {
    fn poll_read(
        &self,
        stream_id: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, H3Error>>> {
        poll_read_frame(&self.handle, stream_id, cx)
    }
}

/// Wakes the body reader for `stream_id` (a `Data` event made progress possible).
pub(crate) fn on_data(
    streams: &mut HashMap<u64, StreamState>,
    stream_id: u64,
    wakeups: &mut Wakeups,
) {
    if let Some(st) = streams.get_mut(&stream_id)
        && let Some(w) = st.read_waker.take()
    {
        wakeups.schedule(w);
    }
}

/// Marks `stream_id`'s read side as ended on a `Finished` event and wakes its
/// reader.
pub(crate) fn on_finished(
    streams: &mut HashMap<u64, StreamState>,
    stream_id: u64,
    wakeups: &mut Wakeups,
) {
    if let Some(st) = streams.get_mut(&stream_id) {
        if matches!(st.read_state, ReadState::Streaming) {
            st.read_state = ReadState::Eof;
        }
        if let Some(w) = st.read_waker.take() {
            wakeups.schedule(w);
        }
    }
}

/// Records a peer `Reset` on `stream_id` and wakes its reader and writer.
pub(crate) fn on_reset(
    streams: &mut HashMap<u64, StreamState>,
    stream_id: u64,
    code: u64,
    wakeups: &mut Wakeups,
) {
    if let Some(st) = streams.get_mut(&stream_id) {
        st.read_state = ReadState::Reset(code);
        if let Some(w) = st.read_waker.take() {
            wakeups.schedule(w);
        }
        if let Some(w) = st.write_waker.take() {
            wakeups.schedule(w);
        }
    }
}

/// Wakes the writers of all streams that have regained capacity.
pub(crate) fn wake_writable(
    conn: &mut squiche::Connection,
    streams: &mut HashMap<u64, StreamState>,
    wakeups: &mut Wakeups,
) {
    for stream_id in conn.writable() {
        if let Some(st) = streams.get_mut(&stream_id)
            && let Some(w) = st.write_waker.take()
        {
            wakeups.schedule(w);
        }
    }
}
