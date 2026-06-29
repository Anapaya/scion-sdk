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

//! The streaming HTTP/3 response body.
//!
//! [`H3ResponseBody`] is the read-side streaming body: each [`Body::poll_frame`]
//! reads directly from the connection via the shared
//! `poll_read_frame`, so backpressure
//! is the QUIC stream's flow-control window (no intermediate buffer). Response
//! data is delivered incrementally and is never fully buffered before the
//! response head is returned. The same read step backs the server's request body
//! and the client's `CONNECT` tunnel reader.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame};

use crate::{
    h3::{
        client::app::{Http3ClientApp, ReadGuard},
        common::{H3Error, read::poll_read_frame},
    },
    quic::connection::WeakConnectionHandle,
};

/// The streaming body of an HTTP/3 response.
///
/// The body owns the stream's read-side guard: dropping it before end-of-stream
/// signals `STOP_SENDING` (cancelling the read side); dropping it after a clean
/// end is a no-op. Either way the shared per-stream bookkeeping is released once
/// the last reference (read or write half) drops.
pub struct H3ResponseBody {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    /// Read-side lifetime guard; its `done` flag suppresses `STOP_SENDING` once
    /// the body has finished cleanly, and its drop tears the read side down.
    read_guard: ReadGuard,
}

impl H3ResponseBody {
    pub(crate) fn new(read_guard: ReadGuard) -> Self {
        Self {
            handle: read_guard.handle(),
            stream_id: read_guard.stream_id(),
            read_guard,
        }
    }
}

impl Body for H3ResponseBody {
    type Data = Bytes;
    type Error = H3Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.read_guard.is_done() {
            return Poll::Ready(None);
        }
        let res = poll_read_frame(&this.handle, this.stream_id, cx);
        if let Poll::Ready(ready) = &res {
            match ready {
                // EOF, an error, or a trailing header section all terminate the
                // body: the stream is finished on the read side, so suppress the
                // STOP_SENDING-on-drop.
                None => this.read_guard.mark_done(),
                Some(Err(_)) => this.read_guard.mark_done(),
                Some(Ok(frame)) if frame.is_trailers() => this.read_guard.mark_done(),
                Some(Ok(_)) => {}
            }
        }
        res
    }
}
