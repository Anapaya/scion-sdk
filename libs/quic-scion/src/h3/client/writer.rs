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

//! The caller-driven request-body writer.
//!
//! [`RequestBodyWriter`] is the write half handed back by
//! [`request`](super::Http3Client::request): it streams the
//! request body out as HTTP/3 DATA frames with QUIC flow control as backpressure
//! (a `write_chunk` pends when the stream lacks capacity rather than buffering
//! without bound), and finishes the message with either a bare FIN
//! ([`finish`](RequestBodyWriter::finish)) or a trailing header section
//! ([`write_trailers`](RequestBodyWriter::write_trailers)).
//!
//! It also implements [`AsyncWrite`] (one DATA frame per `poll_write`, FIN on
//! `poll_shutdown`), which is what [`H3DuplexStream`](super::H3DuplexStream)
//! builds its write half on; trailers remain reachable only through the async
//! [`write_trailers`](RequestBodyWriter::write_trailers).
//!
//! The writer owns the stream's write-side guard: dropping it before the body is
//! finished resets the write side with `H3_REQUEST_CANCELLED`, leaving the read
//! side (the response body) untouched.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::AsyncWrite;

use crate::{
    h3::{
        client::app::{Http3ClientApp, WriteGuard},
        common::{
            H3Error,
            headers::header_map_to_h3,
            write::{send_data, send_trailers},
        },
    },
    quic::connection::{QuicScionConn, WeakConnectionHandle},
};

/// The write half of a streamed HTTP/3 request.
///
/// Returned by [`request`](super::Http3Client::request)
/// alongside the response future. The two operate independently (full-duplex):
/// the caller may observe the response head before finishing the request body.
pub struct RequestBodyWriter {
    guard: WriteGuard,
}

impl RequestBodyWriter {
    pub(crate) fn new(guard: WriteGuard) -> Self {
        Self { guard }
    }

    /// Sends `data` as a DATA frame, applying backpressure (the call pends while
    /// the stream lacks capacity). Does not finish the stream.
    pub async fn write_chunk(&mut self, data: Bytes) -> Result<(), H3Error> {
        send_data(&self.guard.handle(), self.guard.stream_id(), data, false).await
    }

    /// Finishes the request body with a bare FIN and consumes the writer.
    pub async fn finish(mut self) -> Result<(), H3Error> {
        send_data(
            &self.guard.handle(),
            self.guard.stream_id(),
            Bytes::new(),
            true,
        )
        .await?;
        self.guard.mark_done();
        Ok(())
    }

    /// Finishes the request body with a trailing header section (which carries
    /// the FIN) and consumes the writer. Pseudo-headers in `trailers` are
    /// dropped; if nothing remains, the stream is finished with a bare FIN.
    pub async fn write_trailers(mut self, trailers: http::HeaderMap) -> Result<(), H3Error> {
        let h3_trailers = header_map_to_h3(&trailers);
        if h3_trailers.is_empty() {
            send_data(
                &self.guard.handle(),
                self.guard.stream_id(),
                Bytes::new(),
                true,
            )
            .await?;
        } else {
            send_trailers(&self.guard.handle(), self.guard.stream_id(), h3_trailers).await?;
        }
        self.guard.mark_done();
        Ok(())
    }
}

impl AsyncWrite for RequestBodyWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        poll_send(&this.guard.handle(), this.guard.stream_id(), cx, buf, false)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // DATA frames are written straight into quiche (no adapter-side buffer)
        // and the driver is notified on every write, so there is nothing to
        // flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match poll_send(&this.guard.handle(), this.guard.stream_id(), cx, &[], true) {
            Poll::Ready(Ok(_)) => {
                // FIN sent: suppress the write-side reset when the guard drops.
                this.guard.mark_done();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.guard.mark_done();
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Polls a single `send_body` of `buf` (with `fin`) on `stream_id`, registering a
/// write waker and pending when the stream lacks capacity (backpressure).
///
/// Returns the number of bytes accepted by quiche (which may be a partial write;
/// the caller resends the remainder). This is the poll-based core behind the
/// [`AsyncWrite`] impl; the async [`write_chunk`](RequestBodyWriter::write_chunk)
/// uses the shared looping `send_data` instead.
fn poll_send(
    handle: &WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
    cx: &mut Context<'_>,
    buf: &[u8],
    fin: bool,
) -> Poll<io::Result<usize>> {
    let Some(handle) = handle.upgrade() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "connection closed",
        )));
    };
    let mut guard = handle.lock();
    let QuicScionConn { inner, app, .. } = &mut *guard;
    let Some(h3) = app.h3.as_mut() else {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "connection closed",
        )));
    };

    match h3.send_body(inner, stream_id, buf, fin) {
        Ok(written) => {
            drop(guard);
            handle.notify();
            Poll::Ready(Ok(written))
        }
        Err(squiche::h3::Error::Done) | Err(squiche::h3::Error::StreamBlocked) => {
            let Some(st) = app.streams.get_mut(&stream_id) else {
                // No entry means the stream was already torn down; bail instead
                // of resurrecting it with a waker nobody will wake.
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection closed",
                )));
            };
            st.write_waker = Some(cx.waker().clone());
            drop(guard);
            handle.notify();
            Poll::Pending
        }
        Err(err) => Poll::Ready(Err(io::Error::other(format!("h3 send error: {err}")))),
    }
}
