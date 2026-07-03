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

//! A full-duplex `AsyncRead + AsyncWrite` view over a single request stream.
//!
//! [`H3DuplexStream`] composes the two halves of one request stream, the
//! [`RequestBodyWriter`](super::RequestBodyWriter) (write direction, itself
//! [`AsyncWrite`]) and the [`H3ResponseBody`](super::H3ResponseBody) (read
//! direction) into a single byte stream.
//!
//! Half-close (shutdown of the write half) sends a FIN while the read half stays
//! usable until the peer finishes; a peer reset surfaces as an I/O error.
//! Dropping an unfinished stream resets it (via the underlying read/write
//! guards held by the two halves).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{request::RequestBodyWriter, response::H3ResponseBody};
use crate::h3::common::H3Error;

/// A bidirectional byte stream over one HTTP/3 request stream.
///
/// Built with [`H3DuplexStream::new`] from the
/// [`RequestBodyWriter`](super::RequestBodyWriter) and
/// [`H3ResponseBody`](super::H3ResponseBody) of a single `initiate_request` call
/// (typically a `CONNECT` request). Implements [`AsyncRead`] and [`AsyncWrite`];
/// the two directions operate independently (full-duplex).
pub struct H3DuplexStream {
    /// Write direction (one DATA frame per `poll_write`, FIN on shutdown).
    writer: RequestBodyWriter,
    /// Read direction: the response body (owns the read-side guard).
    body: H3ResponseBody,
    /// Bytes from a received DATA frame not yet fully copied to the reader.
    read_leftover: Bytes,
}

impl H3DuplexStream {
    /// Combines the write and read halves of one `request` call into a
    /// single full-duplex byte stream.
    pub fn new(writer: RequestBodyWriter, body: H3ResponseBody) -> Self {
        Self {
            writer,
            body,
            read_leftover: Bytes::new(),
        }
    }
}

impl AsyncRead for H3DuplexStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_leftover.is_empty() {
                let n = this.read_leftover.len().min(buf.remaining());
                buf.put_slice(&this.read_leftover[..n]);
                this.read_leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    match frame.into_data() {
                        Ok(data) => {
                            this.read_leftover = data;
                            // Loop to copy the freshly received bytes.
                        }
                        // A trailing header section has no place in a raw byte
                        // stream; treat it as end-of-stream (buf left unfilled).
                        Err(_non_data) => return Poll::Ready(Ok(())),
                    }
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(h3_to_io(err))),
                // EOF: report by leaving `buf` unfilled.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H3DuplexStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// Maps a body read error to an I/O error for the stream's `AsyncRead`.
fn h3_to_io(err: H3Error) -> io::Error {
    match err {
        H3Error::Reset(code) => {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset by peer (code {code:#x})"),
            )
        }
        H3Error::ConnectionClosed => {
            io::Error::new(io::ErrorKind::NotConnected, "connection closed")
        }
        H3Error::H3(err) => io::Error::other(format!("h3 error: {err}")),
    }
}
