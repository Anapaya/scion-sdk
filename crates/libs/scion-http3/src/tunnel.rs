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

//! Byte streams through `CONNECT` tunnels.

use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use scion_quic::h3::client::{H3DuplexStream, Http3Client};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::authority::Authority;

/// Builds the authority-form `CONNECT` request for `authority`.
pub(crate) fn connect_request(authority: &Authority) -> http::Request<()> {
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{authority}"))
        .body(())
        .expect("a valid authority forms a valid URI")
}

/// A byte stream through an accepted `CONNECT` tunnel.
///
/// The two directions are independent. `shutdown` closes the write half and
/// leaves the read half open. A read returns `Ok(0)` at the end of the stream.
/// A peer reset reads as [`io::ErrorKind::ConnectionReset`], and a closed
/// connection as [`io::ErrorKind::NotConnected`]. Dropping the tunnel resets
/// the stream.
pub struct Tunnel {
    stream: H3DuplexStream,
    /// Keeps the connection alive while the pool may evict its origin.
    _connection: Arc<Http3Client>,
}

impl Tunnel {
    pub(crate) fn new(stream: H3DuplexStream, connection: Arc<Http3Client>) -> Self {
        Tunnel {
            stream,
            _connection: connection,
        }
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel").finish_non_exhaustive()
    }
}
