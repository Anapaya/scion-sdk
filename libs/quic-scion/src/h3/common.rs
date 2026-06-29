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

//! Shared sans-I/O HTTP/3 machinery used by both the server
//! ([`Http3Server`](crate::h3::server::Http3Server)) and the client
//! ([`Http3Client`](crate::h3::client::Http3Client)).

use std::{collections::HashMap, task::Waker};

pub(crate) mod headers;
pub(crate) mod read;
pub(crate) mod write;

/// HTTP/3 internal error code, used when resetting a stream on a body error or
/// closing a connection that does not speak `h3`.
pub(crate) const H3_INTERNAL_ERROR: u64 = 0x0102;

/// HTTP/3 `H3_REQUEST_CANCELLED` error code, used when resetting the write side
/// of a request whose body was abandoned before it finished (RFC 9114 §8.1).
pub(crate) const H3_REQUEST_CANCELLED: u64 = 0x010C;

/// An error observed while reading an HTTP/3 message body.
///
/// Used by both the server's request body and the client's response body.
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

/// A [`QuicScionApplication`] that runs HTTP/3 and exposes the state the shared
/// read/write helpers operate on: the `squiche` HTTP/3 connection and the
/// per-stream bookkeeping map.
///
/// The single combined accessor returns both at once so callers can hold the
/// `h3` connection and the `streams` map simultaneously (they are disjoint
/// fields of the same application).
pub(crate) trait H3App {
    /// Returns the HTTP/3 connection (once established) and the per-stream map.
    fn h3_streams(
        &mut self,
    ) -> (
        Option<&mut squiche::h3::Connection>,
        &mut HashMap<u64, StreamState>,
    );
}

/// Per-stream state shared by the server and client: the read-side state machine
/// plus the read and write wakers. (The client keeps its response-head routing
/// separately.)
#[derive(Default)]
pub(crate) struct StreamState {
    pub(crate) read_state: ReadState,
    /// Waker of the task currently reading the body.
    pub(crate) read_waker: Option<Waker>,
    /// Waker of the task currently writing the body (blocked on stream capacity).
    pub(crate) write_waker: Option<Waker>,
}

/// Per-stream read state, advanced by the application's `update` loop and
/// consumed by the streaming body reader.
#[derive(Default)]
pub(crate) enum ReadState {
    /// More body data may still arrive.
    #[default]
    Streaming,
    /// A trailing header section was received and is ready to be yielded.
    Trailers(http::HeaderMap),
    /// The body has ended (FIN received).
    Eof,
    /// The stream was reset by the peer (or the connection closed) with the
    /// given code.
    Reset(u64),
}
