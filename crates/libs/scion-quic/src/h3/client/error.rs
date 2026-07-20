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

//! Error types for the HTTP/3 client.
//!
//! These mirror [`H3Error`](crate::h3::common::H3Error) where reuse fits: the
//! streaming [`H3ResponseBody`](super::H3ResponseBody) yields `H3Error`
//! directly (it is the read-side body adapted from the server), while the
//! client-specific failures — connection *establishment* and *request*
//! initiation/routing — are captured here.

use crate::socket::BoxedSocketError;

/// An error establishing an HTTP/3 connection (the `connect()` bootstrap).
#[derive(Debug, thiserror::Error)]
pub enum EstablishError {
    /// The local or remote socket address could not be resolved to an
    /// IPv4/IPv6 SCION address.
    #[error("invalid socket address")]
    InvalidAddress,
    /// A socket I/O error occurred while driving the handshake.
    #[error("socket error: {0}")]
    Io(BoxedSocketError),
    /// The QUIC layer reported an error while connecting.
    #[error("QUIC error: {0}")]
    Quic(squiche::Error),
    /// The handshake did not complete (the connection closed before becoming
    /// established).
    #[error("handshake failed")]
    Handshake,
    /// The negotiated ALPN was not `h3`, so no usable connection is exposed.
    #[error("ALPN mismatch: expected h3")]
    AlpnMismatch,
    /// The HTTP/3 layer could not be initialized on the established transport.
    #[error("failed to initialize the HTTP/3 layer")]
    H3Init,
}

/// An error issuing a request or opening a `CONNECT` tunnel.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// Establishing (or re-establishing) the connection failed.
    #[error("connection establishment failed: {0}")]
    Establish(#[from] EstablishError),
    /// The connection closed (or was already closed) before the response head
    /// arrived. In-flight requests faulted this way are **not** retried.
    #[error("connection closed")]
    ConnectionClosed,
    /// The peer reset the request stream with the given HTTP/3 error code.
    #[error("stream reset by peer (code {0:#x})")]
    Reset(u64),
    /// An HTTP/3 protocol error occurred while initiating the request.
    #[error("h3 error: {0}")]
    H3(squiche::h3::Error),
    /// The request could not be initiated because the connection's
    /// concurrent-stream limit is exhausted.
    #[error("request blocked: concurrent stream limit reached")]
    StreamBlocked,
}
