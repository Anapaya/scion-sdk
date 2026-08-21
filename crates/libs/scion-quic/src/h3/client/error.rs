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

use crate::{h3::common::H3Error, socket::BoxedSocketError};

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
    /// The client was closed with
    /// [`Http3Client::close`](super::Http3Client::close). A closed client stays
    /// closed: it never establishes another connection.
    #[error("client closed")]
    Closed,
}

impl EstablishError {
    /// Returns whether the failure is transient, so that a retry may help.
    ///
    /// Prefer this over matching the variants: a new variant would silently fall
    /// into a caller's wildcard arm.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            // A property of the address, not of the network.
            Self::InvalidAddress => false,
            // A handshake packet could not be sent or received, e.g. because the
            // host has no route to the remote.
            Self::Io(_) => true,
            Self::Quic(error) => {
                !matches!(
                    error,
                    // A peer certificate that does not validate, or a QUIC config
                    // whose TLS setup the crypto layer rejects (e.g. a CA bundle
                    // that cannot be loaded), fails the same way on every attempt.
                    squiche::Error::TlsFail
                    | squiche::Error::CryptoFail
                    // The peer does not speak a QUIC version or transport
                    // parameters this client can talk to.
                    | squiche::Error::UnknownVersion
                    | squiche::Error::InvalidTransportParam
                )
            }
            // The connection closed before it was established, which includes the
            // handshake timing out because the remote never answered.
            Self::Handshake => true,
            // The peer does not serve HTTP/3 on this endpoint.
            Self::AlpnMismatch => false,
            // Setting up the HTTP/3 layer on an already-established transport does
            // not depend on the network, so it fails again the same way.
            Self::H3Init => false,
            // A closed client stays closed, so retrying it can never succeed.
            Self::Closed => false,
        }
    }
}

/// An error issuing a request or opening a `CONNECT` tunnel.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// Establishing (or re-establishing) the connection failed.
    #[error("connection establishment failed: {0}")]
    Establish(#[from] EstablishError),
    /// The connection closed (or was already closed) before the response head
    /// arrived — the peer closed it, or it idled out. In-flight requests faulted
    /// this way are **not** retried.
    #[error("connection closed")]
    ConnectionClosed,
    /// The request was in flight when
    /// [`Http3Client::close`](super::Http3Client::close) tore the connection
    /// down locally, as opposed to the peer or idle close reported by
    /// [`ConnectionClosed`](Self::ConnectionClosed).
    #[error("client closed locally")]
    LocallyClosed,
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

/// A failure while streaming a request body
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// The request body yielded an error while being read.
    #[error("request body error: {0}")]
    Body(Box<dyn std::error::Error + Send + Sync>),
    /// Sending request-body bytes to the peer failed (the stream was reset or the
    /// connection went away).
    #[error("send failed: {0}")]
    Send(#[from] H3Error),
}

#[cfg(test)]
mod tests {
    use super::EstablishError;

    #[test]
    fn a_remote_that_did_not_answer_is_transient() {
        assert!(EstablishError::Handshake.is_transient());
        assert!(
            EstablishError::Io(Box::new(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "no route to host",
            )))
            .is_transient()
        );
        assert!(EstablishError::Quic(squiche::Error::InvalidPacket).is_transient());
    }

    #[test]
    fn a_closed_client_is_permanent() {
        // The one that must not be retried: a closed client never establishes another
        // connection, so a retry loop around it cannot terminate on success.
        assert!(!EstablishError::Closed.is_transient());
    }

    #[test]
    fn a_peer_we_cannot_talk_to_is_permanent() {
        assert!(!EstablishError::Quic(squiche::Error::TlsFail).is_transient());
        assert!(!EstablishError::AlpnMismatch.is_transient());
        assert!(!EstablishError::InvalidAddress.is_transient());
    }
}
