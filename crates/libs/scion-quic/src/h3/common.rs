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

use std::{collections::HashMap, io, task::Waker};

pub(crate) mod headers;
pub(crate) mod read;
pub(crate) mod write;

/// HTTP/3 `H3_NO_ERROR` error code, used when closing a connection that has no
/// fault to report (RFC 9114 §8.1).
pub(crate) const H3_NO_ERROR: u64 = 0x0100;

/// HTTP/3 internal error code, used when resetting a stream on a body error or
/// closing a connection that does not speak `h3`.
pub(crate) const H3_INTERNAL_ERROR: u64 = 0x0102;

/// HTTP/3 `H3_REQUEST_CANCELLED` error code, used when resetting the write side
/// of a request whose body was abandoned before it finished (RFC 9114 §8.1).
pub(crate) const H3_REQUEST_CANCELLED: u64 = 0x010C;

/// An error observed while reading or writing an HTTP/3 message body.
///
/// Used by both the server's request body and the client's response body.
#[derive(Debug)]
pub enum H3Error {
    /// The peer reset the stream with the given HTTP/3 error code: a
    /// `RESET_STREAM` on the read side or a `STOP_SENDING` on the write side.
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

/// The I/O view of a body error for the `AsyncRead` and `AsyncWrite`
/// implementations: a peer reset is [`io::ErrorKind::ConnectionReset`], a
/// closed connection is [`io::ErrorKind::NotConnected`].
impl From<H3Error> for io::Error {
    fn from(err: H3Error) -> io::Error {
        match err {
            H3Error::Reset(_) => io::Error::new(io::ErrorKind::ConnectionReset, err.to_string()),
            H3Error::ConnectionClosed => {
                io::Error::new(io::ErrorKind::NotConnected, err.to_string())
            }
            H3Error::H3(_) => io::Error::other(err.to_string()),
        }
    }
}

/// Maps a failed `send_body` to the body error taxonomy. A stream the peer
/// stopped or reset is a [`H3Error::Reset`], like a reset seen on the read side.
///
/// `read_state` is the stream's own bookkeeping. The transport forgets a
/// stream once both directions have ended, and then reports only that the
/// stream does not exist; the read state still says whether the peer reset it
/// or the connection closed.
pub(crate) fn send_error(err: squiche::h3::Error, read_state: Option<&ReadState>) -> H3Error {
    match err {
        squiche::h3::Error::TransportError(squiche::Error::StreamStopped(code))
        | squiche::h3::Error::TransportError(squiche::Error::StreamReset(code)) => {
            H3Error::Reset(code)
        }
        squiche::h3::Error::TransportError(squiche::Error::InvalidStreamState(_)) => {
            match read_state {
                Some(ReadState::Reset(code)) => H3Error::Reset(*code),
                Some(ReadState::Closed) => H3Error::ConnectionClosed,
                _ => H3Error::H3(err),
            }
        }
        err => H3Error::H3(err),
    }
}

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
    /// The stream was reset by the peer with the given code.
    Reset(u64),
    /// The connection closed (locally or by the peer) while the stream was
    /// still open.
    ///
    /// Only a stream still in [`Streaming`](Self::Streaming) reaches this state.
    /// One that had already ended ([`Eof`](Self::Eof), staged
    /// [`Trailers`](Self::Trailers), or [`Reset`](Self::Reset)) keeps that
    /// verdict, so a close never retroactively spoils a body that already
    /// finished.
    Closed,
}

/// Whether `conn` can still carry application data.
///
/// A connection that is closed, draining, or has a queued or received CONNECTION_CLOSE will never
/// again carry application data, so writers must fail instead of parking on a capacity waker nobody
/// will ever wake.
pub(crate) fn is_terminated(conn: &squiche::Connection) -> bool {
    conn.is_closed()
        || conn.is_draining()
        || conn.local_error().is_some()
        || conn.peer_error().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_or_reset_stream_is_a_peer_reset() {
        for err in [
            squiche::Error::StreamStopped(0x10c),
            squiche::Error::StreamReset(0x10c),
        ] {
            let mapped = send_error(squiche::h3::Error::TransportError(err), None);
            assert!(matches!(mapped, H3Error::Reset(0x10c)), "{mapped}");
            assert_eq!(
                io::Error::from(mapped).kind(),
                io::ErrorKind::ConnectionReset
            );
        }

        let other = send_error(
            squiche::h3::Error::TransportError(squiche::Error::StreamLimit),
            None,
        );
        assert!(matches!(other, H3Error::H3(_)), "{other}");
        assert_eq!(io::Error::from(other).kind(), io::ErrorKind::Other);
    }

    /// Once the transport has forgotten the stream, the read state decides.
    #[test]
    fn a_forgotten_stream_takes_its_verdict_from_the_read_state() {
        let gone = || squiche::h3::Error::TransportError(squiche::Error::InvalidStreamState(0));

        assert!(matches!(
            send_error(gone(), Some(&ReadState::Reset(0x10c))),
            H3Error::Reset(0x10c)
        ));
        assert!(matches!(
            send_error(gone(), Some(&ReadState::Closed)),
            H3Error::ConnectionClosed
        ));
        assert!(matches!(
            send_error(gone(), Some(&ReadState::Eof)),
            H3Error::H3(_)
        ));
        assert!(matches!(send_error(gone(), None), H3Error::H3(_)));
    }
}
