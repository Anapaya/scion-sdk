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

//! The lifetime of a single client connection.
//!
//! One [`ConnLifetime`] is created per connection attempt and closed exactly
//! once, by the bootstrap task that owns the connection. [`ConnectionToken`] is
//! the public view of it, handed out by
//! [`Http3Client::connect`](super::Http3Client::connect) so callers can observe
//! *that* connection ending instead of only noticing on their next request.
//!
//! The token is scoped to one connection, not to the client: a client that
//! reconnects lazily gets a fresh lifetime, so a break can never cancel the
//! observation of its successor.

use std::sync::{Arc, OnceLock};

use tokio_util::sync::CancellationToken;

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// Closed locally, by [`Http3Client::close`](super::Http3Client::close) or
    /// by the client being dropped.
    Local,
    /// The QUIC idle timeout elapsed.
    IdleTimeout,
    /// The peer closed the connection.
    Peer,
    /// There was a fatal socket error while reading or writing packets.
    Io,
    /// The connection ended for a reason none of the above cover, for example a
    /// local protocol error raised by the QUIC layer.
    Other,
}

/// The lifetime of one connection: a signal that fires once it ends, plus the
/// reason it ended.
pub(crate) struct ConnLifetime {
    closed: CancellationToken,
    /// Set before `closed` is cancelled, so an observer woken by the signal
    /// always finds the reason.
    reason: OnceLock<CloseReason>,
}

impl ConnLifetime {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            closed: CancellationToken::new(),
            reason: OnceLock::new(),
        })
    }

    /// Ends this lifetime with `reason`.
    ///
    /// Idempotent: only the first call records a reason and the token is
    /// cancelled once, so the connection's owner can close it from a `Drop`
    /// guard without checking whether a specific exit path already did.
    pub(crate) fn close(&self, reason: CloseReason) {
        let _ = self.reason.set(reason);
        self.closed.cancel();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }
}

/// An observable handle on the lifetime of one client connection.
///
/// Returned by [`Http3Client::connect`](super::Http3Client::connect). Cheap to
/// clone, and any number of observers may await the same connection.
///
/// The connection is unusable once this reports closed.
///
/// New connections are established lazily, and are covered by a different token.
#[derive(Clone)]
pub struct ConnectionToken(Arc<ConnLifetime>);

impl ConnectionToken {
    pub(crate) fn new(lifetime: Arc<ConnLifetime>) -> Self {
        Self(lifetime)
    }

    /// Resolves once the connection has ended, yielding why.
    ///
    /// Ready immediately if it has already ended. Cancel-safe.
    pub async fn closed(&self) -> CloseReason {
        self.0.closed.cancelled().await;
        self.close_reason().unwrap_or(CloseReason::Other)
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    /// Why the connection ended, or `None` while it is still up.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.0.reason.get().copied()
    }
}

impl std::fmt::Debug for ConnectionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.close_reason() {
            Some(reason) => write!(f, "ConnectionToken(closed: {reason:?})"),
            None => write!(f, "ConnectionToken(up)"),
        }
    }
}
