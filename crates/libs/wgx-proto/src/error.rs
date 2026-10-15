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

//! The errors of the protocol.

use crate::wire::ParseError;

/// The error that a method of the protocol returns.
///
/// Most variants describe one message. The next message can succeed after any
/// of them. [`Error::ConnectionExpired`] describes the tunnel, and it repeats.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The buffer of the caller cannot hold the message.
    #[error("the buffer is too small")]
    BufferTooSmall,

    /// The length of a field does not match the length that the protocol gives
    /// it.
    #[error("incorrect packet length")]
    IncorrectPacketLength,

    /// The message does not belong to the state of the tunnel.
    #[error("unexpected packet")]
    UnexpectedPacket,

    /// The message names a session that this peer does not hold.
    #[error("wrong session index")]
    WrongIndex,

    /// The static public key in a handshake initiation does not match the
    /// configured key of the peer. A third party that knows the public key of
    /// this peer can send such an initiation.
    #[error("wrong key")]
    WrongKey,

    /// The timestamp of the handshake does not parse.
    #[error("invalid TAI64N timestamp")]
    InvalidTai64nTimestamp,

    /// The timestamp of the handshake is older than the last one. The message
    /// can be a replay.
    #[error("wrong TAI64N timestamp")]
    WrongTai64nTimestamp,

    /// The `mac1` field does not authenticate the message.
    #[error("invalid MAC")]
    InvalidMac,

    /// The tag does not authenticate the ciphertext.
    #[error("invalid AEAD tag")]
    InvalidAeadTag,

    /// The counter of the message is too old.
    #[error("invalid counter")]
    InvalidCounter,

    /// The session received the counter of the message before.
    #[error("duplicate counter")]
    DuplicateCounter,

    /// The tunnel holds no session that can carry the message.
    #[error("no current session")]
    NoCurrentSession,

    /// The tunnel gave up on the handshake. The caller must build a new
    /// tunnel.
    #[error("connection expired")]
    ConnectionExpired,

    /// The buffer does not hold a message of the protocol.
    #[error("malformed message: {0}")]
    Parse(#[from] ParseError),
}

impl Error {
    /// Returns true if the next message can succeed.
    ///
    /// A caller that drives a tunnel uses this to separate a fault of one
    /// message from a fault of the tunnel.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        !matches!(self, Self::ConnectionExpired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_expired_connection_is_not_transient() {
        assert!(Error::WrongKey.is_transient());
        assert!(Error::InvalidMac.is_transient());
        assert!(!Error::ConnectionExpired.is_transient());
    }
}
