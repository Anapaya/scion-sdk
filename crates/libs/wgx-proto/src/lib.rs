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

//! A sans-io implementation of the WireGuard protocol.
//!
//! The crate implements the protocol state machine only. It reads no clock, it
//! opens no socket, and it allocates no packet buffer. The caller passes the
//! time into every method that needs it, and the caller owns the buffer that
//! holds a message.
//!
//! # Difference to WireGuard
//!
//! A responder that holds the socket address of the initiator puts that
//! address into the handshake response. The initiator therefore learns its own
//! address from the handshake, which gives the message the function of a STUN
//! response. A responder that holds no address answers in the form of
//! WireGuard, and the length of the response tells the two forms apart. See
//! [`wire::HandshakeResp`].
//!
//! A tunnel that holds no address of its peer
//! ([`TunnelConfig::peer_sockaddr`] is `None`) therefore speaks the protocol
//! of WireGuard on the wire. An initiator takes either form, whatever it holds
//! itself.
//!
//! The crate does not implement the cookie mechanism of WireGuard, which
//! protects a peer against a denial-of-service attack under load. It writes a
//! zero `mac2` field, and it never answers with a cookie reply. It does
//! consume one, so that a peer that rate limits can complete a handshake with
//! it.

mod crypto;
mod session;

pub mod handshake;
pub mod timers;
pub mod tunnel;

pub mod error;
pub mod wire;

pub use error::Error;
pub use tunnel::{
    DATA_OVERHEAD, PAYLOAD_OFFSET, RecvAction, SendAction, TimerAction, TunnelConfig, TunnelState,
};
