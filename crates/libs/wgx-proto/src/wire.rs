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
//
// This file incorporates code from mullvad/gotatun:
// Copyright (c) 2025 Mullvad VPN AB. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The message formats of the protocol.
//!
//! Every message is a view over a caller-owned buffer. The crate never
//! allocates a buffer and never copies a message. A parse returns a mutable
//! reference into the buffer, and the crypto operations read and write through
//! that reference.
//!
//! All fields have an alignment of one byte, which the `Unaligned` derive
//! enforces. A message therefore has the same layout at every offset of every
//! buffer.
//!
//! # Difference to WireGuard
//!
//! [`HandshakeResp`] has two forms. One is the form of WireGuard. The other
//! carries the socket address of the initiator, as the responder observes it,
//! in the place where WireGuard puts an empty encrypted field. Every other
//! message is the message of WireGuard.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian, little_endian,
};

/// Asserts at compile time that `T` has the size the protocol gives it.
const fn size_must_be<T: Sized>(expected: usize) -> usize {
    assert!(size_of::<T>() == expected);
    expected
}

/// The first byte of a message. It identifies the type of the message.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct MessageType(pub u8);

impl MessageType {
    #![allow(non_upper_case_globals)]

    /// The type of a [`HandshakeInit`] message.
    pub const HandshakeInit: MessageType = MessageType(1);

    /// The type of a [`HandshakeResp`] message.
    pub const HandshakeResp: MessageType = MessageType(2);

    /// The type of a [`CookieReply`] message.
    pub const CookieReply: MessageType = MessageType(3);

    /// The type of a [`Data`] message.
    pub const Data: MessageType = MessageType(4);
}

impl std::fmt::Debug for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            MessageType::HandshakeInit => "HandshakeInit",
            MessageType::HandshakeResp => "HandshakeResp",
            MessageType::CookieReply => "CookieReply",
            MessageType::Data => "Data",
            MessageType(t) => return std::fmt::Debug::fmt(&t, f),
        };
        f.debug_tuple(name).finish()
    }
}

/// An encrypted value and the Poly1305 tag that authenticates it.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
pub struct EncryptedWithTag<T: Sized> {
    /// The ciphertext.
    pub encrypted: T,
    /// The Poly1305 tag over the ciphertext.
    pub tag: [u8; TAG_LEN],
}

/// The length of a Poly1305 authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// The length of `mac1` and of `mac2`, in bytes.
pub const MAC_LEN: usize = 16;

/// A socket address in the format that [`HandshakeResp`] carries.
///
/// The responder writes the address of the initiator into the message. The
/// initiator reads its own address from the message, which gives it the
/// function of a STUN response.
#[derive(
    Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq,
)]
#[repr(C)]
pub struct WireSocketAddr {
    /// The IP version: 4 or 6.
    pub ip_version: u8,
    /// Reserved. The sender writes zero.
    pub reserved_zero: u8,
    /// The port, in network byte order.
    pub port: big_endian::U16,
    /// The address. An IPv4 address occupies the last 4 bytes.
    pub ip_addr: [u8; 16],
}

impl WireSocketAddr {
    /// The length of the address, in bytes.
    pub const LEN: usize = size_must_be::<Self>(20);
}

/// The error that the conversion of a [`WireSocketAddr`] returns.
#[derive(Debug, thiserror::Error)]
pub enum WireSocketAddrError {
    /// The message holds a version that is neither 4 nor 6.
    #[error("invalid IP version: {0}")]
    InvalidVersion(u8),
    /// The message holds a reserved byte that is not zero.
    #[error("reserved byte is not zero: {0}")]
    ReservedNonZero(u8),
}

impl From<SocketAddr> for WireSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::from(v4),
            SocketAddr::V6(v6) => Self::from(v6),
        }
    }
}

impl From<SocketAddrV4> for WireSocketAddr {
    fn from(addr: SocketAddrV4) -> Self {
        let mut ip_addr = [0u8; 16];
        // The IPv4 address occupies the last 4 bytes. The first 12 stay zero.
        ip_addr[12..16].copy_from_slice(&addr.ip().octets());

        Self {
            ip_version: 4,
            reserved_zero: 0,
            port: big_endian::U16::new(addr.port()),
            ip_addr,
        }
    }
}

impl From<SocketAddrV6> for WireSocketAddr {
    fn from(addr: SocketAddrV6) -> Self {
        Self {
            ip_version: 6,
            reserved_zero: 0,
            port: big_endian::U16::new(addr.port()),
            ip_addr: addr.ip().octets(),
        }
    }
}

impl TryFrom<WireSocketAddr> for SocketAddr {
    type Error = WireSocketAddrError;

    fn try_from(value: WireSocketAddr) -> Result<Self, Self::Error> {
        if value.reserved_zero != 0 {
            return Err(WireSocketAddrError::ReservedNonZero(value.reserved_zero));
        }
        let port = value.port.get();
        match value.ip_version {
            4 => {
                let octets: [u8; 4] = value.ip_addr[12..16].try_into().expect("slice is 4 bytes");
                Ok(SocketAddr::from((octets, port)))
            }
            6 => Ok(SocketAddr::from((value.ip_addr, port))),
            v => Err(WireSocketAddrError::InvalidVersion(v)),
        }
    }
}

/// The handshake initiation message.
///
/// See section 5.4.2 of the
/// [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct HandshakeInit {
    // INVARIANT: holds MessageType::HandshakeInit.
    message_type: MessageType,
    _reserved_zeros: [u8; 3],

    /// The session index of the initiator.
    pub sender_idx: little_endian::U32,

    /// The ephemeral public key of the initiator.
    pub unencrypted_ephemeral: [u8; 32],

    /// The encrypted static public key of the initiator.
    pub encrypted_static: EncryptedWithTag<[u8; 32]>,

    /// An encrypted TAI64N timestamp. It protects against a replay.
    pub timestamp: EncryptedWithTag<[u8; 12]>,

    /// The first message authentication code.
    pub mac1: [u8; 16],

    /// The second message authentication code.
    pub mac2: [u8; 16],
}

impl HandshakeInit {
    /// The length of the message, in bytes.
    pub const LEN: usize = size_must_be::<Self>(148);

    /// Returns a message in which every field except the type is zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_type: MessageType::HandshakeInit,
            ..Self::new_zeroed()
        }
    }
}

impl Default for HandshakeInit {
    fn default() -> Self {
        Self::new()
    }
}

/// The fixed head of a [`HandshakeResp`].
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct HandshakeRespHead {
    // INVARIANT: holds MessageType::HandshakeResp.
    message_type: MessageType,
    _reserved_zeros: [u8; 3],

    /// The session index of the responder.
    pub sender_idx: little_endian::U32,

    /// The session index of the initiator.
    pub receiver_idx: little_endian::U32,

    /// The ephemeral public key of the responder.
    pub unencrypted_ephemeral: [u8; 32],
}

impl HandshakeRespHead {
    /// The length of the head, in bytes.
    pub const LEN: usize = size_must_be::<Self>(44);

    /// Returns a head in which every field except the type is zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_type: MessageType::HandshakeResp,
            ..Self::new_zeroed()
        }
    }
}

impl Default for HandshakeRespHead {
    fn default() -> Self {
        Self::new()
    }
}

/// The handshake response message.
///
/// See section 5.4.3 of the
/// [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
///
/// The message has two forms, which its length tells apart:
///
/// * [`HandshakeResp::LEN_PLAIN`], the form of WireGuard. The sealed field holds an empty message,
///   so it is a tag and nothing else.
/// * [`HandshakeResp::LEN_WITH_ADDR`], the form of this protocol. The sealed field holds the socket
///   address of the initiator, as the responder observes it. The initiator learns from it the
///   address that the responder sees, which is what a STUN request asks for.
///
/// A responder sends the second form only when it holds an address of the
/// initiator. Both forms derive the same session keys, because the sealed
/// field enters neither the chaining key nor the hash.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct HandshakeResp {
    /// The fixed head of the message.
    pub head: HandshakeRespHead,

    /// The sealed field, and `mac1` and `mac2` after it.
    sealed_and_macs: [u8],
}

impl HandshakeResp {
    /// The length of a response that carries no socket address, in bytes.
    pub const LEN_PLAIN: usize = HandshakeRespHead::LEN + TAG_LEN + 2 * MAC_LEN;

    /// The length of a response that carries a socket address, in bytes.
    pub const LEN_WITH_ADDR: usize =
        HandshakeRespHead::LEN + WireSocketAddr::LEN + TAG_LEN + 2 * MAC_LEN;

    /// Returns the sealed field, without `mac1` and `mac2`.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed_and_macs[..self.sealed_and_macs.len() - 2 * MAC_LEN]
    }

    /// Returns the sealed field, without `mac1` and `mac2`.
    #[must_use]
    pub fn sealed_mut(&mut self) -> &mut [u8] {
        let end = self.sealed_and_macs.len() - 2 * MAC_LEN;
        &mut self.sealed_and_macs[..end]
    }

    /// Returns true if the sealed field holds a socket address.
    #[must_use]
    pub fn carries_sockaddr(&self) -> bool {
        self.sealed().len() == WireSocketAddr::LEN + TAG_LEN
    }
}

/// The head is the part of the message that both forms share, so a field of
/// the head reads straight off the message.
impl std::ops::Deref for HandshakeResp {
    type Target = HandshakeRespHead;

    fn deref(&self) -> &Self::Target {
        &self.head
    }
}

impl std::ops::DerefMut for HandshakeResp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.head
    }
}

/// The cookie reply message.
///
/// See section 5.4.7 of the
/// [whitepaper](https://www.wireguard.com/papers/wireguard.pdf). A peer that
/// is under load answers a handshake with this message instead of processing
/// it. The initiator then repeats the handshake, keyed with the cookie.
///
/// This crate consumes a cookie reply but never sends one, because it
/// implements no rate limiting and therefore never declares itself under load.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct CookieReply {
    // INVARIANT: holds MessageType::CookieReply.
    message_type: MessageType,
    _reserved_zeros: [u8; 3],

    /// The session index of the peer that sent the handshake.
    pub receiver_idx: little_endian::U32,

    /// The nonce of the encryption.
    pub nonce: [u8; 24],

    /// The encrypted cookie.
    pub encrypted_cookie: EncryptedWithTag<[u8; COOKIE_LEN]>,
}

/// The length of a cookie, in bytes.
pub const COOKIE_LEN: usize = 16;

impl CookieReply {
    /// The length of the message, in bytes.
    pub const LEN: usize = size_must_be::<Self>(64);

    /// Returns a message in which every field except the type is zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_type: MessageType::CookieReply,
            ..Self::new_zeroed()
        }
    }
}

impl Default for CookieReply {
    fn default() -> Self {
        Self::new()
    }
}

/// The header of a [`Data`] message.
///
/// See section 5.4.6 of the
/// [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct DataHeader {
    // INVARIANT: holds MessageType::Data.
    message_type: MessageType,
    _reserved_zeros: [u8; 3],

    /// The session index of the receiver.
    pub receiver_idx: little_endian::U32,

    /// The counter of the message. It protects against a replay.
    pub counter: little_endian::U64,
}

impl DataHeader {
    /// The length of the header, in bytes.
    pub const LEN: usize = size_must_be::<Self>(16);

    /// Returns a header in which every field except the type is zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_type: MessageType::Data,
            ..Self::new_zeroed()
        }
    }

    /// Sets the session index of the receiver.
    #[must_use]
    pub const fn with_receiver_idx(mut self, receiver_idx: u32) -> Self {
        self.receiver_idx = little_endian::U32::new(receiver_idx);
        self
    }

    /// Sets the counter of the message.
    #[must_use]
    pub const fn with_counter(mut self, counter: u64) -> Self {
        self.counter = little_endian::U64::new(counter);
        self
    }
}

impl Default for DataHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A data message: a header, the ciphertext, and the tag.
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
pub struct Data {
    /// The header of the message.
    pub header: DataHeader,

    /// The ciphertext and the tag that follows it.
    ciphertext_and_tag: [u8],
}

impl Data {
    /// The number of bytes that the header and the tag add to the payload.
    pub const OVERHEAD: usize = DataHeader::LEN + TAG_LEN;

    /// Returns the ciphertext and the tag.
    #[must_use]
    pub fn ciphertext_and_tag_mut(&mut self) -> &mut [u8] {
        &mut self.ciphertext_and_tag
    }

    /// Returns the length of the payload, without the tag.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.ciphertext_and_tag.len() - TAG_LEN
    }

    /// Returns true if the message carries no payload.
    ///
    /// A keepalive is a data message with an empty payload.
    #[must_use]
    pub fn is_keepalive(&self) -> bool {
        self.payload_len() == 0
    }
}

/// A parsed message. It borrows the buffer that holds the message.
pub enum Message<'a> {
    /// A handshake initiation.
    HandshakeInit(&'a mut HandshakeInit),
    /// A handshake response.
    HandshakeResp(&'a mut HandshakeResp),
    /// A cookie reply.
    CookieReply(&'a mut CookieReply),
    /// A data message.
    Data(&'a mut Data),
}

/// The error that a parse returns.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// The first byte holds a type that the protocol does not define.
    #[error("unknown message type: {0}")]
    UnknownType(u8),
    /// The length of the buffer does not match the type of the message.
    #[error("message of type {message_type} has a length of {len} bytes")]
    BadLength {
        /// The type byte of the message.
        message_type: u8,
        /// The length of the buffer, in bytes.
        len: usize,
    },
}

/// Parses `buffer` as a message.
///
/// The returned message borrows `buffer`, so a caller decrypts and encrypts in
/// place. The parse reads the type byte and checks the length. It does not
/// authenticate the message.
pub fn parse(buffer: &mut [u8]) -> Result<Message<'_>, ParseError> {
    let &message_type = buffer.first().ok_or(ParseError::BadLength {
        message_type: 0,
        len: 0,
    })?;
    let len = buffer.len();
    let bad_length = || ParseError::BadLength { message_type, len };

    match (MessageType(message_type), len) {
        (MessageType::HandshakeInit, HandshakeInit::LEN) => {
            Ok(Message::HandshakeInit(
                HandshakeInit::mut_from_bytes(buffer).map_err(|_| bad_length())?,
            ))
        }
        (MessageType::HandshakeResp, HandshakeResp::LEN_PLAIN | HandshakeResp::LEN_WITH_ADDR) => {
            Ok(Message::HandshakeResp(
                HandshakeResp::mut_from_bytes(buffer).map_err(|_| bad_length())?,
            ))
        }
        (MessageType::CookieReply, CookieReply::LEN) => {
            Ok(Message::CookieReply(
                CookieReply::mut_from_bytes(buffer).map_err(|_| bad_length())?,
            ))
        }
        (MessageType::Data, Data::OVERHEAD..) => {
            Ok(Message::Data(
                Data::mut_from_bytes(buffer).map_err(|_| bad_length())?,
            ))
        }
        (
            MessageType::HandshakeInit
            | MessageType::HandshakeResp
            | MessageType::CookieReply
            | MessageType::Data,
            _,
        ) => Err(bad_length()),
        _ => Err(ParseError::UnknownType(message_type)),
    }
}

impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeInit(_) => f.debug_tuple("HandshakeInit").finish(),
            Self::HandshakeResp(_) => f.debug_tuple("HandshakeResp").finish(),
            Self::CookieReply(_) => f.debug_tuple("CookieReply").finish(),
            Self::Data(_) => f.debug_tuple("Data").finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_a_bad_length() {
        let mut buffer = [0u8; HandshakeInit::LEN - 1];
        buffer[0] = MessageType::HandshakeInit.0;
        assert!(matches!(
            parse(&mut buffer),
            Err(ParseError::BadLength {
                message_type: 1,
                len: _
            })
        ));
    }

    #[test]
    fn parse_rejects_an_unknown_type() {
        let mut buffer = [9u8; 64];
        assert!(matches!(
            parse(&mut buffer),
            Err(ParseError::UnknownType(9))
        ));
    }

    #[test]
    fn parse_rejects_an_empty_buffer() {
        assert!(parse(&mut []).is_err());
    }

    #[test]
    fn a_handshake_init_writes_into_the_buffer_of_the_caller() {
        let mut buffer = [0u8; 2048];
        let init = HandshakeInit::mut_from_bytes(&mut buffer[..HandshakeInit::LEN])
            .expect("the buffer holds a handshake initiation");
        *init = HandshakeInit::new();
        init.sender_idx.set(0xdead_beef);
        init.unencrypted_ephemeral = [7u8; 32];

        let Message::HandshakeInit(parsed) =
            parse(&mut buffer[..HandshakeInit::LEN]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };
        assert_eq!(parsed.sender_idx.get(), 0xdead_beef);
        assert_eq!(parsed.unencrypted_ephemeral, [7u8; 32]);
    }

    #[test]
    fn a_data_message_splits_into_a_payload_and_a_tag() {
        const PAYLOAD_LEN: usize = 100;
        let mut buffer = [0u8; Data::OVERHEAD + PAYLOAD_LEN];
        buffer[0] = MessageType::Data.0;

        let Message::Data(data) = parse(&mut buffer).expect("the message parses") else {
            panic!("expected a data message");
        };
        assert_eq!(data.payload_len(), PAYLOAD_LEN);
        assert_eq!(data.ciphertext_and_tag_mut().len(), PAYLOAD_LEN + TAG_LEN);
        assert!(!data.is_keepalive());
    }

    #[test]
    fn an_empty_data_message_is_a_keepalive() {
        let mut buffer = [0u8; Data::OVERHEAD];
        buffer[0] = MessageType::Data.0;

        let Message::Data(data) = parse(&mut buffer).expect("the message parses") else {
            panic!("expected a data message");
        };
        assert!(data.is_keepalive());
    }

    #[test]
    fn a_cookie_reply_parses() {
        let mut buffer = [0u8; CookieReply::LEN];
        let reply = CookieReply::mut_from_bytes(&mut buffer).expect("the buffer has the length");
        *reply = CookieReply::new();
        reply.receiver_idx.set(7);

        let Message::CookieReply(parsed) = parse(&mut buffer).expect("the message parses") else {
            panic!("expected a cookie reply");
        };
        assert_eq!(parsed.receiver_idx.get(), 7);
    }

    #[test]
    fn a_cookie_reply_of_the_wrong_length_is_rejected() {
        let mut buffer = [0u8; CookieReply::LEN - 1];
        buffer[0] = MessageType::CookieReply.0;
        assert!(matches!(
            parse(&mut buffer),
            Err(ParseError::BadLength {
                message_type: 3,
                ..
            })
        ));
    }

    #[test]
    fn a_socket_address_survives_a_round_trip() {
        for addr in ["192.0.2.1:1234", "[2001:db8::1]:4321"] {
            let addr: SocketAddr = addr.parse().expect("the address parses");
            let wire = WireSocketAddr::from(addr);
            assert_eq!(
                SocketAddr::try_from(wire).expect("the address parses"),
                addr
            );
        }
    }
}
