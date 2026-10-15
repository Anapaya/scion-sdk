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
// This file incorporates code from mullvad/gotatun, at the v0.2.0 tag that
// ana-gotatun forked from:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49
// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// Copyright (c) 2025 Mullvad VPN.
// SPDX-License-Identifier: BSD-3-Clause
//
// A "BEGIN gotatun verbatim" marker names the code that comes from gotatun
// without a change, and the permalink on the next line points at the lines it
// comes from. Everything outside such a pair is the code of this crate.
// tools/check_verbatim.py compares every marked region against gotatun.

//! The Noise IKpsk2 handshake.
//!
//! The order of the cryptographic operations follows gotatun, which follows
//! the WireGuard whitepaper. The comment above each step names the step of the
//! whitepaper.
//!
//! The module differs from gotatun in three points. It takes the time from the caller, it writes a
//! message into the buffer of the caller, and it optionally puts the socket address of the
//! initiator into the handshake response.

use std::time::{Duration, Instant, SystemTime};

use constant_time_eq::constant_time_eq_n;
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret, StaticSecret};
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use crate::{
    crypto::{
        INITIAL_CHAIN_HASH, INITIAL_CHAIN_KEY, KEY_LEN, LABEL_COOKIE, LABEL_MAC1, aead_open,
        aead_seal, b2s_hash, b2s_hmac, b2s_hmac2, b2s_keyed_mac_16, xaead_open_cookie,
    },
    error::Error,
    session::Session,
    timers::COOKIE_EXPIRATION_TIME,
    wire::{
        COOKIE_LEN, CookieReply, HandshakeInit, HandshakeResp, HandshakeRespHead, WireSocketAddr,
    },
};

const TIMESTAMP_LEN: usize = 12;

/// The number of bytes that follow the start of `mac1` in a handshake
/// message: `mac1` and `mac2`, of 16 bytes each.
const MAC1_FROM_END: usize = 32;
/// The number of bytes that follow the start of `mac2` in a handshake
/// message.
const MAC2_FROM_END: usize = 16;

// BEGIN gotatun verbatim:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L167-L172
#[derive(Debug)]
/// This struct represents a 12 byte [`Tai64N`](https://cr.yp.to/libtai/tai64.html) timestamp
struct Tai64N {
    secs: u64,
    nano: u32,
}
// END gotatun verbatim.

// BEGIN gotatun verbatim:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L203-L235
impl Tai64N {
    /// A zeroed out timestamp
    fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    /// Parse a timestamp from a 12 byte u8 slice
    fn parse(buf: &[u8; 12]) -> Result<Tai64N, Error> {
        if buf.len() < 12 {
            return Err(Error::InvalidTai64nTimestamp);
        }

        let (sec_bytes, nano_bytes) = buf.split_at(std::mem::size_of::<u64>());
        let secs = u64::from_be_bytes(sec_bytes.try_into().unwrap());
        let nano = u32::from_be_bytes(nano_bytes.try_into().unwrap());

        // WireGuard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(Error::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(Error::InvalidTai64nTimestamp);
        //}

        Ok(Tai64N { secs, nano })
    }

    /// Check if this timestamp represents a time that is chronologically after the time represented
    /// by the other timestamp
    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}
// END gotatun verbatim.

/// The source of the timestamp that a handshake initiation carries.
///
/// The caller gives the wall clock once. The stamper then derives every
/// timestamp from the monotonic clock, so that a step of the wall clock cannot
/// make the timestamp go backwards.
#[derive(Debug)]
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    fn new(now: Instant, wall_clock: SystemTime) -> Self {
        Self {
            duration_at_start: wall_clock
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO),
            instant_at_start: now,
        }
    }

    fn stamp(&self, now: Instant) -> [u8; TIMESTAMP_LEN] {
        const TAI64_BASE: u64 = (1u64 << 62) + 37;
        let mut ext_stamp = [0u8; TIMESTAMP_LEN];
        let stamp = now.duration_since(self.instant_at_start) + self.duration_at_start;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + TAI64_BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

/// The keys that the handshake uses.
struct NoiseParams {
    /// The static public key of this peer.
    static_public: PublicKey,
    /// The static private key of this peer.
    static_private: StaticSecret,
    /// The static public key of the remote peer.
    peer_static_public: PublicKey,
    /// `DH(static_private, peer_static_public)`
    static_shared: SharedSecret,
    /// `HASH("mac1----", peer_static_public)`. It authenticates a message that
    /// this peer sends.
    sending_mac1_key: [u8; KEY_LEN],
    /// `HASH("mac1----", static_public)`. It authenticates a message that this
    /// peer receives.
    receiving_mac1_key: [u8; KEY_LEN],
    /// `HASH("cookie--", peer_static_public)`. It opens the cookie that the
    /// remote peer sends.
    peer_cookie_key: [u8; KEY_LEN],
    /// The optional pre-shared key.
    preshared_key: Option<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("static_private", &"<redacted>")
            .field("peer_static_public", &self.peer_static_public)
            .field("static_shared", &"<redacted>")
            .field("preshared_key", &self.preshared_key.map(|_| "<redacted>"))
            .finish()
    }
}

impl NoiseParams {
    fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; KEY_LEN]>,
    ) -> Self {
        let static_public = PublicKey::from(&static_private);
        Self {
            static_shared: static_private.diffie_hellman(&peer_static_public),
            sending_mac1_key: b2s_hash(LABEL_MAC1, peer_static_public.as_bytes()),
            receiving_mac1_key: b2s_hash(LABEL_MAC1, static_public.as_bytes()),
            peer_cookie_key: b2s_hash(LABEL_COOKIE, peer_static_public.as_bytes()),
            static_public,
            static_private,
            peer_static_public,
            preshared_key,
        }
    }
}

struct HandshakeInitSentState {
    local_index: u32,
    hash: [u8; KEY_LEN],
    chaining_key: [u8; KEY_LEN],
    ephemeral_private: ReusableSecret,
    time_sent: Instant,
}

enum HandshakeState {
    /// No handshake is in progress.
    None,
    /// This peer sent an initiation.
    InitSent(HandshakeInitSentState),
    /// The remote peer sent an initiation.
    InitReceived {
        hash: [u8; KEY_LEN],
        chaining_key: [u8; KEY_LEN],
        peer_ephemeral_public: PublicKey,
        peer_index: u32,
    },
    /// The handshake gave up. No handshake is in progress.
    Expired,
}

/// The state of the cookie mechanism, as the sender of a handshake sees it.
///
/// A peer that is under load answers a handshake with a cookie instead of
/// processing it. The sender keys `mac2` of its next handshake with that
/// cookie, which proves that it can receive at the address it sends from.
///
/// This crate never sends a cookie reply, because it declares itself under
/// load nowhere. It consumes one, so that a peer that does rate limit can
/// still complete a handshake with it.
#[derive(Default)]
struct Cookies {
    /// The `mac1` of the last handshake that this peer sent. A cookie reply
    /// authenticates the cookie with it.
    last_mac1: Option<[u8; COOKIE_LEN]>,
    /// The session index of the last handshake that this peer sent.
    index: u32,
    /// The cookie of the remote peer, and the time at which it arrived.
    cookie: Option<([u8; COOKIE_LEN], Instant)>,
}

/// The handshake state of one tunnel.
pub(crate) struct Handshake {
    params: NoiseParams,
    /// The index that the next session gets.
    next_index: u32,
    /// The state before [`Handshake::state`]. A slow network can deliver a
    /// response to the initiation before this one, so the peer keeps two
    /// initiations in flight.
    previous: HandshakeState,
    /// The current state.
    state: HandshakeState,
    /// The timestamp of the last initiation that this peer accepted.
    last_handshake_timestamp: Tai64N,
    cookies: Cookies,
    stamper: TimeStamper,
    /// The socket address of the remote peer, as this peer observes it. A
    /// handshake response carries it when this peer holds one. Without it,
    /// the response takes the form of WireGuard.
    peer_sockaddr: Option<WireSocketAddr>,
    /// The socket address of this peer, as the remote peer observes it. A
    /// handshake response carries it.
    observed_sockaddr: Option<WireSocketAddr>,
}

/// The identity that a handshake initiation carries.
#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity {
    /// The session index of the initiator.
    pub peer_index: u32,
    /// The static public key of the initiator.
    pub peer_static_public: [u8; KEY_LEN],
}

/// Reads the identity of the initiator out of a handshake initiation.
///
/// A peer that holds one private key and many remote identities uses this to
/// find the peer that an initiation belongs to. The function proves that the
/// initiation is addressed to `static_private`, because the static public key
/// of the initiator only opens under a key that the private key derives. It
/// does not prove that the initiation is fresh; only
/// `Handshake::consume_initiation` checks the timestamp.
pub fn peer_identity(
    static_private: &StaticSecret,
    packet: &HandshakeInit,
) -> Result<PeerIdentity, Error> {
    let static_public = PublicKey::from(static_private);

    // BEGIN gotatun verbatim:
    // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L337-L374
    let peer_index = packet.sender_idx.get();
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = PublicKey::from(packet.unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = static_private.diffie_hellman(&peer_ephemeral_public);
    let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_open(
        &mut peer_static_public,
        &key,
        0,
        packet.encrypted_static.as_bytes(),
        &hash,
    )?;

    Ok(PeerIdentity {
        peer_index,
        peer_static_public,
    })
    // END gotatun verbatim.
}

impl Handshake {
    pub(crate) fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; KEY_LEN]>,
        global_idx: u32,
        peer_sockaddr: Option<WireSocketAddr>,
        now: Instant,
        wall_clock: SystemTime,
    ) -> Self {
        Self {
            params: NoiseParams::new(static_private, peer_static_public, preshared_key),
            next_index: global_idx << 8,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            cookies: Cookies::default(),
            stamper: TimeStamper::new(now, wall_clock),
            peer_sockaddr,
            observed_sockaddr: None,
        }
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        !matches!(self.state, HandshakeState::None | HandshakeState::Expired)
    }

    /// Returns the time at which this peer sent the initiation that is in
    /// flight.
    pub(crate) fn time_init_sent(&self) -> Option<Instant> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState { time_sent, .. }) => Some(time_sent),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) fn peer_static_public(&self) -> &PublicKey {
        &self.params.peer_static_public
    }

    /// Returns the socket address of this peer, as the remote peer observed it
    /// during the last handshake that this peer initiated.
    pub(crate) fn observed_sockaddr(&self) -> Option<WireSocketAddr> {
        self.observed_sockaddr
    }

    /// Sets the socket address that the next handshake response carries.
    pub(crate) fn set_peer_sockaddr(&mut self, peer_sockaddr: WireSocketAddr) {
        self.peer_sockaddr = Some(peer_sockaddr);
    }

    // BEGIN gotatun verbatim:
    // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L471-L477
    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits
    // for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index as u8;
        self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1));
        self.next_index
    }
    // END gotatun verbatim.

    /// Checks that `mac1` authenticates the message.
    ///
    /// The check proves that the sender knows the static public key of this
    /// peer. It is cheap, so it rejects a misdirected or a random message
    /// before the expensive operations of the handshake run.
    fn verify_mac1(&self, message: &[u8]) -> Result<(), Error> {
        let (until_mac1, rest) = message.split_at(message.len() - MAC1_FROM_END);
        let mac1: &[u8; COOKIE_LEN] = rest[..COOKIE_LEN]
            .try_into()
            .expect("the slice holds 16 bytes");
        let computed = b2s_keyed_mac_16(&self.params.receiving_mac1_key, until_mac1);
        if constant_time_eq_n(&computed, mac1) {
            Ok(())
        } else {
            Err(Error::InvalidMac)
        }
    }

    /// Writes `mac1` and `mac2` at the end of a handshake message.
    ///
    /// `mac1` proves that this peer knows the static public key of the remote
    /// peer. `mac2` proves that this peer can receive at the address it sends
    /// from, and it stays zero until a cookie reply gives this peer a cookie.
    /// The caller must write every other field of the message first.
    fn write_macs(&mut self, message: &mut [u8], local_index: u32) {
        let mac1_off = message.len() - MAC1_FROM_END;
        let mac2_off = message.len() - MAC2_FROM_END;

        let mac1 = b2s_keyed_mac_16(&self.params.sending_mac1_key, &message[..mac1_off]);
        message[mac1_off..mac2_off].copy_from_slice(&mac1);

        let mac2 = match self.cookies.cookie {
            Some((cookie, _)) => b2s_keyed_mac_16(&cookie, &message[..mac2_off]),
            None => [0u8; COOKIE_LEN],
        };
        message[mac2_off..].copy_from_slice(&mac2);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(mac1);
    }

    /// Consumes a cookie reply, and keeps the cookie for the next handshake.
    ///
    /// The reply names the handshake that it answers, and it authenticates
    /// the cookie with the `mac1` of that handshake. A peer that did not see
    /// the handshake can therefore not plant a cookie.
    pub(crate) fn consume_cookie_reply(
        &mut self,
        reply: &CookieReply,
        now: Instant,
    ) -> Result<(), Error> {
        let Some(mac1) = self.cookies.last_mac1 else {
            return Err(Error::UnexpectedPacket);
        };
        if reply.receiver_idx.get() != self.cookies.index {
            return Err(Error::WrongIndex);
        }

        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public),
        //                              msg.nonce, cookie, last_sent_msg.mac1)
        let cookie = xaead_open_cookie(
            &self.params.peer_cookie_key,
            &reply.nonce,
            &reply.encrypted_cookie,
            &mac1,
        )?;

        self.cookies.cookie = Some((cookie, now));
        Ok(())
    }

    /// Drops the cookie once it is too old to be of use.
    pub(crate) fn expire_cookie(&mut self, now: Instant) {
        if let Some((_, received_at)) = self.cookies.cookie
            && now.saturating_duration_since(received_at) >= COOKIE_EXPIRATION_TIME
        {
            self.cookies.cookie = None;
        }
    }

    /// Returns true if this peer holds a cookie of the remote peer.
    #[cfg(test)]
    pub(crate) fn has_cookie(&self) -> bool {
        self.cookies.cookie.is_some()
    }

    /// Writes a handshake initiation into `buffer`.
    ///
    /// Returns the length of the message.
    pub(crate) fn format_initiation(
        &mut self,
        now: Instant,
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let buffer = buffer
            .get_mut(..HandshakeInit::LEN)
            .ok_or(Error::BufferTooSmall)?;
        let handshake = HandshakeInit::mut_from_bytes(buffer).expect("the buffer has the length");
        *handshake = HandshakeInit::new();

        let local_index = self.inc_index();

        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L712-L768
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) ||
        // responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = ReusableSecret::random();
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        // msg.sender_index = little_endian(initiator.sender_index)
        handshake.sender_idx.set(local_index);
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        handshake
            .unencrypted_ephemeral
            .copy_from_slice(PublicKey::from(&ephemeral_private).as_bytes());
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, &handshake.unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(
            &b2s_hmac(&chaining_key, &handshake.unencrypted_ephemeral),
            &[0x01],
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private,
        // responder.static_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&self.params.peer_static_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_seal(
            handshake.encrypted_static.as_mut_bytes(),
            &key,
            0,
            self.params.static_public.as_bytes(),
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, handshake.encrypted_static.as_bytes());
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private,
        // responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp(now);
        aead_seal(
            handshake.timestamp.as_mut_bytes(),
            &key,
            0,
            &timestamp,
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, handshake.timestamp.as_bytes());
        // END gotatun verbatim.

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        // msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        self.write_macs(handshake.as_mut_bytes(), local_index);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: now,
            }),
        );

        Ok(HandshakeInit::LEN)
    }

    /// Consumes a handshake initiation of the remote peer.
    ///
    /// The caller writes the response with
    /// [`Handshake::format_response`], which the split lets it do in
    /// the buffer that holds the initiation.
    pub(crate) fn consume_initiation(&mut self, packet: &HandshakeInit) -> Result<(), Error> {
        self.verify_mac1(packet.as_bytes())?;

        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L491-L556
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) ||
        // responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.static_public.as_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = PublicKey::from(packet.unencrypted_ephemeral);
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(
            &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
            &[0x01],
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private,
        // responder.static_public))
        let ephemeral_shared = self
            .params
            .static_private
            .diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

        let mut peer_static_public_decrypted = [0u8; KEY_LEN];
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_open(
            &mut peer_static_public_decrypted,
            &key,
            0,
            packet.encrypted_static.as_bytes(),
            &hash,
        )?;

        if !constant_time_eq_n(
            self.params.peer_static_public.as_bytes(),
            &peer_static_public_decrypted,
        ) {
            return Err(Error::WrongKey);
        }

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, packet.encrypted_static.as_bytes());
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private,
        // responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_open(&mut timestamp, &key, 0, packet.timestamp.as_bytes(), &hash)?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(Error::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, packet.timestamp.as_bytes());
        // END gotatun verbatim.

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index: peer_index.get(),
            },
        );

        Ok(())
    }

    /// Writes the response to the initiation that
    /// [`Handshake::consume_initiation`] took, and returns the session that
    /// the handshake established.
    ///
    /// The caller must call this directly after a successful
    /// [`Handshake::consume_initiation`].
    pub(crate) fn format_response(&mut self, buffer: &mut [u8]) -> Result<(usize, Session), Error> {
        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let HandshakeState::InitReceived {
            mut chaining_key,
            mut hash,
            peer_ephemeral_public,
            peer_index,
        } = state
        else {
            return Err(Error::UnexpectedPacket);
        };

        let len = match self.peer_sockaddr {
            Some(_) => HandshakeResp::LEN_WITH_ADDR,
            None => HandshakeResp::LEN_PLAIN,
        };
        let buffer = buffer.get_mut(..len).ok_or(Error::BufferTooSmall)?;
        buffer.fill(0);
        let resp = HandshakeResp::mut_from_bytes(buffer).expect("the buffer has the length");
        resp.head = HandshakeRespHead::new();

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = ReusableSecret::random();
        let local_index = self.inc_index();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        // msg.sender_index = little_endian(responder.sender_index)
        resp.sender_idx.set(local_index);
        // msg.receiver_index = little_endian(initiator.sender_index)
        resp.receiver_idx.set(peer_index);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        resp.unencrypted_ephemeral = PublicKey::from(&ephemeral_private).to_bytes();
        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L817-L849
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, &resp.unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&chaining_key, &resp.unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private,
        // initiator.ephemeral_public))
        let ephemeral_shared = ephemeral_private.diffie_hellman(&peer_ephemeral_public);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private,
        // initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &ephemeral_private
                .diffie_hellman(&self.params.peer_static_public)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; KEY_LEN])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // END gotatun verbatim.

        // This is the one place where the protocol departs from WireGuard.
        // With an address of the initiator, the responder seals that address
        // instead of the empty message that WireGuard seals. The sealed field
        // enters neither the chaining key nor the hash, so the two forms
        // derive the same session keys and only the message differs.
        match self.peer_sockaddr {
            // msg.socketaddr = AEAD(key, 0, initiator.socket_address, responder.hash)
            Some(peer_sockaddr) => {
                aead_seal(resp.sealed_mut(), &key, 0, peer_sockaddr.as_bytes(), &hash)
            }
            // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
            None => aead_seal(resp.sealed_mut(), &key, 0, &[], &hash),
        }

        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L853-L863
        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);
        // END gotatun verbatim.

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])
        // msg.mac2 = MAC(responder.last_received_cookie, msg[0:offsetof(msg.mac2)])
        self.write_macs(resp.as_mut_bytes(), local_index);

        Ok((len, Session::new(local_index, peer_index, temp2, temp3)))
    }

    /// Consumes the response to an initiation that this peer sent, and returns
    /// the session that the handshake established.
    pub(crate) fn consume_response(&mut self, packet: &HandshakeResp) -> Result<Session, Error> {
        self.verify_mac1(packet.as_bytes())?;

        // Find the initiation that the response answers. A slow network can
        // deliver the response to the previous initiation after the peer sent
        // the next one.
        let receiver_idx = packet.receiver_idx.get();
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == receiver_idx => (s, true),
            _ => return Err(Error::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx.get();
        let local_index = state.local_index;

        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L589-L627
        let unencrypted_ephemeral = PublicKey::from(packet.unencrypted_ephemeral);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private,
        // initiator.ephemeral_public))
        let ephemeral_shared = state
            .ephemeral_private
            .diffie_hellman(&unencrypted_ephemeral);
        let temp = b2s_hmac(&chaining_key, &ephemeral_shared.to_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private,
        // initiator.static_public))
        let temp = b2s_hmac(
            &chaining_key,
            &self
                .params
                .static_private
                .diffie_hellman(&unencrypted_ephemeral)
                .to_bytes(),
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; KEY_LEN])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2);
        // END gotatun verbatim.

        // The responder answers in the form of WireGuard, or in the form that
        // carries the address it observed. The length of the message tells
        // the two apart. Both open under the same key, so an initiator takes
        // either one whatever it holds itself.
        let observed_sockaddr = if packet.carries_sockaddr() {
            // msg.socketaddr = AEAD(key, 0, initiator.socket_address, responder.hash)
            let mut sockaddr = WireSocketAddr::new_zeroed();
            aead_open(sockaddr.as_mut_bytes(), &key, 0, packet.sealed(), &hash)?;
            Some(sockaddr)
        } else {
            // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
            aead_open(&mut [], &key, 0, packet.sealed(), &hash)?;
            None
        };

        // BEGIN gotatun verbatim:
        // https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L634-L644
        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);
        // END gotatun verbatim.

        self.observed_sockaddr = observed_sockaddr;
        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }

        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::wire::{Message, parse};

    fn sockaddr(s: &str) -> WireSocketAddr {
        WireSocketAddr::from(s.parse::<SocketAddr>().expect("the address parses"))
    }

    /// Returns the handshake state of an initiator and of a responder that
    /// hold the static key of each other.
    fn handshake_pair(psk: Option<[u8; KEY_LEN]>) -> (Handshake, Handshake) {
        let now = Instant::now();
        let wall = SystemTime::now();

        let initiator_key = StaticSecret::random();
        let responder_key = StaticSecret::random();
        let initiator_public = PublicKey::from(&initiator_key);
        let responder_public = PublicKey::from(&responder_key);

        (
            Handshake::new(
                initiator_key,
                responder_public,
                psk,
                1,
                Some(sockaddr("192.0.2.2:2222")),
                now,
                wall,
            ),
            Handshake::new(
                responder_key,
                initiator_public,
                psk,
                2,
                Some(sockaddr("192.0.2.1:1111")),
                now,
                wall,
            ),
        )
    }

    /// Runs a full handshake in one buffer, and returns the two sessions.
    fn run_handshake(
        initiator: &mut Handshake,
        responder: &mut Handshake,
        now: Instant,
    ) -> Result<(Session, Session), Error> {
        let mut buffer = [0u8; 2048];

        let len = initiator.format_initiation(now, &mut buffer)?;
        let Message::HandshakeInit(init) = parse(&mut buffer[..len])? else {
            panic!("expected a handshake initiation");
        };
        responder.consume_initiation(init)?;
        let (len, responder_session) = responder.format_response(&mut buffer)?;

        let Message::HandshakeResp(resp) = parse(&mut buffer[..len])? else {
            panic!("expected a handshake response");
        };
        let initiator_session = initiator.consume_response(resp)?;

        Ok((initiator_session, responder_session))
    }

    #[test]
    fn a_handshake_establishes_a_session_that_carries_data_both_ways() {
        let (mut initiator, mut responder) = handshake_pair(None);
        let (mut initiator_session, mut responder_session) =
            run_handshake(&mut initiator, &mut responder, Instant::now())
                .expect("the handshake succeeds");

        fn round_trip(sender: &mut Session, receiver: &mut Session) {
            let payload = b"a payload of the caller";
            let mut buffer = [0u8; 256];
            buffer[16..16 + payload.len()].copy_from_slice(payload);
            let len = sender
                .encrypt(&mut buffer, payload.len())
                .expect("the buffer is large enough");

            let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
                panic!("expected a data message");
            };
            let payload_len = receiver.decrypt(data).expect("the message opens");
            assert_eq!(&buffer[16..16 + payload_len], payload);
        }

        round_trip(&mut initiator_session, &mut responder_session);
        round_trip(&mut responder_session, &mut initiator_session);
    }

    #[test]
    fn a_handshake_with_a_preshared_key_establishes_a_session() {
        let (mut initiator, mut responder) = handshake_pair(Some([9u8; KEY_LEN]));
        run_handshake(&mut initiator, &mut responder, Instant::now())
            .expect("the handshake succeeds");
    }

    #[test]
    fn a_peer_that_holds_another_preshared_key_cannot_open_the_response() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let initiator_key = StaticSecret::random();
        let responder_key = StaticSecret::random();
        let initiator_public = PublicKey::from(&initiator_key);
        let responder_public = PublicKey::from(&responder_key);

        let mut initiator = Handshake::new(
            initiator_key,
            responder_public,
            Some([1u8; KEY_LEN]),
            1,
            Some(sockaddr("192.0.2.2:2222")),
            now,
            wall,
        );
        let mut responder = Handshake::new(
            responder_key,
            initiator_public,
            Some([2u8; KEY_LEN]),
            2,
            Some(sockaddr("192.0.2.1:1111")),
            now,
            wall,
        );

        assert!(matches!(
            run_handshake(&mut initiator, &mut responder, now),
            Err(Error::InvalidAeadTag)
        ));
    }

    #[test]
    fn the_initiator_learns_the_address_that_the_responder_observes() {
        let (mut initiator, mut responder) = handshake_pair(None);
        let observed = sockaddr("198.51.100.7:4242");
        responder.set_peer_sockaddr(observed);

        run_handshake(&mut initiator, &mut responder, Instant::now())
            .expect("the handshake succeeds");

        assert_eq!(initiator.observed_sockaddr(), Some(observed));
    }

    #[test]
    fn a_responder_rejects_a_replayed_initiation() {
        let (mut initiator, mut responder) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        let len = initiator
            .format_initiation(Instant::now(), &mut buffer)
            .expect("the buffer is large enough");
        let replay = buffer;

        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };
        responder
            .consume_initiation(init)
            .expect("the first one is accepted");

        let mut buffer = replay;
        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };
        assert!(matches!(
            responder.consume_initiation(init),
            Err(Error::WrongTai64nTimestamp)
        ));
    }

    #[test]
    fn a_responder_rejects_an_initiation_of_another_peer() {
        let (mut initiator, _) = handshake_pair(None);
        // A third peer that holds the key of neither side.
        let (_, mut responder) = handshake_pair(None);

        let mut buffer = [0u8; 2048];
        let len = initiator
            .format_initiation(Instant::now(), &mut buffer)
            .expect("the buffer is large enough");
        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };
        assert!(matches!(
            responder.consume_initiation(init),
            Err(Error::InvalidMac)
        ));
    }

    #[test]
    fn a_response_to_an_unknown_initiation_is_unexpected() {
        let (mut initiator, mut responder) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        let len = initiator
            .format_initiation(Instant::now(), &mut buffer)
            .expect("the buffer is large enough");
        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };
        responder
            .consume_initiation(init)
            .expect("the initiation is accepted");
        let (len, _) = responder
            .format_response(&mut buffer)
            .expect("the buffer is large enough");

        // Name an initiation that the initiator never sent.
        let Message::HandshakeResp(resp) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake response");
        };
        resp.receiver_idx.set(0xffff_ffff);
        // Repair mac1 over the changed message, so that the test reaches the
        // state machine instead of stopping at the MAC.
        let mac1 = b2s_keyed_mac_16(
            &responder.params.sending_mac1_key,
            &resp.as_bytes()[..len - MAC1_FROM_END],
        );
        resp.as_mut_bytes()[len - MAC1_FROM_END..len - MAC2_FROM_END].copy_from_slice(&mac1);

        let Message::HandshakeResp(resp) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake response");
        };
        assert!(matches!(
            initiator.consume_response(resp),
            Err(Error::UnexpectedPacket)
        ));
    }

    /// Builds the cookie reply that a peer under load would answer the
    /// handshake in `buffer` with.
    fn cookie_reply_for(
        peer_cookie_key: &[u8; KEY_LEN],
        message: &[u8],
        receiver_idx: u32,
        cookie: [u8; COOKIE_LEN],
    ) -> CookieReply {
        let mac1 = &message[message.len() - MAC1_FROM_END..message.len() - MAC2_FROM_END];
        let nonce = [0x11u8; 24];

        let mut reply = CookieReply::new();
        reply.receiver_idx.set(receiver_idx);
        reply.nonce = nonce;
        reply.encrypted_cookie =
            crate::crypto::xaead_seal_cookie(peer_cookie_key, &nonce, cookie, mac1);
        reply
    }

    #[test]
    fn a_cookie_keys_mac2_of_the_next_handshake() {
        let now = Instant::now();
        let (mut initiator, _) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        // Without a cookie, mac2 is zero.
        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        assert_eq!(&buffer[len - MAC2_FROM_END..len], &[0u8; COOKIE_LEN]);
        assert!(!initiator.has_cookie());

        // The remote peer is under load and answers with a cookie.
        let cookie = [0x5au8; COOKIE_LEN];
        let reply = cookie_reply_for(
            &initiator.params.peer_cookie_key,
            &buffer[..len],
            initiator.cookies.index,
            cookie,
        );
        initiator
            .consume_cookie_reply(&reply, now)
            .expect("the cookie opens");
        assert!(initiator.has_cookie());

        // The next handshake carries a mac2 that the cookie keys.
        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        let expected = b2s_keyed_mac_16(&cookie, &buffer[..len - MAC2_FROM_END]);
        assert_eq!(&buffer[len - MAC2_FROM_END..len], &expected);
    }

    #[test]
    fn a_cookie_reply_that_answers_no_handshake_is_unexpected() {
        let now = Instant::now();
        let (mut initiator, _) = handshake_pair(None);

        let reply = CookieReply::new();
        assert!(matches!(
            initiator.consume_cookie_reply(&reply, now),
            Err(Error::UnexpectedPacket)
        ));
    }

    #[test]
    fn a_cookie_reply_for_another_handshake_is_rejected() {
        let now = Instant::now();
        let (mut initiator, _) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        let mut reply = cookie_reply_for(
            &initiator.params.peer_cookie_key,
            &buffer[..len],
            initiator.cookies.index,
            [0x5au8; COOKIE_LEN],
        );
        reply
            .receiver_idx
            .set(initiator.cookies.index.wrapping_add(1));

        assert!(matches!(
            initiator.consume_cookie_reply(&reply, now),
            Err(Error::WrongIndex)
        ));
    }

    #[test]
    fn a_cookie_reply_that_did_not_see_the_handshake_is_rejected() {
        let now = Instant::now();
        let (mut initiator, _) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        // Seal the cookie against a mac1 that belongs to no handshake of this
        // peer, which is what an attacker that did not see the handshake has.
        let mut forged = buffer;
        forged[len - MAC1_FROM_END..len - MAC2_FROM_END].copy_from_slice(&[0xffu8; COOKIE_LEN]);
        let reply = cookie_reply_for(
            &initiator.params.peer_cookie_key,
            &forged[..len],
            initiator.cookies.index,
            [0x5au8; COOKIE_LEN],
        );

        assert!(matches!(
            initiator.consume_cookie_reply(&reply, now),
            Err(Error::InvalidAeadTag)
        ));
    }

    #[test]
    fn a_cookie_expires() {
        let now = Instant::now();
        let (mut initiator, _) = handshake_pair(None);
        let mut buffer = [0u8; 2048];

        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        let reply = cookie_reply_for(
            &initiator.params.peer_cookie_key,
            &buffer[..len],
            initiator.cookies.index,
            [0x5au8; COOKIE_LEN],
        );
        initiator
            .consume_cookie_reply(&reply, now)
            .expect("the cookie opens");

        initiator.expire_cookie(now + COOKIE_EXPIRATION_TIME - Duration::from_secs(1));
        assert!(initiator.has_cookie());
        initiator.expire_cookie(now + COOKIE_EXPIRATION_TIME);
        assert!(!initiator.has_cookie());

        // mac2 is zero again once the cookie is gone.
        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        assert_eq!(&buffer[len - MAC2_FROM_END..len], &[0u8; COOKIE_LEN]);
    }

    #[test]
    fn peer_identity_reads_the_static_key_of_the_initiator() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let initiator_key = StaticSecret::random();
        let responder_key = StaticSecret::random();
        let initiator_public = PublicKey::from(&initiator_key);

        let mut initiator = Handshake::new(
            initiator_key,
            PublicKey::from(&responder_key),
            None,
            1,
            Some(sockaddr("192.0.2.2:2222")),
            now,
            wall,
        );

        let mut buffer = [0u8; 2048];
        let len = initiator
            .format_initiation(now, &mut buffer)
            .expect("the buffer is large enough");
        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };

        let identity = peer_identity(&responder_key, init).expect("the identity opens");
        assert_eq!(&identity.peer_static_public, initiator_public.as_bytes());
        assert_eq!(identity.peer_index, init.sender_idx.get());
    }

    #[test]
    fn peer_identity_rejects_an_initiation_for_another_key() {
        let (mut initiator, _) = handshake_pair(None);
        let mut buffer = [0u8; 2048];
        let len = initiator
            .format_initiation(Instant::now(), &mut buffer)
            .expect("the buffer is large enough");
        let Message::HandshakeInit(init) = parse(&mut buffer[..len]).expect("the message parses")
        else {
            panic!("expected a handshake initiation");
        };

        assert!(matches!(
            peer_identity(&StaticSecret::random(), init),
            Err(Error::InvalidAeadTag)
        ));
    }
}
