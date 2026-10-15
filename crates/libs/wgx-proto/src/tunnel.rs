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
// This module holds no verbatim region. It is the sans-io façade of this
// crate, which gotatun has no counterpart for.

//! The state machine of one tunnel.

use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime},
};

use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use crate::{
    error::Error,
    handshake::Handshake,
    session::Session,
    timers::{TimerDecision, TimerName, Timers},
    wire::{DataHeader, HandshakeInit, Message, WireSocketAddr, parse},
};

/// The number of sessions that a tunnel keeps. The protocol needs three, and a
/// power of two keeps the index arithmetic cheap.
pub(crate) const N_SESSIONS: usize = 8;

/// The offset at which the payload of a data message starts.
///
/// A caller writes the payload that [`TunnelState::send_to_net`] encrypts at
/// this offset, and reads the payload that [`TunnelState::recv_from_net`]
/// decrypted at the same offset.
pub const PAYLOAD_OFFSET: usize = DataHeader::LEN;

/// The number of bytes that a data message adds to the payload.
pub const DATA_OVERHEAD: usize = crate::wire::Data::OVERHEAD;

/// The configuration of one tunnel.
pub struct TunnelConfig {
    /// The static private key of this peer.
    pub static_private: StaticSecret,
    /// The static public key of the remote peer.
    pub peer_static_public: PublicKey,
    /// The optional pre-shared key that both peers hold.
    pub preshared_key: Option<[u8; 32]>,
    /// The socket address of the remote peer, as this peer observes it.
    ///
    /// With an address, a handshake response carries it, so the remote peer
    /// learns the address that this peer sees. `None` keeps the response in
    /// the form of WireGuard, which makes the tunnel compatible with a
    /// WireGuard peer, until [`TunnelState::set_peer_sockaddr`] gives the
    /// tunnel an address. See [`TunnelState`].
    pub peer_sockaddr: Option<SocketAddr>,
    /// The index of this tunnel. The peer writes it into the upper 24 bits of
    /// every session index, so one peer can hold 16M tunnels that no index
    /// collides in.
    pub index: u32,
    /// The period at which this peer sends a keepalive, even when it has no
    /// data to send. A peer behind a NAT needs it to keep the mapping.
    pub persistent_keepalive: Option<u16>,
}

/// The action that [`TunnelState::recv_from_net`] asks the caller to take.
#[derive(Debug, PartialEq, Eq)]
pub enum RecvAction {
    /// The message needed no action.
    Nothing,
    /// The buffer holds the payload of the peer at `offset`, for `len` bytes.
    Data {
        /// The offset of the payload in the buffer.
        offset: u16,
        /// The length of the payload, in bytes.
        len: u16,
    },
    /// The first `len` bytes of the buffer hold a message for the peer.
    Send {
        /// The length of the message, in bytes.
        len: u16,
    },
}

/// The action that [`TunnelState::send_to_net`] asks the caller to take.
#[derive(Debug, PartialEq, Eq)]
pub enum SendAction {
    /// The first `len` bytes of the buffer hold a message for the peer.
    Send {
        /// The length of the message, in bytes.
        len: u16,
    },
    /// The tunnel holds no session and starts none by itself. The buffer
    /// still holds the payload of the caller, which the caller keeps until a
    /// session exists. The caller starts the handshake with
    /// [`TunnelState::initiate_session`].
    InitiateSession,
    /// The tunnel holds no session, and a handshake is already in flight. The
    /// buffer still holds the payload of the caller.
    Wait,
}

/// The action that [`TunnelState::update_timers`] asks the caller to take.
#[derive(Debug, PartialEq, Eq)]
pub enum TimerAction {
    /// The tunnel has nothing to do.
    Nothing,
    /// The first `len` bytes of the buffer hold a message for the peer.
    Send {
        /// The length of the message, in bytes.
        len: u16,
    },
    /// The tunnel has to start a handshake. The buffer is unchanged. The
    /// caller starts the handshake with [`TunnelState::initiate_session`].
    InitiateSession,
}

/// The state machine of one point-to-point tunnel.
///
/// The tunnel reads no clock and owns no buffer. Every method takes the
/// current time and the buffer that holds the message.
///
/// # Compatibility with WireGuard
///
/// Without [`TunnelConfig::peer_sockaddr`], the tunnel speaks the protocol of
/// WireGuard, so it can carry a tunnel with a WireGuard peer. With an address,
/// the handshake response that this tunnel sends carries that address, and
/// only a peer of this protocol reads it. The tunnel takes either form of the
/// response whatever it holds itself, so an initiator needs no configuration
/// to match the responder.
///
/// # How to use
///
/// ```text
/// let mut tunnel = TunnelState::new(config, Instant::now(), SystemTime::now());
/// loop {
///   select {
///     len = socket.recv(&mut buffer) => {
///       match tunnel.recv_from_net(Instant::now(), &mut buffer[..len])? {
///         RecvAction::Data { offset, len } => deliver(&buffer[offset..offset + len]),
///         RecvAction::Send { len } => socket.send(&buffer[..len]),
///         RecvAction::Nothing => {}
///       }
///     }
///     payload = application.recv(&mut buffer[PAYLOAD_OFFSET..]) => {
///       match tunnel.send_to_net(Instant::now(), &mut buffer, payload.len())? {
///         SendAction::Send { len } => socket.send(&buffer[..len]),
///         SendAction::InitiateSession => {
///           queue(payload);
///           socket.send(tunnel.initiate_session(Instant::now())?)
///         }
///         SendAction::Wait => queue(payload),
///       }
///     }
///     _ = tick(250ms) => {
///       match tunnel.update_timers(Instant::now(), &mut buffer)? { /* as above */ }
///     }
///   }
/// }
/// ```
pub struct TunnelState {
    handshake: Handshake,
    /// The sessions, indexed by the session index modulo [`N_SESSIONS`].
    sessions: [Option<Session>; N_SESSIONS],
    /// The index of the session that the tunnel sends on.
    current: usize,
    timers: Timers,
    /// The last initiation that [`TunnelState::initiate_session`] wrote. The
    /// tunnel owns it, because the buffer of the caller still holds the
    /// payload that waits for a session.
    initiation: HandshakeInit,
}

impl TunnelState {
    /// Builds a tunnel.
    ///
    /// `now` is the monotonic clock. `wall_clock` seeds the timestamp of the
    /// handshake, which protects the remote peer against a replay across a
    /// restart of this peer.
    #[must_use]
    pub fn new(config: TunnelConfig, now: Instant, wall_clock: SystemTime) -> Self {
        Self {
            handshake: Handshake::new(
                config.static_private,
                config.peer_static_public,
                config.preshared_key,
                config.index,
                config.peer_sockaddr.map(WireSocketAddr::from),
                now,
                wall_clock,
            ),
            sessions: Default::default(),
            current: 0,
            timers: Timers::new(config.persistent_keepalive, now),
            initiation: HandshakeInit::new(),
        }
    }

    /// Returns the static public key of the remote peer.
    #[must_use]
    pub fn peer_static_public(&self) -> &PublicKey {
        self.handshake.peer_static_public()
    }

    /// Returns the socket address of this peer, as the remote peer observed it
    /// during the last handshake that this peer initiated.
    ///
    /// The address is the answer of the remote peer to the question that a
    /// STUN request asks. It stays `None` while the remote peer answers in
    /// the form of WireGuard, which carries no address.
    #[must_use]
    pub fn observed_sockaddr(&self) -> Option<SocketAddr> {
        self.handshake
            .observed_sockaddr()
            .and_then(|addr| SocketAddr::try_from(addr).ok())
    }

    /// Sets the socket address of the remote peer that the next handshake
    /// response carries.
    ///
    /// A tunnel that [`TunnelConfig::peer_sockaddr`] left unset answers in
    /// the form of WireGuard until this call. There is no way back: a peer
    /// that learns the address of its remote peer does not lose it again.
    pub fn set_peer_sockaddr(&mut self, peer_sockaddr: SocketAddr) {
        self.handshake
            .set_peer_sockaddr(WireSocketAddr::from(peer_sockaddr));
    }

    /// Returns the period of the persistent keepalive.
    #[must_use]
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.timers.persistent_keepalive()
    }

    /// Sets the period of the persistent keepalive.
    pub fn set_persistent_keepalive(&mut self, seconds: Option<u16>) {
        self.timers.set_persistent_keepalive(seconds);
    }

    /// Returns true if the tunnel gave up. The caller must discard it.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Returns the age of the current session, if the tunnel holds one.
    #[must_use]
    pub fn time_since_last_handshake(&self, now: Instant) -> Option<Duration> {
        self.sessions[self.current % N_SESSIONS]
            .as_ref()
            .map(|_| self.timers.time_since_last_handshake(now))
    }

    /// Handles a message that arrived from the network.
    ///
    /// `buffer` holds exactly the message. The method decrypts in the buffer,
    /// and it writes a message for the peer into the same buffer.
    pub fn recv_from_net(&mut self, now: Instant, buffer: &mut [u8]) -> Result<RecvAction, Error> {
        match parse(buffer)? {
            Message::HandshakeInit(init) => {
                self.handshake.consume_initiation(init)?;
                self.handle_initiation(now, buffer)
            }
            Message::HandshakeResp(resp) => {
                let session = self.handshake.consume_response(resp)?;
                self.handle_response(now, session, buffer)
            }
            Message::Data(data) => {
                let session_idx = data.header.receiver_idx.get() as usize;
                let session = self.sessions[session_idx % N_SESSIONS]
                    .as_mut()
                    .ok_or(Error::NoCurrentSession)?;
                let len = session.decrypt(data)?;

                self.set_current_session(session_idx);
                self.timers.tick(TimerName::TimeLastPacketReceived, now);
                if len > 0 {
                    self.timers.tick(TimerName::TimeLastDataPacketReceived, now);
                }

                Ok(RecvAction::Data {
                    offset: PAYLOAD_OFFSET as u16,
                    len: u16::try_from(len).map_err(|_| Error::IncorrectPacketLength)?,
                })
            }
            // A cookie reply carries no payload and asks for no answer. It
            // keys `mac2` of the next handshake, which the retransmission
            // timer sends.
            Message::CookieReply(reply) => {
                self.handshake.consume_cookie_reply(reply, now)?;
                Ok(RecvAction::Nothing)
            }
        }
    }

    /// Answers a handshake initiation that the handshake already consumed.
    fn handle_initiation(&mut self, now: Instant, buffer: &mut [u8]) -> Result<RecvAction, Error> {
        let (len, session) = self.handshake.format_response(buffer)?;

        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        // This peer responded, so it is not the initiator of the session.
        self.timers.tick_session_established(false, index, now);

        Ok(RecvAction::Send { len: len as u16 })
    }

    /// Completes a handshake that this peer initiated, and answers with a
    /// keepalive.
    ///
    /// The keepalive tells the responder that the session works, which lets
    /// the responder send data on it.
    fn handle_response(
        &mut self,
        now: Instant,
        mut session: Session,
        buffer: &mut [u8],
    ) -> Result<RecvAction, Error> {
        let len = session.encrypt(buffer, 0)?;

        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timers.tick(TimerName::TimeLastPacketReceived, now);
        self.timers.tick(TimerName::TimeLastPacketSent, now);
        // This peer sent the initiation, so it is the initiator of the
        // session. Only the initiator starts the next handshake.
        self.timers.tick_session_established(true, index, now);
        self.set_current_session(index);

        Ok(RecvAction::Send { len: len as u16 })
    }

    /// Encrypts the payload that sits at [`PAYLOAD_OFFSET`] of `buffer`.
    ///
    /// `buffer` must hold `PAYLOAD_OFFSET + payload_len + 16` bytes. The
    /// method leaves the buffer unchanged if the tunnel holds no session.
    pub fn send_to_net(
        &mut self,
        now: Instant,
        buffer: &mut [u8],
        payload_len: u16,
    ) -> Result<SendAction, Error> {
        let Some(session) = self.sessions[self.current % N_SESSIONS].as_mut() else {
            // A handshake changes the state of the tunnel, so the caller asks
            // for it in a call of its own.
            return Ok(if self.handshake.is_in_progress() {
                SendAction::Wait
            } else {
                SendAction::InitiateSession
            });
        };

        let len = session.encrypt(buffer, usize::from(payload_len))?;

        self.timers.tick(TimerName::TimeLastPacketSent, now);
        if payload_len > 0 {
            self.timers.tick(TimerName::TimeLastDataPacketSent, now);
        }

        Ok(SendAction::Send { len: len as u16 })
    }

    /// Drives the timers of the tunnel.
    ///
    /// The caller must call this at a period that is shorter than
    /// [`REKEY_TIMEOUT`](crate::timers::REKEY_TIMEOUT). The method writes a
    /// keepalive into `buffer` when it returns [`TimerAction::Send`].
    pub fn update_timers(&mut self, now: Instant, buffer: &mut [u8]) -> Result<TimerAction, Error> {
        if self.handshake.is_expired() {
            return Err(Error::ConnectionExpired);
        }

        self.handshake.expire_cookie(now);

        for index in 0..N_SESSIONS {
            if self.sessions[index].is_some() && self.timers.expire_session(index, now) {
                self.sessions[index] = None;
            }
        }

        // The protocol zeroes every key after three reject times without a new
        // handshake.
        if self.timers.is_connection_expired(now) {
            self.expire();
            return Err(Error::ConnectionExpired);
        }

        // A peer stops to retry a handshake after the attempt time.
        if self.handshake.time_init_sent().is_some()
            && self.timers.is_handshake_attempt_expired(now)
        {
            self.expire();
            return Err(Error::ConnectionExpired);
        }

        match self.timers.decide(now, self.handshake.time_init_sent()) {
            TimerDecision::Nothing => Ok(TimerAction::Nothing),
            TimerDecision::Handshake => Ok(TimerAction::InitiateSession),
            TimerDecision::Keepalive => {
                let Some(session) = self.sessions[self.current % N_SESSIONS].as_mut() else {
                    // A peer behind a NAT needs the keepalive to keep the
                    // mapping, so it starts a handshake for a new session.
                    return Ok(TimerAction::InitiateSession);
                };
                let len = session.encrypt(buffer, 0)?;
                self.timers.tick(TimerName::TimeLastPacketSent, now);
                Ok(TimerAction::Send { len: len as u16 })
            }
        }
    }

    /// Starts a handshake, and returns the initiation to send.
    ///
    /// [`SendAction::InitiateSession`] and [`TimerAction::InitiateSession`]
    /// ask for this call. It writes the initiation into the tunnel, and the
    /// returned slice borrows it, so the bytes belong to this call and to no
    /// other.
    ///
    /// The call always starts a handshake, even while one is in flight, which
    /// is what a timeout of an initiation needs.
    pub fn initiate_session(&mut self, now: Instant) -> Result<&[u8], Error> {
        if self.handshake.is_expired() {
            return Err(Error::ConnectionExpired);
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        self.handshake
            .format_initiation(now, self.initiation.as_mut_bytes())?;

        if starting_new_handshake {
            self.timers.tick(TimerName::TimeLastHandshakeStarted, now);
        }
        self.timers.tick(TimerName::TimeLastPacketSent, now);

        Ok(self.initiation.as_bytes())
    }

    /// Discards every key of the tunnel.
    fn expire(&mut self) {
        self.handshake.set_expired();
        for session in &mut self.sessions {
            *session = None;
        }
    }

    /// Moves the tunnel onto a newer session, if `new_idx` names one.
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_time(new_idx) >= self.timers.session_time(cur_idx)
        {
            self.current = new_idx;
        }
    }
}
