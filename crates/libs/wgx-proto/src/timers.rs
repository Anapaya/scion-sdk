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
// This module holds no verbatim region. It follows the timer rules of
// gotatun, but the caller passes the time into every method, so the code
// around each rule differs throughout.

//! The timers of the protocol.
//!
//! The module holds the time at which each event last happened, and it decides
//! what the tunnel must do next. It performs no action itself, and it reads no
//! clock: the caller passes the time into every method.
//!
//! The constants come from section 6.5 of the
//! [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).

use std::{
    ops::{Index, IndexMut},
    time::{Duration, Instant},
};

use crate::tunnel::N_SESSIONS;

/// The initiator starts a new handshake after it sends data on a session of
/// this age.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// A session stops to carry data at this age.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// A peer stops to retry a handshake after this time.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// A peer repeats an initiation that stays unanswered for this time.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// A peer that received data sends a keepalive after this time of silence.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// A peer drops a cookie of this age. The peer that issued it changes the
/// secret that it derives a cookie from at the same period.
pub const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

/// The event whose time the tunnel records.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TimerName {
    /// The time of the last handshake that completed.
    TimeSessionEstablished,
    /// The time at which the last handshake attempt began.
    TimeLastHandshakeStarted,
    /// The time at which this peer last received an authenticated message.
    TimeLastPacketReceived,
    /// The time at which this peer last sent a message.
    TimeLastPacketSent,
    /// The time at which this peer last received an authenticated data
    /// message.
    TimeLastDataPacketReceived,
    /// The time at which this peer last sent a data message.
    TimeLastDataPacketSent,
    /// The time at which this peer last sent a persistent keepalive.
    TimePersistentKeepalive,
    /// The number of timers. It is not an event.
    Top,
}

use TimerName::{
    TimeLastDataPacketReceived, TimeLastDataPacketSent, TimeLastHandshakeStarted,
    TimeLastPacketReceived, TimeLastPacketSent, TimePersistentKeepalive, TimeSessionEstablished,
};

/// The action that the timers ask the tunnel to take.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TimerDecision {
    /// The tunnel has nothing to do.
    Nothing,
    /// The tunnel must send a handshake initiation.
    Handshake,
    /// The tunnel must send a keepalive on the current session.
    Keepalive,
}

/// The time of every event of one tunnel.
#[derive(Debug)]
pub(crate) struct Timers {
    /// True if this peer initiated the handshake of the current session.
    is_initiator: bool,
    /// The time at which the tunnel started. Every other time is a duration
    /// that counts from this instant.
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    /// The time at which each session of the ring was established.
    session_timers: [Duration; N_SESSIONS],
    /// True if this peer received data and sent nothing back.
    want_keepalive: bool,
    /// True if this peer sent data and received nothing back.
    want_handshake: bool,
    persistent_keepalive: Option<u16>,
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl Timers {
    pub(crate) fn new(persistent_keepalive: Option<u16>, now: Instant) -> Self {
        Self {
            is_initiator: false,
            time_started: now,
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: false,
            want_handshake: false,
            persistent_keepalive: persistent_keepalive.filter(|&k| k > 0),
        }
    }

    /// Returns the time that counts from the start of the tunnel.
    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.time_started)
    }

    pub(crate) fn persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }

    pub(crate) fn set_persistent_keepalive(&mut self, seconds: Option<u16>) {
        self.persistent_keepalive = seconds.filter(|&k| k > 0);
        if self.persistent_keepalive.is_none() {
            self[TimePersistentKeepalive] = Duration::ZERO;
        }
    }

    /// Records that the event `timer_name` happened at `now`.
    pub(crate) fn tick(&mut self, timer_name: TimerName, now: Instant) {
        match timer_name {
            TimeLastPacketReceived => {
                self.want_keepalive = true;
                self.want_handshake = false;
            }
            TimeLastPacketSent => {
                self.want_handshake = true;
                self.want_keepalive = false;
            }
            _ => {}
        }
        self[timer_name] = self.elapsed(now);
    }

    /// Records that a handshake established the session at `session_idx`.
    pub(crate) fn tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
        now: Instant,
    ) {
        self.tick(TimeSessionEstablished, now);
        self.session_timers[session_idx % N_SESSIONS] = self.elapsed(now);
        self.is_initiator = is_initiator;
    }

    /// Returns the time at which the session at `session_idx` was
    /// established.
    pub(crate) fn session_time(&self, session_idx: usize) -> Duration {
        self.session_timers[session_idx % N_SESSIONS]
    }

    /// Returns the age of the current session, if the tunnel holds one.
    pub(crate) fn time_since_last_handshake(&self, now: Instant) -> Duration {
        self.elapsed(now)
            .saturating_sub(self[TimeSessionEstablished])
    }

    /// Returns true if the session at `session_idx` is older than
    /// [`REJECT_AFTER_TIME`], and moves the time of that session to `now`.
    ///
    /// The caller drops the session that this reports.
    pub(crate) fn expire_session(&mut self, session_idx: usize, now: Instant) -> bool {
        let elapsed = self.elapsed(now);
        let session_time = &mut self.session_timers[session_idx % N_SESSIONS];
        if elapsed.saturating_sub(*session_time) > REJECT_AFTER_TIME {
            *session_time = elapsed;
            true
        } else {
            false
        }
    }

    /// Returns true if the tunnel held every key for longer than the protocol
    /// allows. The caller must then discard the tunnel.
    pub(crate) fn is_connection_expired(&self, now: Instant) -> bool {
        self.elapsed(now)
            .saturating_sub(self[TimeSessionEstablished])
            >= REJECT_AFTER_TIME * 3
    }

    /// Returns true if the handshake attempt ran for longer than the protocol
    /// allows.
    pub(crate) fn is_handshake_attempt_expired(&self, now: Instant) -> bool {
        self.elapsed(now)
            .saturating_sub(self[TimeLastHandshakeStarted])
            >= REKEY_ATTEMPT_TIME
    }

    /// Decides what the tunnel must do at `now`.
    ///
    /// `time_init_sent` holds the time at which this peer sent the initiation
    /// that is in flight, if one is.
    pub(crate) fn decide(
        &mut self,
        now: Instant,
        time_init_sent: Option<Instant>,
    ) -> TimerDecision {
        let elapsed = self.elapsed(now);

        if let Some(time_init_sent) = time_init_sent {
            // An initiation is in flight. A peer repeats it after
            // REKEY_TIMEOUT, and it sends nothing else until the handshake
            // completes.
            if now.saturating_duration_since(time_init_sent) >= REKEY_TIMEOUT {
                return TimerDecision::Handshake;
            }
            return TimerDecision::Nothing;
        }

        let session_established = self[TimeSessionEstablished];
        let packet_received = self[TimeLastPacketReceived];
        let packet_sent = self[TimeLastPacketSent];
        let data_received = self[TimeLastDataPacketReceived];
        let data_sent = self[TimeLastDataPacketSent];

        if self.is_initiator {
            // After it sends data, the peer that initiated the handshake
            // starts a new one once the session reaches REKEY_AFTER_TIME. The
            // peer that responded does not, which keeps the two peers from
            // initiating at the same time.
            if session_established < data_sent
                && elapsed.saturating_sub(session_established) >= REKEY_AFTER_TIME
            {
                return TimerDecision::Handshake;
            }

            // After it receives data, the peer that initiated the handshake
            // starts a new one in time for the session to stay usable.
            if session_established < data_received
                && elapsed.saturating_sub(session_established)
                    >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
            {
                return TimerDecision::Handshake;
            }
        }

        // The peer sent data and heard nothing back for KEEPALIVE_TIMEOUT +
        // REKEY_TIMEOUT, so it starts a new handshake.
        if data_sent > packet_received
            && elapsed.saturating_sub(packet_received) >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
            && std::mem::replace(&mut self.want_handshake, false)
        {
            return TimerDecision::Handshake;
        }

        // The peer received data and sent nothing back for KEEPALIVE_TIMEOUT,
        // so it sends an empty message.
        if data_received > packet_sent
            && elapsed.saturating_sub(packet_sent) >= KEEPALIVE_TIMEOUT
            && std::mem::replace(&mut self.want_keepalive, false)
        {
            return TimerDecision::Keepalive;
        }

        if let Some(keepalive) = self.persistent_keepalive
            && elapsed.saturating_sub(self[TimePersistentKeepalive])
                >= Duration::from_secs(u64::from(keepalive))
        {
            self.tick(TimePersistentKeepalive, now);
            return TimerDecision::Keepalive;
        }

        TimerDecision::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established(now: Instant, is_initiator: bool) -> Timers {
        let mut timers = Timers::new(None, now);
        timers.tick_session_established(is_initiator, 0, now);
        timers
    }

    #[test]
    fn a_quiet_tunnel_does_nothing() {
        let now = Instant::now();
        let mut timers = established(now, true);
        assert_eq!(timers.decide(now, None), TimerDecision::Nothing);
    }

    #[test]
    fn an_initiation_in_flight_repeats_after_the_rekey_timeout() {
        let now = Instant::now();
        let mut timers = established(now, true);

        assert_eq!(
            timers.decide(now + REKEY_TIMEOUT - Duration::from_secs(1), Some(now)),
            TimerDecision::Nothing
        );
        assert_eq!(
            timers.decide(now + REKEY_TIMEOUT, Some(now)),
            TimerDecision::Handshake
        );
    }

    #[test]
    fn the_initiator_rekeys_after_it_sends_data() {
        let now = Instant::now();
        let mut timers = established(now, true);
        timers.tick(TimeLastDataPacketSent, now + Duration::from_secs(1));

        assert_eq!(
            timers.decide(now + REKEY_AFTER_TIME, None),
            TimerDecision::Handshake
        );
    }

    #[test]
    fn the_responder_waits_longer_than_the_initiator() {
        let now = Instant::now();
        let mut timers = established(now, false);
        timers.tick(TimeLastDataPacketSent, now + Duration::from_secs(1));
        timers.tick(TimeLastPacketReceived, now + Duration::from_secs(1));

        // The responder does not rekey at REKEY_AFTER_TIME, which leaves the
        // rekey to the initiator.
        assert_eq!(
            timers.decide(now + REKEY_AFTER_TIME, None),
            TimerDecision::Nothing
        );
    }

    #[test]
    fn a_peer_that_hears_nothing_back_starts_a_handshake() {
        let start = Instant::now();
        let mut timers = established(start, false);

        // The peer sends data and never hears back.
        let sent = start + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
        timers.tick(TimeLastDataPacketSent, sent);
        timers.tick(TimeLastPacketSent, sent);

        assert_eq!(timers.decide(sent, None), TimerDecision::Handshake);
    }

    #[test]
    fn a_peer_that_only_receives_sends_a_keepalive() {
        let start = Instant::now();
        let mut timers = established(start, false);

        // The peer receives data and sends nothing back.
        let received = start + KEEPALIVE_TIMEOUT;
        timers.tick(TimeLastDataPacketReceived, received);
        timers.tick(TimeLastPacketReceived, received);

        assert_eq!(timers.decide(received, None), TimerDecision::Keepalive);
        // The decision fires once for one silence.
        assert_eq!(timers.decide(received, None), TimerDecision::Nothing);
    }

    #[test]
    fn a_persistent_keepalive_repeats() {
        let now = Instant::now();
        let mut timers = Timers::new(Some(25), now);
        timers.tick_session_established(false, 0, now);

        assert_eq!(
            timers.decide(now + Duration::from_secs(24), None),
            TimerDecision::Nothing
        );
        assert_eq!(
            timers.decide(now + Duration::from_secs(25), None),
            TimerDecision::Keepalive
        );
        assert_eq!(
            timers.decide(now + Duration::from_secs(49), None),
            TimerDecision::Nothing
        );
        assert_eq!(
            timers.decide(now + Duration::from_secs(50), None),
            TimerDecision::Keepalive
        );
    }

    #[test]
    fn a_time_before_the_last_event_does_not_panic() {
        let start = Instant::now();
        let mut timers = Timers::new(None, start);
        let later = start + Duration::from_secs(60);
        timers.tick_session_established(true, 0, later);
        timers.tick(TimeLastDataPacketSent, later);
        timers.tick(TimeLastDataPacketReceived, later);
        timers.tick(TimeLastPacketSent, later);
        timers.tick(TimeLastPacketReceived, later);

        let earlier = start + Duration::from_secs(30);
        assert_eq!(timers.time_since_last_handshake(earlier), Duration::ZERO);
        assert_eq!(timers.decide(earlier, None), TimerDecision::Nothing);
    }

    #[test]
    fn a_session_expires_after_the_reject_time() {
        let now = Instant::now();
        let mut timers = established(now, true);

        assert!(!timers.expire_session(0, now + REJECT_AFTER_TIME));
        assert!(timers.expire_session(0, now + REJECT_AFTER_TIME + Duration::from_secs(1)));
        // The expiry moves the time of the session, so it fires once.
        assert!(!timers.expire_session(0, now + REJECT_AFTER_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn a_connection_expires_after_three_reject_times() {
        let now = Instant::now();
        let timers = established(now, true);

        assert!(!timers.is_connection_expired(now + REJECT_AFTER_TIME * 2));
        assert!(timers.is_connection_expired(now + REJECT_AFTER_TIME * 3));
    }

    #[test]
    fn a_handshake_attempt_expires_after_the_attempt_time() {
        let now = Instant::now();
        let mut timers = Timers::new(None, now);
        timers.tick(TimeLastHandshakeStarted, now);

        assert!(
            !timers.is_handshake_attempt_expired(now + REKEY_ATTEMPT_TIME - Duration::from_secs(1))
        );
        assert!(timers.is_handshake_attempt_expired(now + REKEY_ATTEMPT_TIME));
    }
}
