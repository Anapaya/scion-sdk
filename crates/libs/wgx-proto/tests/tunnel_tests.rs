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

//! Tests that drive two tunnels through the public API.

use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime},
};

use wgx_proto::{
    Error, PAYLOAD_OFFSET, RecvAction, SendAction, TimerAction, TunnelConfig, TunnelState,
    timers::{KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT},
};
use x25519_dalek::{PublicKey, StaticSecret};

const MTU: usize = 1500;

/// The two ends of one tunnel, and the buffer that each end reads and writes.
struct Pair {
    initiator: TunnelState,
    responder: TunnelState,
    buffer: [u8; MTU],
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("the address parses")
}

impl Pair {
    /// Returns a pair whose responder carries the address of the initiator,
    /// which is the form of this protocol.
    fn new(now: Instant, persistent_keepalive: Option<u16>) -> Self {
        Self::with_sockaddrs(
            now,
            persistent_keepalive,
            Some(addr("192.0.2.2:2222")),
            Some(addr("192.0.2.1:1111")),
        )
    }

    /// Returns a pair that holds no address, which is the form of WireGuard.
    fn plain(now: Instant) -> Self {
        Self::with_sockaddrs(now, None, None, None)
    }

    fn with_sockaddrs(
        now: Instant,
        persistent_keepalive: Option<u16>,
        initiator_peer: Option<SocketAddr>,
        responder_peer: Option<SocketAddr>,
    ) -> Self {
        let initiator_key = StaticSecret::random();
        let responder_key = StaticSecret::random();
        let initiator_public = PublicKey::from(&initiator_key);
        let responder_public = PublicKey::from(&responder_key);
        let wall_clock = SystemTime::now();

        Self {
            initiator: TunnelState::new(
                TunnelConfig {
                    static_private: initiator_key,
                    peer_static_public: responder_public,
                    preshared_key: None,
                    peer_sockaddr: initiator_peer,
                    index: 1,
                    persistent_keepalive,
                },
                now,
                wall_clock,
            ),
            responder: TunnelState::new(
                TunnelConfig {
                    static_private: responder_key,
                    peer_static_public: initiator_public,
                    preshared_key: None,
                    peer_sockaddr: responder_peer,
                    index: 2,
                    persistent_keepalive,
                },
                now,
                wall_clock,
            ),
            buffer: [0u8; MTU],
        }
    }

    /// Runs a handshake, and leaves both ends with a session.
    fn handshake(&mut self, now: Instant) {
        let init = self.start_handshake(now);
        self.complete_handshake(now, &init);
    }

    /// Asks the initiator for a handshake initiation.
    fn start_handshake(&mut self, now: Instant) -> Vec<u8> {
        assert_eq!(
            self.initiator
                .send_to_net(now, &mut self.buffer, 0)
                .expect("the send succeeds"),
            SendAction::InitiateSession
        );
        self.initiator
            .initiate_session(now)
            .expect("the initiation succeeds")
            .to_vec()
    }

    /// Carries an initiation and its answers between the two ends.
    fn complete_handshake(&mut self, now: Instant, init: &[u8]) {
        self.buffer[..init.len()].copy_from_slice(init);
        let mut len = init.len();

        let RecvAction::Send { len: resp_len } = self
            .responder
            .recv_from_net(now, &mut self.buffer[..len])
            .expect("the responder answers the initiation")
        else {
            panic!("expected a handshake response");
        };
        len = usize::from(resp_len);

        let RecvAction::Send { len: keepalive_len } = self
            .initiator
            .recv_from_net(now, &mut self.buffer[..len])
            .expect("the initiator answers the response")
        else {
            panic!("expected a keepalive");
        };
        len = usize::from(keepalive_len);

        let RecvAction::Data { len: 0, .. } = self
            .responder
            .recv_from_net(now, &mut self.buffer[..len])
            .expect("the responder takes the keepalive")
        else {
            panic!("expected an empty payload");
        };
    }

    /// Sends `payload` from one end to the other, and returns what arrived.
    fn send(&mut self, now: Instant, from_initiator: bool, payload: &[u8]) -> Vec<u8> {
        let (sender, receiver) = if from_initiator {
            (&mut self.initiator, &mut self.responder)
        } else {
            (&mut self.responder, &mut self.initiator)
        };

        self.buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
        let SendAction::Send { len } = sender
            .send_to_net(
                now,
                &mut self.buffer,
                u16::try_from(payload.len()).expect("the payload fits"),
            )
            .expect("the session carries the payload")
        else {
            panic!("expected a data message");
        };

        let RecvAction::Data { offset, len } = receiver
            .recv_from_net(now, &mut self.buffer[..usize::from(len)])
            .expect("the message opens")
        else {
            panic!("expected a payload");
        };

        self.buffer[usize::from(offset)..usize::from(offset) + usize::from(len)].to_vec()
    }
}

/// Builds the cookie reply that a peer under load answers `handshake` with.
///
/// The test plays that peer, because this crate implements no rate limiting
/// and therefore never sends a cookie reply itself.
fn cookie_reply(peer_static_public: &PublicKey, handshake: &[u8], cookie: [u8; 16]) -> Vec<u8> {
    use blake2::{Blake2s256, Digest};
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305,
        aead::{AeadInPlace, generic_array::GenericArray},
    };

    let receiver_idx: [u8; 4] = handshake[4..8].try_into().expect("the slice holds 4 bytes");
    let mac1 = &handshake[handshake.len() - 32..handshake.len() - 16];
    let nonce = [0x11u8; 24];

    let mut hash = Blake2s256::new();
    hash.update(b"cookie--");
    hash.update(peer_static_public.as_bytes());
    let key: [u8; 32] = hash.finalize().into();

    let mut encrypted = cookie;
    let tag = XChaCha20Poly1305::new(GenericArray::from_slice(&key))
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), mac1, &mut encrypted)
        .expect("the encryption succeeds");

    let mut reply = Vec::with_capacity(64);
    reply.extend_from_slice(&[3, 0, 0, 0]);
    reply.extend_from_slice(&receiver_idx);
    reply.extend_from_slice(&nonce);
    reply.extend_from_slice(&encrypted);
    reply.extend_from_slice(&tag);
    assert_eq!(reply.len(), 64);
    reply
}

#[test]
fn a_peer_under_load_can_still_complete_a_handshake() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);

    // The initiator sends a handshake that carries no mac2.
    let init = pair.start_handshake(now);
    assert_eq!(&init[init.len() - 16..], &[0u8; 16]);

    // The remote peer is under load, so it answers with a cookie instead of
    // processing the handshake.
    let reply = cookie_reply(pair.initiator.peer_static_public(), &init, [0x5a; 16]);
    pair.buffer[..reply.len()].copy_from_slice(&reply);
    assert!(matches!(
        pair.initiator
            .recv_from_net(now, &mut pair.buffer[..reply.len()]),
        Ok(RecvAction::Nothing)
    ));

    // The retransmission carries a mac2 that the cookie keys, which the loaded
    // peer accepts.
    let later = now + REKEY_TIMEOUT;
    assert_eq!(
        pair.initiator
            .update_timers(later, &mut pair.buffer)
            .expect("the timers run"),
        TimerAction::InitiateSession
    );
    let retry = pair
        .initiator
        .initiate_session(later)
        .expect("the initiation succeeds")
        .to_vec();
    assert_ne!(&retry[retry.len() - 16..], &[0u8; 16]);

    // The handshake completes, which proves that the cookie did not disturb
    // the rest of the message.
    pair.complete_handshake(later, &retry);
    assert_eq!(
        pair.send(later, true, b"through a cookie"),
        b"through a cookie"
    );
}

#[test]
fn a_cookie_reply_that_answers_no_handshake_is_rejected() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);

    let mut reply = [0u8; 64];
    reply[0] = 3;
    pair.buffer[..reply.len()].copy_from_slice(&reply);
    assert!(matches!(
        pair.initiator
            .recv_from_net(now, &mut pair.buffer[..reply.len()]),
        Err(Error::UnexpectedPacket)
    ));
}

/// Returns the length of the response that the responder answers `init` with.
fn respond_to(pair: &mut Pair, now: Instant, init: &[u8]) -> usize {
    assert_eq!(init.len(), 148, "the initiation is the same in both forms");
    pair.buffer[..init.len()].copy_from_slice(init);

    let RecvAction::Send { len } = pair
        .responder
        .recv_from_net(now, &mut pair.buffer[..init.len()])
        .expect("the responder answers")
    else {
        panic!("expected a handshake response");
    };
    usize::from(len)
}

/// Starts a handshake and returns the length of the response.
fn response_len(pair: &mut Pair, now: Instant) -> usize {
    let init = pair.start_handshake(now);
    respond_to(pair, now, &init)
}

#[test]
fn a_responder_without_an_address_answers_in_the_form_of_wireguard() {
    let now = Instant::now();
    let mut pair = Pair::plain(now);
    assert_eq!(response_len(&mut pair, now), 92);
}

#[test]
fn a_responder_with_an_address_answers_in_the_form_of_this_protocol() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    assert_eq!(response_len(&mut pair, now), 112);
}

#[test]
fn a_tunnel_without_an_address_carries_data_both_ways() {
    let now = Instant::now();
    let mut pair = Pair::plain(now);
    pair.handshake(now);

    assert_eq!(pair.initiator.observed_sockaddr(), None);
    assert_eq!(
        pair.send(now, true, b"from the initiator"),
        b"from the initiator"
    );
    assert_eq!(
        pair.send(now, false, b"from the responder"),
        b"from the responder"
    );
}

#[test]
fn an_initiator_takes_either_form_whatever_it_holds_itself() {
    // The address of a peer configures what this peer sends as a responder.
    // It must not decide what this peer accepts as an initiator, so both
    // mixtures have to complete.
    for (initiator_peer, responder_peer, expected) in [
        (Some(addr("192.0.2.2:2222")), None, None),
        (
            None,
            Some(addr("198.51.100.7:4242")),
            Some(addr("198.51.100.7:4242")),
        ),
    ] {
        let now = Instant::now();
        let mut pair = Pair::with_sockaddrs(now, None, initiator_peer, responder_peer);
        pair.handshake(now);

        assert_eq!(pair.initiator.observed_sockaddr(), expected);
        assert_eq!(pair.send(now, true, b"either form"), b"either form");
    }
}

#[test]
fn a_responder_takes_an_address_after_it_is_built() {
    let now = Instant::now();
    let mut pair = Pair::plain(now);
    assert_eq!(response_len(&mut pair, now), 92);

    pair.responder.set_peer_sockaddr(addr("198.51.100.7:4242"));

    // The initiator still has that initiation in flight, so the next one
    // comes from the retransmission timer.
    let later = now + REKEY_TIMEOUT;
    assert_eq!(
        pair.initiator
            .update_timers(later, &mut pair.buffer)
            .expect("the timers run"),
        TimerAction::InitiateSession
    );
    let init = pair
        .initiator
        .initiate_session(later)
        .expect("the initiation succeeds")
        .to_vec();
    assert_eq!(respond_to(&mut pair, later, &init), 112);
}

#[test]
fn a_response_of_another_length_is_rejected() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);

    // A length between the two forms belongs to neither.
    let mut reply = [0u8; 100];
    reply[0] = 2;
    pair.buffer[..reply.len()].copy_from_slice(&reply);
    assert!(matches!(
        pair.initiator
            .recv_from_net(now, &mut pair.buffer[..reply.len()]),
        Err(Error::Parse(_))
    ));
}

#[test]
fn a_handshake_lets_both_ends_carry_data() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    assert_eq!(
        pair.send(now, true, b"from the initiator"),
        b"from the initiator"
    );
    assert_eq!(
        pair.send(now, false, b"from the responder"),
        b"from the responder"
    );
}

#[test]
fn a_payload_of_the_full_mtu_survives() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    let payload = vec![0xab; MTU - wgx_proto::DATA_OVERHEAD];
    assert_eq!(pair.send(now, true, &payload), payload);
}

#[test]
fn the_second_send_waits_while_the_handshake_is_in_flight() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);

    assert_eq!(
        pair.initiator.send_to_net(now, &mut pair.buffer, 0),
        Ok(SendAction::InitiateSession)
    );
    pair.initiator
        .initiate_session(now)
        .expect("the initiation succeeds");

    // With that initiation in flight, the tunnel asks the caller to wait
    // rather than to start a second one.
    assert_eq!(
        pair.initiator.send_to_net(now, &mut pair.buffer, 0),
        Ok(SendAction::Wait)
    );
}

#[test]
fn an_unanswered_initiation_repeats_after_the_rekey_timeout() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);

    pair.start_handshake(now);

    assert_eq!(
        pair.initiator.update_timers(
            now + REKEY_TIMEOUT - Duration::from_secs(1),
            &mut pair.buffer
        ),
        Ok(TimerAction::Nothing)
    );
    assert_eq!(
        pair.initiator
            .update_timers(now + REKEY_TIMEOUT, &mut pair.buffer),
        Ok(TimerAction::InitiateSession)
    );
}

#[test]
fn the_initiator_starts_a_new_handshake_after_the_rekey_time() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);
    // The send has to follow the handshake in time: the timer compares the
    // instant of the last data message with the instant of the session.
    let sent = now + Duration::from_secs(1);
    pair.send(sent, true, b"a payload");

    // The responder answers the silence with a keepalive, which leaves it
    // with nothing to do afterwards.
    let TimerAction::Send { len } = pair
        .responder
        .update_timers(sent + KEEPALIVE_TIMEOUT, &mut pair.buffer)
        .expect("the timers run")
    else {
        panic!("expected a keepalive");
    };
    pair.initiator
        .recv_from_net(
            sent + KEEPALIVE_TIMEOUT,
            &mut pair.buffer[..usize::from(len)],
        )
        .expect("the keepalive opens");

    let later = now + REKEY_AFTER_TIME;
    // Only the initiator of the session rekeys on that timer. The responder
    // waits, which keeps the two ends from initiating at the same time.
    assert_eq!(
        pair.responder.update_timers(later, &mut pair.buffer),
        Ok(TimerAction::Nothing)
    );
    assert_eq!(
        pair.initiator.update_timers(later, &mut pair.buffer),
        Ok(TimerAction::InitiateSession)
    );
}

#[test]
fn a_peer_that_only_receives_sends_a_keepalive() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);
    let sent = now + Duration::from_secs(1);
    pair.send(sent, true, b"a payload");

    let later = sent + KEEPALIVE_TIMEOUT;
    let TimerAction::Send { len } = pair
        .responder
        .update_timers(later, &mut pair.buffer)
        .expect("the timers run")
    else {
        panic!("expected a keepalive");
    };

    let RecvAction::Data { len: 0, .. } = pair
        .initiator
        .recv_from_net(later, &mut pair.buffer[..usize::from(len)])
        .expect("the keepalive opens")
    else {
        panic!("expected an empty payload");
    };
}

#[test]
fn a_persistent_keepalive_fires_without_traffic() {
    let now = Instant::now();
    let mut pair = Pair::new(now, Some(25));
    pair.handshake(now);

    assert!(matches!(
        pair.responder
            .update_timers(now + Duration::from_secs(24), &mut pair.buffer),
        Ok(TimerAction::Nothing)
    ));
    assert!(matches!(
        pair.responder
            .update_timers(now + Duration::from_secs(25), &mut pair.buffer),
        Ok(TimerAction::Send { .. })
    ));
}

#[test]
fn a_persistent_keepalive_without_a_session_starts_a_handshake() {
    let now = Instant::now();
    let mut pair = Pair::new(now, Some(25));
    pair.handshake(now);

    // The session expires, and the next persistent keepalive needs a new one.
    let later = now + REJECT_AFTER_TIME + Duration::from_secs(1);
    assert!(matches!(
        pair.initiator.update_timers(later, &mut pair.buffer),
        Ok(TimerAction::InitiateSession)
    ));
}

#[test]
fn a_session_stops_to_carry_data_after_the_reject_time() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    let later = now + REJECT_AFTER_TIME + Duration::from_secs(1);
    pair.responder
        .update_timers(later, &mut pair.buffer)
        .expect("the timers run");

    // The session is gone, so the next payload starts a handshake instead.
    assert_eq!(
        pair.responder.send_to_net(later, &mut pair.buffer, 4),
        Ok(SendAction::InitiateSession)
    );
}

#[test]
fn a_tunnel_that_hears_nothing_expires() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    let later = now + REJECT_AFTER_TIME * 3;
    assert!(matches!(
        pair.initiator.update_timers(later, &mut pair.buffer),
        Err(Error::ConnectionExpired)
    ));
    assert!(pair.initiator.is_expired());
}

#[test]
fn the_initiator_learns_the_address_that_the_responder_observes() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    let observed = addr("198.51.100.7:4242");
    pair.responder.set_peer_sockaddr(observed);

    assert_eq!(pair.initiator.observed_sockaddr(), None);
    pair.handshake(now);
    assert_eq!(pair.initiator.observed_sockaddr(), Some(observed));
}

#[test]
fn a_replayed_data_message_is_rejected() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    let payload = b"a payload";
    pair.buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
    let SendAction::Send { len } = pair
        .initiator
        .send_to_net(now, &mut pair.buffer, 9)
        .expect("the session carries the payload")
    else {
        panic!("expected a data message");
    };
    let len = usize::from(len);
    let message = pair.buffer;

    pair.responder
        .recv_from_net(now, &mut pair.buffer[..len])
        .expect("the message opens");

    pair.buffer = message;
    assert!(matches!(
        pair.responder.recv_from_net(now, &mut pair.buffer[..len]),
        Err(Error::DuplicateCounter)
    ));
}

#[test]
fn a_data_message_of_an_unknown_session_is_rejected() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);

    pair.buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].copy_from_slice(b"data");
    let SendAction::Send { len } = pair
        .initiator
        .send_to_net(now, &mut pair.buffer, 4)
        .expect("the session carries the payload")
    else {
        panic!("expected a data message");
    };

    // Name a session that the responder does not hold.
    pair.buffer[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert!(matches!(
        pair.responder
            .recv_from_net(now, &mut pair.buffer[..usize::from(len)]),
        Err(Error::NoCurrentSession)
    ));
}

#[test]
fn a_handshake_of_an_unknown_peer_is_rejected() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    let mut other = Pair::new(now, None);

    let init = other.start_handshake(now);
    pair.buffer[..init.len()].copy_from_slice(&init);
    assert!(matches!(
        pair.responder
            .recv_from_net(now, &mut pair.buffer[..init.len()]),
        Err(Error::InvalidMac)
    ));
}

#[test]
fn a_rekey_replaces_the_session_and_keeps_the_tunnel_running() {
    let now = Instant::now();
    let mut pair = Pair::new(now, None);
    pair.handshake(now);
    assert_eq!(
        pair.send(now + Duration::from_secs(1), true, b"before"),
        b"before"
    );

    // The second handshake runs on the same pair of tunnels. The initiator
    // starts it from the timer, because it still holds a session.
    let later = now + REKEY_AFTER_TIME + Duration::from_secs(1);
    assert_eq!(
        pair.initiator
            .update_timers(later, &mut pair.buffer)
            .expect("the timers run"),
        TimerAction::InitiateSession
    );
    let init = pair
        .initiator
        .initiate_session(later)
        .expect("the initiation succeeds")
        .to_vec();
    pair.complete_handshake(later, &init);

    assert_eq!(pair.send(later, true, b"after"), b"after");
    assert_eq!(pair.send(later, false, b"back"), b"back");
}
