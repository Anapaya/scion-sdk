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

//! Tests that a tunnel of this crate speaks to a tunnel of gotatun.
//!
//! gotatun is the WireGuard implementation that this crate copies its Noise
//! code from. A tunnel of this crate that holds no socket address of its peer
//! sends the messages of WireGuard, so the two implementations must carry a
//! tunnel between them. These tests hold the two against each other in both
//! roles.
//!
//! The tests move datagrams as byte slices between the two. They open no
//! socket and they start no task: [`Gotatun`] wraps the state machine of
//! gotatun and nothing else, just as [`TunnelState`] is the state machine of
//! this crate and nothing else.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use bytes::BytesMut;
use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::Packet,
};
use wgx_proto::{
    PAYLOAD_OFFSET, RecvAction, SendAction, TimerAction, TunnelConfig, TunnelState,
    timers::KEEPALIVE_TIMEOUT,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// A handshake never rate limits in these tests, so the limit is out of reach.
const HANDSHAKE_RATE_LIMIT: u64 = 1_000;

const MTU: usize = 1500;

/// The address that the tests give a datagram. gotatun keys its cookie on the
/// address of the sender, and nothing else here reads it.
const SRC: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51820));

/// What a peer does after it takes a datagram.
#[derive(Debug, Default, PartialEq, Eq)]
struct Reaction {
    /// The datagram to send back, if the peer answers.
    reply: Option<Vec<u8>>,
    /// The payload to deliver, if the datagram carried one.
    payload: Option<Vec<u8>>,
}

/// The state machine of gotatun, driven with byte slices.
struct Gotatun {
    tunn: Tunn,
    rate_limiter: Arc<RateLimiter>,
}

impl Gotatun {
    fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
    ) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            &PublicKey::from(&static_private),
            HANDSHAKE_RATE_LIMIT,
        ));
        Self {
            tunn: Tunn::new(
                static_private,
                peer_static_public,
                preshared_key,
                persistent_keepalive,
                IndexTable::from_os_rng(),
                Arc::clone(&rate_limiter),
            ),
            rate_limiter,
        }
    }

    /// Encrypts `payload`, or starts a handshake when there is no session.
    ///
    /// gotatun queues the payload itself when it starts a handshake. The
    /// tests send the payload again once the session stands, so that the
    /// queue of gotatun stays out of the comparison.
    fn send(&mut self, payload: &[u8]) -> Vec<u8> {
        let packet = Packet::from_bytes(BytesMut::from(payload));
        let out = self
            .tunn
            .handle_outgoing_packet(packet, None)
            .expect("gotatun sends a message");
        Packet::from(out).to_vec()
    }

    /// Takes a datagram, the way the device of gotatun would.
    ///
    /// The rate limiter is the part of gotatun that checks `mac1`, so the
    /// datagram passes through it. That puts the `mac1` of this crate under
    /// the check of gotatun.
    fn recv(&mut self, datagram: &[u8]) -> Reaction {
        let packet = Packet::from_bytes(BytesMut::from(datagram));
        let packet = self
            .rate_limiter
            .verify_packet(SRC, packet)
            .expect("gotatun accepts the message");

        match self.tunn.handle_incoming_packet(packet) {
            TunnResult::Done => Reaction::default(),
            TunnResult::WriteToNetwork(out) => {
                Reaction {
                    reply: Some(Packet::from(out).to_vec()),
                    payload: None,
                }
            }
            TunnResult::WriteToTunnel(packet) => {
                Reaction {
                    reply: None,
                    payload: Some(packet.to_vec()),
                }
            }
            TunnResult::Err(err) => panic!("gotatun rejected the message: {err:?}"),
        }
    }

    /// Returns true if gotatun refuses the datagram.
    fn rejects(&mut self, datagram: &[u8]) -> bool {
        let packet = Packet::from_bytes(BytesMut::from(datagram));
        match self.rate_limiter.verify_packet(SRC, packet) {
            Err(_) => true,
            Ok(packet) => matches!(self.tunn.handle_incoming_packet(packet), TunnResult::Err(_)),
        }
    }

    /// Starts a handshake, even when gotatun already holds a session.
    fn initiate(&mut self) -> Vec<u8> {
        let init = self
            .tunn
            .format_handshake_initiation(true)
            .expect("gotatun starts a handshake");
        Packet::<[u8]>::from(init).to_vec()
    }
}

/// The state machine of this crate, driven with byte slices.
struct Sansio {
    tunnel: TunnelState,
    buffer: [u8; MTU],
}

impl Sansio {
    fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        peer_sockaddr: Option<SocketAddr>,
        now: Instant,
    ) -> Self {
        Self {
            tunnel: TunnelState::new(
                TunnelConfig {
                    static_private,
                    peer_static_public,
                    preshared_key,
                    peer_sockaddr,
                    index: 1,
                    persistent_keepalive,
                },
                now,
                SystemTime::now(),
            ),
            buffer: [0u8; MTU],
        }
    }

    fn send(&mut self, now: Instant, payload: &[u8]) -> Vec<u8> {
        self.buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(payload);
        let len = u16::try_from(payload.len()).expect("the payload fits");
        match self
            .tunnel
            .send_to_net(now, &mut self.buffer, len)
            .expect("this crate sends a message")
        {
            SendAction::Send { len } => self.buffer[..usize::from(len)].to_vec(),
            SendAction::InitiateSession => {
                self.tunnel
                    .initiate_session(now)
                    .expect("the initiation succeeds")
                    .to_vec()
            }
            SendAction::Wait => panic!("a handshake is already in flight"),
        }
    }

    fn recv(&mut self, now: Instant, datagram: &[u8]) -> Reaction {
        self.buffer[..datagram.len()].copy_from_slice(datagram);
        match self
            .tunnel
            .recv_from_net(now, &mut self.buffer[..datagram.len()])
            .expect("this crate accepts the message")
        {
            RecvAction::Nothing => Reaction::default(),
            RecvAction::Send { len } => {
                Reaction {
                    reply: Some(self.buffer[..usize::from(len)].to_vec()),
                    payload: None,
                }
            }
            RecvAction::Data { offset, len } => {
                let start = usize::from(offset);
                Reaction {
                    reply: None,
                    payload: Some(self.buffer[start..start + usize::from(len)].to_vec()),
                }
            }
        }
    }

    fn update_timers(&mut self, now: Instant) -> Option<Vec<u8>> {
        match self
            .tunnel
            .update_timers(now, &mut self.buffer)
            .expect("the timers of this crate run")
        {
            TimerAction::Nothing => None,
            TimerAction::Send { len } => Some(self.buffer[..usize::from(len)].to_vec()),
            TimerAction::InitiateSession => {
                Some(
                    self.tunnel
                        .initiate_session(now)
                        .expect("the initiation succeeds")
                        .to_vec(),
                )
            }
        }
    }
}

/// Returns a pair that holds the static key of each other.
fn pair(
    preshared_key: Option<[u8; 32]>,
    peer_sockaddr: Option<SocketAddr>,
    now: Instant,
) -> (Sansio, Gotatun) {
    let sansio_key = StaticSecret::random();
    let gotatun_key = StaticSecret::random();
    let sansio_public = PublicKey::from(&sansio_key);
    let gotatun_public = PublicKey::from(&gotatun_key);

    (
        Sansio::new(
            sansio_key,
            gotatun_public,
            preshared_key,
            None,
            peer_sockaddr,
            now,
        ),
        Gotatun::new(gotatun_key, sansio_public, preshared_key, None),
    )
}

#[test]
fn this_crate_initiates_and_gotatun_responds() {
    let now = Instant::now();
    let (mut sansio, mut gotatun) = pair(None, None, now);

    // This crate has no session, so the payload starts a handshake.
    let init = sansio.send(now, b"queued behind the handshake");
    assert_eq!(init.len(), 148);

    let response = gotatun.recv(&init).reply.expect("gotatun responds");
    assert_eq!(
        response.len(),
        92,
        "gotatun answers in the form of WireGuard"
    );

    // This crate answers the response with a keepalive, which tells gotatun
    // that the session works.
    let keepalive = sansio.recv(now, &response).reply.expect("a keepalive");
    assert_eq!(gotatun.recv(&keepalive).payload, Some(Vec::new()));

    // The session now carries data in both directions.
    let data = sansio.send(now, b"from this crate");
    assert_eq!(
        gotatun.recv(&data).payload.as_deref(),
        Some(&b"from this crate"[..])
    );

    let data = gotatun.send(b"from gotatun");
    assert_eq!(
        sansio.recv(now, &data).payload.as_deref(),
        Some(&b"from gotatun"[..])
    );
}

#[test]
fn gotatun_initiates_and_this_crate_responds() {
    let now = Instant::now();
    let (mut sansio, mut gotatun) = pair(None, None, now);

    let init = gotatun.send(b"queued behind the handshake");
    assert_eq!(init.len(), 148);

    let response = sansio.recv(now, &init).reply.expect("this crate responds");
    assert_eq!(
        response.len(),
        92,
        "without an address, this crate answers in the form of WireGuard"
    );

    // gotatun answers the response with a keepalive.
    let keepalive = gotatun.recv(&response).reply.expect("a keepalive");
    assert_eq!(sansio.recv(now, &keepalive).payload, Some(Vec::new()));

    let data = gotatun.send(b"from gotatun");
    assert_eq!(
        sansio.recv(now, &data).payload.as_deref(),
        Some(&b"from gotatun"[..])
    );

    let data = sansio.send(now, b"from this crate");
    assert_eq!(
        gotatun.recv(&data).payload.as_deref(),
        Some(&b"from this crate"[..])
    );
}

/// Runs a handshake, and leaves both ends with a session.
fn handshake(sansio: &mut Sansio, gotatun: &mut Gotatun, now: Instant, sansio_starts: bool) {
    if sansio_starts {
        let init = sansio.send(now, b"");
        let response = gotatun.recv(&init).reply.expect("gotatun responds");
        let keepalive = sansio.recv(now, &response).reply.expect("a keepalive");
        gotatun.recv(&keepalive);
    } else {
        let init = gotatun.send(b"");
        let response = sansio.recv(now, &init).reply.expect("this crate responds");
        let keepalive = gotatun.recv(&response).reply.expect("a keepalive");
        sansio.recv(now, &keepalive);
    }
}

#[test]
fn a_preshared_key_works_in_both_roles() {
    for sansio_starts in [true, false] {
        let now = Instant::now();
        let (mut sansio, mut gotatun) = pair(Some([0x2b; 32]), None, now);
        handshake(&mut sansio, &mut gotatun, now, sansio_starts);

        let data = sansio.send(now, b"under a preshared key");
        assert_eq!(
            gotatun.recv(&data).payload.as_deref(),
            Some(&b"under a preshared key"[..])
        );

        let data = gotatun.send(b"and back");
        assert_eq!(
            sansio.recv(now, &data).payload.as_deref(),
            Some(&b"and back"[..])
        );
    }
}

#[test]
fn a_peer_that_holds_another_preshared_key_cannot_join() {
    let now = Instant::now();
    let sansio_key = StaticSecret::random();
    let gotatun_key = StaticSecret::random();
    let mut sansio = Sansio::new(
        sansio_key.clone(),
        PublicKey::from(&gotatun_key),
        Some([1u8; 32]),
        None,
        None,
        now,
    );
    let mut gotatun = Gotatun::new(
        gotatun_key,
        PublicKey::from(&sansio_key),
        Some([2u8; 32]),
        None,
    );

    // The handshake itself completes: the pre-shared key enters the keys of
    // the session, not the initiation.
    let init = sansio.send(now, b"");
    let response = gotatun.recv(&init).reply.expect("gotatun responds");

    // This crate cannot open the response, because the keys differ.
    assert!(
        sansio
            .tunnel
            .recv_from_net(now, &mut response.clone())
            .is_err()
    );
}

#[test]
fn a_payload_of_the_full_mtu_survives_in_both_roles() {
    for sansio_starts in [true, false] {
        let now = Instant::now();
        let (mut sansio, mut gotatun) = pair(None, None, now);
        handshake(&mut sansio, &mut gotatun, now, sansio_starts);

        let payload = vec![0xa5; MTU - wgx_proto::DATA_OVERHEAD];
        let data = sansio.send(now, &payload);
        assert_eq!(data.len(), MTU);
        assert_eq!(gotatun.recv(&data).payload.as_deref(), Some(&payload[..]));

        let data = gotatun.send(&payload);
        assert_eq!(
            sansio.recv(now, &data).payload.as_deref(),
            Some(&payload[..])
        );
    }
}

#[test]
fn a_keepalive_of_this_crate_reaches_gotatun() {
    let now = Instant::now();
    let (mut sansio, mut gotatun) = pair(None, None, now);
    handshake(&mut sansio, &mut gotatun, now, true);

    // gotatun sends data, so this crate owes it a keepalive.
    let received = now + Duration::from_secs(1);
    let data = gotatun.send(b"a payload");
    sansio.recv(received, &data);

    let keepalive = sansio
        .update_timers(received + KEEPALIVE_TIMEOUT)
        .expect("this crate sends a keepalive");
    assert_eq!(gotatun.recv(&keepalive).payload, Some(Vec::new()));
}

#[test]
fn a_keepalive_of_gotatun_reaches_this_crate() {
    let now = Instant::now();
    let (mut sansio, mut gotatun) = pair(None, None, now);
    handshake(&mut sansio, &mut gotatun, now, false);

    // A keepalive is a data message with an empty payload. gotatun reads the
    // clock itself, and it exposes no way to move that clock, so the test
    // asks gotatun for the message instead of waiting for its timer. The
    // timer of this crate is under test in the case above, which does drive
    // it.
    let keepalive = gotatun.send(b"");
    assert_eq!(keepalive.len(), wgx_proto::DATA_OVERHEAD);
    assert_eq!(sansio.recv(now, &keepalive).payload, Some(Vec::new()));
}

#[test]
fn a_response_that_carries_an_address_is_no_wireguard_message() {
    let now = Instant::now();
    let sockaddr: SocketAddr = "198.51.100.7:4242".parse().expect("the address parses");
    let (mut sansio, mut gotatun) = pair(None, Some(sockaddr), now);

    let init = gotatun.send(b"");
    let response = sansio.recv(now, &init).reply.expect("this crate responds");
    assert_eq!(response.len(), 112, "the response carries the address");

    // gotatun knows the response of WireGuard and nothing else, so the longer
    // form has to fail. This is the reason the address is optional.
    assert!(gotatun.rejects(&response));
}

#[test]
fn a_rekey_of_gotatun_replaces_the_session() {
    let now = Instant::now();
    let (mut sansio, mut gotatun) = pair(None, None, now);
    handshake(&mut sansio, &mut gotatun, now, true);
    let data = sansio.send(now, b"before");
    assert_eq!(gotatun.recv(&data).payload.as_deref(), Some(&b"before"[..]));

    // gotatun starts a second handshake on the tunnel that already stands.
    let later = now + Duration::from_secs(1);
    let init = gotatun.initiate();
    let response = sansio
        .recv(later, &init)
        .reply
        .expect("this crate responds");
    let keepalive = gotatun.recv(&response).reply.expect("a keepalive");
    sansio.recv(later, &keepalive);

    // Both ends carry data on the session that the second handshake made.
    let data = gotatun.send(b"after");
    assert_eq!(
        sansio.recv(later, &data).payload.as_deref(),
        Some(&b"after"[..])
    );
    let data = sansio.send(later, b"and back");
    assert_eq!(
        gotatun.recv(&data).payload.as_deref(),
        Some(&b"and back"[..])
    );
}
