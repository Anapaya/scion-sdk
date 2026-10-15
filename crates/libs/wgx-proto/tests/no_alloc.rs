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

//! Tests that a tunnel reaches the heap nowhere.
//!
//! The crate promises that it allocates no buffer: the caller owns every
//! buffer, and the crate works in it. A global allocator that counts holds
//! that promise to account.
//!
//! The file holds one test, so no other test can add to the count. The test
//! itself allocates nowhere either: it moves bytes between fixed arrays.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime},
};

use wgx_proto::{
    PAYLOAD_OFFSET, RecvAction, SendAction, TimerAction, TunnelConfig, TunnelState,
    timers::{KEEPALIVE_TIMEOUT, REKEY_AFTER_TIME},
};
use x25519_dalek::{PublicKey, StaticSecret};

/// The number of allocations since the start of the test binary.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, with a counter in front of it.
struct Counting;

// SAFETY: every method passes its arguments straight to the system allocator,
// which holds the contract of the trait. The counter adds no state that the
// allocator reads.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn count() -> usize {
    ALLOCATIONS.load(Ordering::Relaxed)
}

const MTU: usize = 1500;

/// Carries the message in `buffer[..len]` to `peer`, and returns what the peer
/// answers with.
fn deliver(peer: &mut TunnelState, now: Instant, buffer: &mut [u8], len: usize) -> RecvAction {
    peer.recv_from_net(now, &mut buffer[..len])
        .expect("the peer accepts the message")
}

#[test]
fn a_tunnel_reaches_the_heap_nowhere() {
    let now = Instant::now();
    let wall_clock = SystemTime::now();
    let initiator_key = StaticSecret::random();
    let responder_key = StaticSecret::random();
    let initiator_public = PublicKey::from(&initiator_key);
    let responder_public = PublicKey::from(&responder_key);

    let before_build = count();
    let mut initiator = TunnelState::new(
        TunnelConfig {
            static_private: initiator_key,
            peer_static_public: responder_public,
            preshared_key: None,
            peer_sockaddr: None,
            index: 1,
            persistent_keepalive: None,
        },
        now,
        wall_clock,
    );
    let mut responder = TunnelState::new(
        TunnelConfig {
            static_private: responder_key,
            peer_static_public: initiator_public,
            preshared_key: None,
            peer_sockaddr: None,
            index: 2,
            persistent_keepalive: None,
        },
        now,
        wall_clock,
    );
    let after_build = count();

    let mut buffer = [0u8; MTU];

    // Everything from here on is what a tunnel does for as long as it lives.
    let before = count();

    // The payload of the caller asks the caller to start a handshake.
    let SendAction::InitiateSession = initiator
        .send_to_net(now, &mut buffer, 0)
        .expect("the send succeeds")
    else {
        panic!("expected a request for a handshake");
    };
    let init = initiator
        .initiate_session(now)
        .expect("the initiation succeeds");
    let mut init_bytes = [0u8; 148];
    let len = init.len();
    init_bytes[..len].copy_from_slice(init);
    buffer[..len].copy_from_slice(&init_bytes[..len]);

    let RecvAction::Send { len } = deliver(&mut responder, now, &mut buffer, len) else {
        panic!("expected a handshake response");
    };
    let RecvAction::Send { len } = deliver(&mut initiator, now, &mut buffer, usize::from(len))
    else {
        panic!("expected a keepalive");
    };
    let RecvAction::Data { len: 0, .. } =
        deliver(&mut responder, now, &mut buffer, usize::from(len))
    else {
        panic!("expected an empty payload");
    };

    // The session carries a payload from the initiator.
    let sent = now + Duration::from_secs(1);
    let payload = [0xa5u8; 1000];
    buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
    let SendAction::Send { len } = initiator
        .send_to_net(sent, &mut buffer, 1000)
        .expect("the session carries the payload")
    else {
        panic!("expected a data message");
    };
    let RecvAction::Data { offset, len } =
        deliver(&mut responder, sent, &mut buffer, usize::from(len))
    else {
        panic!("expected a payload");
    };
    assert_eq!(
        &buffer[usize::from(offset)..usize::from(offset) + usize::from(len)],
        &payload[..]
    );

    // The responder heard data and sent nothing back, so its timers answer
    // the silence with a keepalive.
    let quiet = sent + KEEPALIVE_TIMEOUT;
    let TimerAction::Send { len } = responder
        .update_timers(quiet, &mut buffer)
        .expect("the timers run")
    else {
        panic!("expected a keepalive");
    };
    let RecvAction::Data { len: 0, .. } =
        deliver(&mut initiator, quiet, &mut buffer, usize::from(len))
    else {
        panic!("expected an empty payload");
    };

    // The session carries a payload back.
    let back = quiet + Duration::from_secs(1);
    buffer[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
    let SendAction::Send { len } = responder
        .send_to_net(back, &mut buffer, 1000)
        .expect("the session carries the payload")
    else {
        panic!("expected a data message");
    };
    let RecvAction::Data { offset, len } =
        deliver(&mut initiator, back, &mut buffer, usize::from(len))
    else {
        panic!("expected a payload");
    };
    assert_eq!(
        &buffer[usize::from(offset)..usize::from(offset) + usize::from(len)],
        &payload[..]
    );

    // The timers ask for the next handshake.
    let TimerAction::InitiateSession = initiator
        .update_timers(now + REKEY_AFTER_TIME, &mut buffer)
        .expect("the timers run")
    else {
        panic!("expected a request for a handshake");
    };
    let init = initiator
        .initiate_session(now + REKEY_AFTER_TIME)
        .expect("the initiation succeeds");
    let len = init.len();
    init_bytes[..len].copy_from_slice(init);
    buffer[..len].copy_from_slice(&init_bytes[..len]);
    let RecvAction::Send { .. } = deliver(&mut responder, now + REKEY_AFTER_TIME, &mut buffer, len)
    else {
        panic!("expected a handshake response");
    };

    let after = count();

    assert_eq!(
        after - before,
        0,
        "a tunnel allocated {} times: handshake, data, and timers must reach no heap",
        after - before
    );
    // The constructor is measured on its own, because a caller pays it once
    // per tunnel and not once per packet.
    assert_eq!(
        after_build - before_build,
        0,
        "building two tunnels allocated {} times",
        after_build - before_build
    );
}
