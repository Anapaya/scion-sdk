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
//! Module for common helper functions used by both the client and server edge
//! tunn states.

use std::{collections::VecDeque, net::IpAddr};

use ana_gotatun::{
    noise::{Tunn, TunnResult},
    packet::{Packet, PacketBufPool, WgKind},
};
use scion_proto::address::SocketAddr as EndhostSocketAddr;

use crate::fragmenting::{Fragmenter, FragmenterSendError};

/// Maximum per-packet buffer size for WireGuard tunnel packets.
///
/// As we are dealing with tunneled packets, we might actually encounter extra
/// large packets.
pub const PER_PACKET_MAX_SIZE: usize = 64 * 1024;
/// Buffer pool type used across edge-tun WireGuard tunnels.
pub type EdgePacketBufPool = PacketBufPool<PER_PACKET_MAX_SIZE>;

/// Trait for types that can yield an IP address (e.g. a network remote endpoint).
pub trait AsIpAddr {
    /// Return the IP address component of this endpoint, if available.
    fn ip(&self) -> Option<IpAddr>;
}

impl AsIpAddr for EndhostSocketAddr {
    fn ip(&self) -> Option<IpAddr> {
        self.local_address().map(|x| x.ip())
    }
}

// A small helper to allocate a packet from the given packet pool with content
// `payload`.
//
// ## Panics
//
// Panics if the buffer allocated from the buffer pool does not provide
// enough capacity to hold `payload`.
pub(crate) fn pool_allocate_packet_with_payload<B: AsRef<[u8]>>(
    pool: &EdgePacketBufPool,
    payload: B,
) -> Packet {
    let mut final_packet = pool.get();
    let buf = final_packet.buf_mut();
    let payload = payload.as_ref();
    assert!(payload.len() <= buf.capacity());
    buf.truncate(0);
    final_packet.buf_mut().extend_from_slice(payload);
    final_packet
}

pub(crate) fn handle_incoming_and_drain_queue(
    q: &mut VecDeque<WgKind>,
    p: WgKind,
    tunn: &mut Tunn,
) -> TunnResult {
    let r = match tunn.handle_incoming_packet(p) {
        TunnResult::WriteToNetwork(p) => {
            q.push_back(p);
            TunnResult::Done
        }
        // incoming keep alive
        TunnResult::WriteToTunnel(p) if p.is_empty() => TunnResult::Done,
        r => r,
    };
    for p in tunn.get_queued_packets() {
        q.push_back(p);
    }
    r
}

pub(crate) fn fragment_and_dispatch(
    packet: &[u8],
    fragmenter: &mut Fragmenter,
    tunn: &mut Tunn,
    pool: &EdgePacketBufPool,
    mut sink_cb: impl FnMut(WgKind),
) -> Result<u64, FragmenterSendError> {
    fragmenter.send(packet, |fragment| {
        let len = fragment.encoded_len();
        let mut final_packet = pool.get();
        let buf = final_packet.buf_mut();
        assert!(len <= buf.capacity());
        // SAFETY: asserted enough capacity above
        unsafe { buf.set_len(len) };
        fragment.write_to_slice(&mut buf[0..len]);
        if let Some(to_net) = tunn.handle_outgoing_packet(final_packet) {
            sink_cb(to_net);
        }
    })
}
