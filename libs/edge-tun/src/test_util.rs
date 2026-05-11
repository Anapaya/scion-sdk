// Copyright 2025 Anapaya Systems
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
//! # Test utilities
//!
//! This module exposes utility functions for testing.

use byteorder::{BigEndian, ByteOrder};
use etherparse::PacketBuilder;
use rand::{Rng as _, SeedableRng};
use rand_xorshift::XorShiftRng;

/// Generate an IPv6 packet from id and packet size.
///
/// The contents of the packet are randomly generated; the seed of the rng encodes
/// both the id and the lenght of the packet. The id is encoded as the first
/// 32-bits of the source address and the length is the payload length of the
/// packet. Thus, the integrity of a packet can be checked without any
/// additional external information.
pub fn gen_ip_packet(id: u32, payload_length: u16) -> Vec<u8> {
    let mut rng = XorShiftRng::seed_from_u64(get_seed(id, payload_length));
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    BigEndian::write_u32(&mut src[..4], id);
    // fill source address
    rng.fill_bytes(&mut src[4..]);
    // fill dest address
    rng.fill_bytes(&mut dst[..]);
    // set hop limit
    let hop_limit: u8 = rng.next_u32() as u8;
    // fill payload
    let mut payload = vec![0u8; payload_length as usize];
    rng.fill_bytes(&mut payload[..]);

    let mut res = vec![];
    PacketBuilder::ipv6(src, dst, hop_limit)
        .write(&mut res, etherparse::IpNumber::default(), &payload)
        .unwrap();

    res
}

/// Check integrity of a given IPv6 packet and return its id.
pub fn assert_integrity(raw_packet: &[u8]) -> u32 {
    let packet = etherparse::IpSlice::from_slice(raw_packet).unwrap();
    let header = packet.ipv6().unwrap().header();
    let src = header.source();
    let id = BigEndian::read_u32(&src[..4]);
    let payload_length = header.payload_length();
    let expected_packet = gen_ip_packet(id, payload_length);

    assert_eq!(expected_packet, raw_packet);
    id
}

fn get_seed(id: u32, payload_length: u16) -> u64 {
    (id as u64) | ((payload_length as u64) << 32)
}
