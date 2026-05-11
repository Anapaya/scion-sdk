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
//! Layout definitions for UDP datagrams (bit ranges and sizes).

use crate::core::layout::{Layout, macros::gen_bitrange_const};

/// Layout for a UDP datagram header (fixed 8 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Length            |            Checksum           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Payload ...                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct UdpDatagramLayout;

impl UdpDatagramLayout {
    gen_bitrange_const!(SRC_PORT_RNG, 0, 16);
    gen_bitrange_const!(DST_PORT_RNG, 16, 16);
    gen_bitrange_const!(LENGTH_RNG, 32, 16);
    gen_bitrange_const!(CHECKSUM_RNG, 48, 16);
    gen_bitrange_const!(HEADER_RNG, 0, 64);

    /// Size of the UDP header in bytes (fixed 8 bytes).
    pub const HEADER_SIZE_BYTES: usize = Self::HEADER_RNG.end / 8;
}

impl Layout for UdpDatagramLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::HEADER_SIZE_BYTES
    }
}
