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

pub mod encode;
pub mod scmp;
pub mod udp;

/// SCION protocol numbers for payloads.
///
/// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
///
///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolNumber {
    /// SCION/TCP next-header protocol number.
    Tcp  = 6,
    /// SCION/UDP next-header protocol number.
    Udp  = 17,
    /// SCION/Hop-by-hop options.
    Hbh  = 43,
    /// SCION End-to-End Options.
    E2e  = 201,
    /// SCION protocol number for SCMP.
    Scmp = 202,
    /// SCION/BFD next-header protocol number.
    Bfd  = 203,
    /// Other, unrecognized protocol numbers.
    Other(u8),
}

impl From<u8> for ProtocolNumber {
    fn from(value: u8) -> Self {
        match value {
            6 => ProtocolNumber::Tcp,
            43 => ProtocolNumber::Hbh,
            201 => ProtocolNumber::E2e,
            17 => ProtocolNumber::Udp,
            202 => ProtocolNumber::Scmp,
            203 => ProtocolNumber::Bfd,
            other => ProtocolNumber::Other(other),
        }
    }
}
impl From<ProtocolNumber> for u8 {
    fn from(value: ProtocolNumber) -> Self {
        match value {
            ProtocolNumber::Tcp => 6,
            ProtocolNumber::Udp => 17,
            ProtocolNumber::Hbh => 43,
            ProtocolNumber::E2e => 201,
            ProtocolNumber::Scmp => 202,
            ProtocolNumber::Bfd => 203,
            ProtocolNumber::Other(other) => other,
        }
    }
}
