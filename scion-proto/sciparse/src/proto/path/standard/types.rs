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

//! Standard SCION path types and related structures.

use std::{fmt::Debug, time::Duration};

/// Path types used in SCION packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PathType {
    /// The empty path type.
    Empty = 0,
    /// The standard SCION path type.
    Scion = 1,
    /// One-hop paths between neighboring border routers.
    OneHop = 2,
    /// Experimental Epic path type.
    Epic = 3,
    /// Experimental Colibri path type.
    Colibri = 4,
    /// Other, unrecognized path types.
    Other(u8),
}
impl From<u8> for PathType {
    fn from(value: u8) -> Self {
        match value {
            0 => PathType::Empty,
            1 => PathType::Scion,
            2 => PathType::OneHop,
            3 => PathType::Epic,
            4 => PathType::Colibri,
            other => PathType::Other(other),
        }
    }
}
impl From<PathType> for u8 {
    fn from(val: PathType) -> Self {
        match val {
            PathType::Empty => 0,
            PathType::Scion => 1,
            PathType::OneHop => 2,
            PathType::Epic => 3,
            PathType::Colibri => 4,
            PathType::Other(other) => other,
        }
    }
}

/// MAC (Message Authentication Code) used in HopFields.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HopFieldMac(pub [u8; 6]);
impl HopFieldMac {
    /// Creates a new HopFieldMac from the given byte array.
    pub fn new(bytes: [u8; 6]) -> Self {
        HopFieldMac(bytes)
    }

    /// Returns the byte array representation of the HopFieldMac.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}
impl From<[u8; 6]> for HopFieldMac {
    fn from(bytes: [u8; 6]) -> Self {
        HopFieldMac::new(bytes)
    }
}
impl Debug for HopFieldMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

// InfoFieldFlags
bitflags::bitflags! {
    /// InfoField flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct InfoFieldFlags: u8 {
        /// If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
        /// (i.e. Core AS where the beacon originated )
        const CONS_DIR= 0b0000_0001;

        /// If set to true then the path is a peering path requiring special handling on the dataplane
        const PEERING = 0b0000_0010;

        // Other bits are reserved.
        const _ = !0;
    }
}

// HopFieldFlags
bitflags::bitflags! {
    /// HopField flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct HopFieldFlags: u8 {
        /// If ConsIngress Router Alert is set, the ingress router in construction direction will process the L4 payload in the packet.
        const CONS_INGRESS_ROUTER_ALERT = 0b0000_0001;
        /// If ConsEgress Router Alert is set, the egress router in construction direction will process the L4 payload in the packet.
        const CONS_EGRESS_ROUTER_ALERT = 0b0000_0010;

        // Other bits are reserved.
        const _ = !0;
    }
}
impl HopFieldFlags {
    /// Returns true if the ConsIngress Router Alert flag is set.
    pub fn cons_ingress_router_alert(&self) -> bool {
        self.contains(HopFieldFlags::CONS_INGRESS_ROUTER_ALERT)
    }

    /// Returns true if the ConsEgress Router Alert flag is set.
    pub fn cons_egress_router_alert(&self) -> bool {
        self.contains(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT)
    }

    /// Returns the normalized router alert flag based on the construction direction.
    ///
    /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
    /// is reversed.
    pub fn normalized_ingress_router_alert(&self, cons_dir: bool) -> bool {
        if cons_dir {
            self.cons_ingress_router_alert()
        } else {
            self.cons_egress_router_alert()
        }
    }

    /// Returns the normalized router alert flag based on the construction direction.
    ///
    /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
    /// is reversed.
    pub fn normalized_egress_router_alert(&self, cons_dir: bool) -> bool {
        if cons_dir {
            self.cons_egress_router_alert()
        } else {
            self.cons_ingress_router_alert()
        }
    }
}

// MaxTTL / 256 (5m38.5s) see the following for reference:
// https://datatracker.ietf.org/doc/html/draft-dekater-scion-dataplane#name-hop-field
/// Expiration Duration per ExpTime unit on a HopField.
pub const EXP_TIME_UNIT: Duration = Duration::new(337, 500_000_000);
