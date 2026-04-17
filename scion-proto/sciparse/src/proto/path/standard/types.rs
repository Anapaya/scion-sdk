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

use std::{fmt::Debug, ops::Deref, time::Duration};

use serde::{Deserialize, Serialize};

/// MAC (Message Authentication Code) used in HopFields.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct HopFieldMac(pub [u8; 6]);
impl HopFieldMac {
    /// Creates a new HopFieldMac from the given byte array.
    pub fn new(bytes: [u8; 6]) -> Self {
        HopFieldMac(bytes)
    }

    /// Returns a HopFieldMac with all bytes set to zero.
    ///
    /// This can be used as a placeholder or default value when a valid MAC is not available.
    pub fn zero() -> Self {
        HopFieldMac([0; 6])
    }

    /// Returns the byte array representation of the HopFieldMac.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}
impl Deref for HopFieldMac {
    type Target = [u8; 6];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<[u8; 6]> for HopFieldMac {
    fn from(bytes: [u8; 6]) -> Self {
        HopFieldMac::new(bytes)
    }
}
impl From<HopFieldMac> for [u8; 6] {
    fn from(mac: HopFieldMac) -> Self {
        mac.0
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
    pub struct HopFieldFlags: u8 {
        /// If ConsEgress Router Alert is set, the egress router in construction direction will process the L4 payload in the packet.
        const CONS_EGRESS_ROUTER_ALERT = 0b0000_0001;
        /// If ConsIngress Router Alert is set, the ingress router in construction direction will process the L4 payload in the packet.
        const CONS_INGRESS_ROUTER_ALERT = 0b0000_0010;

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

/// Converts the ExpTime value from a HopField to a Duration.
///
/// One unit of ExpTime corresponds to [EXP_TIME_UNIT] (5m38.5s).\
/// The lowest possible expiration time is [EXP_TIME_UNIT] (when `exp_time` is 0).\
/// The highest possible expiration time is 256 * [EXP_TIME_UNIT] (when `exp_time` is 255).
pub fn exp_time_to_duration(exp_time: u8) -> Duration {
    EXP_TIME_UNIT.saturating_mul(exp_time as u32 + 1)
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;

    impl Arbitrary for InfoFieldFlags {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            any::<u8>()
                .prop_map(InfoFieldFlags::from_bits_retain)
                .boxed()
        }
    }

    impl Arbitrary for HopFieldFlags {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            any::<u8>()
                .prop_map(HopFieldFlags::from_bits_retain)
                .boxed()
        }
    }
}
