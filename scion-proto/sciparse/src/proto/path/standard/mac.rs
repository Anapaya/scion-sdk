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

//! SCION path MAC calculation and validation logic.

use aes::cipher::{consts::U16, generic_array::GenericArray};

use crate::path::standard::{mac::algo::calculate_hop_mac, types::HopFieldMac};

/// 16 Byte Forwarding Key
pub type ForwardingKey = GenericArray<u8, U16>;

/// Allows types to provide the necessary input for MAC calculation for a hop field.
///
/// Automatically implements [`HopMacCalculate`](crate::path::standard::mac::HopMacCalculate) for
/// any type that implements this trait.
pub(crate) trait HopMacInputSource {
    /// Returns the input required for calculating the MAC of a hop field.
    fn get_mac_input(&self) -> HopMacInput;
}

/// Trait to allow calculating HopField MACs for any type that can provide the necessary input via
/// `MacInputSource`.
pub trait HopMacCalculate {
    /// Calculates the MAC for a hop field based on the provided parameters and returns it.
    ///
    /// ## Parameters
    /// * `mac_chain_beta` is an accumulator for MAC chaining, and is derived from the segment ID
    ///   and previous hop MACs. See [`algo::mac_chaining_beta`] and [`algo::mac_beta_step`] for
    ///   details on how to compute it.
    /// * `info_timestamp` is the timestamp from the info field, used in MAC computation.
    /// * `key` is the key used for MAC calculation
    fn calculate_mac(
        &self,
        mac_chain_beta: u16,
        info_timestamp: u32,
        key: &ForwardingKey,
    ) -> HopFieldMac;
}
// Blanket implementation of `HopMacCalculate` for any type that implements `HopMacInputSource`.
impl<AnySource: HopMacInputSource> HopMacCalculate for AnySource {
    #[inline]
    fn calculate_mac(
        &self,
        mac_chain_beta: u16,
        info_timestamp: u32,
        key: &ForwardingKey,
    ) -> HopFieldMac {
        let HopMacInput {
            exp_time,
            cons_ingress,
            cons_egress,
        } = self.get_mac_input();

        let mac = calculate_hop_mac(
            mac_chain_beta,
            info_timestamp,
            exp_time,
            cons_ingress,
            cons_egress,
            key,
        );

        HopFieldMac(mac)
    }
}

/// Represents the input required for MAC calculation of a hop field.
pub(crate) struct HopMacInput {
    pub exp_time: u8,
    pub cons_ingress: u16,
    pub cons_egress: u16,
}

/// Algorithm implementations for MAC calculation and validation.
pub mod algo {
    use crate::path::standard::mac::ForwardingKey;

    // https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/pkg/slayers/path/mac.go#L40
    /// Calculates the MAC for a hop field.
    #[inline]
    pub fn calculate_hop_mac(
        mac_chain_beta: u16,
        timestamp: u32,
        exp_time: u8,
        cons_ingress: u16,
        cons_egress: u16,
        key: &ForwardingKey,
    ) -> [u8; 6] {
        use cmac::Mac;

        // Input data format (All fields are BE):
        //
        //	 0                   1                   2                   3
        //	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //	|               0               |       SegID/Accumulator       |
        //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //	|                           Timestamp                           |
        //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //	|       0       |    ExpTime    |          ConsIngress          |
        //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //	|          ConsEgress           |               0               |
        //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let mut mac_input_data = [0u8; 16];
        // mac_input_data[0..2]; // 0
        mac_input_data[2..4].copy_from_slice(&mac_chain_beta.to_be_bytes());
        mac_input_data[4..8].copy_from_slice(&timestamp.to_be_bytes());
        // mac_input_data[8]; // 0
        mac_input_data[9] = exp_time;
        mac_input_data[10..12].copy_from_slice(&cons_ingress.to_be_bytes());
        mac_input_data[12..14].copy_from_slice(&cons_egress.to_be_bytes());
        // mac_input_data[14..16]; // 0

        let mut maccer = cmac::Cmac::<aes::Aes128>::new(key);

        maccer.update(&mac_input_data);

        let mac: [u8; 16] = maccer.finalize().into_bytes().into();

        let mut result = [0u8; 6];
        result.copy_from_slice(&mac[..6]);

        result
    }

    // Ref: https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/control/beaconing/extender.go#L356
    /// Calculates a hop's beta value for MAC chaining.
    ///
    /// `segment_id` of the segment this hop belongs to.
    /// `hop_macs` iterates over previous Hop fields' MACs in the segment.
    #[inline]
    pub fn mac_chaining_beta(segment_id: u16, hop_macs: impl Iterator<Item = [u8; 6]>) -> u16 {
        let mut accumulator = segment_id; // Beta

        for hop_mac in hop_macs {
            accumulator = mac_beta_step(accumulator, hop_mac);
        }

        accumulator
    }

    /// Calculates the next value for `beta` in the MAC chaining process.
    ///
    /// `accumulator` is the current value of `beta`, starting at the segment ID from the InfoField.
    #[inline]
    pub fn mac_beta_step(accumulator: u16, hop_mac: [u8; 6]) -> u16 {
        let partial_mac = u16::from_be_bytes([hop_mac[0], hop_mac[1]]); // Sigma
        accumulator ^ partial_mac
    }
}
