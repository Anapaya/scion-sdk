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

//! Cryptographic utilities for creating and validating SCION paths.

use aes::cipher::{consts::U16, generic_array::GenericArray};
use thiserror::Error;

use crate::path::{HopField, InfoField};

/// 16 Byte Forwarding Key
pub type ForwardingKey = GenericArray<u8, U16>;

// https://github.com/scionproto/scion/blob/1615ae80e004f1753028a9990abd9928c8aa332d/pkg/slayers/path/mac.go#L40

/// Calculates the MAC for a hop field.
///
/// `mac_chain_beta` see [`mac_chaining_step`].
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
#[allow(unused)]
pub fn mac_chaining_beta(segment_id: u16, hop_macs: impl Iterator<Item = [u8; 6]>) -> u16 {
    let mut accumulator = segment_id; // Beta

    for hop_mac in hop_macs {
        let partial_mac = u16::from_be_bytes([hop_mac[0], hop_mac[1]]); // Sigma
        accumulator ^= partial_mac;
    }

    accumulator
}

/// Calculates the next value for `beta` in the MAC chaining process.
///
/// `accumulator` is the current value of `beta`, starting at the segment ID from the InfoField.
pub fn mac_chaining_step(accumulator: u16, hop_mac: [u8; 6]) -> u16 {
    let partial_mac = u16::from_be_bytes([hop_mac[0], hop_mac[1]]); // Sigma
    accumulator ^ partial_mac
}

/// Validates all MACs in a segment. Requires access to all ForwardingKeys
///
/// `info` is the InfoField of the segment.
/// `fields` containing the ForwardingKey and HopField for each hop
#[allow(unused)]
pub fn validate_segment_macs(
    info: &InfoField,
    fields: &[(HopField, ForwardingKey)],
    is_construction_direction: bool,
) -> Result<(), MacValidateError> {
    let mut accumulator = if is_construction_direction {
        info.seg_id
    } else {
        // use the accumulator at the last hop as Segment ID
        mac_chaining_beta(info.seg_id, fields.iter().map(|(hop, _)| hop.mac))
    };

    let iter: Box<dyn DoubleEndedIterator<Item = _>> = if is_construction_direction {
        Box::new(fields.iter())
    } else {
        Box::new(fields.iter().rev())
    };

    for (i, (hop, hop_key)) in iter.enumerate() {
        if !is_construction_direction {
            accumulator = mac_chaining_step(accumulator, hop.mac);
        }

        let expected_mac = calculate_hop_mac(
            accumulator,
            info.timestamp_epoch,
            hop.exp_time,
            hop.cons_ingress,
            hop.cons_egress,
            hop_key,
        );

        if expected_mac != hop.mac {
            return Err(MacValidateError {
                hop_index: i,
                expected_mac,
                actual_mac: hop.mac,
                accumulator,
                is_construction_direction,
            });
        }

        if is_construction_direction {
            accumulator = mac_chaining_step(accumulator, hop.mac);
        }
    }

    Ok(())
}

/// Error returned when MAC validation fails for a hop.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
#[error("MAC mismatch at hop {hop_index}")]
pub struct MacValidateError {
    /// Index of the hop where the MAC validation failed.
    pub hop_index: usize,
    /// The expected MAC value.
    pub expected_mac: [u8; 6],
    /// The actual MAC value found in the HopField.
    pub actual_mac: [u8; 6],
    /// The accumulator value at the point of failure.
    pub accumulator: u16,
    /// Whether the validation was done in construction direction.
    pub is_construction_direction: bool,
}
