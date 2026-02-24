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

//! Model for one-hop paths between neighboring border routers in SCION.

use crate::{
    core::encode::WireEncode,
    path::{
        onehop::layout::OneHopPathLayout,
        standard::{
            mac::{ForwardingKey, algo::mac_beta_step},
            model::{HopField, InfoField},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
        },
    },
};

/// Represents a one-hop path between neighboring border routers in SCION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneHopPath {
    /// Info field
    pub info: InfoField,
    /// Hop fields
    pub hops: [HopField; 2],
}
impl OneHopPath {
    /// Creates a new OneHopPath from the given info field and hop fields.
    ///
    /// No validation is performed on the provided data.
    pub fn new_from_parts(info: InfoField, hops: [HopField; 2]) -> Self {
        Self { info, hops }
    }

    /// Creates a new OneHopPath with the given parameters, calculating the MACs for the hop fields.
    pub fn new(
        egress_interface: u16,
        segment_id: u16,
        timestamp: u32,
        forwarding_key: ForwardingKey,
        expiration_units: u8,
    ) -> Self {
        let info = InfoField {
            flags: InfoFieldFlags::CONS_DIR,
            segment_id,
            timestamp,
        };

        let hop1 = HopField {
            flags: HopFieldFlags::empty(),
            cons_ingress: 0,
            cons_egress: egress_interface,
            expiration_units,
            mac: HopFieldMac([0u8; 6]),
        }
        .with_calculated_mac(info.segment_id, info.timestamp, &forwarding_key);

        // When creating a one-hop path, the second hop is typically empty and serves as a
        // placeholder.
        let hop2 = HopField::empty();

        Self {
            info,
            hops: [hop1, hop2],
        }
    }

    /// Sets the second hop field with the given ingress interface and recalculates the MAC.
    pub fn set_second_hop(&mut self, ingress_interface: u16, forwarding_key: ForwardingKey) {
        let beta = mac_beta_step(self.info.segment_id, self.hops[0].mac.into());

        self.hops[1] = HopField {
            flags: HopFieldFlags::empty(),
            cons_ingress: ingress_interface,
            cons_egress: 0,
            expiration_units: 0,
            mac: HopFieldMac([0u8; 6]),
        }
        .with_calculated_mac(beta, self.info.timestamp, &forwarding_key);
    }
}
impl OneHopPath {
    /// Creates a OneHopPath from a OneHopPathView.
    pub fn from_view(view: &crate::proto::path::onehop::view::OneHopPathView) -> Self {
        let info: InfoField = InfoField::from_view(view.info_field());
        let [hop1, hop2] = view.hop_fields();
        let hops = [HopField::from_view(hop1), HopField::from_view(hop2)];

        Self { info, hops }
    }
}
impl WireEncode for OneHopPath {
    fn required_size(&self) -> usize {
        OneHopPathLayout::SIZE_BYTES
    }

    fn wire_valid(&self) -> Result<(), crate::core::encode::InvalidStructureError> {
        // No specific validation rules for OneHopPath, so we consider it always valid.
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use OneHopPathLayout as OHPL;
            // Encode the info field
            self.info
                .encode_unchecked(&mut buf[OHPL::INFO_FIELD.aligned_byte_range()]);

            // Encode the hop fields
            self.hops[0].encode_unchecked(&mut buf[OHPL::HOP_FIELD_1.aligned_byte_range()]);
            self.hops[1].encode_unchecked(&mut buf[OHPL::HOP_FIELD_2.aligned_byte_range()]);
        }

        OneHopPathLayout::SIZE_BYTES
    }
}
