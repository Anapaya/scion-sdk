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

use tinyvec::{array_vec, tiny_vec};

use crate::{
    core::encode::WireEncode,
    path::{
        onehop::layout::OneHopPathLayout,
        standard::{
            mac::{ForwardingKey, algo::mac_beta_step},
            model::{HopField, InfoField, Segment, StandardPath},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
        },
    },
};

/// Represents a one-hop path between neighboring border routers in SCION.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    ///
    /// # Parameters
    /// * `ingress_interface` is the interface on which the packet is expected to arrive at the
    ///   second hop.
    /// * `forwarding_key` is the key used for MAC calculation
    /// * `segment_id_was_advanced` indicates whether the segment ID was advanced to the next hop
    ///   before calling this method, or if it is still at the first hop
    pub fn set_second_hop(
        &mut self,
        ingress_interface: u16,
        forwarding_key: ForwardingKey,
        segment_id_was_advanced: bool,
    ) {
        let beta = if segment_id_was_advanced {
            self.info.segment_id
        } else {
            mac_beta_step(self.info.segment_id, self.hops[0].mac.into())
        };

        self.hops[1] = HopField {
            flags: HopFieldFlags::empty(),
            cons_ingress: ingress_interface,
            cons_egress: 0,
            expiration_units: 0,
            mac: HopFieldMac([0u8; 6]),
        }
        .with_calculated_mac(beta, self.info.timestamp, &forwarding_key);
    }

    /// Reverses the one-hop path to create a standard path with two hops in the opposite direction.
    ///
    /// If the second hop field is not set, this will return an error containing the original
    /// OneHopPath.
    ///
    /// ## Note
    /// This assumes that the Segment ID was advanced to the last hop of the path.
    ///
    /// Since the One Hop does not track which hop it is currently on, the caller must ensure that
    /// the Segment ID is correctly set to reflect the final hop of the path before calling this
    /// method.
    pub fn into_reversed_standard_path(self) -> Result<StandardPath, Self> {
        if self.hops[1].cons_ingress == 0 {
            // The second hop is not set, we cannot reverse the path
            return Err(self);
        }

        let OneHopPath {
            mut info,
            hops: [hop1, hop2],
        } = self;

        // Segment ID is final segment ID, so we can use it directly, we just need to reverse the
        // CONS_DIR flag to indicate the reversed direction.
        info.flags ^= InfoFieldFlags::CONS_DIR;

        let standard_path = StandardPath {
            current_info_field: 0,
            curr_hop_field: 0,
            segments: array_vec!(Segment {
                info_field: info,
                hop_fields: tiny_vec!(hop2, hop1),
            }),
        };

        Ok(standard_path)
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

#[cfg(feature = "proptest")]
mod ptest {
    use ::proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryOneHopPathContext {
        // Not implemented yet, but would allow providing ForwardingKeys for generating valid MACs,
        // or even generating paths valid on a topology
    }

    impl Arbitrary for OneHopPath {
        type Parameters = ArbitraryOneHopPathContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_ctx: Self::Parameters) -> Self::Strategy {
            // For simplicity, we generate random values for the fields without ensuring valid MACs.
            // In a more advanced implementation, we could use the context to generate valid paths.
            (
                any::<InfoField>(),
                any::<HopField>(),
                any::<Option<HopField>>(),
            )
                .prop_map(|(info, hop1, hop2)| {
                    Self {
                        info,
                        hops: [hop1, hop2.unwrap_or_else(HopField::empty)],
                    }
                })
                .boxed()
        }
    }
}
