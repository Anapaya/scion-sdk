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

//! One-hop SCION path routing logic

use sciparse::{
    address::host_addr::HostAddressSizeError,
    dataplane_path::{
        onehop::view::OneHopPathView,
        standard::{mac::ForwardingKey, types::InfoFieldFlags},
    },
    identifier::isd_asn::IsdAsn,
    packet::view::ScionRawPacketView,
    payload::scmp::model::ScmpErrorMessage,
};

use crate::network::scion::routing::{
    AsRoutingAction, AsRoutingInterfaceState, LocalAsRoutingAction, ScionNetworkTime,
    spec::IngressNextAction,
};

/// Routing logic for packets with one-hop paths.
pub struct OneHopRoutingLogic;
impl OneHopRoutingLogic {
    /// Handles routing of a one-hop path.
    ///
    /// Returns the next routing action to take for the packet, or an error if the packet is invalid
    /// and cannot be routed.
    pub fn handle_one_hop_path(
        local_as: IsdAsn,
        path: &mut OneHopPathView,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        ignore_macs: bool,
    ) -> Result<AsRoutingAction, OneHopRoutingError> {
        // TODO: We skip all non required checks at the moment as well as SCMP handling

        // Ingress
        let next_action = Self::handle_one_hop_path_ingress(
            local_as,
            path,
            ingress_interface_id,
            now,
            as_forwarding_key,
            interface_link_type_lookup,
            ignore_macs,
        )?;

        match next_action {
            IngressNextAction::Complete(action) => return Ok(action),
            IngressNextAction::ContinueEgress { .. } => {}
        };

        // Egress
        Self::handle_one_hop_path_egress(
            local_as,
            path,
            now,
            as_forwarding_key,
            interface_link_type_lookup,
            ignore_macs,
        )
    }

    /// Handle incoming packet with one-hop path on the ingress interface.
    pub fn handle_one_hop_path_ingress(
        _local_as: IsdAsn,
        path: &mut OneHopPathView,
        ingress_interface_id: u16,
        _now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        _interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        _ignore_macs: bool,
    ) -> Result<IngressNextAction, OneHopRoutingError> {
        // TODO: We skip all non required checks at the moment, as well as SCMP handling and
        // interface down handling

        if ingress_interface_id == 0 {
            return Ok(IngressNextAction::ContinueEgress {
                egress_interface_id: path.hop_fields()[0].egress_interface(path.info_field()),
            });
        }

        let is_construction_dir = path.info_field().flags().contains(InfoFieldFlags::CONS_DIR);

        // check if the hop field is empty
        if *path.hop_fields()[1].mac().as_bytes() == [0u8; 6] {
            if !is_construction_dir {
                tracing::warn!("One-hop path in non-construction direction has empty hop field");
                return Err(OneHopRoutingError::EmptyHopFieldInNonConstructionDirection);
            }

            path.set_second_hop(ingress_interface_id, *as_forwarding_key, true);
        } else {
            // TODO: Skipped checks
        }

        // If not in construction direction, update segment id
        if !is_construction_dir {
            let curr_hop_mac = {
                let [_, hf2] = path.hop_fields();
                hf2.mac()
            };

            let info_field = path.info_field_mut();
            let current_seg_id = info_field.segment_id();
            let new_seg_id =
                current_seg_id ^ u16::from_be_bytes([curr_hop_mac[0], curr_hop_mac[1]]);

            info_field.set_segment_id(new_seg_id);
        }

        // Since this is a one hop received from external, this must be forwarded locally
        Ok(IngressNextAction::Complete(
            LocalAsRoutingAction::ForwardLocal.into(),
        ))
    }

    /// Handle outgoing packet with one-hop path on the egress interface.
    pub fn handle_one_hop_path_egress(
        _local_as: IsdAsn,
        path: &mut OneHopPathView,
        _now: ScionNetworkTime,
        _forwarding_key: &ForwardingKey,
        _interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        _ignore_macs: bool,
    ) -> Result<AsRoutingAction, OneHopRoutingError> {
        // TODO: We skip all non required checks at the moment, as well as SCMP handling and
        // interface down handling
        let is_construction_dir = path.info_field().flags().contains(InfoFieldFlags::CONS_DIR);

        // UPDATE: Segment ID if we are in construction direction
        if is_construction_dir {
            let curr_hop_mac = {
                let [hf1, _] = path.hop_fields();
                hf1.mac()
            };

            let info_field = path.info_field_mut();
            let current_seg_id = info_field.segment_id();
            let new_seg_id =
                current_seg_id ^ u16::from_be_bytes([curr_hop_mac[0], curr_hop_mac[1]]);

            info_field.set_segment_id(new_seg_id);
        } else {
            tracing::warn!(
                "One-hop path in non-construction direction should be upgraded to a standard path"
            );
        }

        let egress = path.hop_fields()[0].cons_egress();

        // Since this is a one hop path going out from local, we forward to the next hop
        Ok(AsRoutingAction::ForwardNextHop {
            egress_interface_id: egress,
        })
    }
}

/// Errors that can occur during one-hop path routing.
#[derive(Debug, thiserror::Error)]
pub enum OneHopRoutingError {
    /// The packet's path could not be advanced because it is invalid or malformed
    #[error("failed to advance one-hop path due to invalid or malformed path")]
    AdvanceFailed,

    /// The packet contains an empty hop field in a non-construction direction, which is invalid
    #[error("o`ne-hop path in non-construction direction has empty hop field")]
    EmptyHopFieldInNonConstructionDirection,

    /// The packet's destination address is invalid or malformed
    #[error("the packet's destination address is invalid or malformed ({0})")]
    InvalidDstAddress(HostAddressSizeError),
}

impl OneHopRoutingError {
    /// Convert the routing error to a SCMP error message if possible. Returns None if no SCMP
    /// error message can be generated for this error.
    pub fn to_scmp_error(&self, _scion_packet: &ScionRawPacketView) -> Option<ScmpErrorMessage> {
        match self {
            Self::AdvanceFailed => None,
            Self::EmptyHopFieldInNonConstructionDirection => None,
            Self::InvalidDstAddress(_) => None,
        }
    }
}
