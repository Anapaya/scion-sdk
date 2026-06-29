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

//! Standard SCION path routing logic

use sciparse::{
    core::view::View,
    dataplane_path::standard::{
        mac::{ForwardingKey, algo::calculate_hop_mac},
        routing::{AdvanceError, AdvanceValidator, IngressAdvanceAction},
        types::InfoFieldFlags,
        view::{HopFieldView, InfoFieldView, StandardPathView},
    },
    identifier::isd_asn::IsdAsn,
    packet::view::ScionRawPacketView,
    payload::scmp::{
        model::{ScmpErrorMessage, ScmpExternalInterfaceDown, ScmpParameterProblem},
        types::ScmpParameterProblemCode,
    },
};

use crate::network::scion::routing::{
    AsRoutingAction, AsRoutingInterfaceState, LocalAsRoutingAction, ScionNetworkTime,
    spec::IngressNextAction,
};

/// Implements the standard SCION path routing logic for ASes.
pub struct StdRoutingLogic;
impl StdRoutingLogic {
    /// Handles routing of a standard path.
    ///
    /// Returns the next routing action to take for the packet, or an error if the packet is invalid
    /// and cannot be routed.
    pub fn handle_standard_path(
        local_as: IsdAsn,
        path: &mut StandardPathView,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        ignore_macs: bool,
    ) -> Result<AsRoutingAction, StandardRoutingError> {
        let next_action = Self::standard_path_ingress(
            local_as,
            path,
            ingress_interface_id,
            now,
            as_forwarding_key,
            interface_link_type_lookup,
            ignore_macs,
        )?;

        let egress_id = match next_action {
            IngressNextAction::Complete(action) => return Ok(action),
            IngressNextAction::ContinueEgress {
                egress_interface_id,
            } => egress_interface_id,
        };

        let hop_index = path.curr_hop_field_idx();
        let cons_dir = path
            .curr_info_field()
            .ok_or(AdvanceError::InfoOutOfBounds(path.curr_info_field_idx()))?
            .flags()
            .contains(InfoFieldFlags::CONS_DIR);

        let Some(egress_if) = (interface_link_type_lookup)(egress_id) else {
            return Err(StandardRoutingError::UnknownEgressInterface {
                hop_index: hop_index as usize,
                cons_dir,
                if_id: egress_id,
            });
        };

        if !egress_if.is_up {
            return Err(StandardRoutingError::EgressInterfaceDown {
                hop_index: hop_index as usize,
                if_id: egress_id,
            });
        }

        Self::standard_path_egress(
            path,
            egress_id,
            now,
            as_forwarding_key,
            interface_link_type_lookup,
            ignore_macs,
        )
    }

    /// Handle the ingress of a standard path.
    pub fn standard_path_ingress(
        _local_as: IsdAsn,
        path: &mut StandardPathView,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        ignore_macs: bool,
    ) -> Result<IngressNextAction, StandardRoutingError> {
        // Advance the path
        let advance_result = path.advance_ingress_with_validator(
            StandardValidator {
                ingress: true,
                now,
                interface_link_type_lookup,
                current_interface_id: ingress_interface_id,
                forwarding_key,
                ignore_macs,
            },
            ingress_interface_id == 0,
        );

        // Check if the path was advanced successfully or if there was an error
        let validate_result = match advance_result {
            Ok(result) => result.into_result(),
            Err(err) => {
                return Err(StandardRoutingError::AdvanceFailed(err));
            }
        };

        // Handle validation errors
        let advance = match validate_result {
            Ok(advance_result) => advance_result,
            Err((_, validate_error)) => {
                return Err(validate_error);
            }
        };

        // Handle SCMP alert at ingress
        if advance.scmp_alert {
            return Ok(IngressNextAction::Complete(
                LocalAsRoutingAction::IngressSCMPHandleRequest {
                    interface_id: ingress_interface_id,
                }
                .into(),
            ));
        }

        // Handle the next action after advancing the path
        match advance.action {
            IngressAdvanceAction::ContinueEgress { egress_if } => {
                Ok(IngressNextAction::ContinueEgress {
                    egress_interface_id: egress_if,
                })
            }
            IngressAdvanceAction::ForwardLocal => {
                Ok(IngressNextAction::Complete(
                    LocalAsRoutingAction::ForwardLocal.into(),
                ))
            }
        }
    }

    /// Handle the egress of a standard path.
    pub fn standard_path_egress(
        path: &mut StandardPathView,
        egress_if_id: u16,
        now: ScionNetworkTime,
        forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        ignore_macs: bool,
    ) -> Result<AsRoutingAction, StandardRoutingError> {
        // Advance the path
        let advance_result = path.advance_egress_with_validator(StandardValidator {
            ingress: false,
            current_interface_id: egress_if_id,
            now,
            interface_link_type_lookup,
            forwarding_key,
            ignore_macs,
        });

        // Check if the path was advanced successfully or if there was an error
        let validate_result = match advance_result {
            Ok(result) => result.into_result(),
            Err(err) => {
                return Err(StandardRoutingError::AdvanceFailed(err));
            }
        };

        // Handle validation errors
        let advance = match validate_result {
            Ok(advance_result) => advance_result,
            Err((_, validate_error)) => {
                return Err(validate_error);
            }
        };

        // Handle SCMP alert at egress
        if advance.scmp_alert {
            return Ok(AsRoutingAction::Local(
                LocalAsRoutingAction::EgressSCMPHandleRequest {
                    interface_id: advance.egress_interface,
                },
            ));
        }

        // Forward the packet to the next hop
        Ok(AsRoutingAction::ForwardNextHop {
            egress_interface_id: advance.egress_interface,
        })
    }
}

/// Errors that can occur during standard SCION path routing.
#[derive(Debug, thiserror::Error)]
pub enum StandardRoutingError {
    /// The path could not be advanced because it is broken or malformed in some way
    #[error("Failed to advance path: {0}")]
    AdvanceFailed(#[from] AdvanceError),
    /// The path finished, but the destination is not the AS it was supposed to be delivered to
    #[error("Packet is not destined for the local AS")]
    NonLocalDelivery,
    /// The Packet's ingress id does not match id of the interface it was received on
    #[error(
        "hop[{hop_index}] Packet received on wrong ingress interface: expected {expected}, found {found}"
    )]
    InvalidIngressInterface {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The expected ingress interface id
        expected: u16,
        /// The actual ingress interface id found in the packet
        found: u16,
        /// Whether the path is in construction direction
        cons_dir: bool,
    },
    /// The Packet's egress id does not match id of the interface it was sent on
    #[error(
        "hop[{hop_index}] Packet handled at wrong egress interface: expected {expected}, found {found}"
    )]
    InvalidEgressInterface {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The expected egress interface id
        expected: u16,
        /// The actual egress interface id found in the packet
        found: u16,
        /// Whether the path is in construction direction
        cons_dir: bool,
    },
    /// The Packet's timestamp is in the future
    #[error("hop[{hop_index}] Packet has a future timestamp")]
    FutureTimestamp {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
    },
    /// A hop field in the packet has an expiry timestamp that is in the past
    #[error("hop[{hop_index}] Packet segment has expired")]
    SegmentExpired {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
    },
    /// The packet contains an ingress interface that is not known to the router
    #[error("hop[{hop_index}] Packet contained unknown ingress interface {if_id}")]
    UnknownIngressInterface {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The unknown ingress interface id
        if_id: u16,
        /// Whether the path is in construction direction
        cons_dir: bool,
    },
    /// The packet contains an egress interface that is not known to the router
    #[error("hop[{hop_index}] Packet contained unknown egress interface {if_id}")]
    UnknownEgressInterface {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The unknown egress interface id
        if_id: u16,
        /// Whether the path is in construction direction
        cons_dir: bool,
    },
    /// The packet contains an egress interface that is not up
    #[error("hop[{hop_index}] Invalid MAC: expected {expected:?}, actual {actual:?}")]
    InvalidMacError {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The expected MAC address
        expected: [u8; 6],
        /// The actual MAC address found in the packet
        actual: [u8; 6],
    },
    /// The path has an invalid combination of link types at a segment change
    #[error("hop[{hop_index}] Segment change has invalid link type combination")]
    InvalidSegmentChange {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
    },
    /// The Packet's egress interface is disconnected
    #[error("hop[{hop_index}] Egress interface {if_id} is down")]
    EgressInterfaceDown {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// The egress interface id
        if_id: u16,
    },

    /// The packet contained a SCMP alert which would not be handled correctly by the router.
    #[error("hop[{hop_index}] Packet contained SCMP alert which cannot be handled by the router")]
    InvalidScmpAlert {
        /// The index of the hop field in the path where the error occurred
        hop_index: usize,
        /// Whether the path is in construction direction
        cons_dir: bool,
    },
}
impl StandardRoutingError {
    /// Convert the routing error into an SCMP error message, if applicable.
    pub fn to_scmp_error(
        &self,
        local_ia: IsdAsn,
        scion_packet: &ScionRawPacketView,
    ) -> Option<ScmpErrorMessage> {
        // TODO: Packet pointers
        match self {
            Self::AdvanceFailed(_advance_error) => None, // Can't reply if the path is malformed
            Self::NonLocalDelivery => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::NonLocalDelivery,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::UnknownIngressInterface {
                hop_index: _,
                if_id: _,
                cons_dir,
            } => {
                let code = match cons_dir {
                    true => ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
                    false => ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                };

                Some(ScmpParameterProblem::new(code, 0, scion_packet.as_slice().to_vec()).into())
            }
            Self::InvalidIngressInterface {
                hop_index: _,
                expected: _,
                found: _,
                cons_dir,
            } => {
                let code = match cons_dir {
                    true => ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
                    false => ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                };

                Some(ScmpParameterProblem::new(code, 0, scion_packet.as_slice().to_vec()).into())
            }
            Self::UnknownEgressInterface {
                hop_index: _,
                if_id: _,
                cons_dir,
            } => {
                let code = match cons_dir {
                    true => ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                    false => ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
                };

                Some(ScmpParameterProblem::new(code, 0, scion_packet.as_slice().to_vec()).into())
            }
            Self::InvalidEgressInterface {
                hop_index: _,
                expected: _,
                found: _,
                cons_dir,
            } => {
                let code = match cons_dir {
                    true => ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                    false => ScmpParameterProblemCode::UnknownHopFieldConsIngressInterface,
                };

                Some(ScmpParameterProblem::new(code, 0, scion_packet.as_slice().to_vec()).into())
            }
            Self::FutureTimestamp { hop_index: _ } => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::InvalidPath,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::SegmentExpired { hop_index: _ } => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::PathExpired,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::InvalidMacError {
                hop_index: _,
                expected: _,
                actual: _,
            } => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::InvalidHopFieldMac,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::InvalidSegmentChange { hop_index: _ } => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::InvalidSegmentChange,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::EgressInterfaceDown {
                hop_index: _,
                if_id,
            } => {
                Some(
                    ScmpExternalInterfaceDown::new(
                        local_ia,
                        *if_id,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
            Self::InvalidScmpAlert {
                hop_index: _,
                cons_dir: _,
            } => {
                Some(
                    ScmpParameterProblem::new(
                        ScmpParameterProblemCode::ErroneousHeaderField,
                        0,
                        scion_packet.as_slice().to_vec(),
                    )
                    .into(),
                )
            }
        }
    }
}

struct StandardValidator<'a, Lookup: Fn(u16) -> Option<AsRoutingInterfaceState>> {
    ingress: bool,
    now: ScionNetworkTime,
    interface_link_type_lookup: Lookup,
    current_interface_id: u16,
    forwarding_key: &'a ForwardingKey,
    ignore_macs: bool,
}
impl<'a, Lookup: Fn(u16) -> Option<AsRoutingInterfaceState>> AdvanceValidator
    for StandardValidator<'a, Lookup>
{
    type Error = StandardRoutingError;

    #[inline]
    fn validate_hop(
        &self,
        hop_index: usize,
        hop_field: &HopFieldView,
        info_field: &InfoFieldView,
        _is_segment_start: bool,
        _is_segment_end: bool,
    ) -> Result<(), StandardRoutingError> {
        let cons_dir = info_field.flags().contains(InfoFieldFlags::CONS_DIR);
        let ingress_interface = hop_field.ingress_interface(info_field);
        let egress_interface = hop_field.egress_interface(info_field);

        // Check validity of interfaces
        match self.ingress {
            // Checks done on ingress
            true => {
                if self.current_interface_id != 0
                    && ingress_interface != 0
                    && ingress_interface != self.current_interface_id
                {
                    return Err(StandardRoutingError::InvalidIngressInterface {
                        hop_index,
                        expected: self.current_interface_id,
                        found: ingress_interface,
                        cons_dir,
                    });
                }
            }
            // Checks done on egress
            false => {
                if egress_interface != self.current_interface_id {
                    return Err(StandardRoutingError::InvalidEgressInterface {
                        hop_index,
                        expected: self.current_interface_id,
                        found: egress_interface,
                        cons_dir,
                    });
                }
            }
        }

        // Check validity of timestamp and expiration
        if info_field.timestamp() > self.now.timestamp_secs() {
            return Err(StandardRoutingError::FutureTimestamp { hop_index });
        }

        if hop_field.expiry_timestamp(info_field) < self.now.timestamp_secs() {
            return Err(StandardRoutingError::SegmentExpired { hop_index });
        }

        // Validate MAC
        if !self.ignore_macs {
            let mac = hop_field.mac();
            let expected_mac = calculate_hop_mac(
                info_field.segment_id(),
                info_field.timestamp(),
                hop_field.exp_time(),
                hop_field.cons_ingress(),
                hop_field.cons_egress(),
                self.forwarding_key,
            );

            if mac.0 != expected_mac {
                return Err(StandardRoutingError::InvalidMacError {
                    hop_index,
                    expected: expected_mac,
                    actual: mac.into(),
                });
            }
        }

        Ok(())
    }

    #[inline]
    fn validate_segment_change(
        &self,
        hop_index: usize,
        current_hop_field: &HopFieldView,
        current_info_field: &InfoFieldView,
        next_hop_field: &HopFieldView,
        next_info_field: &InfoFieldView,
    ) -> Result<(), StandardRoutingError> {
        let current_hop_ingress = current_hop_field.ingress_interface(current_info_field);
        let next_hop_egress = next_hop_field.egress_interface(next_info_field);

        // Check if there is a SCMP alert between the segment change. While a real SCION router
        // might ignore this. For PocketSCION we will be strict and return an error.
        if current_hop_field.egress_scmp_alert(current_info_field) {
            return Err(StandardRoutingError::InvalidScmpAlert {
                hop_index,
                cons_dir: current_info_field
                    .flags()
                    .contains(InfoFieldFlags::CONS_DIR),
            });
        }

        if next_hop_field.ingress_scmp_alert(next_info_field) {
            return Err(StandardRoutingError::InvalidScmpAlert {
                hop_index,
                cons_dir: next_info_field.flags().contains(InfoFieldFlags::CONS_DIR),
            });
        }

        // CHECK: Segment change must have valid link combinations
        let in_link_type = (self.interface_link_type_lookup)(current_hop_ingress)
            .ok_or(StandardRoutingError::UnknownIngressInterface {
                hop_index,
                if_id: current_hop_ingress,
                cons_dir: current_info_field
                    .flags()
                    .contains(InfoFieldFlags::CONS_DIR),
            })?
            .link_type;

        let out_link_type = (self.interface_link_type_lookup)(next_hop_egress)
            .ok_or(StandardRoutingError::UnknownEgressInterface {
                hop_index,
                if_id: next_hop_egress,
                cons_dir: next_info_field.flags().contains(InfoFieldFlags::CONS_DIR),
            })?
            .link_type;

        use crate::network::scion::routing::AsRoutingLinkType as LinkType;
        let segment_change_valid = match (in_link_type, out_link_type) {
            // Valid
            (LinkType::LinkToCore, LinkType::LinkToChild) => true, // CORE to DOWN
            (LinkType::LinkToChild, LinkType::LinkToCore) => true, // UP to CORE
            (LinkType::LinkToChild, LinkType::LinkToChild) => true, // UP to DOWN
            (LinkType::LinkToChild, LinkType::LinkToPeer) => true, // UP to PEER
            (LinkType::LinkToPeer, LinkType::LinkToChild) => true, // PEER to DOWN

            // Drop (Core loop)
            (LinkType::LinkToCore, LinkType::LinkToCore) => false, // CORE to CORE
            // Drop (Valley routing)
            (LinkType::LinkToParent, LinkType::LinkToParent) => false, // DOWN to UP
            (LinkType::LinkToPeer, LinkType::LinkToParent) => false,   // PEER to UP

            // Drop (Path Splicing)
            (LinkType::LinkToParent, LinkType::LinkToChild) => false, // DOWN to UP
            (LinkType::LinkToChild, LinkType::LinkToParent) => false, // UP to UP
            // Invalid configuration
            _ => false,
        };

        match segment_change_valid {
            true => Ok(()),
            false => Err(StandardRoutingError::InvalidSegmentChange { hop_index }),
        }
    }
}
