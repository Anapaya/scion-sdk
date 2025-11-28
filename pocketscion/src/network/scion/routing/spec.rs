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
//! Routing Logic based on the Scion Specification

// TODO: Peer link handling is not implemented yet

use bytes::Bytes;
use scion_proto::{
    address::IsdAsn,
    packet::{
        ScionHeaders, ScionPacketRaw,
        layout::{BitOffset, ScionPacketOffset},
    },
    path::{
        DataPlanePath, HopField, HopFieldIndex, InfoField, InfoFieldIndex, MetaHeader,
        StandardPath, crypto::ForwardingKey,
    },
    scmp::{
        ParameterProblemCode, ScmpErrorMessage, ScmpExternalInterfaceDown, ScmpParameterProblem,
    },
    wire_encoding::WireEncodeVec,
};
use tracing::info_span;

use crate::network::scion::routing::{
    AsRoutingAction, AsRoutingInterfaceState, AsRoutingLinkType as LinkType, LocalAsRoutingAction,
    RoutingLogic, ScionNetworkTime,
};

/// Routing Logic based on the Scion Specification.
pub struct SpecRoutingLogic;

impl RoutingLogic for SpecRoutingLogic {
    fn route(
        local_as: IsdAsn,
        scion_packet: &mut ScionPacketRaw,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_link_type_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    ) -> Result<super::AsRoutingAction, scion_proto::scmp::ScmpErrorMessage> {
        // Extract path from the packet

        info_span!("route", ias=?local_as, iid=?ingress_interface_id).in_scope(|| {
            match &scion_packet.headers.path {
                DataPlanePath::Standard(encoded_standard_path) => {
                    let mut standard_path =
                        match StandardPath::try_from(encoded_standard_path.clone()) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to decode standard path");
                                return Err(create_path_decode_error(scion_packet, e));
                            }
                        };

                    let result = Self::handle_standard_path(
                        local_as,
                        scion_packet,
                        &mut standard_path,
                        ingress_interface_id,
                        now,
                        as_forwarding_key,
                        &interface_link_type_lookup,
                    );

                    // always update packet path
                    scion_packet.headers.path = DataPlanePath::Standard(standard_path.into());

                    result
                }
                DataPlanePath::EmptyPath => {
                    let target_address =
                        scion_packet.headers.address.destination().ok_or_else(|| {
                            tracing::warn!("Could not read destination address");
                            scmp_parameter_problem(
                                scion_packet,
                                ParameterProblemCode::UnknownAddressFormat,
                                |_| ScionPacketOffset::address_header().dst_host_addr(),
                            )
                        })?;

                    Ok(LocalAsRoutingAction::ForwardLocal { target_address }.into())
                }
                DataPlanePath::Unsupported {
                    path_type,
                    bytes: _,
                } => {
                    tracing::warn!(path_type = ?path_type, "Received unsupported path type");
                    Err(scmp_parameter_problem(
                        scion_packet,
                        ParameterProblemCode::UnknownPathType,
                        |_| ScionPacketOffset::common_header().path_type(),
                    ))
                }
            }
        })
    }
}

/// Next Action to be taken after Ingress Router processing
enum IngressNextAction {
    /// Processing is complete
    Complete(AsRoutingAction),
    /// Processing continues at the given egress interface
    #[expect(unused)]
    ContinueEgress { egress_interface_id: u16 },
}

impl From<AsRoutingAction> for IngressNextAction {
    fn from(action: AsRoutingAction) -> Self {
        IngressNextAction::Complete(action)
    }
}

impl SpecRoutingLogic {
    fn handle_standard_path(
        local_as: IsdAsn,
        scion_packet: &ScionPacketRaw,
        standard_path: &mut StandardPath,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    ) -> Result<AsRoutingAction, ScmpErrorMessage> {
        // Ingress checks are not run for packets coming from inside the AS
        if ingress_interface_id != 0 {
            let next_action = info_span!("ingress").in_scope(|| {
                Self::standard_path_ingress(
                    local_as,
                    scion_packet,
                    &scion_packet.headers,
                    standard_path,
                    ingress_interface_id,
                    now,
                    as_forwarding_key,
                    interface_link_type_lookup,
                )
            })?;

            match next_action {
                IngressNextAction::Complete(action) => return Ok(action),
                IngressNextAction::ContinueEgress { .. } => {}
            };
        }

        info_span!("egress").in_scope(|| {
            Self::standard_path_egress(
                local_as,
                scion_packet,
                standard_path,
                now,
                as_forwarding_key,
                interface_link_type_lookup,
            )
        })
    }

    /// Ingress processing of a standard path
    ///
    /// Returns [IngressNextAction]
    fn standard_path_ingress(
        local_as: IsdAsn,
        scion_packet: &ScionPacketRaw,
        headers: &ScionHeaders,
        path: &mut StandardPath,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    ) -> Result<IngressNextAction, ScmpErrorMessage> {
        let StandardPath {
            hop_fields,
            info_fields,
            path_meta,
        } = path;

        // We don't handle messages from local in this function
        if ingress_interface_id == 0 {
            let msg = "Packet reached ingress function from interface ID 0";
            debug_assert!(false, "{msg}");
            tracing::warn!(msg);
            return Ok(AsRoutingAction::Drop.into());
        }

        // Extracting all our data
        let current_hop_index = path_meta.hop_field_index();
        let current_hop = try_get_hop(scion_packet, hop_fields, current_hop_index)?;

        let current_info_index = path_meta.info_field_index();
        let current_info = try_get_mut_info(scion_packet, info_fields, current_info_index)?;

        let _span = info_span!("@", hop = current_hop_index, seg = current_info_index).entered();
        let current_cons_dir = current_info.cons_dir;

        let (in_interface, out_interface) = current_hop.interfaces(current_info.cons_dir);
        let (in_scmp_alert, out_scmp_alert) = current_hop.alerts(current_info.cons_dir);

        let (current_segment_start, current_segment_end) =
            try_get_segment_range(scion_packet, path_meta, current_info_index as u8)?;

        let is_final_hop = current_hop_index == hop_fields.len() - 1;
        let is_segment_end = current_hop_index == current_segment_end - 1;
        let is_segment_change = is_segment_end && !is_final_hop;
        let is_construction_dir = current_info.cons_dir;

        // CHECK: Ingress Interface must be the same as the one in the current hop
        if ingress_interface_id != in_interface {
            tracing::warn!(
                expected = in_interface,
                found = ingress_interface_id,
                "Received packet on wrong ingress interface"
            );

            let packet = scion_packet.encode_to_bytes_vec().concat();
            let (code, pointer) = match is_construction_dir {
                true => {
                    (
                        ParameterProblemCode::UnknownHopFieldConsIngressInterface,
                        ScionPacketOffset::std_path(&packet)
                            .hop_field(current_hop_index as u8)
                            .cons_ingress(),
                    )
                }
                false => {
                    (
                        ParameterProblemCode::UnknownHopFieldConsEgressInterface,
                        ScionPacketOffset::std_path(&packet)
                            .hop_field(current_hop_index as u8)
                            .cons_egress(),
                    )
                }
            };

            return Err(ScmpParameterProblem::new(code, pointer.bytes(), packet.into()).into());
        }

        // CHECK: Hop Field must be valid
        Self::validate_hop_field(
            scion_packet,
            (current_segment_start, current_segment_end),
            current_info,
            current_info_index,
            current_hop,
            current_hop_index,
            now,
        )?;

        // UPDATE: Segment ID if we are going against construction direction
        if !is_construction_dir {
            current_info.seg_id ^= u16::from_be_bytes([current_hop.mac[0], current_hop.mac[1]]);
        }

        // CHECK: MAC Auth
        if calculate_hop_mac(current_hop, current_info, forwarding_key) != current_hop.mac {
            return Err(mac_error(
                scion_packet,
                current_hop_index,
                current_info_index,
                current_info,
            ));
        }

        // CHECK: Ensure egress is valid if it exists
        if out_interface != 0 {
            ensure_interface_up(
                local_as,
                scion_packet,
                out_interface,
                true,
                current_cons_dir,
                current_hop_index,
                interface_link_type_lookup,
            )?;
        }

        // HANDLING: Packet request SCMP handling at ingress router
        if in_scmp_alert {
            // UPDATE: Unset the router alert
            let hop_field = &mut hop_fields[current_hop_index];
            match is_construction_dir {
                true => hop_field.ingress_router_alert = false,
                false => hop_field.egress_router_alert = false,
            }

            return Ok(IngressNextAction::Complete(
                LocalAsRoutingAction::IngressSCMPHandleRequest {
                    interface_id: in_interface,
                }
                .into(),
            ));
        }

        // HANDLING: Packet was valid, we are the final hop -> Forward packet locally
        if is_final_hop {
            let target_address = headers.address.destination().ok_or_else(|| {
                tracing::warn!("Unknown destination address");
                scmp_parameter_problem(
                    scion_packet,
                    ParameterProblemCode::UnknownAddressFormat,
                    |_| ScionPacketOffset::address_header().dst_host_addr(),
                )
            })?;

            if target_address.isd_asn() != local_as {
                tracing::warn!("Destination address not in local AS: {target_address:?}");
                return Err(scmp_parameter_problem(
                    scion_packet,
                    ParameterProblemCode::NonLocalDelivery,
                    |_| ScionPacketOffset::address_header().dst_host_addr(),
                ));
            };

            return Ok(IngressNextAction::Complete(
                super::LocalAsRoutingAction::ForwardLocal { target_address }.into(),
            ));
        };

        // HANDLING: Packet was valid, no segment change, continue egress processing
        if !is_segment_change {
            return Ok(IngressNextAction::ContinueEgress {
                egress_interface_id: out_interface,
            });
        }

        // ########################################################
        // Segment Change

        if out_scmp_alert {
            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::ErroneousHeaderField,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .hop_field(current_hop_index as u8)
                        .travel_ingress_router_alert(current_info.cons_dir)
                },
            ));
        }

        // UPDATE: Advance Hop and Info field index
        let new_info_index = current_info_index + 1;
        let new_info = try_get_mut_info(scion_packet, info_fields, new_info_index)?;

        let new_hop_index = current_hop_index + 1;
        let new_hop = try_get_hop(scion_packet, hop_fields, new_hop_index)?;

        let (new_in_scmp_alert, _) = new_hop.alerts(new_info.cons_dir);
        if new_in_scmp_alert {
            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::ErroneousHeaderField,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .hop_field(new_hop_index as u8)
                        .travel_ingress_router_alert(new_info.cons_dir)
                },
            ));
        }

        let (_, new_out_interface) = new_hop.interfaces(new_info.cons_dir);

        path_meta.current_info_field =
            InfoFieldIndex::new(new_info_index as u8).ok_or_else(|| {
                tracing::warn!("Info field was out of bounds after update: {new_info_index}",);
                scmp_parameter_problem(scion_packet, ParameterProblemCode::InvalidPath, |p| {
                    ScionPacketOffset::std_path(p)
                        .path_meta_header()
                        .current_info_field()
                })
            })?;

        path_meta.current_hop_field = HopFieldIndex::new(new_hop_index as u8).ok_or_else(|| {
            tracing::warn!("Hop field was out of bounds after update: {new_hop_index}",);
            scmp_parameter_problem(scion_packet, ParameterProblemCode::InvalidPath, |p| {
                ScionPacketOffset::std_path(p)
                    .path_meta_header()
                    .current_hop_field()
            })
        })?;

        // CHECK: Hop Field must be valid
        Self::validate_hop_field(
            scion_packet,
            try_get_segment_range(scion_packet, path_meta, new_info_index as u8)?,
            new_info,
            new_info_index,
            new_hop,
            new_hop_index,
            now,
        )?;

        // CHECK: Segment change must have valid link combinations
        let initial_in_link_type = get_interface_type(
            scion_packet,
            current_hop_index,
            true,
            current_cons_dir,
            interface_link_type_lookup,
            in_interface,
        )?;
        let new_out_link_type = get_interface_type(
            scion_packet,
            new_hop_index,
            false,
            new_info.cons_dir,
            interface_link_type_lookup,
            new_out_interface,
        )?;
        let segment_change_valid = match (initial_in_link_type, new_out_link_type) {
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

        if !segment_change_valid {
            tracing::warn!(
                "Invalid Segment Change ({initial_in_link_type:?}, {new_out_link_type:?})"
            );

            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::InvalidSegmentChange,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .hop_field(current_hop_index as u8)
                        .base()
                },
            ));
        }

        Ok(IngressNextAction::ContinueEgress {
            egress_interface_id: new_out_interface,
        })
    }

    fn standard_path_egress(
        local_as: IsdAsn,
        scion_packet: &ScionPacketRaw,
        path: &mut StandardPath,
        now: ScionNetworkTime,
        forwarding_key: &ForwardingKey,
        interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    ) -> Result<AsRoutingAction, ScmpErrorMessage> {
        let StandardPath {
            hop_fields,
            info_fields,
            path_meta,
        } = path;

        // Extracting all our data
        let current_hop_index = path_meta.hop_field_index();
        let current_hop = try_get_hop(scion_packet, hop_fields, current_hop_index)?;

        let current_info_index = path_meta.info_field_index();
        let current_info = try_get_mut_info(scion_packet, info_fields, current_info_index)?;

        let _span = info_span!("", hop = current_hop_index, seg = current_info_index).entered();

        let (_, out_interface) = current_hop.interfaces(current_info.cons_dir);
        let (_, out_scmp_alert) = current_hop.alerts(current_info.cons_dir);

        let (current_segment_start, current_segment_end) =
            try_get_segment_range(scion_packet, path_meta, current_info_index as u8)?;

        let is_final_hop = path_meta.hop_field_index() == hop_fields.len() - 1;
        let is_seg_end = current_hop_index + 1 == current_segment_end;
        let is_seg_change = is_seg_end && !is_final_hop;
        let is_construction_dir = current_info.cons_dir;

        if is_final_hop {
            debug_assert!(false, "No final hop should reach egress code");
            return Ok(AsRoutingAction::Drop);
        }
        if is_seg_change {
            debug_assert!(false, "No segment change should reach egress code");
            return Ok(AsRoutingAction::Drop);
        }
        if is_seg_end {
            debug_assert!(false, "No segment end should reach egress code");
            return Ok(AsRoutingAction::Drop);
        }

        // CHECK: Valid egress interface
        if out_interface == 0 {
            tracing::warn!("Packet egress interface can't be 0 at egress");
            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::ErroneousHeaderField,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .hop_field(current_hop_index as u8)
                        .travel_egress(current_info.cons_dir)
                },
            ));
        }

        // CHECK: Hop Field must be valid
        Self::validate_hop_field(
            scion_packet,
            (current_segment_start, current_segment_end),
            current_info,
            current_info_index,
            current_hop,
            current_hop_index,
            now,
        )?;

        // CHECK: MAC Auth
        if calculate_hop_mac(current_hop, current_info, forwarding_key) != current_hop.mac {
            return Err(mac_error(
                scion_packet,
                current_hop_index,
                current_info_index,
                current_info,
            ));
        }

        // CHECK: Ensure egress interface is valid and up
        ensure_interface_up(
            local_as,
            scion_packet,
            out_interface,
            true,
            current_info.cons_dir,
            current_hop_index,
            interface_link_type_lookup,
        )?;

        // HANDLING: Packet request SCMP handling at egress router
        if out_scmp_alert {
            // UPDATE: Unset the router alert
            let hop_field = &mut hop_fields[current_hop_index];
            match is_construction_dir {
                true => hop_field.egress_router_alert = false,
                false => hop_field.ingress_router_alert = false,
            }
            return Ok(LocalAsRoutingAction::EgressSCMPHandleRequest {
                interface_id: out_interface,
            }
            .into());
        }

        // UPDATE: Segment ID if we are in construction direction
        if is_construction_dir {
            current_info.seg_id ^= u16::from_be_bytes([current_hop.mac[0], current_hop.mac[1]]);
        }

        // UPDATE: Advance Hop Field
        path_meta.current_hop_field =
            HopFieldIndex::new(current_hop_index as u8 + 1).ok_or_else(|| {
                tracing::warn!(
                    "Hop field was out of bounds after update: {}",
                    current_hop_index + 1
                );
                scmp_parameter_problem(scion_packet, ParameterProblemCode::InvalidPath, |p| {
                    ScionPacketOffset::std_path(p)
                        .path_meta_header()
                        .current_hop_field()
                })
            })?;

        // Forward to the next hop
        Ok(super::AsRoutingAction::ForwardNextHop {
            link_interface_id: out_interface,
        })
    }

    fn validate_hop_field(
        scion_packet: &ScionPacketRaw,
        (segment_start, segment_end): (usize, usize),
        info_field: &InfoField,
        info_field_index: usize,
        hop_field: &HopField,
        hop_index: usize,
        now: ScionNetworkTime,
    ) -> Result<(), ScmpErrorMessage> {
        // CHECK: Hop index must be within the segment range
        if hop_index < segment_start || hop_index >= segment_end {
            tracing::warn!(
                idx = hop_index,
                start = segment_start,
                end = segment_end,
                "Hop index out of bounds for the current segment"
            );

            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::InvalidPath,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .path_meta_header()
                        .current_hop_field()
                },
            ));
        }

        // CHECK: Time must not be in the future
        if info_field.timestamp() > now.date_time() {
            tracing::warn!(
                "Packet has a future timestamp: {} > {}",
                info_field.timestamp(),
                now.date_time()
            );

            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::InvalidPath,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .info_field(info_field_index as u8)
                        .timestamp()
                },
            ));
        }

        // CHECK: Expiration must not be in the past
        if hop_field.expiry_time(info_field) < now.date_time() {
            tracing::warn!(
                "Packet Segment has expired: {} < {}",
                hop_field.expiry_time(info_field),
                now.date_time()
            );
            return Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::PathExpired,
                |p| {
                    ScionPacketOffset::std_path(p)
                        .hop_field(hop_index as u8)
                        .exp_time()
                },
            ));
        }

        Ok(())
    }
}

fn calculate_hop_mac(
    hop_field: &HopField,
    info_field: &InfoField,
    forwarding_key: &ForwardingKey,
) -> [u8; 6] {
    scion_proto::path::crypto::calculate_hop_mac(
        info_field.seg_id,
        info_field.timestamp_epoch,
        hop_field.exp_time,
        hop_field.cons_ingress,
        hop_field.cons_egress,
        forwarding_key,
    )
}

//
// Data Accessor helpers

fn get_interface_type(
    scion_packet: &ScionPacketRaw,
    hop_field_index: usize,
    egress: bool,
    cons_dir: bool,
    interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    interface_id: u16,
) -> Result<LinkType, ScmpErrorMessage> {
    return match interface_id {
        0 => {
            tracing::warn!(
                hop = hop_field_index,
                "Interface ID 0 is not valid for link type lookup"
            );
            Err(scmp_parameter_problem(
                scion_packet,
                ParameterProblemCode::InvalidPath,
                |p| calc_offset(p, hop_field_index, egress == cons_dir),
            ))
        }
        _ => {
            match interface_link_type_lookup(interface_id) {
                Some(link_type) => Ok(link_type.link_type),
                None => {
                    tracing::warn!(
                        hop = hop_field_index,
                        if_id = interface_id,
                        "Unknown interface id"
                    );

                    let cons_egress = egress == cons_dir;
                    let code = match cons_egress {
                        true => ParameterProblemCode::UnknownHopFieldConsEgressInterface,
                        false => ParameterProblemCode::UnknownHopFieldConsIngressInterface,
                    };

                    Err(scmp_parameter_problem(scion_packet, code, |p| {
                        calc_offset(p, hop_field_index, cons_egress)
                    }))
                }
            }
        }
    };

    fn calc_offset(scion_packet: &[u8], hop_field_index: usize, cons_egress: bool) -> BitOffset {
        match cons_egress {
            true => {
                ScionPacketOffset::std_path(scion_packet)
                    .hop_field(hop_field_index as u8)
                    .cons_egress()
            }
            false => {
                ScionPacketOffset::std_path(scion_packet)
                    .hop_field(hop_field_index as u8)
                    .cons_ingress()
            }
        }
    }
}

/// Returns the index range of the current segment in the path.
///
/// The returned tuple (start, end) represents a half-open range where:
/// - `start` is the index of the first hop field in the segment (inclusive)
/// - `end` is the index just after the last hop field in the segment (exclusive)
///
/// Returns None if the current hop field index is out of bounds.
pub fn try_get_segment_range(
    scion_packet: &ScionPacketRaw,
    meta_header: &MetaHeader,
    segment_index: u8,
) -> Result<(usize, usize), ScmpErrorMessage> {
    let segment_index = segment_index as usize;

    // Check if segment index is valid
    if segment_index >= meta_header.segment_lengths.len() {
        tracing::warn!("Segment index {segment_index} is out of bounds for the segment lengths");
        return Err(scmp_parameter_problem(
            scion_packet,
            ParameterProblemCode::InvalidPath,
            |p| {
                ScionPacketOffset::std_path(p)
                    .path_meta_header()
                    .current_info_field()
            },
        ));
    }

    // Sum up every segment length before the current segment to get the start index
    let start_idx = meta_header.segment_lengths[..segment_index]
        .iter()
        .map(|length| length.get() as usize)
        .sum();

    // The end index is the start index plus the length of the current segment
    let end_idx = start_idx + meta_header.segment_lengths[segment_index].get() as usize;

    Ok((start_idx, end_idx))
}

//
// Error generation helpers

fn mac_error(
    scion_packet: &ScionPacketRaw,
    current_hop_index: usize,
    current_info_index: usize,
    current_info: &InfoField,
) -> ScmpErrorMessage {
    tracing::warn!(
        "MAC does not match C:{} @ S{}:H{} - SegId: {}",
        current_info.cons_dir,
        current_info_index,
        current_hop_index,
        current_info.seg_id
    );
    scmp_parameter_problem(
        scion_packet,
        ParameterProblemCode::InvalidHopFieldMac,
        |p| {
            ScionPacketOffset::std_path(p)
                .hop_field(current_hop_index as u8)
                .mac()
        },
    )
}

fn scmp_parameter_problem(
    scion_packet: &ScionPacketRaw,
    code: ParameterProblemCode,
    pointer: impl FnOnce(&[u8]) -> BitOffset,
) -> ScmpErrorMessage {
    let packet: Bytes = scion_packet.encode_to_bytes_vec().concat().into();
    ScmpParameterProblem::new(code, pointer(&packet).bytes(), packet).into()
}

/// Ensure that the interface is valid and up
fn ensure_interface_up(
    local_ias: IsdAsn,
    scion_packet: &ScionPacketRaw,
    interface_id: u16,
    egress: bool,
    is_cons_dir: bool,
    hop_field_index: usize,
    interface_link_type_lookup: &impl Fn(u16) -> Option<AsRoutingInterfaceState>,
) -> Result<(), ScmpErrorMessage> {
    match interface_link_type_lookup(interface_id) {
        Some(interface) => {
            if interface.is_up {
                return Ok(());
            }

            tracing::warn!("Interface {interface_id} is down");

            Err(ScmpExternalInterfaceDown::new(
                local_ias,
                interface_id as u64,
                scion_packet.encode_to_bytes_vec().concat().into(),
            )
            .into())
        }
        None => {
            let cons_egress = egress == is_cons_dir;

            tracing::warn!("Unknown interface id: {interface_id}");

            match cons_egress {
                true => {
                    Err(scmp_parameter_problem(
                        scion_packet,
                        ParameterProblemCode::UnknownHopFieldConsEgressInterface,
                        |p| {
                            ScionPacketOffset::std_path(p)
                                .hop_field(hop_field_index as u8)
                                .cons_egress()
                        },
                    ))
                }
                false => {
                    Err(scmp_parameter_problem(
                        scion_packet,
                        ParameterProblemCode::UnknownHopFieldConsIngressInterface,
                        |p| {
                            ScionPacketOffset::std_path(p)
                                .hop_field(hop_field_index as u8)
                                .cons_ingress()
                        },
                    ))
                }
            }
        }
    }
}

fn create_path_decode_error(
    scion_packet: &mut ScionPacketRaw,
    e: scion_proto::packet::DecodeError,
) -> scion_proto::scmp::ScmpErrorMessage {
    let packet: Bytes = scion_packet.encode_to_bytes_vec().concat().into();
    let path_offset = ScionPacketOffset::std_path(&packet);
    let (code, pointer) = match e {
        scion_proto::packet::DecodeError::InvalidPath(kind) => {
            match kind {
                scion_proto::path::DataPlanePathErrorKind::InvalidSegmentLengths => {
                    (
                        ParameterProblemCode::InvalidPath,
                        path_offset.path_meta_header().seg_len_0(),
                    )
                }
                scion_proto::path::DataPlanePathErrorKind::InfoFieldOutOfRange => {
                    (
                        ParameterProblemCode::InvalidPath,
                        path_offset.path_meta_header().current_info_field(),
                    )
                }
                scion_proto::path::DataPlanePathErrorKind::HopFieldOutOfRange => {
                    (
                        ParameterProblemCode::InvalidPath,
                        path_offset.path_meta_header().current_hop_field(),
                    )
                }
                _ => (ParameterProblemCode::InvalidPath, path_offset.base()),
            }
        }
        _ => (ParameterProblemCode::InvalidPath, path_offset.base()),
    };
    ScmpParameterProblem::new(code, pointer.bytes(), packet).into()
}

fn try_get_hop<'hop>(
    scion_packet: &ScionPacketRaw,
    hop_fields: &'hop [HopField],
    hop_index: usize,
) -> Result<&'hop HopField, ScmpErrorMessage> {
    if let Some(hop) = hop_fields.get(hop_index) {
        return Ok(hop);
    }

    tracing::warn!(
        index = hop_index,
        actual = hop_fields.len(),
        "Hop field index out of bounds",
    );

    Err(scmp_parameter_problem(
        scion_packet,
        ParameterProblemCode::InvalidPath,
        |p| {
            ScionPacketOffset::std_path(p)
                .path_meta_header()
                .current_hop_field()
        },
    ))
}

fn try_get_mut_info<'info>(
    scion_packet: &ScionPacketRaw,
    info_fields: &'info mut [InfoField],
    info_index: usize,
) -> Result<&'info mut InfoField, ScmpErrorMessage> {
    let len = info_fields.len();
    if let Some(info) = info_fields.get_mut(info_index) {
        return Ok(info);
    }

    tracing::warn!(
        index = info_index,
        actual = len,
        "Info field index out of bounds",
    );

    Err(scmp_parameter_problem(
        scion_packet,
        ParameterProblemCode::InvalidPath,
        |p| {
            ScionPacketOffset::std_path(p)
                .path_meta_header()
                .current_info_field()
        },
    ))
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use helper::*;
    use scion_proto::{address::EndhostAddr, path::test_builder::TestPathBuilder};

    use super::*;

    const SECONDS_PER_EXP_UNIT: u32 = 337;

    #[test_log::test]
    fn should_correctly_route_empty_path() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();
        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .build(1);

        let action = SpecRoutingLogic::route(
            IsdAsn(0),
            &mut test_ctx.scion_packet_udp(&[1, 2], 1234, 1234).into(),
            0,
            ScionNetworkTime::from_timestamp_secs(test_ctx.timestamp),
            &ForwardingKey::default(),
            |_| None,
        )
        .expect("Empty path should not fail");

        assert_eq!(
            action,
            AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal {
                target_address: dst_address.into()
            }),
            "Empty path should forward to local address"
        );
    }

    #[test_log::test]
    fn should_correctly_route_simple_path() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .using_forwarding_key([3; 16].into())
            .add_hop(0, 1)
            .using_forwarding_key([1; 16].into())
            .add_hop(2, 0)
            .build(1);

        SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                link_interface_id: 1,
            }))
            .next_hop_should_succeed(Some(AsRoutingAction::Local(
                LocalAsRoutingAction::ForwardLocal {
                    target_address: dst_address.into(),
                },
            )));

        // Final Egress interface can also be non 0
        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .add_hop(0, 1)
            .add_hop(2, 4)
            .build(1);

        SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                link_interface_id: 1,
            }))
            .next_hop_should_succeed(Some(AsRoutingAction::Local(
                LocalAsRoutingAction::ForwardLocal {
                    target_address: dst_address.into(),
                },
            )));
    }

    #[test_log::test]
    fn should_correctly_route_segment_changes() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();
        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .core()
            .add_hop(0, 10)
            .add_hop(11, 0)
            .down()
            .add_hop(0, 3)
            .add_hop(4, 0)
            .build(1);

        helper::SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                link_interface_id: 1,
            }))
            .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                link_interface_id: 10,
            }))
            .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                link_interface_id: 3,
            }))
            .next_hop_should_succeed(Some(AsRoutingAction::Local(
                LocalAsRoutingAction::ForwardLocal {
                    target_address: dst_address.into(),
                },
            )));
    }

    #[test_log::test]
    fn should_fail_on_invalid_segment_change() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();
        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .core()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .up()
            .add_hop(0, 3)
            .add_hop(4, 0)
            .build(1);

        helper::SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(None)
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::InvalidSegmentChange);

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .down()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .up()
            .add_hop(0, 3)
            .add_hop(4, 0)
            .build(1);

        helper::SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(None)
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::InvalidSegmentChange);

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .up()
            .add_hop(0, 3)
            .add_hop(4, 0)
            .build(1);

        helper::SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(None)
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::InvalidSegmentChange);
    }

    #[test_log::test]
    fn should_fail_with_non_local_destination() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .build(1);

        helper::SpecTestCtx::new(test_ctx)
            .next_hop_should_succeed(None)
            .next_hop_should_fail_with_local_as(IsdAsn(1234))
            .expect_parameter_problem(ParameterProblemCode::NonLocalDelivery);
    }

    #[test_log::test]
    fn should_fail_on_invalid_egress() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .down()
            .add_hop(0, 1)
            .add_hop(2, 0)
            .build(1);

        SpecTestCtx::new(test_ctx)
            .with_custom_link_lookup(|_| None)
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::UnknownHopFieldConsEgressInterface);
    }

    #[test_log::test]
    fn should_fail_on_down_egress() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .down()
            .add_hop_with_egress_down(0, 1)
            .add_hop(2, 0)
            .build(1);

        SpecTestCtx::new(test_ctx)
            .next_hop_should_fail()
            .expect_external_interface_down();
    }

    #[test_log::test]
    fn should_fail_on_invalid_mac() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .up()
            .using_forwarding_key([3; 16].into())
            .add_hop(0, 1)
            .using_forwarding_key([1; 16].into())
            .add_hop(2, 0)
            .build_with_path_modifier(1, |mut p| {
                p.hop_fields[0].mac = [0; 6]; // Invalid MAC
                p
            });
        SpecTestCtx::new(test_ctx)
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::InvalidHopFieldMac);
    }

    #[test_log::test]
    #[should_panic(expected = "No final hop should reach egress code")]
    fn should_fail_with_a_single_hop() {
        let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
        let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();
        let test_ctx = TestPathBuilder::new(src_address, dst_address)
            .using_info_timestamp(0)
            .core()
            .add_hop(0, 1)
            .build(1);

        // Note: This hits a debug_assert in the egress code - on release it will drop the packet
        helper::SpecTestCtx::new(test_ctx).next_hop_should_fail();
    }

    mod time {
        use super::*;

        #[test_log::test]
        fn should_fail_with_bad_timestamps() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            // Timestamp in future
            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(1)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(0),
            )
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::InvalidPath);

            // Timestamp expired
            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(0)
                    .with_hop_expiry(0)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(SECONDS_PER_EXP_UNIT + 1),
            )
            .next_hop_should_fail()
            .expect_parameter_problem(ParameterProblemCode::PathExpired);
        }

        #[test_log::test]
        fn should_not_fail_with_good_timestamp() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(0)
                    .with_hop_expiry(0)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(SECONDS_PER_EXP_UNIT),
            )
            .next_hop_should_succeed(None);
        }
    }

    mod scmp {
        use super::*;

        #[test_log::test]
        fn should_handle_ingress_scmp_requests() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, true, 0, false)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    link_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::IngressSCMPHandleRequest { interface_id: 2 },
                )));
        }

        #[test_log::test]
        fn should_handle_egress_scmp_requests() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 3, true)
                .add_hop(4, 5)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    link_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::EgressSCMPHandleRequest { interface_id: 3 },
                )));
        }

        #[test_log::test]
        fn should_ignore_egress_scmp_on_final_hop() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            // No egress scmp on final hop
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 0, true)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    link_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal {
                        target_address: dst_address.into(),
                    },
                )));
        }

        #[test_log::test]
        fn should_ignore_ingress_scmp_on_first_hop() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            // No ingress scmp on first hop
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop_with_alerts(0, true, 1, false)
                .add_hop(2, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    link_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal {
                        target_address: dst_address.into(),
                    },
                )));
        }

        #[test_log::test]
        fn should_fail_with_scmp_during_segment_change() {
            let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = EndhostAddr::from_str("1-3,4.4.4.4").unwrap();

            // Not before segment change
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 0, true)
                .down()
                .add_hop(2, 0)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ParameterProblemCode::ErroneousHeaderField);

            // Not after segment change
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .down()
                .add_hop_with_alerts(3, true, 4, false)
                .add_hop(5, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ParameterProblemCode::ErroneousHeaderField);
        }
    }

    mod helper {
        use scion_proto::{
            address::IsdAsn,
            packet::ScionPacketRaw,
            path::{
                DataPlanePath,
                test_builder::{TestPathBuilderHopField, TestPathContext},
            },
            scmp::{ParameterProblemCode, ScmpErrorMessage},
        };

        use crate::network::scion::routing::{
            AsRoutingAction, AsRoutingInterfaceState, RoutingLogic, ScionNetworkTime,
            spec::SpecRoutingLogic,
        };

        /// Helper to iterate over test steps
        pub struct SpecTestCtx {
            pub test_context: TestPathContext,
            pub packet: ScionPacketRaw,
            pub last_error: Option<ScmpErrorMessage>,
            pub custom_link_lookup: Option<Box<dyn Fn(u16) -> Option<AsRoutingInterfaceState>>>,
        }

        impl SpecTestCtx {
            pub fn new(test_context: TestPathContext) -> Self {
                Self {
                    packet: test_context.scion_packet_udp(&[1, 2], 22222, 11111).into(),
                    test_context,
                    last_error: None,
                    custom_link_lookup: None,
                }
            }

            /// Registers a custom link lookup function to be used for interface lookups during
            /// routing
            pub fn with_custom_link_lookup(
                mut self,
                custom_link_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState> + 'static,
            ) -> Self {
                self.custom_link_lookup = Some(Box::new(custom_link_lookup));
                self
            }

            /// Looks up the interface type through the.
            ///
            /// If a segment change is detected, this will also allow the interfaces of the next hop
            /// field to be used.
            fn lookup_interface(
                custom_link_lookup: Option<impl Fn(u16) -> Option<AsRoutingInterfaceState>>,
                hop_fields: &[TestPathBuilderHopField],
                current_hop_index: usize,
                interface_id: u16,
            ) -> Option<AsRoutingInterfaceState> {
                if let Some(ref custom_lookup) = custom_link_lookup {
                    return custom_lookup(interface_id);
                }

                let current = &hop_fields[current_hop_index];

                match interface_id {
                    val if current.ingress_if == val => {
                        return current.ingress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    val if current.egress_if == val => {
                        return current.egress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    _ => {}
                }

                if !current.segment_change_next {
                    return None;
                };

                // On segment change, can also use the next hop fields interfaces
                let next = &hop_fields[current_hop_index + 1];

                match interface_id {
                    val if next.ingress_if == val => {
                        return next.ingress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    val if next.egress_if == val => {
                        return next.egress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    _ => {}
                }

                None
            }

            /// Performs the next hop routing step and expects it to succeed.
            pub fn next_hop_should_succeed(self, expected_action: Option<AsRoutingAction>) -> Self {
                // Use the destination AS as the local AS if not specified
                let default_as = self.test_context.dst_address.isd_asn();
                self.next_hop_should_succeed_with_local_as(expected_action, default_as)
            }

            /// Performs the next hop routing step with a specified local AS and expects it to
            /// succeed.
            pub fn next_hop_should_succeed_with_local_as(
                mut self,
                expected_action: Option<AsRoutingAction>,
                local_as: IsdAsn,
            ) -> Self {
                let test_hops = self
                    .test_context
                    .test_segments
                    .iter()
                    .flat_map(|s| s.hop_fields.clone())
                    .collect::<Vec<_>>();

                let current_hop_index = match self.packet.headers.path {
                    DataPlanePath::Standard(ref mut path) => {
                        path.meta_header().current_hop_field.get() as usize
                    }
                    _ => panic!("Unexpected path type"),
                };

                let hop = &test_hops[current_hop_index];

                let custom_lookup = self.custom_link_lookup.as_ref().map(|f| f.as_ref());
                let action = SpecRoutingLogic::route(
                    local_as,
                    &mut self.packet,
                    hop.ingress_if,
                    ScionNetworkTime::from_timestamp_secs(self.test_context.timestamp),
                    &hop.forwarding_key,
                    |interface_id| {
                        Self::lookup_interface(
                            custom_lookup,
                            &test_hops,
                            current_hop_index,
                            interface_id,
                        )
                    },
                )
                .inspect_err(|e| {
                    tracing::warn!(
                        "Hop {} failed unexpectedly with error: {:#?}",
                        current_hop_index,
                        e
                    );
                })
                .unwrap_or_else(|_| panic!("Hop {current_hop_index} should not fail"));

                if let Some(expected_action) = expected_action {
                    assert_eq!(
                        action, expected_action,
                        "Hop {current_hop_index} did not return the expected action"
                    );
                }

                self.last_error = None;
                self
            }

            /// Performs the next hop routing step and expects it to fail.
            pub fn next_hop_should_fail(self) -> Self {
                // Use the destination AS as the local AS if not specified
                let default_as = self.test_context.dst_address.isd_asn();
                self.next_hop_should_fail_with_local_as(default_as)
            }

            /// Performs the next hop routing step with a specified local AS and expects it to fail.
            pub fn next_hop_should_fail_with_local_as(mut self, local_as: IsdAsn) -> Self {
                let test_hops = self
                    .test_context
                    .test_segments
                    .iter()
                    .flat_map(|s| s.hop_fields.clone())
                    .collect::<Vec<_>>();

                let current_hop_index = match self.packet.headers.path {
                    DataPlanePath::Standard(ref mut path) => {
                        path.meta_header().current_hop_field.get() as usize
                    }
                    _ => panic!("Unexpected path type"),
                };

                let hop = &test_hops[current_hop_index];

                let custom_lookup = self.custom_link_lookup.as_ref().map(|f| f.as_ref());
                let err = SpecRoutingLogic::route(
                    local_as,
                    &mut self.packet,
                    hop.ingress_if,
                    ScionNetworkTime::from_timestamp_secs(self.test_context.timestamp),
                    &hop.forwarding_key,
                    |interface_id| {
                        Self::lookup_interface(
                            custom_lookup,
                            &test_hops,
                            current_hop_index,
                            interface_id,
                        )
                    },
                )
                .inspect_err(|e| {
                    tracing::info!(
                        "Hop {} failed as expected with error: {:#?}",
                        current_hop_index,
                        e
                    );
                })
                .expect_err(&format!("Hop {current_hop_index} should have failed",));

                self.last_error = Some(err);

                self
            }

            /// Expects the last error to be an ExternalInterfaceDown error.
            pub fn expect_external_interface_down(self) -> Self {
                let Some(ScmpErrorMessage::ExternalInterfaceDown(err)) = &self.last_error else {
                    panic!(
                        "Expected an ExternalInterfaceDown error but had {:?}",
                        self.last_error
                    );
                };

                tracing::info!(
                    "Got expected ExternalInterfaceDown for interface {}#{}",
                    err.isd_asn,
                    err.interface_id,
                );

                self
            }

            /// Expects the last error to be a ParameterProblem error with the specified code.
            pub fn expect_parameter_problem(self, expected_code: ParameterProblemCode) -> Self {
                let Some(ScmpErrorMessage::ParameterProblem(problem)) = &self.last_error else {
                    panic!(
                        "Expected a ParameterProblem error but had {:?}",
                        self.last_error
                    );
                };

                if problem.code != expected_code {
                    panic!(
                        "Expected ParameterProblem code {:?}, but got {:?}",
                        expected_code, problem.code
                    );
                }

                tracing::info!("Got expected ParameterProblem code: {:?}", expected_code);

                self
            }
        }
    }
}
