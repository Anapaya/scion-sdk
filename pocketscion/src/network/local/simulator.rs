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
//! Local Network Simulation
//!
//! Simulates a specific routers dispatching or SCMP request behaviour

use std::net::Ipv4Addr;

use anyhow::{Context, bail};
use bytes::Bytes;
use scion_proto::{
    address::{IsdAsn, ScionAddr, ScionAddrV4, SocketAddr},
    packet::{
        ByEndpoint, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp, classify_scion_packet,
        layout::ScionPacketOffset,
    },
    path::{DataPlanePath, PathType, StandardPath},
    scmp::{
        DestinationUnreachableCode, ParameterProblemCode, ScmpDestinationUnreachable,
        ScmpEchoReply, ScmpErrorMessage, ScmpMessage, ScmpMessageBase, ScmpParameterProblem,
        ScmpTracerouteReply,
    },
    wire_encoding::WireEncodeVec,
};
use scion_protobuf::control_plane::v1::{ServiceResolutionResponse, Transport};
use sciparse::{
    core::view::View,
    path::onehop::{model::OneHopPath, view::OneHopPathView},
};
use tracing::info_span;

use crate::network::{
    local::{external_as_registry::ExternalAsRegistry, receiver_registry::NetworkReceiverRegistry},
    scion::{routing::LocalAsRoutingAction, topology::ScionGlobalInterfaceId},
};

/// A local network simulation.
pub struct LocalNetworkSimulation<'input> {
    local_as: IsdAsn,
    local_if_id: u16,
    /// Dispatchers available to the simulation.
    receivers: &'input NetworkReceiverRegistry,
    /// Registry of external ASes, needed for forwarding to external ASes
    external_ases: &'input ExternalAsRegistry,
}

impl LocalNetworkSimulation<'_> {
    /// Creates a new Simulator at given AS and Interface
    pub fn new<'input>(
        local_as: IsdAsn,
        local_if_id: u16,
        receivers: &'input NetworkReceiverRegistry,
        external_ases: &'input ExternalAsRegistry,
    ) -> LocalNetworkSimulation<'input> {
        LocalNetworkSimulation {
            local_if_id,
            local_as,
            receivers,
            external_ases,
        }
    }
}

/// Effect of a dispatched packet
pub enum DispatchEffect {
    /// A SCMP reply should be sent back
    ScmpReply(ScmpErrorMessage),
    /// Some other reply should be sent back
    OtherReply {
        /// The reply payload
        payload: Vec<u8>,
    },
}

impl LocalNetworkSimulation<'_> {
    /// Best effort dispatch of a packet into given local AS.
    ///
    /// Reads destination from packet.
    pub fn dispatch(&self, packet: ScionPacketRaw) -> Option<DispatchEffect> {
        tracing::trace!(local_as = %self.local_as, "Dispatching packet into AS");
        // Get Dest Addr
        let Some(dest_addr) = packet.headers.address.destination() else {
            tracing::warn!("No local address found in packet destination, cannot dispatch");
            return Some(DispatchEffect::ScmpReply(
                ScmpDestinationUnreachable::new(
                    DestinationUnreachableCode::AddressUnreachable,
                    packet.encode_to_bytes_vec().concat().into(),
                )
                .into(),
            ));
        };

        // Can't handle if non local
        if dest_addr.isd_asn() != self.local_as {
            tracing::warn!(
                dest_as = %dest_addr.isd_asn(),
                local_as = %self.local_as,
                "Packet destination AS does not match local AS, cannot dispatch"
            );

            return Some(DispatchEffect::ScmpReply(
                ScmpParameterProblem::new(
                    ParameterProblemCode::NonLocalDelivery,
                    ScionPacketOffset::address_header().dst_host_addr().bytes(),
                    packet.encode_to_bytes_vec().concat().into(),
                )
                .into(),
            ));
        }

        // Maybe do service resolution
        if let ScionAddr::Svc(dst_svc) = dest_addr {
            // XXX: This is usually not done in the router, but the control service, for simplicity
            // we do it here.
            use prost::Message;

            if let Some(transports) = self
                .receivers
                .svc_mappings(dest_addr.isd_asn(), dst_svc.host())
            {
                let reply = ServiceResolutionResponse {
                    transports: transports
                        .iter()
                        .map(|(protocol, socket_addr)| {
                            (
                                protocol.clone(),
                                Transport {
                                    address: socket_addr.to_string(),
                                },
                            )
                        })
                        .collect(),
                };

                let reply = reply.encode_to_vec();
                return Some(DispatchEffect::OtherReply { payload: reply });
            } else {
                tracing::debug!(
                    "received packet with SVC destination {}, but no mapping found",
                    dst_svc
                );
                return Some(DispatchEffect::OtherReply {
                    payload: ServiceResolutionResponse::default().encode_to_vec(),
                });
            }
        }

        let local_addr = dest_addr
            .local_address()
            .expect("checked above that dest is not SVC");

        // Try dispatch
        let Some(receiver) = self.receivers.by_addr(self.local_as, local_addr) else {
            tracing::warn!(%dest_addr, "No dispatcher found");
            return Some(DispatchEffect::ScmpReply(
                ScmpDestinationUnreachable::new(
                    DestinationUnreachableCode::AddressUnreachable,
                    packet.encode_to_bytes_vec().concat().into(),
                )
                .into(),
            ));
        };

        receiver.receive_packet(packet);

        None
    }

    /// Handles a Routing Action at this specific router
    ///
    /// `action` the local routing action
    /// `packet` the packet for this action
    ///
    /// Returns
    /// - Error If the Simulation failed
    /// - Some  If a response should send
    pub fn handle_local_routing_action(
        &self,
        action: LocalAsRoutingAction,
        packet: ScionPacketRaw,
    ) -> anyhow::Result<Option<ScionPacketRaw>> {
        let pkt_source_as = packet
            .headers
            .address
            .source()
            .map(|s| s.isd_asn())
            .unwrap_or(IsdAsn(0));

        let reply: Option<ScionPacketRaw> = match action {
            LocalAsRoutingAction::ForwardLocal { target_address: _ } => {
                match self.dispatch(packet.clone()) {
                    None => None,
                    Some(DispatchEffect::ScmpReply(scmp_reply)) => {
                        maybe_create_scmp_reply(self.local_as, scmp_reply.into(), packet)
                            .context("error creating SCMP reply after dispatching")?
                            .map(Into::into)
                    }
                    // XXX: this is used for SVC resolution, this is usually not done in the router,
                    // but the control service, for simplicity we do it here.
                    Some(DispatchEffect::OtherReply { payload }) => {
                        create_udp_reply(self.local_as, payload, packet)
                            .context("error creating UDP reply after dispatching")?
                            .into()
                    }
                }
            }
            LocalAsRoutingAction::SendSCMPErrorResponse(scmp_error_message) => {
                maybe_create_scmp_reply(self.local_as, scmp_error_message.into(), packet)?
                    .map(Into::into)
            }
            LocalAsRoutingAction::IngressSCMPHandleRequest { interface_id } => {
                debug_assert_eq!(
                    self.local_if_id, interface_id,
                    "This should always be the interface of the router"
                );
                self.handle_scmp(false, packet)
                    .context("error handling SCMP request")?
                    .map(Into::into)
            }
            LocalAsRoutingAction::EgressSCMPHandleRequest { interface_id } => {
                debug_assert_eq!(
                    self.local_if_id, interface_id,
                    "This should always be the interface of the router"
                );
                self.handle_scmp(true, packet)
                    .context("error handling SCMP request")?
                    .map(Into::into)
            }
            LocalAsRoutingAction::ForwardExternal {
                sim_egress_interface_id,
                extern_ingress_interface_id,
                external_as,
            } => {
                match self.external_ases.get(&external_as) {
                    Some(adapter) => {
                        adapter.handle_incoming_packet(
                            ScionGlobalInterfaceId {
                                isd_as: pkt_source_as,
                                if_id: sim_egress_interface_id,
                            },
                            ScionGlobalInterfaceId {
                                isd_as: external_as,
                                if_id: extern_ingress_interface_id,
                            },
                            &mut packet.clone(),
                        )
                    }
                    None => {
                        tracing::info!(
                            external_as = %external_as,
                            "No adapter found for external AS, dropping packet"
                        );
                    }
                }

                return Ok(None);
            }
        };

        let Some(reply) = reply else {
            // No reply, we are done
            return Ok(None);
        };

        if pkt_source_as != self.local_as {
            // Packet needs to be dispatched through SCION Network
            return Ok(Some(reply));
        }

        // Packet comes from this AS, dispatch, we don't generate any responses for this case
        match self.dispatch(reply) {
            None => {}
            Some(DispatchEffect::ScmpReply(_)) => {
                tracing::warn!("Internal AS dispatch generated SCMP reply, not forwarding");
            }
            Some(DispatchEffect::OtherReply { .. }) => {
                tracing::warn!("Internal AS dispatch generated reply, not forwarding");
            }
        };

        Ok(None) // Handling complete
    }

    /// Handles an incoming SCMP packet, generating a reply if needed.
    pub fn handle_scmp(
        &self,
        egress: bool,
        packet: ScionPacketRaw,
    ) -> anyhow::Result<Option<ScionPacketScmp>> {
        let _s = info_span!(
            "loc-scmp",
            local = %self.local_as,
            iid = self.local_if_id,
            egress = egress
        )
        .entered();

        tracing::trace!("Handling SCMP");
        let request = classify_scion_packet(packet)
            .context("error classifying SCION packet for SCMP response")?
            .try_into_scmp()
            .map_err(|_| anyhow::anyhow!("packet was not a SCMP message"))?;

        match &request.message {
            ScmpMessage::EchoRequest(scmp_echo_request) => {
                tracing::trace!("Handling SCMP echo request");
                maybe_create_scmp_reply(
                    self.local_as,
                    ScmpMessage::EchoReply(ScmpEchoReply::new(
                        scmp_echo_request.identifier,
                        scmp_echo_request.sequence_number,
                        scmp_echo_request.data.clone(),
                    )),
                    request.into(),
                )
            }
            ScmpMessage::TracerouteRequest(scmp_traceroute_request) => {
                tracing::trace!("Handling SCMP traceroute request");
                maybe_create_scmp_reply(
                    self.local_as,
                    ScmpMessage::TracerouteReply(ScmpTracerouteReply::new(
                        scmp_traceroute_request.identifier,
                        scmp_traceroute_request.sequence_number,
                        self.local_as,
                        self.local_if_id as u64,
                    )),
                    request.into(),
                )
            }
            _ => {
                tracing::warn!(message = ?request.message, "Received unexpected SCMP message");

                bail!("Unexpected SCMP message");
            }
        }
    }
}

fn create_udp_reply(
    local_as: IsdAsn,
    payload: Vec<u8>,
    respond_to: ScionPacketRaw,
) -> anyhow::Result<ScionPacketRaw> {
    let respond_to_udp: ScionPacketUdp = respond_to
        .try_into()
        .context("packet is not a UDP packet, cannot create reply")?;

    // Note: if src address is a multicast address, this should not generate a response.
    let packet_src = respond_to_udp
        .source()
        .context("UDP packet has no source socket address")?;
    let endhosts = ByEndpoint::<SocketAddr> {
        // XXX(ake): This would be set to the IP of the router socket, we however do not simulate
        // these
        source: SocketAddr::new(
            ScionAddrV4::new(local_as, Ipv4Addr::new(0, 0, 0, 0)).into(),
            0,
        ),
        destination: packet_src,
    };

    let path = if packet_src.isd_asn() == local_as {
        // If we send packet locally, empty path is fine
        DataPlanePath::EmptyPath
    } else if let DataPlanePath::Unsupported {
        path_type: PathType::OneHop,
        bytes,
    } = respond_to_udp.headers.path
    {
        // One hop path gets updated to a standard path
        let (ohp, _) =
            OneHopPathView::from_slice(&bytes).context("error parsing one-hop path from packet")?;
        let ohp = OneHopPath::from_view(ohp);

        let rev_std_path = ohp.into_reversed_standard_path().map_err(|_| {
            anyhow::anyhow!("error converting one-hop path to standard path for reply")
        })?;
        let rev_std_path = StandardPath::from_sciparse_standard_path(rev_std_path);
        DataPlanePath::Standard(rev_std_path.into())
    } else {
        // Otherwise reverse the path
        let mut path = respond_to_udp.headers.path.clone();
        path.reverse().context("error reversing path from packet")?;

        path
    };

    Ok(
        ScionPacketUdp::new(endhosts, path, Bytes::from_owner(payload))
            .context("error creating reply packet")?
            .into(),
    )
}

/// Creates a SCMP Response to given packet
///
/// If the packet is a SCMP Error Message, no response is created.
fn maybe_create_scmp_reply(
    local_as: IsdAsn,
    scmp: ScmpMessage,
    respond_to: ScionPacketRaw,
) -> anyhow::Result<Option<ScionPacketScmp>> {
    let classify = classify_scion_packet(respond_to.clone())
        .context("error classifying SCION packet for SCMP response")?;

    match classify {
        // If the packet is a SCMP Error Message, we do not create a response
        scion_proto::packet::PacketClassification::ScmpWithDestination(_, pkt)
        | scion_proto::packet::PacketClassification::ScmpWithoutDestination(pkt)
            if pkt.message.is_error() =>
        {
            return Ok(None);
        }
        _ => {}
    }

    let packet_src = respond_to
        .headers
        .address
        .source()
        .context("packet has no source address")?;

    // Note: if src address is a multicast address, this should not generate a response.

    let endhosts = ByEndpoint::<ScionAddr> {
        // XXX(ake): This would be set to the IP of the router socket, we however do not simulate
        // these
        source: ScionAddr::V4(ScionAddrV4::new(local_as, Ipv4Addr::new(0, 0, 0, 0))),
        destination: packet_src,
    };

    let path = if packet_src.isd_asn() == local_as {
        // If we send packet locally, empty path is fine
        DataPlanePath::EmptyPath
    } else if let DataPlanePath::Unsupported {
        path_type: PathType::OneHop,
        bytes,
    } = respond_to.headers.path
    {
        // One hop path gets updated to a standard path
        let (ohp, _) =
            OneHopPathView::from_slice(&bytes).context("error parsing one-hop path from packet")?;
        let ohp = OneHopPath::from_view(ohp);

        let rev_std_path = ohp.into_reversed_standard_path().map_err(|_| {
            anyhow::anyhow!("error converting one-hop path to standard path for reply")
        })?;
        let rev_std_path = StandardPath::from_sciparse_standard_path(rev_std_path);
        DataPlanePath::Standard(rev_std_path.into())
    } else {
        // Otherwise reverse the path
        let mut path = respond_to.headers.path.clone();
        path.reverse().context("error reversing path from packet")?;

        path
    };

    ScionPacketScmp::new(endhosts, path, scmp)
        .context("error creating SCMP packet")
        .map(Some)
}
