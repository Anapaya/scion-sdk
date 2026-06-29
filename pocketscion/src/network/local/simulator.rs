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

use anyhow::{Context, bail};
use scion_protobuf::control_plane::v1::{ServiceResolutionResponse, Transport};
use sciparse::{
    address::{addr::ScionAddr, socket_addr::ScionSocketAddr},
    core::{model::Model, view::View},
    dataplane_path::view::ScionDpPathViewExt,
    identifier::isd_asn::IsdAsn,
    packet::{
        classify::ClassifiedPacketView,
        model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
        view::ScionRawPacketView,
    },
    payload::scmp::{
        model::{
            ScmpDestinationUnreachable, ScmpEchoReply, ScmpErrorMessage, ScmpMessage,
            ScmpParameterProblem, ScmpTracerouteReply,
        },
        types::{ScmpDestinationUnreachableCode, ScmpParameterProblemCode},
        view::{ScmpMessageExt, ScmpMessageView},
    },
};
use tracing::info_span;

use crate::network::{
    local::{external_as_registry::ExternalAsRegistry, receiver_registry::NetworkReceiverRegistry},
    scion::{
        routing::LocalAsRoutingAction,
        topology::{ScionGlobalInterfaceId, ScionRouter},
    },
};

/// A local network simulation.
pub struct LocalNetworkSimulation<'input> {
    /// The router for which this simulation is running
    router: &'input ScionRouter,
    /// The AS for which this simulation is running
    local_as: IsdAsn,
    /// The interface for which this simulation is running
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
        router: &'input ScionRouter,
    ) -> LocalNetworkSimulation<'input> {
        LocalNetworkSimulation {
            local_if_id,
            local_as,
            receivers,
            external_ases,
            router,
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
    pub fn dispatch(&self, packet: &ScionRawPacketView) -> Option<DispatchEffect> {
        tracing::trace!(local_as = %self.local_as, "Dispatching packet into AS");
        // Get Dest Addr
        let Ok(dest_addr) = packet.dst_scion_addr() else {
            tracing::warn!("Invalid Address found in packet destination, cannot dispatch");

            return Some(DispatchEffect::ScmpReply(
                ScmpParameterProblem::new(
                    ScmpParameterProblemCode::InvalidAddressHeader,
                    0, // TODO: Packet offset calculation
                    packet.as_slice().to_vec(),
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
                    ScmpParameterProblemCode::NonLocalDelivery,
                    0, // TODO: ScionPacketOffset::address_header().dst_host_addr().bytes(),
                    packet.as_slice().to_vec(),
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
                .svc_mappings(dest_addr.isd_asn(), &dst_svc.host)
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

        let local_addr = dest_addr.ip().expect("checked above that dest is not SVC");

        // Try dispatch
        let Some(receiver) = self.receivers.by_addr(self.local_as, local_addr) else {
            tracing::warn!(%dest_addr, "No dispatcher found");
            return Some(DispatchEffect::ScmpReply(
                ScmpDestinationUnreachable::new(
                    ScmpDestinationUnreachableCode::AddressUnreachable,
                    packet.as_slice().to_vec(),
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
    /// - Some  If a response should be send
    pub fn handle_local_routing_action(
        &self,
        action: LocalAsRoutingAction,
        packet: &mut ScionRawPacketView,
    ) -> anyhow::Result<Option<ScionRawPacket>> {
        let pkt_source_as = packet.header().src_ia();

        let reply: Option<ScionRawPacket> = match action {
            LocalAsRoutingAction::ForwardLocal => {
                // TODO: Inspect Dst Address and IsdAsn
                match self.dispatch(packet) {
                    None => None,
                    Some(DispatchEffect::ScmpReply(scmp_reply)) => {
                        maybe_create_scmp_reply(
                            self.local_as,
                            self.router,
                            scmp_reply.into(),
                            packet,
                        )
                        .context("error creating SCMP reply after dispatching")?
                        .map(Into::into)
                    }
                    // XXX: this is used for SVC resolution, this is usually not done in the router,
                    // but the control service, for simplicity we do it here.
                    Some(DispatchEffect::OtherReply { payload }) => {
                        let rsp = create_udp_reply(self.local_as, self.router, payload, packet)
                            .context("error creating UDP reply after dispatching")?
                            .into();

                        Some(rsp)
                    }
                }
            }
            LocalAsRoutingAction::SendSCMPErrorResponse(scmp_error_message) => {
                maybe_create_scmp_reply(
                    self.local_as,
                    self.router,
                    scmp_error_message.into(),
                    packet,
                )?
                .map(Into::into)
            }
            LocalAsRoutingAction::IngressSCMPHandleRequest { interface_id } => {
                if interface_id != 0 {
                    debug_assert_eq!(
                        self.local_if_id, interface_id,
                        "This should always be the interface of the router"
                    );
                }
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
                                isd_as: self.local_as,
                                if_id: sim_egress_interface_id,
                            },
                            ScionGlobalInterfaceId {
                                isd_as: external_as,
                                if_id: extern_ingress_interface_id,
                            },
                            packet,
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
        match self.dispatch(
            &reply
                .encode_to_owned_view()
                .context("failed to encode reply for dispatching")?,
        ) {
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
        packet: &ScionRawPacketView,
    ) -> anyhow::Result<Option<ScionScmpPacket>> {
        // TODO: SCMP should inspect the dst address to determine if the packet is meant for this
        // router.

        let at = if egress { "egress" } else { "ingress" };
        let _s = info_span!("scmp", iid = self.local_if_id, at = at).entered();

        let request = packet
            .try_into_scmp()
            .context("error classifying SCION packet for SCMP response")?;

        match request.scmp().message() {
            ScmpMessageView::EchoRequest(scmp_echo_request) => {
                tracing::trace!("Handling SCMP echo request");
                maybe_create_scmp_reply(
                    self.local_as,
                    self.router,
                    ScmpMessage::EchoReply(ScmpEchoReply::new(
                        scmp_echo_request.identifier(),
                        scmp_echo_request.sequence_number(),
                        scmp_echo_request.data().to_vec(),
                    )),
                    request.into(),
                )
            }
            ScmpMessageView::TracerouteRequest(scmp_traceroute_request) => {
                tracing::trace!("Handling SCMP traceroute request");
                maybe_create_scmp_reply(
                    self.local_as,
                    self.router,
                    ScmpMessage::TracerouteReply(ScmpTracerouteReply::new(
                        scmp_traceroute_request.identifier(),
                        scmp_traceroute_request.sequence_number(),
                        self.local_as,
                        self.local_if_id,
                    )),
                    request.into(),
                )
            }
            message => {
                tracing::warn!(?message, "Received unexpected SCMP message");

                bail!("Unexpected SCMP message");
            }
        }
    }
}

fn create_udp_reply(
    local_as: IsdAsn,
    router: &ScionRouter,
    payload: Vec<u8>,
    respond_to: &ScionRawPacketView,
) -> anyhow::Result<ScionUdpPacket> {
    let respond_to_udp = respond_to
        .try_into_udp()
        .context("packet is not a UDP packet, cannot create reply")?;

    // Note: if src address is a multicast address, this should not generate a response.
    let packet_src = respond_to_udp
        .src_socket_addr()
        .context("invalid source socket address")?;

    let mut path = respond_to.header().path().to_model();
    path.try_reverse()
        .context("error reversing path from packet for UDP reply")?;

    Ok(ScionUdpPacket::new(
        ScionSocketAddr::new(local_as, router.address.ip().into(), router.address.port()),
        packet_src,
        path,
        payload,
    ))
}

/// Creates a SCMP Response to given packet
///
/// If the packet is a SCMP Error Message, no response is created.
fn maybe_create_scmp_reply(
    local_as: IsdAsn,
    router: &ScionRouter,
    scmp: ScmpMessage,
    respond_to: &ScionRawPacketView,
) -> anyhow::Result<Option<ScionScmpPacket>> {
    let classify = respond_to
        .classify()
        .context("can't classify SCION packet for SCMP response")?;

    match classify {
        ClassifiedPacketView::Scmp(scmp_view) if scmp_view.scmp().message().is_error() => {
            // Don't reply to SCMP Error Messages
            return Ok(None);
        }
        _ => {}
    }

    let packet_src = respond_to
        .src_scion_addr()
        .context("can't get source address from packet for SCMP response")?;
    let response_src = ScionAddr::new(local_as, router.address.ip().into());

    if let Some(ip) = packet_src.ip()
        && ip.is_multicast()
    {
        // For Multicast addresses, no response should be generated.
        return Ok(None);
    }

    // Reverse the path

    let mut path = respond_to.header().path().to_model();
    path.try_reverse()
        .context("error reversing path from packet for SCMP response")?;

    Ok(Some(ScionScmpPacket::new(
        response_src,
        packet_src,
        path,
        scmp,
    )))
}
