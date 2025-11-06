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
use scion_proto::{
    address::{IsdAsn, ScionAddr, ScionAddrV4},
    packet::{
        ByEndpoint, ScionPacketRaw, ScionPacketScmp, classify_scion_packet,
        layout::ScionPacketOffset,
    },
    path::DataPlanePath,
    scmp::{
        DestinationUnreachableCode, ParameterProblemCode, ScmpDestinationUnreachable,
        ScmpEchoReply, ScmpErrorMessage, ScmpMessage, ScmpMessageBase, ScmpParameterProblem,
        ScmpTracerouteReply,
    },
    wire_encoding::WireEncodeVec,
};
use tracing::info_span;

use crate::network::{
    local::receiver_registry::NetworkReceiverRegistry, scion::routing::LocalAsRoutingAction,
};

/// A local network simulation.
pub struct LocalNetworkSimulation<'input> {
    local_as: IsdAsn,
    local_if_id: u16,
    /// Dispatchers available to the simulation.
    receivers: &'input NetworkReceiverRegistry,
}

impl LocalNetworkSimulation<'_> {
    /// Creates a new Simulator at given AS and Interface
    pub fn new(
        local_as: IsdAsn,
        local_if_id: u16,
        receivers: &NetworkReceiverRegistry,
    ) -> LocalNetworkSimulation<'_> {
        LocalNetworkSimulation {
            local_if_id,
            local_as,
            receivers,
        }
    }

    /// Best effort dispatch of a packet into given local AS.
    ///
    /// Reads destination from packet.
    pub fn dispatch(&self, packet: ScionPacketRaw) -> Result<(), ScmpErrorMessage> {
        tracing::trace!(local_as = %self.local_as, "Dispatching packet into AS");
        // Get Dest Addr
        let Some(dest_ip) = packet.headers.address.destination() else {
            tracing::warn!("No local address found in packet destination, cannot dispatch");
            return Err(ScmpDestinationUnreachable::new(
                DestinationUnreachableCode::AddressUnreachable,
                packet.encode_to_bytes_vec().concat().into(),
            )
            .into());
        };

        // Can't handle if non local
        if dest_ip.isd_asn() != self.local_as {
            tracing::warn!(
                dest_as = %dest_ip.isd_asn(),
                local_as = %self.local_as,
                "Packet destination AS does not match local AS, cannot dispatch"
            );

            return Err(ScmpParameterProblem::new(
                ParameterProblemCode::NonLocalDelivery,
                ScionPacketOffset::address_header().dst_host_addr().bytes(),
                packet.encode_to_bytes_vec().concat().into(),
            )
            .into());
        }

        // Try dispatch
        self.receivers
            .by_addr(dest_ip)
            .ok_or_else(|| {
                tracing::warn!(%dest_ip, "No dispatcher found");
                ScmpDestinationUnreachable::new(
                    DestinationUnreachableCode::AddressUnreachable,
                    packet.encode_to_bytes_vec().concat().into(),
                )
            })?
            .receive_packet(packet);

        Ok(())
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
    ) -> anyhow::Result<Option<ScionPacketScmp>> {
        let pkt_source_as = packet
            .headers
            .address
            .source()
            .map(|s| s.isd_asn())
            .unwrap_or(IsdAsn(0));

        let scmp_reply = match action {
            LocalAsRoutingAction::ForwardLocal { target_address: _ } => {
                match self.dispatch(packet.clone()) {
                    Ok(_) => None,
                    Err(scmp_error_message) => {
                        maybe_create_scmp_reply(self.local_as, scmp_error_message.into(), packet)
                            .context("error creating SCMP reply after dispatching failed with ")?
                    }
                }
            }
            LocalAsRoutingAction::SendSCMPErrorResponse(scmp_error_message) => {
                maybe_create_scmp_reply(self.local_as, scmp_error_message.into(), packet)?
            }
            LocalAsRoutingAction::IngressSCMPHandleRequest { interface_id } => {
                debug_assert_eq!(
                    self.local_if_id, interface_id,
                    "This should always be the interface of the router"
                );
                self.handle_scmp(false, packet)
                    .context("error handling SCMP request")?
            }
            LocalAsRoutingAction::EgressSCMPHandleRequest { interface_id } => {
                debug_assert_eq!(
                    self.local_if_id, interface_id,
                    "This should always be the interface of the router"
                );
                self.handle_scmp(true, packet)
                    .context("error handling SCMP request")?
            }
        };

        let Some(scmp_reply) = scmp_reply else {
            // No reply, we are done
            return Ok(None);
        };

        if pkt_source_as != self.local_as {
            // Packet needs to be dispatched through SCION Network
            return Ok(Some(scmp_reply));
        }

        // Packet comes from this AS, dispatch
        let _ = self
            .dispatch(scmp_reply.into())
            .inspect_err(|e| tracing::warn!(error = %e, "Error dispatching SCMP back into AS"));

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
