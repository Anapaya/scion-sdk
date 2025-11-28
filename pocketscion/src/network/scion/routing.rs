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
//! Routing Logic at a SCION AS
//!
//! This module defines the interface and types for processing SCION packets in a routing context.

use chrono::{DateTime, Utc};
use derive_more::Display;
use scion_proto::{
    address::{IsdAsn, ScionAddr},
    packet::ScionPacketRaw,
    path::crypto::ForwardingKey,
    scmp::ScmpErrorMessage,
};

pub mod spec;

/// The current unix epoch in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScionNetworkTime(pub u32);
impl ScionNetworkTime {
    /// Returns the current unix epoch in seconds.
    pub fn now() -> Self {
        ScionNetworkTime(Utc::now().timestamp() as u32)
    }

    /// New ScionNetworkTime from a unix epoch in seconds.
    pub fn from_timestamp_secs(secs: u32) -> Self {
        ScionNetworkTime(secs)
    }

    /// Converts the internal timestamp to a [`DateTime<Utc>`].
    pub fn date_time(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.0 as i64, 0)
            .expect("u32 timestamp can not be out of range")
    }

    /// Returns the inner unix epoch in seconds.
    pub fn inner(&self) -> u32 {
        self.0
    }
}

/// Trait for routing SCION packets in a SCION AS.
pub trait RoutingLogic {
    /// Processes a SCION packet and decides on the next step which should be taken for it.
    ///
    /// The function will modify the packet in place, updating its headers and hop fields as
    /// necessary.
    ///
    ///
    /// # Parameters
    /// * `local_as` - The AS processing the packet
    /// * `scion_packet` - The SCION packet to be processed
    /// * `ingress_interface_id` - The interface ID where the packet was received
    /// * `interface_lookup` - Callback to get interface state by interface ID
    /// * `now` - current Unix Epoch in seconds
    /// * `as_forwarding_key` - Optional cryptographic key for MAC verification
    ///
    /// # Returns
    /// * Ok([AsRoutingAction]) - How the packet should be handled next
    /// * Err([ScmpErrorMessage]) - An error message to be sent back to the sender
    ///
    /// Note; You can .into the result into a [AsRoutingAction] directly.
    fn route(
        local_as: IsdAsn,
        scion_packet: &mut ScionPacketRaw,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState>,
    ) -> Result<AsRoutingAction, ScmpErrorMessage>;
}

// Allows ScmpErrorMessages to be returned either as a decision, or an error
impl From<Result<AsRoutingAction, ScmpErrorMessage>> for AsRoutingAction {
    fn from(value: Result<AsRoutingAction, ScmpErrorMessage>) -> Self {
        match value {
            Ok(decision) => decision,
            Err(err) => AsRoutingAction::Local(LocalAsRoutingAction::SendSCMPErrorResponse(err)),
        }
    }
}

/// Routing action to be executed on the current AS
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAsRoutingAction {
    /// Packet should be handled as a SCMP request at the ingress interface
    IngressSCMPHandleRequest {
        /// Interface ID where the packet was received
        interface_id: u16,
    },
    /// Packet should be handled as a SCMP request at the egress interface
    EgressSCMPHandleRequest {
        /// Interface ID where the packet should be sent
        interface_id: u16,
    },
    /// Packet should be forwarded to the given local address
    ForwardLocal {
        /// Address to forward the packet to.
        target_address: ScionAddr,
    },
    /// A SCMP error response should be sent
    SendSCMPErrorResponse(ScmpErrorMessage),
}

impl From<LocalAsRoutingAction> for AsRoutingAction {
    fn from(value: LocalAsRoutingAction) -> Self {
        AsRoutingAction::Local(value)
    }
}

/// Action to be taken after a the routing step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsRoutingAction {
    /// Packet is to be handled at the current AS
    Local(LocalAsRoutingAction),
    /// Packet should be forwarded to the next hop through the given interface id
    ForwardNextHop {
        /// Interface ID to forward the packet to.
        link_interface_id: u16,
    },
    /// Packet should be dropped
    Drop,
}

/// State of a given interface in the AS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRoutingInterfaceState {
    pub(crate) link_type: AsRoutingLinkType,
    pub(crate) is_up: bool,
}

/// Defines the Link Type of a given Interface
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsRoutingLinkType {
    /// Link to a core AS.
    LinkToCore,
    /// Link to a parent AS.
    LinkToParent,
    /// Link to a child AS.
    LinkToChild,
    /// Link to a peer AS.
    LinkToPeer,
}

impl AsRoutingLinkType {
    /// Returns the reverse link type of the current link type.
    pub fn reverse(&self) -> Self {
        match self {
            AsRoutingLinkType::LinkToCore => AsRoutingLinkType::LinkToCore,
            AsRoutingLinkType::LinkToParent => AsRoutingLinkType::LinkToChild,
            AsRoutingLinkType::LinkToChild => AsRoutingLinkType::LinkToParent,
            AsRoutingLinkType::LinkToPeer => AsRoutingLinkType::LinkToPeer,
        }
    }
}
