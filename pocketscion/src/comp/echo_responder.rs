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

//! A small server, which responds to SCMP echo requests with echo replies

use anyhow::Context;
use ipnet::IpNet;
use sciparse::{
    core::model::Model,
    dataplane_path::view::ScionDpPathViewExt,
    packet::{
        model::ScionScmpPacket,
        view::{ScionRawPacketView, ScionScmpPacketView},
    },
    payload::scmp::{
        model::{ScmpEchoReply, ScmpMessage},
        view::ScmpMessageView,
    },
};

use crate::{
    network::{local::receivers::Receiver, scion::routing::ScionNetworkTime},
    state::PocketScionState,
};

/// A small server, which responds to SCMP echo requests with echo replies
pub struct PsEchoResponder {
    state: PocketScionState,
}

impl PsEchoResponder {
    /// Creates a new SCMP echo responder with the given state.
    pub fn new(state: PocketScionState) -> Self {
        Self { state }
    }

    fn handle_receive(&self, recv: &ScionRawPacketView) {
        let scmp_message = match ScionScmpPacketView::try_from_raw(recv) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("Failed to parse incoming bytes as SCMP message: {:?}", e);
                return;
            }
        };

        let Some(reply) = self.handle_scmp_message(scmp_message) else {
            return;
        };

        let reply = match reply.try_encode_to_owned_view() {
            Ok(repl) => repl,
            Err(e) => {
                tracing::error!("Failed to encode SCMP reply: {:?}", e);
                return;
            }
        };

        // Spawn in task to avoid deadlock
        tokio::spawn({
            let state_c = self.state.clone();

            async move {
                let local_as = reply.header().src_ia();
                let mut raw = reply.into_raw();
                state_c.dispatch_to_network_sim(local_as, 0, ScionNetworkTime::now(), &mut raw);
            }
        });
    }

    fn handle_scmp_message(&self, scmp_message: &ScionScmpPacketView) -> Option<ScionScmpPacket> {
        let _span = tracing::debug_span!(
            "scmp",
            src = tracing::field::Empty,
            dst = tracing::field::Empty,
        )
        .entered();

        let fallible = || {
            let src = scmp_message
                .src_scion_addr()
                .context("Failed to get source SCION address")?;
            tracing::span::Span::current().record("src", tracing::field::display(src));
            let dst = scmp_message
                .dst_scion_addr()
                .context("Failed to get destination SCION address")?;
            tracing::span::Span::current().record("dst", tracing::field::display(dst));

            let reply = match scmp_message.scmp().message() {
                ScmpMessageView::EchoRequest(req) => {
                    tracing::debug!("Received SCMP echo request");

                    ScmpMessage::EchoReply(ScmpEchoReply {
                        identifier: req.identifier(),
                        sequence_number: req.sequence_number(),
                        data: req.data().to_vec(),
                    })
                }
                _ => {
                    tracing::warn!("Received unsupported SCMP message type: {:?}", scmp_message);
                    return Ok(None);
                }
            };

            let reply_path = scmp_message
                .header()
                .path()
                .to_model()
                .try_into_reversed()
                .map_err(|(_, e)| e)
                .context("Failed to reverse path")?;

            // We respond with swapped source and destination addresses, and the reversed path.
            let reply_packet = ScionScmpPacket::new(dst, src, reply_path, reply);

            anyhow::Ok(Some(reply_packet))
        };

        match fallible() {
            Ok(reply_packet) => reply_packet,
            Err(e) => {
                tracing::error!("Failed to handle SCMP message: {:?}", e);
                None
            }
        }
    }
}

impl Receiver for PsEchoResponder {
    fn receive_packet(&self, packet: &sciparse::packet::view::ScionRawPacketView) {
        self.handle_receive(packet);
    }
}

impl PocketScionState {
    /// Enables a SCMP echo responder for all ASes in the system, with the given listen address.
    ///
    /// This will cause the system to respond to all SCMP echo request to the given listen address,
    /// regardless of the destination AS. As long as packets actually arrive their destination AS.
    pub fn enable_global_scmp_echo_responder(&self, listen_addr: IpNet) {
        self.write().global_scmp_echo_responder = Some(listen_addr);
    }
}
