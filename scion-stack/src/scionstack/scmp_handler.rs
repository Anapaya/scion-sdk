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
//! SCION stack SCMP handler.

use std::pin::Pin;

use scion_proto::{
    packet::{ByEndpoint, ScionPacketScmp},
    scmp::{ScmpEchoReply, ScmpMessage},
    wire_encoding::WireEncodeVec as _,
};

use crate::snap_tunnel::SnapTunnelSender;

/// A trait for handling SCMP packets when they are received.
/// It will be called with all SCMP packets that are received irrespective
/// whether a destination port is specified or not.
pub trait ScmpHandler: Send + Sync {
    /// Handle a received SCMP packet.
    fn handle_packet(
        &self,
        packet: ScionPacketScmp,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Default SCMP handller.
pub struct DefaultScmpHandler {
    tunnel_sender: SnapTunnelSender,
}

impl Clone for DefaultScmpHandler {
    fn clone(&self) -> Self {
        Self {
            tunnel_sender: self.tunnel_sender.clone(),
        }
    }
}

impl DefaultScmpHandler {
    /// Creates a new default SCMP handler.
    pub fn new(tunnel_sender: SnapTunnelSender) -> Self {
        Self { tunnel_sender }
    }
}

impl ScmpHandler for DefaultScmpHandler {
    fn handle_packet(&self, p: ScionPacketScmp) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let reply = match p.message {
                ScmpMessage::EchoRequest(r) => {
                    tracing::debug!("Echo request received, sending echo reply");
                    ScmpMessage::EchoReply(ScmpEchoReply::new(
                        r.identifier,
                        r.sequence_number,
                        r.data,
                    ))
                }
                _ => return,
            };

            let reply_path = match p.headers.reversed_path(None) {
                Ok(path) => path.data_plane_path,
                Err(e) => {
                    tracing::debug!(error = %e, "Error reversing path of SCMP packet");
                    return;
                }
            };

            let src = match p.headers.address.source() {
                Some(src) => src,
                None => {
                    tracing::debug!("Error decoding source address of SCMP packet");
                    return;
                }
            };
            let dst = match p.headers.address.destination() {
                Some(dst) => dst,
                None => {
                    tracing::debug!("Error decoding destination address of SCMP packet");
                    return;
                }
            };

            let reply_packet = match ScionPacketScmp::new(
                ByEndpoint {
                    source: dst,
                    destination: src,
                },
                reply_path,
                reply,
            ) {
                Ok(packet) => packet,
                Err(e) => {
                    tracing::debug!(error = %e, "Error encoding SCMP reply");
                    return;
                }
            };
            match self
                .tunnel_sender
                .send_datagram(reply_packet.encode_to_bytes_vec().concat().into())
            {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Error sending SCMP reply");
                }
            }
        })
    }
}
