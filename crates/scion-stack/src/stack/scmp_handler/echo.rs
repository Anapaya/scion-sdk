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
//! Default SCMP echo handler.

use anyhow::Context as _;
use sciparse::{
    dataplane_path::view::ScionDpPathViewExt,
    packet::{
        model::{ScionRawPacket, ScionScmpPacket},
        view::ScionRawPacketView,
    },
    payload::scmp::{
        model::{ScmpEchoReply, ScmpMessage},
        view::ScmpMessageView,
    },
};

use super::ScmpHandler;

/// Handler to reply to echo requests. The handler only makes sense for sockets that are bound
/// to the default SCION port 30041 <https://docs.scion.org/en/latest/dev/design/router-port-dispatch.html#scmp>
pub struct DefaultEchoHandler;

impl Default for DefaultEchoHandler {
    fn default() -> Self {
        Self
    }
}

impl DefaultEchoHandler {
    /// Create a new default echo handler.
    pub fn new() -> Self {
        Self
    }

    fn try_echo_reply(
        &self,
        p_raw: &ScionRawPacketView,
    ) -> anyhow::Result<Option<ScionScmpPacket>> {
        let p = p_raw
            .try_as_scmp()
            .context("Packet is not a valid SCMP packet")?;

        let reply_msg = match p.scmp().message() {
            ScmpMessageView::EchoRequest(r) => {
                tracing::debug!("Echo request received, sending echo reply");
                ScmpMessage::EchoReply(ScmpEchoReply::new(
                    r.identifier(),
                    r.sequence_number(),
                    r.data().to_vec(),
                ))
            }
            _ => return Ok(None),
        };
        let reply_path = p
            .header()
            .path()
            .to_model()
            .try_into_reversed()
            .map_err(|(_, e)| anyhow::anyhow!("Failed to reverse path: {e:?}"))?;

        let src = p
            .src_scion_addr()
            .context("Failed to decode source address")?;

        let dst = p
            .dst_scion_addr()
            .context("Failed to decode destination address")?;

        let reply = ScionScmpPacket::new(dst, src, reply_path, reply_msg);

        Ok(Some(reply))
    }
}

impl ScmpHandler for DefaultEchoHandler {
    fn handle(&self, p_raw: &ScionRawPacketView) -> Option<ScionRawPacket> {
        match self.try_echo_reply(p_raw) {
            Ok(Some(reply)) => {
                tracing::debug!(
                    src = ?reply.src_scion_addr(),
                    dst = ?reply.dst_scion_addr(),
                    "Sending echo reply"
                );
                Some(reply.into())
            }
            Ok(None) => None,
            Err(e) => {
                tracing::info!(error = %e, "Received invalid SCMP echo request");
                None
            }
        }
    }
}

#[cfg(test)]
mod default_echo_handler_tests {
    use sciparse::{
        address::ip_addr::ScionIpAddr,
        core::model::Model,
        identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
        payload::scmp::model::ScmpEchoRequest,
        util::test_builder::{TestPathBuilder, TestPathContext},
    };

    use super::*;

    fn test_context() -> TestPathContext {
        let src = ScionIpAddr::new(IsdAsn::new(Isd(1), Asn(10)), [192, 0, 2, 1].into());
        let dst = ScionIpAddr::new(IsdAsn::new(Isd(1), Asn(20)), [198, 51, 100, 1].into());
        TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(42)
            .up()
            .add_hop(0, 11)
            .add_hop(12, 0)
            .build(77)
    }

    #[test]
    fn replies_to_echo_request() {
        let ctx = test_context();
        let expected_src = ctx.dst_address;
        let expected_dst = ctx.src_address;
        let request = ctx
            .scion_packet_scmp(ScmpEchoRequest::new(7, 9, b"payload".to_vec()).into())
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");

        let handler = DefaultEchoHandler::new();
        let reply = handler.handle(&request);
        assert!(reply.is_some());
        let reply = reply.unwrap();
        let reply = reply
            .try_into_scmp()
            .expect("valid SCMP packet in returning");
        match &reply.payload {
            ScmpMessage::EchoReply(r) => {
                assert_eq!(r.identifier, 7);
                assert_eq!(r.sequence_number, 9);
                assert_eq!(r.data, b"payload");
            }
            other => panic!("unexpected reply message: {other:?}"),
        }
        assert_eq!(reply.src_scion_addr().unwrap(), expected_src);
        assert_eq!(reply.dst_scion_addr().unwrap(), expected_dst);
    }

    #[test]
    fn ignores_non_echo_messages() {
        let ctx = test_context();
        let handler = DefaultEchoHandler::new();

        let non_echo = ctx
            .scion_packet_scmp(ScmpEchoReply::new(1, 2, b"resp".to_vec()).into())
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");

        let reply = handler.handle(&non_echo);
        assert!(reply.is_none());
    }

    #[test]
    fn ignores_packets_that_fail_decoding() {
        let ctx = test_context();
        let handler = DefaultEchoHandler::new();

        let wrong_protocol = ctx
            .scion_packet_raw(b"not scmp")
            .try_encode_to_owned_view()
            .expect("should encode");
        let reply = handler.handle(&wrong_protocol);
        assert!(reply.is_none());
    }
}
