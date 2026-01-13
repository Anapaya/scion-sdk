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
use scion_proto::{
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketScmp},
    scmp::{ScmpEchoReply, ScmpMessage},
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

    fn try_echo_reply(&self, p_raw: ScionPacketRaw) -> anyhow::Result<Option<ScionPacketScmp>> {
        let p: ScionPacketScmp = p_raw.try_into().context("Failed to decode packet")?;
        let reply_msg = match p.message {
            ScmpMessage::EchoRequest(r) => {
                tracing::debug!("Echo request received, sending echo reply");
                ScmpMessage::EchoReply(ScmpEchoReply::new(r.identifier, r.sequence_number, r.data))
            }
            _ => return Ok(None),
        };
        let reply_path = p
            .headers
            .reversed_path(None)
            .context("Failed to reverse SCMP echo path")?
            .data_plane_path;

        let src = p
            .headers
            .address
            .source()
            .context("Failed to decode source address")?;

        let dst = p
            .headers
            .address
            .destination()
            .context("Failed to decode destination address")?;

        let reply = ScionPacketScmp::new(
            ByEndpoint {
                source: dst,
                destination: src,
            },
            reply_path,
            reply_msg,
        )
        .context("Failed to encode reply")?;
        Ok(Some(reply))
    }
}

impl ScmpHandler for DefaultEchoHandler {
    fn handle(&self, p_raw: ScionPacketRaw) -> Option<ScionPacketRaw> {
        match self.try_echo_reply(p_raw) {
            Ok(Some(reply)) => {
                tracing::debug!(
                    src = ?reply.headers.address.source(),
                    dst = ?reply.headers.address.destination(),
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
    use bytes::Bytes;
    use scion_proto::{
        address::{Asn, EndhostAddr, Isd, IsdAsn},
        path::test_builder::{TestPathBuilder, TestPathContext},
        scmp::{ScmpEchoReply, ScmpEchoRequest, ScmpMessage},
    };

    use super::*;

    fn test_context() -> TestPathContext {
        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(10)), [192, 0, 2, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(20)), [198, 51, 100, 1].into());
        TestPathBuilder::new(src, dst)
            .using_info_timestamp(42)
            .up()
            .add_hop(0, 11)
            .add_hop(12, 0)
            .build(77)
    }

    #[test]
    fn replies_to_echo_request() {
        let ctx = test_context();
        let expected_src = ctx.dst_address.into();
        let expected_dst = ctx.src_address.into();
        let request = ctx.scion_packet_scmp(ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            7,
            9,
            Bytes::from_static(b"payload"),
        )));

        let handler = DefaultEchoHandler::new();
        let reply = handler.handle(request.into());
        assert!(reply.is_some());
        let reply = reply.unwrap();
        let reply: ScionPacketScmp = reply.try_into().expect("valid SCMP packet in returning");
        match reply.message {
            ScmpMessage::EchoReply(r) => {
                assert_eq!(r.get_identifier(), 7);
                assert_eq!(r.get_sequence_number(), 9);
                assert_eq!(r.data, Bytes::from_static(b"payload"));
            }
            other => panic!("unexpected reply message: {other:?}"),
        }
        assert_eq!(reply.headers.address.source().unwrap(), expected_src);
        assert_eq!(reply.headers.address.destination().unwrap(), expected_dst);
    }

    #[test]
    fn ignores_non_echo_messages() {
        let ctx = test_context();
        let handler = DefaultEchoHandler::new();

        let non_echo = ctx.scion_packet_scmp(ScmpMessage::EchoReply(ScmpEchoReply::new(
            1,
            2,
            Bytes::from_static(b"resp"),
        )));

        let reply = handler.handle(non_echo.into());
        assert!(reply.is_none());
    }

    #[test]
    fn ignores_packets_that_fail_decoding() {
        let ctx = test_context();
        let handler = DefaultEchoHandler::new();

        let wrong_protocol = ctx.scion_packet_raw(b"not scmp");
        let reply = handler.handle(wrong_protocol);
        assert!(reply.is_none());
    }
}
