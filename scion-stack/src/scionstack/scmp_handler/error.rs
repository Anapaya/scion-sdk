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
//! SCMP error handling implementation.

use scion_proto::{
    packet::{ScionPacketRaw, ScionPacketScmp},
    scmp::ScmpErrorMessage,
};

use super::ScmpHandler;
use crate::{scionstack::scmp_handler::ScmpErrorReceiver, types::Subscribers};

/// A SCMP handler that forwards SCMP messages to SCMP error receivers.
pub struct ScmpErrorHandler {
    receivers: Subscribers<dyn ScmpErrorReceiver>,
}

impl ScmpErrorHandler {
    /// Creates a new forwarding SCMP handler.
    pub fn new(receivers: Subscribers<dyn ScmpErrorReceiver>) -> Self {
        Self { receivers }
    }
}

impl ScmpHandler for ScmpErrorHandler {
    fn handle(&self, pkt: ScionPacketRaw) -> Option<ScionPacketRaw> {
        let path = pkt.headers.path();
        let scmp_pkg: ScionPacketScmp = if let Ok(scmp_pkg) = pkt.try_into() {
            scmp_pkg
        } else {
            return None;
        };

        let scmp_error: ScmpErrorMessage = match scmp_pkg.message.try_into() {
            Ok(scmp_error) => scmp_error,
            Err(_) => {
                tracing::debug!("ignoring non error SCMP message");
                return None;
            }
        };

        tracing::debug!(err = ?scmp_error, "reporting SCMP error");
        self.receivers.for_each(|receiver| {
            receiver.report_scmp_error(scmp_error.clone(), &path);
        });
        None
    }
}

#[cfg(test)]
mod scmp_error_handler_tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use scion_proto::{
        address::{Asn, EndhostAddr, Isd, IsdAsn},
        path::{
            Path,
            test_builder::{TestPathBuilder, TestPathContext},
        },
        scmp::{
            DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpEchoReply, ScmpEchoRequest,
            ScmpMessage,
        },
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
    fn forwards_scmp_error_messages_to_receivers() {
        let ctx = test_context();
        let scmp_msg = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet"),
        ));
        let packet = ctx.scion_packet_scmp(scmp_msg);
        let expected_path = packet.headers.path();

        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, p: &Path| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_)) && p == &expected_path
            })
            .times(1)
            .returning(|_, _| {});

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(packet.into());

        assert!(result.is_none());
        drop(receiver_arc); // ensure mock lives until assertions complete
    }

    #[test]
    fn ignores_non_error_scmp_messages() {
        let ctx = test_context();
        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver.expect_report_scmp_error().times(0);

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);

        // Test with EchoRequest
        let echo_request = ctx.scion_packet_scmp(ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            1,
            2,
            Bytes::from_static(b"data"),
        )));
        let result = handler.handle(echo_request.into());
        assert!(result.is_none());

        // Test with EchoReply
        let echo_reply = ctx.scion_packet_scmp(ScmpMessage::EchoReply(ScmpEchoReply::new(
            1,
            2,
            Bytes::from_static(b"data"),
        )));
        let result = handler.handle(echo_reply.into());
        assert!(result.is_none());
        drop(receiver_arc);
    }

    #[test]
    fn ignores_invalid_packets() {
        let ctx = test_context();
        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver.expect_report_scmp_error().times(0);

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);

        // Test with invalid packet data
        let invalid_packet = ctx.scion_packet_raw(b"not scmp");
        let result = handler.handle(invalid_packet);
        assert!(result.is_none());
        drop(receiver_arc);
    }

    #[test]
    fn handles_multiple_receivers() {
        let ctx = test_context();
        let error_msg = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet"),
        ));
        let packet = ctx.scion_packet_scmp(error_msg);
        let expected_path = packet.headers.path();

        let expected_path_clone1 = expected_path.clone();
        let expected_path_clone2 = expected_path.clone();
        let mut mock_receiver1 = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver1
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, p: &Path| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_))
                    && p == &expected_path_clone1
            })
            .times(1)
            .returning(|_, _| {});

        let mut mock_receiver2 = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver2
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, p: &Path| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_))
                    && p == &expected_path_clone2
            })
            .times(1)
            .returning(|_, _| {});

        let receiver1_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver1);
        let receiver2_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver2);
        let subscribers = Subscribers::new();
        subscribers.register(receiver1_arc.clone());
        subscribers.register(receiver2_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(packet.into());

        assert!(result.is_none());
        drop(receiver1_arc);
        drop(receiver2_arc);
    }

    #[test]
    fn handles_weak_references() {
        let ctx = test_context();
        let error_msg = ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable::new(
            DestinationUnreachableCode::AddressUnreachable,
            Bytes::from_static(b"offending packet"),
        ));
        let packet = ctx.scion_packet_scmp(error_msg);

        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        // When the strong reference is dropped, the weak reference won't upgrade,
        // so report_scmp_error should not be called
        mock_receiver.expect_report_scmp_error().times(0);

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc);

        // The Arc was moved into register, so the weak reference should not upgrade

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(packet.into());

        // Handler should return None even when weak references fail to upgrade
        assert!(result.is_none());
    }
}
