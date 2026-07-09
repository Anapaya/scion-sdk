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

use sciparse::{
    packet::{model::ScionRawPacket, view::ScionRawPacketView},
    payload::scmp::view::ScmpMessageExt,
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
    fn handle(&self, pkt: &ScionRawPacketView) -> Option<ScionRawPacket> {
        let path = pkt.header().path();
        let Ok(scmp_pkg) = pkt.try_as_scmp() else {
            tracing::debug!("ignoring non SCMP packet");
            return None;
        };

        if !scmp_pkg.scmp().message().is_error() {
            tracing::debug!("ignoring non error SCMP message");
            return None;
        }

        let scmp_error = scmp_pkg
            .scmp()
            .message()
            .to_model()
            .try_into_error_message()
            .inspect_err(|e| {
                debug_assert!(false, "scmp error was not an error: {e:?}");
            })
            .ok()?;

        tracing::debug!(err = ?scmp_error, "reporting SCMP error");
        self.receivers.for_each(|receiver| {
            receiver.report_scmp_error(scmp_error.clone(), path);
        });
        None
    }
}

#[cfg(test)]
mod scmp_error_handler_tests {
    use std::sync::Arc;

    use sciparse::{
        address::ip_addr::ScionIpAddr,
        core::model::Model,
        dataplane_path::view::{ScionDpPathViewExt, ScionDpPathViewRef},
        identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
        payload::scmp::{
            model::{ScmpDestinationUnreachable, ScmpEchoReply, ScmpEchoRequest, ScmpErrorMessage},
            types::ScmpDestinationUnreachableCode,
        },
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
    fn forwards_scmp_error_messages_to_receivers() {
        let ctx = test_context();
        let scmp_msg = ScmpDestinationUnreachable::new(
            ScmpDestinationUnreachableCode::AddressUnreachable,
            b"offending packet".to_vec(),
        )
        .into();

        let packet = ctx
            .scion_packet_scmp(scmp_msg)
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");

        let expected_path = packet.header().path().to_owned_view();

        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, path: &ScionDpPathViewRef| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_))
                    && *path == expected_path.as_ref()
            })
            .times(1)
            .returning(|_, _| {});

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(&packet);

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
        let echo_request = ctx
            .scion_packet_scmp(ScmpEchoRequest::new(1, 2, b"data".to_vec()).into())
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");
        let result = handler.handle(&echo_request);
        assert!(result.is_none());

        // Test with EchoReply
        let echo_reply = ctx
            .scion_packet_scmp(ScmpEchoReply::new(1, 2, b"data".to_vec()).into())
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");
        let result = handler.handle(&echo_reply);
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
        let result = handler.handle(
            &invalid_packet
                .try_encode_to_owned_view()
                .expect("failed to encode packet"),
        );
        assert!(result.is_none());
        drop(receiver_arc);
    }

    #[test]
    fn handles_multiple_receivers() {
        let ctx = test_context();
        let error_msg = ScmpDestinationUnreachable::new(
            ScmpDestinationUnreachableCode::AddressUnreachable,
            b"offending packet".to_vec(),
        )
        .into();

        let packet = ctx
            .scion_packet_scmp(error_msg)
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");
        let expected_path = packet.header().path().to_owned_view();

        let expected_path_clone1 = expected_path.clone();
        let expected_path_clone2 = expected_path.clone();
        let mut mock_receiver1 = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver1
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, p: &ScionDpPathViewRef| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_))
                    && p == &expected_path_clone1.as_ref()
            })
            .times(1)
            .returning(|_, _| {});

        let mut mock_receiver2 = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        mock_receiver2
            .expect_report_scmp_error()
            .withf(move |error: &ScmpErrorMessage, p: &ScionDpPathViewRef| {
                matches!(error, ScmpErrorMessage::DestinationUnreachable(_))
                    && p == &expected_path_clone2.as_ref()
            })
            .times(1)
            .returning(|_, _| {});

        let receiver1_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver1);
        let receiver2_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver2);
        let subscribers = Subscribers::new();
        subscribers.register(receiver1_arc.clone());
        subscribers.register(receiver2_arc.clone());

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(&packet);

        assert!(result.is_none());
        drop(receiver1_arc);
        drop(receiver2_arc);
    }

    #[test]
    fn handles_weak_references() {
        let ctx = test_context();
        let error_msg = ScmpDestinationUnreachable::new(
            ScmpDestinationUnreachableCode::AddressUnreachable,
            b"offending packet".to_vec(),
        )
        .into();

        let packet = ctx
            .scion_packet_scmp(error_msg)
            .into_raw()
            .try_encode_to_owned_view()
            .expect("should encode");

        let mut mock_receiver = crate::scionstack::scmp_handler::MockScmpErrorReceiver::new();
        // When the strong reference is dropped, the weak reference won't upgrade,
        // so report_scmp_error should not be called
        mock_receiver.expect_report_scmp_error().times(0);

        let receiver_arc: Arc<dyn ScmpErrorReceiver> = Arc::new(mock_receiver);
        let subscribers = Subscribers::new();
        subscribers.register(receiver_arc);

        // The Arc was moved into register, so the weak reference should not upgrade

        let handler = ScmpErrorHandler::new(subscribers);
        let result = handler.handle(&packet);

        // Handler should return None even when weak references fail to upgrade
        assert!(result.is_none());
    }
}
