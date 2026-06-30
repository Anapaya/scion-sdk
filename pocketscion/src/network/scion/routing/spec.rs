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

//! SCION routing logic

// TODO: Peer link handling is not implemented yet

use sciparse::{
    core::view::View,
    dataplane_path::{standard::mac::ForwardingKey, view::ScionDpPathViewRefMut},
    identifier::isd_asn::IsdAsn,
    packet::view::ScionRawPacketView,
    payload::scmp::{
        model::{ScmpErrorMessage, ScmpParameterProblem},
        types::ScmpParameterProblemCode,
    },
};

use crate::network::scion::routing::{
    AsRoutingAction, AsRoutingInterfaceState, LocalAsRoutingAction, RoutingLogic, ScionNetworkTime,
    spec::{onehop::OneHopRoutingLogic, standard::StdRoutingLogic},
};

pub mod onehop;
pub mod standard;

/// SCION Routing logic
pub struct SpecRoutingLogic;

impl RoutingLogic for SpecRoutingLogic {
    fn route(
        local_as: IsdAsn,
        scion_packet: &mut ScionRawPacketView,
        ingress_interface_id: u16,
        now: ScionNetworkTime,
        as_forwarding_key: &ForwardingKey,
        interface_link_type_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState>,
        ignore_macs: bool,
    ) -> Result<super::AsRoutingAction, ScmpErrorMessage> {
        // Extract path from the packet

        let res = match scion_packet.header_mut().path_mut() {
            ScionDpPathViewRefMut::Standard(path) => {
                let result = StdRoutingLogic::handle_standard_path(
                    local_as,
                    path,
                    ingress_interface_id,
                    now,
                    as_forwarding_key,
                    &interface_link_type_lookup,
                    ignore_macs,
                );

                match result {
                    Ok(action) => Ok(action),
                    Err(err) => {
                        match err.to_scmp_error(local_as, scion_packet) {
                            Some(reply) => Err(reply),
                            None => Ok(AsRoutingAction::Drop),
                        }
                    }
                }
            }
            ScionDpPathViewRefMut::OneHop(path) => {
                let result = OneHopRoutingLogic::handle_one_hop_path(
                    local_as,
                    path,
                    ingress_interface_id,
                    now,
                    as_forwarding_key,
                    &interface_link_type_lookup,
                    ignore_macs,
                );

                match result {
                    Ok(action) => Ok(action),
                    Err(err) => {
                        match err.to_scmp_error(scion_packet) {
                            Some(reply) => Err(reply),
                            None => Ok(AsRoutingAction::Drop),
                        }
                    }
                }
            }
            ScionDpPathViewRefMut::Empty => Ok(LocalAsRoutingAction::ForwardLocal.into()),
            ScionDpPathViewRefMut::Unsupported { .. } => {
                // Can't send a reply, since we don't know the path type, so we just drop
                // the packet
                return Ok(AsRoutingAction::Drop);
            }
        };

        let action = res?;

        if let AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal) = action {
            let dst_ia = scion_packet.header().dst_ia();
            if local_as != dst_ia {
                return Err(ScmpParameterProblem::new(
                    ScmpParameterProblemCode::NonLocalDelivery,
                    0,
                    scion_packet.as_slice().to_vec(),
                )
                .into());
            };
        }

        Ok(action)
    }
}

/// Next Action to be taken after Ingress Router processing
pub enum IngressNextAction {
    /// Processing is complete
    Complete(AsRoutingAction),
    /// Processing continues at the given egress interface
    ContinueEgress {
        /// The egress interface id to continue processing at
        egress_interface_id: u16,
    },
}

impl From<AsRoutingAction> for IngressNextAction {
    fn from(action: AsRoutingAction) -> Self {
        IngressNextAction::Complete(action)
    }
}

#[cfg(test)]
mod tests {

    use helper::*;

    use super::*;
    const SECONDS_PER_EXP_UNIT: u32 = 337;

    mod one_hop_path {
        use std::str::FromStr;

        use sciparse::{
            address::ip_addr::ScionIpAddr,
            core::{convert::ToModel, model::Model},
            dataplane_path::{onehop::model::OneHopPath, view::ScionDpPathViewRef},
            packet::model::ScionRawPacket,
            payload::ProtocolNumber,
        };

        use super::*;
        use crate::network::scion::{routing::AsRoutingLinkType, topology::ScionAs};

        #[test_log::test]
        fn should_ping_pong_one_hop_path() {
            let src_address = ScionIpAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionIpAddr::from_str("1-3,4.4.4.4").unwrap();

            let src_as = ScionAs::new_core(src_address.isd_asn());
            let src_forwarding_key = src_as.forwarding_key().unwrap();

            let dst_as = ScionAs::new_core(dst_address.isd_asn());
            let dst_forwarding_key = dst_as.forwarding_key().unwrap();

            // Packet flow is 1-1#1 > 1-3#2

            let src_interface = 1;
            let dst_interface = 2;

            let lookup_fn = |id| {
                match id {
                    1 => {
                        Some(AsRoutingInterfaceState {
                            is_up: true,
                            link_type: AsRoutingLinkType::LinkToCore,
                        })
                    }
                    2 => {
                        Some(AsRoutingInterfaceState {
                            is_up: true,
                            link_type: AsRoutingLinkType::LinkToCore,
                        })
                    }
                    _ => None,
                }
            };

            let mut packet = ScionRawPacket::new(
                src_address.into(),
                dst_address.into(),
                OneHopPath::new(src_interface, 0, 0, src_forwarding_key, 255).into(),
                ProtocolNumber::Other(0),
                Vec::new(),
            )
            .encode_to_owned_view()
            .expect("Failed to encode packet");

            let action = SpecRoutingLogic::route(
                src_address.isd_asn(),
                &mut packet,
                0,
                ScionNetworkTime::from_timestamp_secs(0),
                &src_forwarding_key,
                lookup_fn,
                false,
            )
            .unwrap();

            assert_eq!(
                action,
                AsRoutingAction::ForwardNextHop {
                    egress_interface_id: src_interface
                },
                "One-hop path should forward to the correct egress interface"
            );

            let action = SpecRoutingLogic::route(
                dst_address.isd_asn(),
                &mut packet,
                dst_interface,
                ScionNetworkTime::from_timestamp_secs(0),
                &dst_forwarding_key,
                lookup_fn,
                false,
            )
            .unwrap();

            assert_eq!(
                action,
                AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal),
                "Packet should be forwarded locally at the destination"
            );

            let path = match packet.header().path() {
                ScionDpPathViewRef::OneHop(path) => {
                    path.to_model()
                        .into_reversed_standard_path()
                        .expect("Failed to convert OneHopPath to StandardPath")
                }
                _ => panic!("Path should be decodable as OneHop"),
            };

            let mut packet = ScionRawPacket::new(
                dst_address.into(),
                src_address.into(),
                path.into(),
                ProtocolNumber::Other(0),
                Vec::new(),
            )
            .encode_to_owned_view()
            .expect("Failed to encode packet");

            let action = SpecRoutingLogic::route(
                dst_address.isd_asn(),
                &mut packet,
                0,
                ScionNetworkTime::from_timestamp_secs(0),
                &dst_forwarding_key,
                lookup_fn,
                false,
            )
            .unwrap();

            // Should forward to the next hop again, since the reversed path is a standard path with
            // one hop field
            assert_eq!(
                action,
                AsRoutingAction::ForwardNextHop {
                    egress_interface_id: dst_interface
                },
                "After reversing, the path should forward to the next hop again"
            );

            let action = SpecRoutingLogic::route(
                src_address.isd_asn(),
                &mut packet,
                src_interface,
                ScionNetworkTime::from_timestamp_secs(0),
                &src_forwarding_key,
                lookup_fn,
                false,
            )
            .unwrap();

            assert_eq!(
                action,
                AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal),
                "After reversing, the packet should be forwarded locally at the src"
            );
        }
    }

    mod standard_path {

        use std::str::FromStr;

        use sciparse::{
            address::addr::ScionAddr, payload::scmp::types::ScmpParameterProblemCode,
            util::test_builder::TestPathBuilder,
        };

        use super::*;

        #[test_log::test]
        fn should_correctly_route_simple_path() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .using_forwarding_key([3; 16])
                .add_hop(0, 1)
                .using_forwarding_key([1; 16])
                .add_hop(2, 0)
                .build(1);

            SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal,
                )));

            // Final Egress interface can also be non 0
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 4)
                .build(1);

            SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal,
                )));
        }

        #[test_log::test]
        fn should_correctly_route_segment_changes() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .core()
                .add_hop(0, 10)
                .add_hop(11, 0)
                .down()
                .add_hop(0, 3)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 10,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 3,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal,
                )));
        }

        #[test_log::test]
        fn should_fail_on_invalid_segment_change() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .core()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .up()
                .add_hop(0, 3)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::InvalidSegmentChange);

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .down()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .up()
                .add_hop(0, 3)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::InvalidSegmentChange);

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .up()
                .add_hop(0, 3)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::InvalidSegmentChange);
        }

        #[test_log::test]
        fn should_fail_with_non_local_destination() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail_with_local_as(IsdAsn(1234))
                .expect_parameter_problem(ScmpParameterProblemCode::NonLocalDelivery);
        }

        #[test_log::test]
        fn should_fail_on_invalid_egress() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .down()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .build(1);

            SpecTestCtx::new(test_ctx)
                .with_custom_link_lookup(|_| None)
                .next_hop_should_fail()
                .expect_parameter_problem(
                    ScmpParameterProblemCode::UnknownHopFieldConsEgressInterface,
                );
        }

        #[test_log::test]
        fn should_fail_on_down_egress() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .down()
                .add_hop_with_egress_down(0, 1)
                .add_hop(2, 0)
                .build(1);

            SpecTestCtx::new(test_ctx)
                .next_hop_should_fail()
                .expect_external_interface_down();
        }

        #[test_log::test]
        fn should_fail_on_invalid_mac() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .using_forwarding_key([3; 16])
                .add_hop(0, 1)
                .using_forwarding_key([1; 16])
                .add_hop(2, 0)
                .build_with_path_modifier(1, |mut p| {
                    p.segments[0].hop_fields[0].mac = [0; 6].into(); // Invalid MAC
                    p
                });
            SpecTestCtx::new(test_ctx)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::InvalidHopFieldMac);
        }

        #[test_log::test]
        fn should_drop_on_single_hop() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .core()
                .add_hop(0, 1)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Option::Some(AsRoutingAction::Drop));
        }
    }

    mod empty_path {
        use std::str::FromStr;

        use sciparse::{
            address::addr::ScionAddr, core::model::Model,
            dataplane_path::standard::mac::ForwardingKey, util::test_builder::TestPathBuilder,
        };

        use crate::network::scion::routing::{
            AsRoutingAction, LocalAsRoutingAction, RoutingLogic, ScionNetworkTime,
            spec::SpecRoutingLogic,
        };

        #[test_log::test]
        fn should_correctly_route_empty_path() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-1,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .build(1);

            let action = SpecRoutingLogic::route(
                src_address.isd_asn(),
                &mut test_ctx
                    .scion_packet_udp(&[1, 2], 1234, 1234)
                    .into_raw()
                    .encode_to_owned_view()
                    .unwrap(),
                0,
                ScionNetworkTime::from_timestamp_secs(test_ctx.timestamp),
                &ForwardingKey::default(),
                |_| None,
                false,
            )
            .expect("Empty path should not fail");

            assert_eq!(
                action,
                AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal),
                "Empty path should forward to local address"
            );
        }
    }

    mod time {
        use std::str::FromStr;

        use sciparse::{
            address::addr::ScionAddr, payload::scmp::types::ScmpParameterProblemCode,
            util::test_builder::TestPathBuilder,
        };

        use super::*;

        #[test_log::test]
        fn should_fail_with_bad_timestamps() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            // Timestamp in future
            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(1)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(0),
            )
            .next_hop_should_fail()
            .expect_parameter_problem(ScmpParameterProblemCode::InvalidPath);

            // Timestamp expired
            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(0)
                    .with_hop_expiry(0)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(SECONDS_PER_EXP_UNIT + 1),
            )
            .next_hop_should_fail()
            .expect_parameter_problem(ScmpParameterProblemCode::PathExpired);
        }

        #[test_log::test]
        fn should_not_fail_with_good_timestamp() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            helper::SpecTestCtx::new(
                TestPathBuilder::new(src_address, dst_address)
                    .using_info_timestamp(0)
                    .with_hop_expiry(0)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 0)
                    .build(SECONDS_PER_EXP_UNIT),
            )
            .next_hop_should_succeed(None);
        }
    }

    mod scmp {
        use std::str::FromStr;

        use sciparse::{
            address::addr::ScionAddr, payload::scmp::types::ScmpParameterProblemCode,
            util::test_builder::TestPathBuilder,
        };

        use super::*;

        #[test_log::test]
        fn should_handle_ingress_scmp_requests_on_first_hop() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop_with_alerts(0, true, 1, false)
                .add_hop(2, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx).next_hop_should_succeed(Some(
                AsRoutingAction::Local(LocalAsRoutingAction::IngressSCMPHandleRequest {
                    interface_id: 0,
                }),
            ));
        }

        #[test_log::test]
        fn should_handle_ingress_scmp_requests() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, true, 0, false)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::IngressSCMPHandleRequest { interface_id: 2 },
                )));
        }

        #[test_log::test]
        fn should_handle_egress_scmp_requests() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 3, true)
                .add_hop(4, 5)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::EgressSCMPHandleRequest { interface_id: 3 },
                )));
        }

        #[test_log::test]
        fn should_ignore_egress_scmp_on_final_hop() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            // No egress scmp on final hop
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 0, true)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(Some(AsRoutingAction::ForwardNextHop {
                    egress_interface_id: 1,
                }))
                .next_hop_should_succeed(Some(AsRoutingAction::Local(
                    LocalAsRoutingAction::ForwardLocal,
                )));
        }

        #[test_log::test]
        fn should_fail_with_scmp_during_segment_change() {
            let src_address = ScionAddr::from_str("1-1,2.2.2.2").unwrap();
            let dst_address = ScionAddr::from_str("1-3,4.4.4.4").unwrap();

            // Not before segment change
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop_with_alerts(2, false, 0, true)
                .down()
                .add_hop(2, 0)
                .add_hop(4, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::ErroneousHeaderField);

            // Not after segment change
            let test_ctx = TestPathBuilder::new(src_address, dst_address)
                .using_info_timestamp(0)
                .up()
                .add_hop(0, 1)
                .add_hop(2, 0)
                .down()
                .add_hop_with_alerts(3, true, 4, false)
                .add_hop(5, 0)
                .build(1);

            helper::SpecTestCtx::new(test_ctx)
                .next_hop_should_succeed(None)
                .next_hop_should_fail()
                .expect_parameter_problem(ScmpParameterProblemCode::ErroneousHeaderField);
        }
    }

    mod helper {

        use sciparse::{
            core::model::Model,
            dataplane_path::view::ScionDpPathViewRef,
            identifier::isd_asn::IsdAsn,
            packet::view::ScionRawPacketView,
            payload::scmp::{model::ScmpErrorMessage, types::ScmpParameterProblemCode},
            util::test_builder::{TestPathBuilderHopField, TestPathContext},
        };

        use crate::network::scion::routing::{
            AsRoutingAction, AsRoutingInterfaceState, RoutingLogic, ScionNetworkTime,
            spec::SpecRoutingLogic,
        };

        /// Helper to iterate over test steps
        pub struct SpecTestCtx {
            pub test_context: TestPathContext,
            pub packet: Box<ScionRawPacketView>,
            pub last_error: Option<ScmpErrorMessage>,
            pub custom_link_lookup: Option<Box<dyn Fn(u16) -> Option<AsRoutingInterfaceState>>>,
        }

        impl SpecTestCtx {
            pub fn new(test_context: TestPathContext) -> Self {
                Self {
                    packet: test_context
                        .scion_packet_udp(&[1, 2], 22222, 11111)
                        .into_raw()
                        .encode_to_owned_view()
                        .expect("Failed to encode packet"),
                    test_context,
                    last_error: None,
                    custom_link_lookup: None,
                }
            }

            /// Registers a custom link lookup function to be used for interface lookups during
            /// routing
            pub fn with_custom_link_lookup(
                mut self,
                custom_link_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState> + 'static,
            ) -> Self {
                self.custom_link_lookup = Some(Box::new(custom_link_lookup));
                self
            }

            /// Looks up the interface type through the.
            ///
            /// If a segment change is detected, this will also allow the interfaces of the next hop
            /// field to be used.
            fn lookup_interface(
                custom_link_lookup: Option<impl Fn(u16) -> Option<AsRoutingInterfaceState>>,
                hop_fields: &[TestPathBuilderHopField],
                current_hop_index: u8,
                interface_id: u16,
            ) -> Option<AsRoutingInterfaceState> {
                if let Some(ref custom_lookup) = custom_link_lookup {
                    return custom_lookup(interface_id);
                }

                let current = &hop_fields[current_hop_index as usize];

                match interface_id {
                    val if current.ingress_if == val => {
                        return current.ingress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    val if current.egress_if == val => {
                        return current.egress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    _ => {}
                }

                if !current.segment_change_next {
                    return None;
                };

                // On segment change, can also use the next hop fields interfaces
                let next = &hop_fields[current_hop_index as usize + 1];

                match interface_id {
                    val if next.ingress_if == val => {
                        return next.ingress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    val if next.egress_if == val => {
                        return next.egress_link_type.map(|l| {
                            AsRoutingInterfaceState {
                                link_type: l.into(),
                                is_up: !current.egress_interface_down,
                            }
                        });
                    }
                    _ => {}
                }

                None
            }

            /// Performs the next hop routing step and expects it to succeed.
            pub fn next_hop_should_succeed(self, expected_action: Option<AsRoutingAction>) -> Self {
                // Use the destination AS as the local AS if not specified
                let default_as = self.test_context.dst_address.isd_asn();
                self.next_hop_should_succeed_with_local_as(expected_action, default_as)
            }

            /// Performs the next hop routing step with a specified local AS and expects it to
            /// succeed.
            pub fn next_hop_should_succeed_with_local_as(
                mut self,
                expected_action: Option<AsRoutingAction>,
                local_as: IsdAsn,
            ) -> Self {
                let test_hops = self
                    .test_context
                    .test_segments
                    .iter()
                    .flat_map(|s| s.hop_fields.clone())
                    .collect::<Vec<_>>();

                let current_hop_index = match self.packet.header().path() {
                    ScionDpPathViewRef::Standard(ref mut path) => path.curr_hop_field_idx(),
                    _ => panic!("Unexpected path type"),
                };

                let hop = &test_hops[current_hop_index as usize];

                let custom_lookup = self.custom_link_lookup.as_ref().map(|f| f.as_ref());
                let action = SpecRoutingLogic::route(
                    local_as,
                    &mut self.packet,
                    hop.ingress_if,
                    ScionNetworkTime::from_timestamp_secs(self.test_context.timestamp),
                    &hop.forwarding_key,
                    |interface_id| {
                        Self::lookup_interface(
                            custom_lookup,
                            &test_hops,
                            current_hop_index,
                            interface_id,
                        )
                    },
                    false,
                )
                .inspect_err(|e| {
                    tracing::warn!(
                        "Hop {} failed unexpectedly with error: {:#?}",
                        current_hop_index,
                        e
                    );
                })
                .unwrap_or_else(|_| panic!("Hop {current_hop_index} should not fail"));

                if let Some(expected_action) = expected_action {
                    assert_eq!(
                        action, expected_action,
                        "Hop {current_hop_index} did not return the expected action"
                    );
                }

                self.last_error = None;
                self
            }

            /// Performs the next hop routing step and expects it to fail.
            pub fn next_hop_should_fail(self) -> Self {
                // Use the destination AS as the local AS if not specified
                let default_as = self.test_context.dst_address.isd_asn();
                self.next_hop_should_fail_with_local_as(default_as)
            }

            /// Performs the next hop routing step with a specified local AS and expects it to fail.
            pub fn next_hop_should_fail_with_local_as(mut self, local_as: IsdAsn) -> Self {
                let test_hops = self
                    .test_context
                    .test_segments
                    .iter()
                    .flat_map(|s| s.hop_fields.clone())
                    .collect::<Vec<_>>();

                let current_hop_index = match self.packet.header().path() {
                    ScionDpPathViewRef::Standard(ref mut path) => path.curr_hop_field_idx(),
                    _ => panic!("Unexpected path type"),
                };

                let hop = &test_hops[current_hop_index as usize];
                let custom_lookup = self.custom_link_lookup.as_ref().map(|f| f.as_ref());
                let err = SpecRoutingLogic::route(
                    local_as,
                    &mut self.packet,
                    hop.ingress_if,
                    ScionNetworkTime::from_timestamp_secs(self.test_context.timestamp),
                    &hop.forwarding_key,
                    |interface_id| {
                        Self::lookup_interface(
                            custom_lookup,
                            &test_hops,
                            current_hop_index,
                            interface_id,
                        )
                    },
                    false,
                )
                .inspect_err(|e| {
                    tracing::info!(
                        "Hop {} failed as expected with error: {:#?}",
                        current_hop_index,
                        e
                    );
                })
                .expect_err(&format!("Hop {current_hop_index} should have failed",));

                self.last_error = Some(err);

                self
            }

            /// Expects the last error to be an ExternalInterfaceDown error.
            pub fn expect_external_interface_down(self) -> Self {
                let Some(ScmpErrorMessage::ExternalInterfaceDown(err)) = &self.last_error else {
                    panic!(
                        "Expected an ExternalInterfaceDown error but had {:?}",
                        self.last_error
                    );
                };

                tracing::info!(
                    "Got expected ExternalInterfaceDown for interface {}#{}",
                    err.isd_asn,
                    err.interface_id,
                );

                self
            }

            /// Expects the last error to be a ParameterProblem error with the specified code.
            pub fn expect_parameter_problem(self, expected_code: ScmpParameterProblemCode) -> Self {
                let Some(ScmpErrorMessage::ParameterProblem(problem)) = &self.last_error else {
                    panic!(
                        "Expected a ParameterProblem error but had {:?}",
                        self.last_error
                    );
                };

                if problem.code != expected_code {
                    panic!(
                        "Expected ParameterProblem code {:?}, but got {:?}",
                        expected_code, problem.code
                    );
                }

                tracing::info!("Got expected ParameterProblem code: {:?}", expected_code);

                self
            }
        }
    }
}
