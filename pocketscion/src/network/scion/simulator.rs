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
//! Inter AS Routing Simulation of Packets
//!
//! Takes a [ScionTopology] and simulates the traversal of a SCION packet through it.
//!
//! Returns the Action the Packet has to take at the final AS

use anyhow::Context;
use scion_proto::{address::IsdAsn, packet::ScionPacketRaw, path::crypto::ForwardingKey};

use crate::network::scion::{
    routing::{
        AsRoutingAction, AsRoutingInterfaceState, AsRoutingLinkType, LocalAsRoutingAction,
        RoutingLogic, ScionNetworkTime,
    },
    topology::{ScionLinkType, ScionTopology},
};

/// Simulates traversal in a SCION Network
pub struct ScionNetworkSim;

impl ScionNetworkSim {
    /// Simulates the traversal of a SCION packet through the given topology.
    ///
    /// Applies the [RoutingLogic] per AS to processing the packet until it reaches a final
    /// decision.
    ///
    /// Returns a [ScionNetworkSimOutput] indicating the next step for the packet.
    /// Unexpected errors will be returned as an [anyhow::Error].
    pub fn simulate_traversal<RoutingImpl: RoutingLogic>(
        topology: &ScionTopology,
        scion_packet: &mut ScionPacketRaw,
        now: ScionNetworkTime,
        ingress_asn: IsdAsn,
    ) -> anyhow::Result<ScionNetworkSimOutput> {
        let iter =
            ScionNetworkSimIter::<RoutingImpl>::new(topology, scion_packet, now, ingress_asn)?;
        let iter_result = iter
            .last()
            .context("traversal of topology returned none")??;

        let local_action = match iter_result.action {
            AsRoutingAction::Local(action) => action,
            _ => {
                return Err(anyhow::anyhow!(
                    "topology iteration should return a local action, but got: {:?}",
                    iter_result.action
                ));
            }
        };

        Ok(ScionNetworkSimOutput {
            at_as: iter_result.at_as,
            at_ingress_interface: iter_result.at_ingress_interface,
            action: local_action,
        })
    }

    /// Returns an iterator over the traversal steps of a SCION packet through the topology.
    pub fn iter<'input, AsRoutingImpl: RoutingLogic>(
        topology: &'input ScionTopology,
        scion_packet: &'input mut ScionPacketRaw,
        now: ScionNetworkTime,
        ingress_asn: IsdAsn,
    ) -> anyhow::Result<ScionNetworkSimIter<'input, AsRoutingImpl>> {
        ScionNetworkSimIter::new(topology, scion_packet, now, ingress_asn)
    }
}

/// Iterator over the traversal steps of a SCION packet through a topology.
pub struct ScionNetworkSimIter<'input, AsRoutingImpl: RoutingLogic> {
    topology: &'input ScionTopology,
    scion_packet: &'input mut ScionPacketRaw,
    now: ScionNetworkTime,

    current_as: IsdAsn,
    current_ingress_interface_id: u16,
    current_forwarding_key: ForwardingKey,

    finished: bool,

    _phantom: std::marker::PhantomData<AsRoutingImpl>,
}

impl<'input, AsRoutingImpl: RoutingLogic> ScionNetworkSimIter<'input, AsRoutingImpl> {
    fn new(
        topology: &'input ScionTopology,
        scion_packet: &'input mut ScionPacketRaw,
        now: ScionNetworkTime,
        ingress_as: IsdAsn,
    ) -> anyhow::Result<Self> {
        let current_forwarding_key = topology
            .as_map
            .get(&ingress_as)
            .with_context(|| format!("AS {ingress_as} does not exist in the topology"))?
            .forwarding_key
            .into();

        Ok(Self {
            topology,
            scion_packet,
            now,
            current_as: ingress_as,
            current_ingress_interface_id: 0,
            current_forwarding_key,
            finished: false,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Returns the AS which will process the packet next.
    pub fn get_processing_as(&self) -> IsdAsn {
        self.current_as
    }

    /// Returns the ingress interface ID where the packet will be processed next.
    pub fn get_processing_interface_id(&self) -> u16 {
        self.current_ingress_interface_id
    }

    /// Processes the packet at the current AS and interface, advancing the iterator.
    /// Returns Ok(None) if all routing steps are finished.
    /// Returns [anyhow::Error] on unexpected errors.
    fn next_step(&mut self) -> anyhow::Result<Option<ScionNetworkSimIterOutput>> {
        if self.finished {
            return Ok(None);
        }

        let processing_as = self.current_as;
        let processing_ingress_interface_id = self.current_ingress_interface_id;

        // Process the packet at the current AS and interface
        let processing_result = AsRoutingImpl::route(
            processing_as,
            self.scion_packet,
            self.current_ingress_interface_id,
            self.now,
            &self.current_forwarding_key,
            |if_id| {
                let link = self.topology.scion_link(&processing_as, if_id)?;
                let link_type = link.get_link_type(&processing_as)?;

                // ScionLinkType states that this is the X of something, InterfaceLinkType states
                // that this is a link to X - so needs to swap
                let link_type = match link_type {
                    ScionLinkType::Core => AsRoutingLinkType::LinkToCore,
                    ScionLinkType::Child => AsRoutingLinkType::LinkToParent,
                    ScionLinkType::Parent => AsRoutingLinkType::LinkToChild,
                    ScionLinkType::Peer => AsRoutingLinkType::LinkToPeer,
                };

                Some(AsRoutingInterfaceState {
                    link_type,
                    is_up: link.is_up,
                })
            },
        );

        let processing_result: AsRoutingAction = processing_result.into();

        if let AsRoutingAction::ForwardNextHop { link_interface_id } = processing_result {
            // If the decision is to forward, prepare current variables for the next iteration
            let uplink = self
                .topology
                .scion_link(&self.current_as, link_interface_id)
                .with_context(|| {
                    format!(
                        "no link for {}#{} to AS does not exist in the topology",
                        self.current_as, link_interface_id
                    )
                })?;

            let link_partner = uplink.get_peer(&self.current_as).with_context(|| {
                format!("link {uplink:?} does not contain AS {}", self.current_as)
            })?;

            self.current_as = link_partner.isd_as;
            self.current_ingress_interface_id = link_partner.if_id;
            self.current_forwarding_key = self
                .topology
                .as_map
                .get(&self.current_as)
                .with_context(|| {
                    format!(
                        "AS {} does not exist in the topology even though a link to it exists",
                        self.current_as
                    )
                })?
                .forwarding_key
                .into();
        } else {
            // If the decision is not to forward to the next hop, we can finalize the iteration
            self.finished = true;
        }

        // Return the result of processing
        Ok(Some(ScionNetworkSimIterOutput {
            at_as: processing_as,
            at_ingress_interface: processing_ingress_interface_id,
            action: processing_result,
            finished: self.finished,
        }))
    }
}

impl<'input, AsRoutingImpl: RoutingLogic> Iterator for ScionNetworkSimIter<'input, AsRoutingImpl> {
    type Item = anyhow::Result<ScionNetworkSimIterOutput>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_step().transpose()
    }
}

/// Result of a single step in of the [ScionNetworkSimIter]
pub struct ScionNetworkSimIterOutput {
    /// The ISD-ASN at which the result was produced
    pub at_as: IsdAsn,
    /// The ingress interface ID at which the ASN received the packet
    pub at_ingress_interface: u16,
    /// Action which should be taken for the packet at this step
    pub action: AsRoutingAction,
    /// Iteration is finished, next call to `next()` will return None
    pub finished: bool,
}

/// Final result of routing
#[derive(Debug)]
pub struct ScionNetworkSimOutput {
    /// The ISD-ASN at which the result was produced
    pub at_as: IsdAsn,
    /// The ingress interface ID at which the ASN received the packet
    pub at_ingress_interface: u16,
    /// The decision made for the packet
    pub action: LocalAsRoutingAction,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::{Bytes, BytesMut};
    use helper::*;
    use scion_proto::{
        address::{ScionAddr, ScionAddrV4},
        packet::{ByEndpoint, FlowId, ScionPacketRaw},
        path::{DataPlanePath, EncodedStandardPath},
        scmp::ScmpErrorMessage,
    };

    use super::*;
    use crate::network::scion::topology::ScionAs;

    #[test_log::test]
    fn should_successfully_route_on_existing_path() {
        let mut topology = ScionTopology::new(); // Assume this creates a valid topology

        topology
            .add_as(ScionAs::new("1-1".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new("1-2".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new("1-3".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new("1-4".parse().unwrap()))
            .unwrap();

        topology
            .add_link("1-1#1 up_to 1-2#2".parse().unwrap())
            .unwrap()
            .add_link("1-2#3 up_to 1-3#4".parse().unwrap())
            .unwrap()
            .add_link("1-3#5 up_to 1-4#6".parse().unwrap())
            .unwrap();

        let src_addr = ScionAddr::V4(ScionAddrV4::new(
            "1-1".parse().unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
        ));
        let dst_addr = ScionAddr::V4(ScionAddrV4::new(
            "1-4".parse().unwrap(),
            Ipv4Addr::new(2, 2, 2, 2),
        ));
        let mut packet = raw_scion_packet(src_addr, dst_addr, &Bytes::from_static(b"Test Payload"));

        let result = ScionNetworkSim::simulate_traversal::<MockScionPacketProcessor>(
            &topology,
            &mut packet,
            ScionNetworkTime::from_timestamp_secs(0),
            src_addr.isd_asn(),
        )
        .expect("should not fail to route");

        match result.action {
            LocalAsRoutingAction::ForwardLocal { target_address } => {
                assert_eq!(target_address, dst_addr, "Target address mismatch");
            }
            _ => {
                panic!(
                    "expected a local forwarding decision, but got: {:?}",
                    result.action
                )
            }
        }

        assert_eq!(result.at_as, dst_addr.isd_asn(), "Final ISD-ASN mismatch");
        assert_eq!(
            result.at_ingress_interface, 6,
            "Final ingress interface ID mismatch"
        );
    }

    #[test_log::test]
    fn should_fail_to_route_if_path_is_broken() {
        // Note - kind of a mixed test as the mock impl needs to report that the path is broken,
        // otherwise the Network Sim would just throw an anyhow error
        let mut topology = ScionTopology::new();

        let failing_as = "1-2".parse().unwrap();

        topology
            .add_as(ScionAs::new("1-1".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new(failing_as))
            .unwrap()
            .add_as(ScionAs::new("1-3".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new("1-4".parse().unwrap()))
            .unwrap();

        topology
            .add_link("1-1#1 up_to 1-2#2".parse().unwrap())
            .unwrap()
            // .add_link("1-2#3 up_to 1-3#4".parse().unwrap())
            // .unwrap()
            .add_link("1-3#5 up_to 1-4#6".parse().unwrap())
            .unwrap();

        let src_addr = ScionAddr::V4(ScionAddrV4::new(
            "1-1".parse().unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
        ));

        let dst_addr = ScionAddr::V4(ScionAddrV4::new(
            "1-4".parse().unwrap(),
            Ipv4Addr::new(2, 2, 2, 2),
        ));

        let mut packet = raw_scion_packet(src_addr, dst_addr, &Bytes::from_static(b"Test Payload"));

        let result = ScionNetworkSim::simulate_traversal::<MockScionPacketProcessor>(
            &topology,
            &mut packet,
            ScionNetworkTime::from_timestamp_secs(0),
            src_addr.isd_asn(),
        )
        .expect("should not fail to simulate");

        assert!(result.at_as == failing_as, "Final ISD-ASN mismatch");
        assert!(
            result.at_ingress_interface == 2,
            "Final ingress interface ID mismatch"
        );

        match result.action {
            LocalAsRoutingAction::SendSCMPErrorResponse(err) => {
                assert!(
                    matches!(err, ScmpErrorMessage::ParameterProblem(_)),
                    "expected a ParameterProblem SCMP error"
                );
            }
            _ => panic!("expected a SCMP error response due to broken path"),
        }
    }

    #[test_log::test]
    fn should_iterate_as_expected() {
        let mut topology = ScionTopology::new(); // Assume this creates a valid topology

        let as1 = ScionAs::new("1-1".parse().unwrap());
        let as2 = ScionAs::new("1-2".parse().unwrap());
        let as3 = ScionAs::new("1-3".parse().unwrap());
        let as4 = ScionAs::new("1-4".parse().unwrap());

        topology
            .add_as(as1)
            .unwrap()
            .add_as(as2)
            .unwrap()
            .add_as(as3)
            .unwrap()
            .add_as(as4)
            .unwrap();

        topology
            .add_link("1-1#1 up_to 1-2#2".parse().unwrap())
            .unwrap()
            .add_link("1-2#3 up_to 1-3#4".parse().unwrap())
            .unwrap()
            .add_link("1-3#5 up_to 1-4#6".parse().unwrap())
            .unwrap();

        let src_addr = ScionAddr::V4(ScionAddrV4::new(as1.isd_as, Ipv4Addr::new(1, 1, 1, 1)));
        let dst_addr = ScionAddr::V4(ScionAddrV4::new(as4.isd_as, Ipv4Addr::new(2, 2, 2, 2)));
        let mut packet = raw_scion_packet(src_addr, dst_addr, &Bytes::from_static(b"Test Payload"));

        let mut iter = ScionNetworkSim::iter::<MockScionPacketProcessor>(
            &topology,
            &mut packet,
            ScionNetworkTime::from_timestamp_secs(0),
            src_addr.isd_asn(),
        )
        .expect("should not fail to route");

        check_step(
            &mut iter,
            0,
            src_addr.isd_asn(),
            AsRoutingAction::ForwardNextHop {
                link_interface_id: 1,
            },
            false,
        );
        check_step(
            &mut iter,
            2,
            as2.isd_as,
            AsRoutingAction::ForwardNextHop {
                link_interface_id: 3,
            },
            false,
        );
        check_step(
            &mut iter,
            4,
            as3.isd_as,
            AsRoutingAction::ForwardNextHop {
                link_interface_id: 5,
            },
            false,
        );
        check_step(
            &mut iter,
            6,
            as4.isd_as,
            AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal {
                target_address: dst_addr,
            }),
            true,
        );

        fn check_step(
            iter: &mut ScionNetworkSimIter<MockScionPacketProcessor>,
            expected_ingress_interface: u16,
            expected_isd_asn: IsdAsn,
            expected_action: AsRoutingAction,
            expected_finished: bool,
        ) {
            let res = iter.next().expect("Step").expect("No error");
            assert_eq!(
                res.at_ingress_interface, expected_ingress_interface,
                "ingress interface should match expected value at this step"
            );
            assert_eq!(
                res.at_as, expected_isd_asn,
                "AS should match expected IsdAsn at this step"
            );
            assert_eq!(
                res.action, expected_action,
                "routing action should match expected action at this step"
            );
            assert_eq!(
                res.finished, expected_finished,
                "finished flag should match expected state at this step"
            );
        }

        // No more steps should be available
        assert!(
            iter.next().is_none(),
            "iter.next() returned Some. no more steps should be available after the last one"
        );
    }

    mod helper {
        use bytes::BufMut;
        use scion_proto::{
            scmp::{ScmpErrorMessage, ScmpParameterProblem},
            wire_encoding::{WireDecode, WireEncodeVec},
        };

        use super::*;

        /// Mock implementation of the [ScionPacketProcessingLogic] trait for testing purposes.
        ///
        /// Passes the packet to the the next interface id (e.g. ingress interface id + 1)
        /// If the ingress interface ID is 6, it simulates a decision to forward the packet locally
        pub struct MockScionPacketProcessor;
        impl RoutingLogic for MockScionPacketProcessor {
            fn route(
                _local_as: IsdAsn,
                scion_packet: &mut ScionPacketRaw,
                ingress_interface_id: u16,
                _now: ScionNetworkTime,
                _as_forwarding_key: &ForwardingKey,
                interface_link_type_lookup: impl Fn(u16) -> Option<AsRoutingInterfaceState>,
            ) -> Result<AsRoutingAction, ScmpErrorMessage> {
                if ingress_interface_id == 6 {
                    // Simulate a decision to handle the packet as a SCMP request at the ingress
                    // interface
                    return Ok(AsRoutingAction::Local(LocalAsRoutingAction::ForwardLocal {
                        target_address: scion_packet.headers.address.destination().unwrap(),
                    }));
                }

                interface_link_type_lookup(ingress_interface_id + 1) // For mock - Egress must be one higher than ingress
                    .ok_or_else(|| {
                        tracing::warn!(
                            interface_id = ingress_interface_id,
                            "No link type found for interface ID"
                        );
                        ScmpErrorMessage::ParameterProblem(
                            ScmpParameterProblem::new(
                                scion_proto::scmp::ParameterProblemCode::UnknownHopFieldConsEgressInterface // note - this would need to be normalized from travel direction but not for mock
                                , 0
                                , scion_packet.encode_to_bytes_vec().concat().into())
                        )
                    })?;

                // For testing, we just return a decision to forward to the next hop
                // This is a mock implementation and should be replaced with actual logic
                Ok(AsRoutingAction::ForwardNextHop {
                    link_interface_id: ingress_interface_id + 1, /* Just incrementing for the
                                                                  * sake of example */
                })
            }
        }

        /// Builds a SCION packet with the given payload and source address.
        pub fn raw_scion_packet(
            source_addr: ScionAddr,
            dest_addr: ScionAddr,
            payload: &Bytes,
        ) -> ScionPacketRaw {
            let endpoints = ByEndpoint {
                source: source_addr,
                destination: dest_addr,
            };

            // Construct a simple one hop path:
            // https://docs.scion.org/en/latest/protocols/scion-header.html#path-type-onehoppath
            let mut path_raw = BytesMut::with_capacity(36);
            path_raw.put_u32(0x0000_2000);
            path_raw.put_slice(&[0_u8; 32]);
            let dp_path = DataPlanePath::Standard(
                EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap(),
            );

            ScionPacketRaw::new(
                endpoints,
                dp_path,
                payload.clone(),
                0,
                FlowId::new(0).unwrap(),
            )
            .unwrap()
        }
    }
}
