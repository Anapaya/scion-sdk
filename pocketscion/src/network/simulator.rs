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
//! Full network Simulation for SCION and Local Network

use anyhow::Context;
use scion_proto::{address::IsdAsn, packet::ScionPacketRaw, scmp::ScmpErrorMessage};
use tracing::info_span;

use crate::network::{
    local::{receiver_registry::NetworkReceiverRegistry, simulator::LocalNetworkSimulation},
    scion::{
        routing::{LocalAsRoutingAction, ScionNetworkTime, spec::SpecRoutingLogic},
        simulator::{ScionNetworkSim, ScionNetworkSimOutput},
        topology::ScionTopology,
    },
};

/// Network simulation for SCION, modelling inter-AS and intra-AS routing
///
/// Use [NetworkSimulator::dispatch] to simulate the dispatch of a packet through the SCION
/// network.
pub struct NetworkSimulator<'input> {
    /// Network Targets to dispatch packets to
    network_receivers: &'input NetworkReceiverRegistry,
    /// Topology to simulate, if none routing just works
    topology: Option<&'input ScionTopology>,
}
// General
impl NetworkSimulator<'_> {
    /// Creates a new PocketSCION network simulator.
    pub fn new<'input>(
        lan_ip_targets: &'input NetworkReceiverRegistry,
        topology: Option<&'input ScionTopology>,
    ) -> NetworkSimulator<'input> {
        NetworkSimulator {
            network_receivers: lan_ip_targets,
            topology,
        }
    }
}
// Dispatching
impl NetworkSimulator<'_> {
    /// Best effort dispatch of a packet.
    ///
    /// Simulates Routing and AS internal dispatching.
    pub fn dispatch(&self, local_as: IsdAsn, now: ScionNetworkTime, mut packet: ScionPacketRaw) {
        let fallible = || {
            let _s = info_span!("net-sim", local = %local_as).entered();

            // Simulate routing
            tracing::trace!(%local_as, "Dispatching packet at AS");
            let routing_output = match self.topology {
                Some(topology) => {
                    ScionNetworkSim::simulate_traversal::<SpecRoutingLogic>(
                        topology,
                        &mut packet,
                        now,
                        local_as,
                    )
                    .context("error simulating packet traversal")?
                }
                // If no topology is provided, we just skip routing and dispatch the packet directly
                // to the destination
                None => {
                    let dst = packet
                        .headers
                        .address
                        .destination()
                        .context("no destination address in packet")?;

                    ScionNetworkSimOutput {
                        at_as: dst.isd_asn(),
                        at_ingress_interface: 1,
                        action: LocalAsRoutingAction::ForwardLocal {
                            target_address: dst,
                        },
                    }
                }
            };

            // Simulate Local Handling
            if let Some(reply) = LocalNetworkSimulation::new(
                routing_output.at_as,
                routing_output.at_ingress_interface,
                self.network_receivers,
            )
            .handle_local_routing_action(routing_output.action, packet)
            .context("local simulation failed")?
            {
                self.dispatch(routing_output.at_as, now, reply.into());
            };

            anyhow::Ok(())
        };

        match fallible() {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = ?e, "Failed to dispatch packet");
            }
        }
    }

    /// Best effort dispatch of a packet into given local AS.
    ///
    /// Reads destination from packet.
    ///
    /// Prefer [Self::dispatch] as a general dispatch method.
    pub fn dispatch_into(
        &self,
        local_as: IsdAsn,
        local_router_if: u16,
        packet: ScionPacketRaw,
    ) -> Result<(), ScmpErrorMessage> {
        LocalNetworkSimulation::new(local_as, local_router_if, self.network_receivers)
            .dispatch(packet)
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::Ipv4Addr,
        str::FromStr,
        sync::{Arc, Mutex, atomic::AtomicUsize},
    };

    use ipnet::IpNet;
    use scion_proto::{
        address::{EndhostAddr, ScionAddr},
        packet::classify_scion_packet,
        path::test_builder::{TestPathBuilder, TestPathContext},
    };

    use super::*;
    use crate::network::local::receivers::Receiver;

    struct TestSetup {
        src: ScionAddr,
        src_dp: Arc<MockReceiver>,
        #[expect(unused)]
        dst: ScionAddr,
        dst_dp: Arc<MockReceiver>,
        ctx: TestPathContext,
        targets: NetworkReceiverRegistry,
        packet: ScionPacketRaw,
    }

    /// Sets up a bidirectional test with two endpoints, each having a MockReceiver.
    fn setup(
        builder_cb: impl FnOnce(EndhostAddr, EndhostAddr) -> TestPathBuilder,
        timestamp: u32,
        overwrite_dst: Option<EndhostAddr>,
    ) -> TestSetup {
        let src_ip_net: IpNet = "10.0.0.1/32".parse().unwrap();
        let src_ip = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let src_ia = IsdAsn::from_str("1-1").unwrap();
        let src = ScionAddr::new(src_ia, src_ip.into());

        let dst_ip_net: IpNet = "11.0.0.1/32".parse().unwrap();
        let dst_ip = Ipv4Addr::from_str("11.0.0.1").unwrap();
        let dst_ia = IsdAsn::from_str("1-99").unwrap();
        let dst = ScionAddr::new(dst_ia, dst_ip.into());

        let mut targets = NetworkReceiverRegistry::new();

        // Add Mock Receiver locally, will get the SCMPResponse if everything works
        let src_dp = Arc::new(MockReceiver::default());
        let dst_dp = Arc::new(MockReceiver::default());

        targets
            .add_receiver(src_ia, src_ip_net, src_dp.clone())
            .unwrap();
        targets
            .add_receiver(dst_ia, dst_ip_net, dst_dp.clone())
            .unwrap();

        let builder = builder_cb(
            EndhostAddr::try_from(src).unwrap(),
            overwrite_dst.unwrap_or_else(|| EndhostAddr::try_from(dst).unwrap()),
        );

        let test = builder.build(timestamp);

        TestSetup {
            src,
            dst,
            src_dp,
            dst_dp,
            packet: test.scion_packet_udp(&[1, 2], 22222, 11111).into(),
            ctx: test,
            targets,
        }
    }

    mod scmp_handling {
        use scion_proto::scmp::{ScmpEchoRequest, ScmpMessage};

        use super::*;
        use crate::network::scion::util::test_topology_ext::TestPathContextTopologyExt;

        #[test_log::test]
        fn should_dispatch_scmp_reply_for_echo_requests() {
            let test = |src, dst| {
                TestPathBuilder::new(src, dst)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(2, 3)
                    .add_hop_with_alerts(1, true, 2, false)
                    .add_hop(1, 0)
            };

            let test = setup(test, 0, None);

            let topology = test.ctx.build_topology();

            println!("{}", topology.format_mermaid());
            NetworkSimulator::new(&test.targets, Some(&topology)).dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.ctx
                    .scion_packet_scmp(ScmpMessage::EchoRequest(ScmpEchoRequest::new(
                        1,
                        2,
                        vec![1, 2, 3].into(),
                    )))
                    .into(),
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(
                test.src_dp.rx_scmp(),
                1,
                "Should have received one SCMP packet"
            );

            let scmp_packet = test.src_dp.last_recv().unwrap();
            let scmp = classify_scion_packet(scmp_packet.clone())
                .expect("Should classify SCMP packet")
                .try_into_scmp()
                .expect("Should convert to SCMP packet");

            let ScmpMessage::EchoReply(scmp_echo_reply) = scmp.message else {
                panic!("Expected SCMP EchoReply message, got {:?}", scmp.message);
            };

            assert_eq!(
                scmp_echo_reply.identifier, 1,
                "Expected SCMP EchoReply with identifier 1"
            );
            assert_eq!(
                scmp_echo_reply.sequence_number, 2,
                "Expected SCMP EchoReply with sequence number 2"
            );
            assert_eq!(
                scmp_echo_reply.data,
                vec![1, 2, 3],
                "Expected SCMP EchoReply with data [1, 2, 3]"
            );
        }
    }

    mod dispatch {

        use scion_proto::scmp::{
            DestinationUnreachableCode, ScmpDestinationUnreachable, ScmpMessage,
        };

        use super::*;
        use crate::network::scion::util::test_topology_ext::TestPathContextTopologyExt;

        #[test_log::test]
        fn should_dispatch_outgoing_packet() {
            let test = setup(
                |src, dst| {
                    TestPathBuilder::new(src, dst)
                        .up()
                        .add_hop(0, 1)
                        .add_hop(1, 0)
                },
                0,
                None,
            );
            let topology = test.ctx.build_topology();
            let sim = NetworkSimulator::new(&test.targets, Some(&topology));

            sim.dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.dst_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(test.src_dp.rx_count(), 0, "Src should not have rx");
        }

        #[test_log::test]
        fn should_dispatch_outgoing_packet_without_topo() {
            let test = setup(
                |src, dst| {
                    TestPathBuilder::new(src, dst)
                        .up()
                        .add_hop(0, 1)
                        .add_hop(1, 0)
                },
                0,
                None,
            );
            let sim = NetworkSimulator::new(&test.targets, None);

            sim.dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.dst_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(test.src_dp.rx_count(), 0, "Src should not have rx");
        }

        #[test_log::test]
        fn should_respond_with_destination_unreachable_when_ip_not_bound() {
            let test = setup(
                |src, dst| {
                    TestPathBuilder::new(src, dst)
                        .up()
                        .add_hop(0, 1)
                        .add_hop(1, 0)
                },
                0,
                Some("1-99,1.2.3.4".parse().unwrap()), // Invalid destination IP
            );

            let topology = test.ctx.build_topology();
            NetworkSimulator::new(&test.targets, Some(&topology)).dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(
                test.src_dp.rx_scmp(),
                1,
                "Should have received one SCMP packet"
            );

            let scmp_packet = test.src_dp.last_recv().unwrap();
            let scmp = classify_scion_packet(scmp_packet.clone())
                .expect("Should classify SCMP packet")
                .try_into_scmp()
                .expect("Should convert to SCMP packet");

            let ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable {
                code: DestinationUnreachableCode::AddressUnreachable,
                ..
            }) = scmp.message
            else {
                panic!(
                    "Expected SCMP Destination Unreachable message with AddressUnreachable code"
                );
            };
        }

        #[test_log::test]
        fn should_respond_with_destination_unreachable_when_ip_not_bound_with_topo() {
            let test = setup(
                |src, dst| {
                    TestPathBuilder::new(src, dst)
                        .up()
                        .add_hop(0, 1)
                        .add_hop(1, 0)
                },
                0,
                Some("1-99,1.2.3.4".parse().unwrap()), // Invalid destination IP
            );
            NetworkSimulator::new(&test.targets, None).dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(
                test.src_dp.rx_scmp(),
                1,
                "Should have received one SCMP packet"
            );

            let scmp_packet = test.src_dp.last_recv().unwrap();
            let scmp = classify_scion_packet(scmp_packet.clone())
                .expect("Should classify SCMP packet")
                .try_into_scmp()
                .expect("Should convert to SCMP packet");

            let ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable {
                code: DestinationUnreachableCode::AddressUnreachable,
                ..
            }) = scmp.message
            else {
                panic!(
                    "Expected SCMP Destination Unreachable message with AddressUnreachable code"
                );
            };
        }

        #[test_log::test]
        fn should_respond_with_scmp_error_if_routing_failed_locally() {
            let test = |src, dst| {
                TestPathBuilder::new(src, dst)
                    .up()
                    .add_hop(0, 1)
                    .add_hop(1, 0)
            };
            let test = setup(test, 1234567, None); // Packet TTL expired - fails directly

            let topology = test.ctx.build_topology();
            NetworkSimulator::new(&test.targets, Some(&topology)).dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.src_dp.rx_count(), 1, "Should have rx one packet");
            assert_eq!(test.src_dp.rx_scmp(), 1, "Should have rx one SCMP packet");
            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
        }

        #[test_log::test]
        fn should_respond_with_scmp_error_if_routing_failed_on_route() {
            let test = |src, dst| {
                TestPathBuilder::new(src, dst)
                    .up()
                    .add_hop(0, 1)
                    .add_hop_with_egress_down(1, 2)
                    .add_hop(1, 0)
            };

            let test = setup(test, 1234567, None);

            let topology = test.ctx.build_topology();
            NetworkSimulator::new(&test.targets, Some(&topology)).dispatch(
                test.src.isd_asn(),
                ScionNetworkTime(test.ctx.timestamp),
                test.packet.clone(),
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Src Should have rx one packet");
            assert_eq!(test.src_dp.rx_scmp(), 1, "Src Should have rx SCMP packet");
        }
    }

    #[derive(Default)]
    struct MockReceiver {
        dispatch_count: AtomicUsize,
        scmp_count: AtomicUsize,
        last_packet: Mutex<Option<ScionPacketRaw>>,
    }
    impl MockReceiver {
        pub fn rx_count(&self) -> usize {
            self.dispatch_count
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn rx_scmp(&self) -> usize {
            self.scmp_count.load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn last_recv(&self) -> Option<ScionPacketRaw> {
            self.last_packet.lock().unwrap().clone()
        }
    }

    impl Receiver for MockReceiver {
        fn receive_packet(&self, packet: ScionPacketRaw) {
            let packet_type =
                classify_scion_packet(packet.clone()).expect("All packets should be valid");
            self.dispatch_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            match packet_type {
                scion_proto::packet::PacketClassification::ScmpWithDestination(..)
                | scion_proto::packet::PacketClassification::ScmpWithoutDestination(..) => {
                    self.scmp_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {}
            }

            self.last_packet.lock().unwrap().replace(packet);
        }
    }
}
