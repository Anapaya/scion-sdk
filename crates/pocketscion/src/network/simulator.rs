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

use std::sync::atomic::AtomicU64;

use anyhow::Context;
use sciparse::{core::model::Model, identifier::isd_asn::IsdAsn, packet::view::ScionRawPacketView};
use tracing::info_span;

use crate::network::{
    local::{
        external_as_registry::ExternalAsRegistry,
        receiver_registry::NetworkReceiverRegistry,
        simulator::{DispatchEffect, LocalNetworkSimulation},
    },
    scion::{
        routing::{ScionNetworkTime, spec::SpecRoutingLogic},
        simulator::ScionNetworkSim,
        topology::ScionTopology,
    },
};

// We trace the dispatch of each packet with a unique ID for better observability.
static ID_CTR: AtomicU64 = AtomicU64::new(1);

/// Network simulation for SCION, modelling inter-AS and intra-AS routing
///
/// Use [NetworkSimulator::dispatch] to simulate the dispatch of a packet through the SCION
/// network.
pub struct NetworkSimulator<'input> {
    /// Network Targets to dispatch packets to
    network_receivers: &'input NetworkReceiverRegistry,
    /// Registry of external ASes, needed for forwarding to external ASes
    external_ases: &'input ExternalAsRegistry,
    /// Topology to simulate, if none routing just works
    topology: &'input ScionTopology,
    /// Whether to ignore MAC authentication during simulation
    ignore_macs: bool,
}
// General
impl NetworkSimulator<'_> {
    /// Creates a new PocketSCION network simulator.
    pub fn new<'input>(
        lan_ip_targets: &'input NetworkReceiverRegistry,
        external_ases: &'input ExternalAsRegistry,
        topology: &'input ScionTopology,
        ignore_macs: bool,
    ) -> NetworkSimulator<'input> {
        NetworkSimulator {
            network_receivers: lan_ip_targets,
            external_ases,
            topology,
            ignore_macs,
        }
    }
}
// Dispatching
impl NetworkSimulator<'_> {
    /// Best effort dispatch of a packet.
    ///
    /// Simulates Routing and AS internal dispatching.
    ///
    /// ## Parameters
    /// - `local_as`: AS where the packet is being processed, used for routing decisions.
    /// - `local_interface`: Interface where the packet is being processed. 0 means packet
    ///   originated in the AS.
    /// - `now`: Current network time, used for routing decisions
    /// - `packet`: Packet to dispatch, will be modified by the simulation (e.g. for path
    ///   processing)
    pub fn dispatch(
        &self,
        local_as: IsdAsn,
        local_interface: u16,
        now: ScionNetworkTime,
        packet: &mut ScionRawPacketView,
    ) {
        let mut fallible = || {
            // Simulate routing
            tracing::trace!("Dispatching packet at AS");
            let routing_output = ScionNetworkSim::simulate_traversal::<SpecRoutingLogic>(
                self.topology,
                packet,
                now,
                local_as,
                local_interface,
                self.ignore_macs,
            )
            .context("error simulating packet traversal")?;

            let router = self
                .topology
                .get_router(&routing_output.at_as, routing_output.at_ingress_interface);

            // Add dst AS to span for better observability of routing results
            tracing::Span::current().record("eas", tracing::field::display(&routing_output.at_as));

            tracing::trace!(
                ?routing_output.action,
                "Routing result"
            );

            // Simulate Local Handling
            if let Some(reply) = LocalNetworkSimulation::new(
                routing_output.at_as,
                routing_output.at_ingress_interface,
                self.network_receivers,
                self.external_ases,
                router,
            )
            .handle_local_routing_action(routing_output.action, packet)
            .context("local simulation failed")?
            {
                tracing::trace!("Dispatching local reply");

                self.dispatch(
                    routing_output.at_as,
                    0,
                    now,
                    &mut reply
                        .try_encode_to_owned_view()
                        .context("Failed to encode response")?,
                );
            };

            anyhow::Ok(())
        };

        let id = ID_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _s = info_span!("sim", p = id, ias = %local_as, eas = tracing::field::Empty).entered();

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
        packet: &mut ScionRawPacketView,
    ) -> Option<DispatchEffect> {
        let router = self.topology.get_router(&local_as, local_router_if);

        LocalNetworkSimulation::new(
            local_as,
            local_router_if,
            self.network_receivers,
            self.external_ases,
            router,
        )
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
    use sciparse::{
        address::addr::ScionAddr,
        core::convert::TryToModel,
        packet::{classify::ClassifiedPacketView, model::ScionRawPacket},
        util::test_builder::{TestPathBuilder, TestPathContext},
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
        packet: Box<ScionRawPacketView>,
    }

    /// Sets up a bidirectional test with two endpoints, each having a MockReceiver.
    fn setup(
        builder_cb: impl FnOnce(ScionAddr, ScionAddr) -> TestPathBuilder,
        timestamp: u32,
        overwrite_dst: Option<ScionAddr>,
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

        let builder = builder_cb(src, overwrite_dst.unwrap_or(dst));

        let test = builder.build(timestamp);

        TestSetup {
            src,
            dst,
            src_dp,
            dst_dp,
            packet: test
                .scion_packet_udp(&[1, 2], 22222, 11111)
                .into_raw()
                .try_encode_to_owned_view()
                .expect("Failed to encode packet"),
            ctx: test,
            targets,
        }
    }

    mod scmp_handling {

        use sciparse::payload::scmp::model::{ScmpEchoRequest, ScmpMessage};

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

            NetworkSimulator::new(&test.targets, &Default::default(), &topology, false).dispatch(
                test.src.isd_asn(),
                0,
                ScionNetworkTime(test.ctx.timestamp),
                &mut test
                    .ctx
                    .scion_packet_scmp(ScmpMessage::EchoRequest(ScmpEchoRequest::new(
                        1,
                        2,
                        vec![1, 2, 3],
                    )))
                    .into_raw()
                    .try_encode_to_owned_view()
                    .expect("Failed to encode SCMP EchoRequest"),
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(
                test.src_dp.rx_scmp(),
                1,
                "Should have received one SCMP packet"
            );

            let scmp_packet = test.src_dp.last_recv().unwrap();
            let scmp = scmp_packet
                .try_classify()
                .expect("Should classify SCMP packet")
                .try_into_scmp()
                .expect("Should convert to SCMP packet");

            let ScmpMessage::EchoReply(scmp_echo_reply) = scmp.payload else {
                panic!("Expected SCMP EchoReply message, got {:?}", scmp.payload);
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

    mod svc_resolution {

        use std::{io::Cursor, net::SocketAddr};

        use scion_protobuf::control_plane::v1::{
            ServiceResolutionRequest, ServiceResolutionResponse,
        };
        use sciparse::{
            address::{addr::ScionAddrSvc, host_addr::ServiceAddr, socket_addr::ScionSocketAddr},
            dataplane_path::{model::DpPath, view::ScionDpPathViewExt},
            packet::model::ScionUdpPacket,
        };

        use super::*;
        use crate::network::scion::topology::{ScionAs, ScionTopologyBuilder};

        #[test_log::test]
        fn should_resolve_svc_address() {
            let src_ia = IsdAsn::from_str("1-1").unwrap();
            let dst_ia = IsdAsn::from_str("1-99").unwrap();
            let src_ip_net: IpNet = "10.0.0.1/32".parse().unwrap();
            let svc_addr: SocketAddr = "10.1.2.3:54321".parse().unwrap();

            let mut topology = ScionTopologyBuilder::new();
            topology
                .add_as(ScionAs::new_core(src_ia).with_forwarding_key([0; 16])) // Src AS
                .unwrap()
                .add_as(ScionAs::new_core(dst_ia).with_forwarding_key([0; 16])) // Dst AS
                .unwrap()
                .add_link("1-1#1 core 1-99#1".parse().unwrap())
                .unwrap();
            let topology = topology.build().expect("building topology");

            let src_receiver = Arc::new(MockReceiver::default());
            let mut network_receivers = NetworkReceiverRegistry::new();
            network_receivers
                .add_svc_mapping(dst_ia, ServiceAddr::CONTROL, "test".to_string(), svc_addr)
                .unwrap();

            network_receivers
                .add_receiver(src_ia, src_ip_net, src_receiver.clone())
                .unwrap();

            let src_addr = ScionAddr::new(src_ia, src_ip_net.addr().into());
            let dst_addr = ScionAddrSvc::new(dst_ia, ServiceAddr::CONTROL);

            let path = TestPathBuilder::new(src_addr, dst_addr.into())
                .core()
                .add_hop(0, 1)
                .add_hop(1, 0)
                .build(0)
                .path();

            use prost::Message;

            let mut req_packet = ScionUdpPacket::new(
                ScionSocketAddr::new(src_addr.isd_asn(), src_addr.host(), 12345),
                ScionSocketAddr::new(dst_addr.isd_asn, dst_addr.host.into(), 54321),
                path.dp_path().to_model(),
                ServiceResolutionRequest {}.encode_to_vec(),
            )
            .into_raw()
            .try_encode_to_owned_view()
            .expect("Should encode");

            NetworkSimulator::new(&network_receivers, &Default::default(), &topology, false)
                .dispatch(src_ia, 0, ScionNetworkTime(0), &mut req_packet);

            let recv = src_receiver
                .last_recv()
                .expect("Should have received a packet");

            let udp: ScionUdpPacket = recv.try_into().expect("Should have received a udp packet");
            assert!(
                matches!(udp.header.path, DpPath::Standard(_)),
                "Expected a Standard path in the response"
            );

            let rsp = ServiceResolutionResponse::decode(Cursor::new(&udp.payload.payload))
                .expect("Should decode ServiceResolutionResponse");

            let ip = rsp
                .transports
                .get("test")
                .expect("Should have resolution for 'test'")
                .address
                .parse::<SocketAddr>()
                .expect("Should have valid IP in resolution");

            assert_eq!(ip, svc_addr);
        }
    }

    mod dispatch {

        use sciparse::payload::scmp::{
            model::{ScmpDestinationUnreachable, ScmpMessage},
            types::ScmpDestinationUnreachableCode,
        };

        use super::*;
        use crate::network::scion::util::test_topology_ext::TestPathContextTopologyExt;

        #[test_log::test]
        fn should_dispatch_outgoing_packet() {
            let mut test = setup(
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
            let ext_as_registry = ExternalAsRegistry::new();
            let sim = NetworkSimulator::new(&test.targets, &ext_as_registry, &topology, false);

            sim.dispatch(
                test.src.isd_asn(),
                0,
                ScionNetworkTime(test.ctx.timestamp),
                &mut test.packet,
            );

            assert_eq!(test.dst_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(test.src_dp.rx_count(), 0, "Src should not have rx");
        }

        #[test_log::test]
        fn should_respond_with_destination_unreachable_when_ip_not_bound() {
            let mut test = setup(
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
            let ext_as_registry = ExternalAsRegistry::new();
            NetworkSimulator::new(&test.targets, &ext_as_registry, &topology, false).dispatch(
                test.src.isd_asn(),
                0,
                ScionNetworkTime(test.ctx.timestamp),
                &mut test.packet,
            );

            assert_eq!(test.dst_dp.rx_count(), 0, "Dst should not have rx");
            assert_eq!(test.src_dp.rx_count(), 1, "Should have received one packet");
            assert_eq!(
                test.src_dp.rx_scmp(),
                1,
                "Should have received one SCMP packet"
            );

            let scmp_packet = test.src_dp.last_recv().unwrap();
            let scmp = scmp_packet
                .try_classify()
                .expect("Should classify SCMP packet")
                .try_into_scmp()
                .expect("Should convert to SCMP packet");

            let ScmpMessage::DestinationUnreachable(ScmpDestinationUnreachable {
                code: ScmpDestinationUnreachableCode::AddressUnreachable,
                ..
            }) = scmp.payload
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
            let mut test = setup(test, 1234567, None); // Packet TTL expired - fails directly

            let topology = test.ctx.build_topology();
            let ext_as_registry = ExternalAsRegistry::new();
            NetworkSimulator::new(&test.targets, &ext_as_registry, &topology, false).dispatch(
                test.src.isd_asn(),
                0,
                ScionNetworkTime(test.ctx.timestamp),
                &mut test.packet,
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

            let mut test = setup(test, 1234567, None);

            let topology = test.ctx.build_topology();
            let ext_as_registry = ExternalAsRegistry::new();
            NetworkSimulator::new(&test.targets, &ext_as_registry, &topology, false).dispatch(
                test.src.isd_asn(),
                0,
                ScionNetworkTime(test.ctx.timestamp),
                &mut test.packet,
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
        last_packet: Mutex<Option<ScionRawPacket>>,
    }
    impl MockReceiver {
        pub fn rx_count(&self) -> usize {
            self.dispatch_count
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn rx_scmp(&self) -> usize {
            self.scmp_count.load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn last_recv(&self) -> Option<ScionRawPacket> {
            self.last_packet.lock().unwrap().clone()
        }
    }

    impl Receiver for MockReceiver {
        fn receive_packet(&self, packet: &ScionRawPacketView) {
            let packet_type = packet.try_classify().expect("All packets should be valid");
            self.dispatch_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if let ClassifiedPacketView::Scmp(..) = packet_type {
                self.scmp_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            self.last_packet
                .lock()
                .unwrap()
                .replace(packet.try_to_model().expect("Should convert to model"));
        }
    }
}
