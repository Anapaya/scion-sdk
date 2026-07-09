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
//! Utility for constructing deterministic tests for SCION packets
//!
//! The [`TestPathBuilder`] defines:
//! - the exact sequence and state of hops a packet takes
//! - the path metadata such as expiration and interfaces
//!
//!  #### To create a basic path
//! ```ignore
//! let segment_creation_timestamp = Utc::now().timestamp() as u32;
//! let routing_timestamp = segment_creation_timestamp + 1000;
//! let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
//! let dst_address = EndhostAddr::from_str("1-10,4.4.4.4").unwrap();
//!
//! let context: TestContext = TestPathBuilder::new()
//!     .using_info_timestamp(segment_creation_timestamp)
//!     .up()
//!     .add_hop(0, 1)
//!     .add_hop(1, 0)
//!     .build(src_address, dst_address, routing_timestamp);
//! ```
//!
//! ----
//!
//! #### Creating SCION Packets
//!
//! ```ignore
//! let mut scion_raw = context.scion_packet_raw(b"example");
//! let scion_scmp =
//!     context.scion_packet_scmp(ScmpEchoRequest::new(1, 1, b"example".to_vec().into()).into());
//! let scion_udp = context.scion_packet_udp(b"example", 54000, 8080);
//! ```
//! ----
//!
//! #### Using the Test Context
//!
//! The test context can be directly used with any type taking a Topology and a Packet
//! ```ignore
//! let result = TopologyNetworkSim::simulate_traversal::<SpecRoutingLogic>(
//!     &ctx_topology,
//!     &mut scion_raw,
//!     ScionNetworkTime(context.timestamp),
//!     context.src_address.isd_asn(),
//! )
//! ```
//!
//! ----
//!
//! #### More Complex Paths
//! ```ignore
//! let context: TestContext = TestBuilder::new()
//!     .down() // Following hops are part of a down segment
//!     .add_hop(0, 2) // Normal entry hop, egress through interface 2
//!     .add_hop_with_egress_down(3, 4) // This hop will have egress interface down
//!     .add_hop_with_alerts(2, true, 0, false) // This hop has SCMP alert on ingress
//!     .core() // Following hops are part of a core segment
//!     .using_forwarding_key([2; 16].into()) // Following hops use this key
//!     .add_hop(0, 1) // Normal core hop
//!     .add_hop(1, 0) // Core hop to local
//!     .build_with_path_modifier(src_address, dst_address, routing_timestamp, |mut path| {
//!         // Allow any modifications to the path
//!         path.hop_fields[1].mac = [0u8; 6]; // E.g. Tamper with the hop mac to simulate a fault
//!         path
//!     });
//! ```
//!
//! ----
//!
//! #### More Complex Use Cases
//!
//! [`TestPathContext`] exposes the [`TestPathBuilderSegment`] it used to build the Path
//!
//! You can use these to build wrappers around the TestPathContext for specialized use
//! cases.

use tinyvec::ArrayVec;

use crate::{
    address::{addr::ScionAddr, socket_addr::ScionSocketAddr},
    dataplane_path::{
        model::DpPath,
        standard::{
            mac::{ForwardingKey, algo::mac_beta_step},
            model::{HopField, InfoField, Segment, StandardPath},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags, exp_time_to_duration},
        },
    },
    identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
    packet::model::{ScionRawPacket, ScionScmpPacket, ScionUdpPacket},
    path::{
        ScionPath,
        metadata::{InterfaceMetadata, PathMetadata, path_interface::PathInterface},
    },
    payload::scmp::model::ScmpMessage,
};

/// A builder for constructing deterministic SCION Path tests.
///
/// The [`TestPathBuilder`] lets you define the exact hop sequence a packet
/// will traverse in a simulated SCION network.
///
/// It produces a [`TestPathContext`] which supplies valid packets.
///
/// This is intended for tests only, not for constructing production paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestPathBuilder {
    segments: Vec<TestPathBuilderSegment>,
    src_address: ScionAddr,
    dst_address: ScionAddr,
    current_isd: u16,
    current_asn: u32,
    default_timestamp: u32,
    default_hop_expiry: u8,
    default_key: ForwardingKey,
}

impl TestPathBuilder {
    /// Creates a new TestBuilder
    pub fn new(src_address: ScionAddr, dst_address: ScionAddr) -> Self {
        let current_isd = src_address.isd_asn().isd().0;
        let current_asn = src_address.isd_asn().asn().0 as u32;

        TestPathBuilder {
            src_address,
            dst_address,
            current_isd,
            current_asn,
            default_timestamp: 0,
            default_hop_expiry: 255,
            segments: Vec::new(),
            default_key: [0u8; 16],
        }
    }

    /// Sets the timestamp used in the following info fields
    #[inline]
    pub fn using_info_timestamp(mut self, timestamp: u32) -> Self {
        self.default_timestamp = timestamp;
        self
    }

    /// Sets the hop expiry time used in the following hop fields
    #[inline]
    pub fn with_hop_expiry(mut self, exp_time: u8) -> Self {
        self.default_hop_expiry = exp_time;
        self
    }

    /// Sets the forwarding key used in the following hop fields
    #[inline]
    pub fn using_forwarding_key(mut self, key: ForwardingKey) -> Self {
        self.default_key = key;
        self
    }

    /// Sets the ISD used in the next hops
    ///
    /// Note: This can make the path invalid if the ISD changes do not align with segment changes
    #[inline]
    pub fn with_isd(mut self, isd: u16) -> Self {
        self.current_isd = isd;
        self
    }

    /// Sets the ASN used for the next hop
    ///
    /// ASN is automatically incremented when adding a hop
    ///
    /// The set ASN will be ignored on the last hop of the path, which is always set to the
    /// destination isd-asn.
    ///
    /// Note: This can make the path invalid if the first or last ASNs do not match the source or
    /// destination addresses
    #[inline]
    pub fn with_asn(mut self, asn: u32) -> Self {
        self.current_asn = asn;
        self
    }

    /// Adds a down segment to the path
    #[inline]
    pub fn down(mut self) -> Self {
        self.add_segment(
            true,
            self.default_timestamp,
            TestRoutingLinkType::LinkToChild,
        );
        self
    }

    /// Adds a core segment to the path
    #[inline]
    pub fn core(mut self) -> Self {
        self.add_segment(
            true,
            self.default_timestamp,
            TestRoutingLinkType::LinkToCore,
        );
        self
    }

    /// Adds an up segment to the path
    #[inline]
    pub fn up(mut self) -> Self {
        self.add_segment(
            false,
            self.default_timestamp,
            TestRoutingLinkType::LinkToParent,
        );
        self
    }

    /// Adds a hop to the current segment with given ingress and egress interfaces
    #[inline]
    pub fn add_hop(self, ingress_if: u16, egress_if: u16) -> Self {
        self.add_hop_internal(ingress_if, false, egress_if, false, false)
    }

    /// Adds a hop to the current segment with given ingress and egress interface where the egress
    /// is down
    #[inline]
    pub fn add_hop_with_egress_down(self, ingress_if: u16, egress_if: u16) -> Self {
        self.add_hop_internal(ingress_if, false, egress_if, false, true)
    }

    /// Adds a hop to the current segment with given ingress and egress interfaces and router alerts
    #[inline]
    pub fn add_hop_with_alerts(
        self,
        ingress_if: u16,
        ingress_alert: bool,
        egress_if: u16,
        egress_alert: bool,
    ) -> Self {
        self.add_hop_internal(ingress_if, ingress_alert, egress_if, egress_alert, false)
    }

    fn add_hop_internal(
        mut self,
        ingress_if: u16,
        ingress_alert: bool,
        egress_if: u16,
        egress_alert: bool,
        egress_down: bool,
    ) -> Self {
        let current_segment = self
            .segments
            .last_mut()
            .expect("Path must have at least one segment");

        let isd = self.current_isd;
        let asn = self.current_asn;

        // Increment ASN for next hop, only if we are not at beginning of a segment change
        if egress_if != 0 {
            self.current_asn += 1;
        }

        let dst_isd = self.dst_address.isd_asn().isd();

        // If we are in a core segment, change current ISD to destination ISD after first hop
        // User still can override ISD with `with_isd` before adding each hop
        if current_segment.uplink_type == TestRoutingLinkType::LinkToCore {
            self.current_isd = dst_isd.0;
        }

        let cons_dir = current_segment
            .info_field
            .flags
            .contains(InfoFieldFlags::CONS_DIR);

        let (ingress_link_type, egress_link_type) = match (ingress_if, egress_if) {
            (0, 0) => (None, None),                                        // Local
            (0, _) => (None, Some(current_segment.uplink_type)),           // Local to egress
            (_, 0) => (Some(current_segment.uplink_type.reverse()), None), /* Ingress to local */
            (..) => {
                (
                    Some(current_segment.uplink_type.reverse()),
                    Some(current_segment.uplink_type),
                )
            }
        };

        current_segment.hop_fields.push(TestPathBuilderHopField {
            isd_asn: IsdAsn::new(Isd(isd), Asn(asn as u64)),
            cons_dir,
            ingress_link_type,
            ingress_if,
            egress_if,
            egress_link_type,
            egress_interface_down: egress_down,
            ingress_router_alert: ingress_alert,
            egress_router_alert: egress_alert,
            exp_time: self.default_hop_expiry,
            segment_change_next: false,
            forwarding_key: self.default_key,
        });

        self
    }

    /// Creates a test context
    ///
    /// Contains a valid SCION packet derived from the segments defined in the builder.
    ///
    /// Will set the last hop's ISD-AS to the destination address's ISD-AS.
    #[inline]
    pub fn build(self, routing_timestamp: u32) -> TestPathContext {
        self.build_with_path_modifier(routing_timestamp, |p| p)
    }

    /// Creates a test context
    ///
    /// Contains a valid SCION packet derived from the segments defined in the builder.
    ///
    /// Will set the last hop's ISD-AS to the destination address's ISD-AS.
    pub fn build_with_path_modifier(
        mut self,
        routing_timestamp: u32,
        path_modifier: impl FnOnce(StandardPath) -> StandardPath,
    ) -> TestPathContext {
        let src_address = self.src_address;
        let dst_address = self.dst_address;

        let mut segment_lengths: [u8; 3] = [0; 3];
        self.segments.iter().enumerate().for_each(|(i, segment)| {
            segment_lengths[i] = segment.hop_fields.len() as u8;
        });

        let path = match self.segments.is_empty() {
            true => DpPath::Empty,
            false => {
                // Set IsdAsn of last hop to destination AS
                if let Some(last_segment) = self.segments.iter_mut().last()
                    && let Some(last_hop) = last_segment.hop_fields.iter_mut().last()
                {
                    last_hop.isd_asn = dst_address.isd_asn();
                }

                let mut path_segments = ArrayVec::new();

                // Calculate MACs and build the hops
                for segment in &self.segments {
                    let mut previous_accumulator = segment.info_field.segment_id;
                    let mut accumulator = previous_accumulator;

                    // Calculating the macs has to happen in order of construction
                    let const_dir_iter: Box<
                        dyn DoubleEndedIterator<Item = &TestPathBuilderHopField>,
                    > = match segment.info_field.flags.contains(InfoFieldFlags::CONS_DIR) {
                        true => Box::new(segment.hop_fields.iter()),
                        false => Box::new(segment.hop_fields.iter().rev()),
                    };

                    // Calculate the MACs
                    let mut hops = const_dir_iter
                        .cloned()
                        .map(|hop_definition| {
                            let forwarding_key = hop_definition.forwarding_key;
                            let hop = hop_definition
                                .into_hop_field(accumulator, segment.info_field.timestamp);

                            previous_accumulator = accumulator;
                            accumulator = mac_beta_step(accumulator, *hop.mac);

                            (hop, forwarding_key)
                        })
                        .collect::<Vec<_>>();

                    let mut final_info = segment.info_field;

                    // If against the construction direction, the segment id is set to the previous
                    // accumulator
                    if !segment.info_field.flags.contains(InfoFieldFlags::CONS_DIR) {
                        // Reverse the hops
                        hops.reverse();
                        final_info.segment_id = previous_accumulator;
                    };

                    path_segments.push(Segment {
                        info_field: final_info,
                        hop_fields: hops.into_iter().map(|(hop, _)| hop).collect(),
                    });
                }

                let path = StandardPath {
                    current_info_field: 0,
                    current_hop_field: 0,
                    segments: path_segments,
                };

                path_modifier(path).into()
            }
        };

        // Find expiration of this path - lowest expiration of all hops
        let expiration = self
            .segments
            .iter()
            .flat_map(|seg| {
                seg.hop_fields.iter().map(|hop| {
                    seg.info_field.timestamp + exp_time_to_duration(hop.exp_time).as_secs() as u32
                })
            })
            .min()
            .unwrap_or(u32::MAX);

        // Collect interfaces for metadata
        let mut interfaces = Vec::new();
        for segment in &self.segments {
            for hop in &segment.hop_fields {
                let isd_asn = hop.isd_asn;
                if hop.ingress_if != 0 {
                    interfaces.push(InterfaceMetadata::new_without_metadata(PathInterface {
                        isd_asn,
                        id: hop.ingress_if,
                    }));
                }

                if hop.egress_if != 0 {
                    interfaces.push(InterfaceMetadata::new_without_metadata(PathInterface {
                        isd_asn,
                        id: hop.egress_if,
                    }));
                }
            }
        }

        let path_meta = PathMetadata {
            expiration: expiration as u64,
            mtu: 1280,
            interfaces: Some(interfaces),
            epic_auth: None,
            notes: None,
        };

        TestPathContext {
            data_plane_path: path,
            path_meta,
            timestamp: routing_timestamp,
            test_segments: self.segments,
            dst_address,
            src_address,
        }
    }

    fn add_segment(
        &mut self,
        is_construction_dir: bool,
        timestamp: u32,
        uplink_type: TestRoutingLinkType,
    ) {
        if self.segments.len() >= 3 {
            panic!("Path can not have more than 3 segments");
        }
        let info_field = InfoField {
            flags: match is_construction_dir {
                true => InfoFieldFlags::CONS_DIR,
                false => InfoFieldFlags::empty(),
            },
            segment_id: 0,
            timestamp,
        };

        if let Some(last) = self.segments.iter_mut().last() {
            last.hop_fields
                .iter_mut()
                .last()
                .expect("Last segment must have at least one hop")
                .segment_change_next = true;
        }

        self.segments.push(TestPathBuilderSegment {
            hop_fields: Vec::new(),
            info_field,
            uplink_type,
        });
    }
}

/// Test Context providing a Path and relevant per hop information
#[derive(Debug, Clone, PartialEq)]
pub struct TestPathContext {
    /// The path used in the SCION packets
    pub data_plane_path: DpPath,
    /// The metadata for the path
    pub path_meta: PathMetadata,
    /// The timestamp used when simulating the packet traversal
    pub timestamp: u32,

    /// Defines the segments used to build the packet
    pub test_segments: Vec<TestPathBuilderSegment>,

    /// The source address of the packet
    pub src_address: ScionAddr,
    /// The destination address of the packet
    pub dst_address: ScionAddr,
}

impl TestPathContext {
    /// Creates a raw SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_raw(&self, payload: &[u8]) -> ScionRawPacket {
        ScionRawPacket::new(
            self.src_address,
            self.dst_address,
            self.data_plane_path.clone(),
            crate::payload::ProtocolNumber::Other(0),
            payload.to_owned(),
        )
    }

    /// Creates a udp SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_udp(&self, payload: &[u8], src_port: u16, dst_port: u16) -> ScionUdpPacket {
        ScionUdpPacket::new(
            ScionSocketAddr::new(
                self.src_address.isd_asn(),
                self.src_address.host(),
                src_port,
            ),
            ScionSocketAddr::new(
                self.dst_address.isd_asn(),
                self.dst_address.host(),
                dst_port,
            ),
            self.data_plane_path.clone(),
            payload.to_owned(),
        )
    }

    /// Creates a scmp SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_scmp(&self, message: ScmpMessage) -> ScionScmpPacket {
        ScionScmpPacket::new(
            self.src_address,
            self.dst_address,
            self.data_plane_path.clone(),
            message,
        )
    }

    /// Creates a [ScionPath] from the context
    pub fn path(&self) -> ScionPath {
        ScionPath::new(
            self.src_address.isd_asn(),
            self.dst_address.isd_asn(),
            self.data_plane_path
                .try_encode_to_owned_view()
                .expect("Failed to encode path"),
            Some(self.path_meta.clone()),
            None,
        )
    }
}

/// General Definition of a Hop Field
///
/// Together with [TestPathBuilderSegment], this contains all relevant information to build a
/// [HopField]
///
/// For fields which mirror hop fields, see [HopField] for documentation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestPathBuilderHopField {
    /// The ISD-AS of this Hop
    pub isd_asn: IsdAsn,

    /// If the Hop field is defined in Construction direction
    /// ingress/egress in this struct are travel direction
    pub cons_dir: bool,

    /// Ingress interface (normalized to travel direction)
    pub ingress_if: u16,
    /// The link type to the ingress interface (None = Local)
    /// If e.g. LinkToParent, we are the Parent
    pub ingress_link_type: Option<TestRoutingLinkType>,
    /// If true, the ingress interface of this Hop will have a router alert
    pub ingress_router_alert: bool,

    /// Egress interface (normalized to travel direction)
    pub egress_if: u16,
    /// The link type from the egress interface (None = Local)
    /// If e.g. LinkToParent, we are the Child
    pub egress_link_type: Option<TestRoutingLinkType>,
    /// If true, the egress interface of this Hop will have a router alert
    pub egress_router_alert: bool,

    /// If true, the egress interface of this Hop will be down
    pub egress_interface_down: bool,

    /// Expiration time units for this hop
    pub exp_time: u8,

    /// Forwarding key to use to authenticate this packet
    pub forwarding_key: ForwardingKey,

    /// If after this Hop there will be a segment change
    pub segment_change_next: bool,
}

impl TestPathBuilderHopField {
    fn into_hop_field(self, mac_beta: u16, timestamp: u32) -> HopField {
        let (cons_ingress, cons_egress) = match self.cons_dir {
            true => (self.ingress_if, self.egress_if),
            false => (self.egress_if, self.ingress_if),
        };

        let (ingress_router_alert, egress_router_alert) = match self.cons_dir {
            true => (self.ingress_router_alert, self.egress_router_alert),
            false => (self.egress_router_alert, self.ingress_router_alert),
        };

        let mut flags = HopFieldFlags::empty();
        flags.set(
            HopFieldFlags::CONS_INGRESS_ROUTER_ALERT,
            ingress_router_alert,
        );
        flags.set(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT, egress_router_alert);

        HopField {
            cons_ingress,
            cons_egress,
            mac: HopFieldMac::zero(),
            expiration_units: self.exp_time,
            flags,
        }
        .with_calculated_mac(mac_beta, timestamp, &self.forwarding_key)
    }
}

/// General Definition of Segments
///
/// Contains all relevant information to build a PathSegment
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestPathBuilderSegment {
    /// Information field for this segment
    pub info_field: InfoField,
    /// Hop fields for this segment
    pub hop_fields: Vec<TestPathBuilderHopField>,
    /// Link type all egress interfaces have in this segment
    pub uplink_type: TestRoutingLinkType,
}

/// Defines the Link Type of a given Interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestRoutingLinkType {
    /// Link to a core AS.
    LinkToCore,
    /// Link to a parent AS.
    LinkToParent,
    /// Link to a child AS.
    LinkToChild,
    /// Link to a peer AS.
    LinkToPeer,
}

impl TestRoutingLinkType {
    /// Returns the reverse link type of the current link type.
    #[inline]
    pub const fn reverse(&self) -> Self {
        match self {
            TestRoutingLinkType::LinkToCore => TestRoutingLinkType::LinkToCore,
            TestRoutingLinkType::LinkToParent => TestRoutingLinkType::LinkToChild,
            TestRoutingLinkType::LinkToChild => TestRoutingLinkType::LinkToParent,
            TestRoutingLinkType::LinkToPeer => TestRoutingLinkType::LinkToPeer,
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::{
        address::addr::ScionAddr,
        identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
        path::metadata::path_interface::PathInterface,
    };

    #[test]
    fn should_generate_correct_interfaces() {
        let ctx = super::TestPathBuilder::new(
            ScionAddr::new(
                IsdAsn::new(Isd(1), Asn(2)),
                IpAddr::from([192, 168, 0, 1]).into(),
            ),
            ScionAddr::new(
                IsdAsn::new(Isd(2), Asn(2)),
                IpAddr::from([10, 0, 0, 1]).into(),
            ),
        )
        .using_info_timestamp(1000)
        .up()
        .add_hop(0, 1) // ISD 1-2
        .with_asn(8)
        .add_hop(2, 3) // ISD 1-3
        .with_asn(4)
        .add_hop(4, 0) // ISD 1-4
        .core()
        .add_hop(0, 5) // ISD 1-4
        .add_hop(6, 7) // ISD 2-5
        .add_hop(8, 0) // ISD 2-2
        .build(2000);

        let expected_interfaces = vec![
            (IsdAsn::new(Isd(1), Asn(2)), 1),
            (IsdAsn::new(Isd(1), Asn(8)), 2),
            (IsdAsn::new(Isd(1), Asn(8)), 3),
            (IsdAsn::new(Isd(1), Asn(4)), 4),
            (IsdAsn::new(Isd(1), Asn(4)), 5),
            (IsdAsn::new(Isd(2), Asn(5)), 6),
            (IsdAsn::new(Isd(2), Asn(5)), 7),
            (IsdAsn::new(Isd(2), Asn(2)), 8),
        ]
        .into_iter()
        .map(|(isd_asn, id)| PathInterface { isd_asn, id })
        .collect::<Vec<_>>();

        let interfaces = ctx
            .path_meta
            .interfaces
            .unwrap()
            .iter()
            .map(|interfaces| interfaces.interface)
            .collect::<Vec<_>>();

        assert_eq!(expected_interfaces, interfaces);
    }
}
