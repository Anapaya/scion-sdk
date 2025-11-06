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

//! Helper to calculate field offsets in a SCION packet

/// Generates basic member functions like
///
/// ```ignore
/// pub fn field_a(&self) -> BitOffset {
///     BitOffset(Self::START + 10)
/// }
/// ```
macro_rules! gen_static_field_offset {
    ($(($offset:expr, $name:ident)),* $(,)?) => {
        $(
            /// Returns the offset in bits to the field.
            #[allow(unused)]
            pub fn $name(&self) -> BitOffset {
                BitOffset(Self::START + $offset)
            }
        )*
    };
}

/// Generates basic member functions like
///
/// ```ignore
/// pub fn field_b(&self) -> BitOffset {
///     BitOffset(self.base_offset + 10)
/// }
/// ```
macro_rules! gen_variable_field_offset {
    ($(($offset:expr, $name:ident)),* $(,)?) => {
        $(
            /// Returns the offset in bits to the field.
            ///
            /// If packet is badly formatted, offset will point to the wrong location.
            #[allow(unused)]
            pub fn $name(&self) -> BitOffset {
                BitOffset(self.base_offset + $offset)
            }
        )*
    };
}

/// Bit offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitOffset(u16);
impl BitOffset {
    /// Returns the offset in bytes
    pub fn bytes(self) -> u16 {
        self.0 / 8
    }

    /// Returns the offset in bits
    pub fn bits(self) -> u16 {
        self.0
    }
}
impl From<BitOffset> for u16 {
    fn from(value: BitOffset) -> Self {
        value.0
    }
}
impl std::fmt::Display for BitOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bit", self.bits())
    }
}

///
/// Helper to calculate field offsets in a SCION packet
pub struct ScionPacketOffset;
impl ScionPacketOffset {
    /// Returns the offsets for the common header fields.
    pub fn common_header() -> CommonHeaderLayout {
        CommonHeaderLayout
    }

    /// Returns the offsets for the address header fields.
    pub fn address_header() -> AddressHeaderLayout {
        AddressHeaderLayout
    }

    /// Returns the offsets for the standard path fields.
    ///
    /// If packet is malformed, this will return invalid offsets.
    pub fn std_path(encoded_packet: &[u8]) -> StandardPathLayout {
        let offset = AddressHeaderLayout::end(encoded_packet);
        let info_field_count = PathMetaHeaderLayout::info_field_count(offset, encoded_packet);
        StandardPathLayout::new(offset, info_field_count)
    }
}

/// Common header layout.
pub struct CommonHeaderLayout;
impl CommonHeaderLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Version| TrafficClass  |                FlowID                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    NextHdr    |    HdrLen     |          PayloadLen           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    PathType   |DT |DL |ST |SL |              RSV              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const COMMON_HEADER_SIZE: u16 = 96;

    /// Start offset.
    pub const START: u16 = 0;
    /// End offset.
    pub const END: u16 = Self::COMMON_HEADER_SIZE;

    /// Returns lengths of src and dst address fields in bits.
    ///
    /// (src, dst)
    fn addr_lengths(encoded_packet: &[u8]) -> (u16, u16) {
        const MIN_LENGTH: usize = 12;
        if encoded_packet.len() < MIN_LENGTH {
            return (32, 32); // Default to 32 bits if packet is invalid
        }

        const SRC_LEN_MASK: u8 = 0b00000011;
        const DST_LEN_MASK: u8 = 0b00110000;

        let addr_len_part = encoded_packet[9];

        let src_addr_len = (((addr_len_part & SRC_LEN_MASK) + 1) * 4) as u16;
        let dst_addr_len = ((((addr_len_part & DST_LEN_MASK) >> 4) + 1) * 4) as u16;

        (src_addr_len * 8, dst_addr_len * 8)
    }

    gen_static_field_offset! {
        (0, base),
        (0, version),
        (4, traffic_class),
        (12, flow_id),
        (32, next_header),
        (40, hdr_length),
        (48, payload_len),
        (64, path_type),
        (72, dst_addr_type),
        (74, dst_addr_len),
        (76, src_addr_type),
        (78, src_addr_len),
        (80, reserved),
    }
}

/// Address header layout.
pub struct AddressHeaderLayout;
impl AddressHeaderLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            DstISD             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                             DstAS                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            SrcISD             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                             SrcAS                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    DstHostAddr (variable Len)                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    SrcHostAddr (variable Len)                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const ADDRESS_HEADER_STATIC_SIZE: u16 = 128;

    /// Start offset.
    pub const START: u16 = CommonHeaderLayout::END;
    /// Final static offset
    const STATIC_END: u16 = Self::START + Self::ADDRESS_HEADER_STATIC_SIZE;

    /// Returns the offset in bits to the end of the address header.
    fn end(encoded_packet: &[u8]) -> u16 {
        let (src_addr_len, dst_addr_len) = CommonHeaderLayout::addr_lengths(encoded_packet);
        Self::STATIC_END + src_addr_len + dst_addr_len
    }

    gen_static_field_offset! {
        (0, base),
        (0, dst_isd),
        (16, dst_as),
        (64, src_isd),
        (80, src_as),
        (128, dst_host_addr),
    }

    /// Returns the source host address offset
    pub fn src_host_addr(&self, encoded_packet: &[u8]) -> BitOffset {
        let (_, dst_addr_len) = CommonHeaderLayout::addr_lengths(encoded_packet);
        BitOffset(Self::STATIC_END + dst_addr_len)
    }
}

///
/// Standard Path Offsets
pub struct StandardPathLayout {
    base_offset: u16,
    info_field_count: u8,
}
impl StandardPathLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          PathMetaHdr                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+`

    fn new(base_offset: u16, info_field_count: u8) -> Self {
        Self {
            base_offset,
            info_field_count,
        }
    }

    /// Returns the base offset.
    pub fn base(&self) -> BitOffset {
        BitOffset(self.base_offset)
    }

    /// Return the path meta header offset.
    pub fn path_meta_header(&self) -> PathMetaHeaderLayout {
        PathMetaHeaderLayout {
            base_offset: self.base_offset,
        }
    }

    /// Get the offset for the info field at the given index.
    pub fn info_field(&self, index: u8) -> InfoFieldLayout {
        let base_offset = self.base_offset
            + PathMetaHeaderLayout::META_HEADER_SIZE
            + InfoFieldLayout::INFO_FIELD_SIZE * index as u16;
        InfoFieldLayout { base_offset }
    }

    /// Get the offset for the .
    pub fn hop_field(&self, index: u8) -> HopFieldLayout {
        // Add info field size to the base offset
        let base_offset = self.base_offset
            + PathMetaHeaderLayout::META_HEADER_SIZE
            + InfoFieldLayout::INFO_FIELD_SIZE * self.info_field_count as u16
            + HopFieldLayout::HOP_FIELD_SIZE * index as u16;

        HopFieldLayout { base_offset }
    }
}

/// Path meta header layout
pub struct PathMetaHeaderLayout {
    base_offset: u16,
}
impl PathMetaHeaderLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | C |  CurrHF   |    RSV    |  Seg0Len  |  Seg1Len  |  Seg2Len  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const META_HEADER_SIZE: u16 = 32;

    /// Returns the count of info fields in the path meta header.
    fn info_field_count(base_offset: u16, encoded_packet: &[u8]) -> u8 {
        debug_assert!(
            base_offset.is_multiple_of(8),
            "Path meta header base offset must be a multiple of 8 bits but got {base_offset}"
        );

        let offset = (base_offset / 8) as usize;
        let min_length = offset + (Self::META_HEADER_SIZE / 8) as usize;
        if encoded_packet.len() < min_length {
            return 0;
        }

        let path_meta_header = u32::from_be_bytes([
            encoded_packet[offset],
            encoded_packet[offset + 1],
            encoded_packet[offset + 2],
            encoded_packet[offset + 3],
        ]);

        // 6 bits for each segment length
        const SEG2_MASK: u32 = 0b11_1111;
        const SEG1_MASK: u32 = SEG2_MASK << 6;
        const SEG0_MASK: u32 = SEG2_MASK << 12;

        let seg0 = (path_meta_header & SEG0_MASK) > 0;
        let seg1 = (path_meta_header & SEG1_MASK) > 0;
        let seg2 = (path_meta_header & SEG2_MASK) > 0;

        seg0 as u8 + seg1 as u8 + seg2 as u8
    }

    gen_variable_field_offset!(
        (0, base),
        (0, current_info_field),
        (2, current_hop_field),
        (8, reserved),
        (14, seg_len_0),
        (20, seg_len_1),
        (26, seg_len_2)
    );
}

#[doc(hidden)]
pub struct InfoFieldLayout {
    base_offset: u16,
}
impl InfoFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |r r r r r r P C|      RSV      |             SegID             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           Timestamp                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const INFO_FIELD_SIZE: u16 = 64;

    gen_variable_field_offset! {
        (0, base),
        (0, flags),
        (6, peering_flag),
        (7, construction_dir_flag),
        (8, reserved),
        (16, segment_id),
        (32, timestamp),
    }
}

#[doc(hidden)]
pub struct HopFieldLayout {
    base_offset: u16,
}
impl HopFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |r r r r r r I E|    ExpTime    |           ConsIngress         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ConsEgress             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                              MAC                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    const HOP_FIELD_SIZE: u16 = 96;

    gen_variable_field_offset! {
        (0, base),
        (0, flags),
        (6, ingress_router_alert),
        (7, egress_router_alert),
        (8, exp_time),
        (16, cons_ingress),
        (32, cons_egress),
        (48, mac),
    }

    /// Returns the offset to the normalized ingress router alert bit.
    pub fn travel_ingress_router_alert(&self, is_construction_dir: bool) -> BitOffset {
        if is_construction_dir {
            self.ingress_router_alert()
        } else {
            self.egress_router_alert()
        }
    }

    /// Returns the offset to the normalized egress router alert bit.
    pub fn travel_egress_router_alert(&self, is_construction_dir: bool) -> BitOffset {
        if is_construction_dir {
            self.egress_router_alert()
        } else {
            self.ingress_router_alert()
        }
    }

    /// Returns the offset to the normalized ingress.
    pub fn travel_ingress(&self, is_construction_dir: bool) -> BitOffset {
        if is_construction_dir {
            self.cons_ingress()
        } else {
            self.cons_egress()
        }
    }

    /// Returns the offset to the normalized egress.
    pub fn travel_egress(&self, is_construction_dir: bool) -> BitOffset {
        if is_construction_dir {
            self.cons_egress()
        } else {
            self.cons_ingress()
        }
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use bytes::Bytes;

    use super::*;
    use crate::{
        address::{ScionAddr, ScionAddrV4, ScionAddrV6},
        packet::{ByEndpoint, FlowId, ScionPacketRaw},
        path::{DataPlanePath, HopField, InfoField, StandardPath},
        wire_encoding::WireEncodeVec,
    };

    #[test]
    fn should_work_for_all_variants() {
        test_variant(32, 32, 0);
        test_variant(32, 32, 3);
        test_variant(32, 128, 0);
        test_variant(32, 128, 3);
        test_variant(128, 32, 0);
        test_variant(128, 32, 3);
        test_variant(128, 128, 0);
        test_variant(128, 128, 3);

        fn test_variant(src_addr_len: u8, dst_addr_len: u8, info_fields: u8) {
            let src_addr = match src_addr_len {
                32 => ScionAddr::V4(ScionAddrV4::from_str("1-1,10.1.1.1").unwrap()),
                128 => ScionAddr::V6(ScionAddrV6::from_str("1-1,::1").unwrap()),
                _ => panic!("Invalid source address length, can only be 32 or 128 bits"),
            };

            let dst_addr = match dst_addr_len {
                32 => ScionAddr::V4(ScionAddrV4::from_str("1-1,10.1.1.1").unwrap()),
                128 => ScionAddr::V6(ScionAddrV6::from_str("1-1,::1").unwrap()),
                _ => panic!("Invalid destination address length, can only be 32 or 128 bits"),
            };

            let endpoints = ByEndpoint {
                source: src_addr,
                destination: dst_addr,
            };

            let mut standard_path = StandardPath::new();
            for _ in 0..info_fields {
                standard_path
                    .add_segment(
                        InfoField {
                            peer: false,
                            cons_dir: false,
                            seg_id: 0,
                            timestamp_epoch: 0,
                        },
                        vec![HopField::default()],
                    )
                    .expect("failed to add segment")
            }

            let data_plane_path = DataPlanePath::Standard(standard_path.into());

            let packet = ScionPacketRaw::new(
                endpoints,
                data_plane_path,
                Bytes::new(),
                0,
                FlowId::new(0).unwrap(),
            )
            .unwrap();

            let pck = packet.encode_to_bytes_vec().concat();

            validate(src_addr_len, dst_addr_len, info_fields, pck);
        }
    }

    #[test]
    fn should_never_panic() {
        // If packet is invalid, it should just assume 32bit addresses and no info fields
        let pck = vec![];
        validate(32, 32, 0, pck);
    }

    fn validate(src_addr_len: u8, dst_addr_len: u8, info_fields: u8, pck: Vec<u8>) {
        let expected_src_host_addr_offset = AddressHeaderLayout::STATIC_END + dst_addr_len as u16;

        let expected_path_meta_header_base =
            AddressHeaderLayout::STATIC_END + dst_addr_len as u16 + src_addr_len as u16;

        let expected_info_field_base =
            expected_path_meta_header_base + PathMetaHeaderLayout::META_HEADER_SIZE;

        let expected_hop_field_base =
            expected_info_field_base + InfoFieldLayout::INFO_FIELD_SIZE * info_fields as u16;

        // Common Header
        {
            let ch = ScionPacketOffset::common_header();
            assert_eq!(0, ch.version().bits());
            assert_eq!(4, ch.traffic_class().bits());
            assert_eq!(12, ch.flow_id().bits());
            assert_eq!(32, ch.next_header().bits());
            assert_eq!(40, ch.hdr_length().bits());
            assert_eq!(48, ch.payload_len().bits());
            assert_eq!(64, ch.path_type().bits());
            assert_eq!(72, ch.dst_addr_type().bits());
            assert_eq!(74, ch.dst_addr_len().bits());
            assert_eq!(76, ch.src_addr_type().bits());
            assert_eq!(78, ch.src_addr_len().bits());
        }

        // Address Header
        {
            let base = AddressHeaderLayout::START;
            let ah = ScionPacketOffset::address_header();
            assert_eq!(base, ah.dst_isd().bits());
            assert_eq!(base + 16, ah.dst_as().bits());
            assert_eq!(base + 64, ah.src_isd().bits());
            assert_eq!(base + 80, ah.src_as().bits());
            assert_eq!(base + 128, ah.dst_host_addr().bits());
            assert_eq!(expected_src_host_addr_offset, ah.src_host_addr(&pck).bits());
        }

        // Std Path
        {
            let path = ScionPacketOffset::std_path(&pck);
            assert_eq!(path.info_field_count, info_fields);
        }

        // Info Field
        {
            let info_field = ScionPacketOffset::std_path(&pck).info_field(0);
            let base = info_field.base().bits();
            assert_eq!(expected_info_field_base, base);
            assert_eq!(base, info_field.flags().bits());
            assert_eq!(base + 6, info_field.peering_flag().bits());
            assert_eq!(base + 7, info_field.construction_dir_flag().bits());
            assert_eq!(base + 8, info_field.reserved().bits());
            assert_eq!(base + 16, info_field.segment_id().bits());
            assert_eq!(base + 32, info_field.timestamp().bits());

            let info_field = ScionPacketOffset::std_path(&pck).info_field(1);
            let base = info_field.base().bits();
            assert_eq!(
                expected_info_field_base + InfoFieldLayout::INFO_FIELD_SIZE,
                base
            );
            assert_eq!(base, info_field.flags().bits());
            assert_eq!(base + 6, info_field.peering_flag().bits());
            assert_eq!(base + 7, info_field.construction_dir_flag().bits());
            assert_eq!(base + 8, info_field.reserved().bits());
            assert_eq!(base + 16, info_field.segment_id().bits());
            assert_eq!(base + 32, info_field.timestamp().bits());
        }

        // Hop Field
        {
            let hop_field = ScionPacketOffset::std_path(&pck).hop_field(0);
            let base = hop_field.base().bits();
            assert_eq!(expected_hop_field_base, base);
            assert_eq!(base, hop_field.flags().bits());
            assert_eq!(base + 6, hop_field.ingress_router_alert().bits());
            assert_eq!(base + 7, hop_field.egress_router_alert().bits());
            assert_eq!(base + 8, hop_field.exp_time().bits());
            assert_eq!(base + 16, hop_field.cons_ingress().bits());
            assert_eq!(base + 32, hop_field.cons_egress().bits());
            assert_eq!(base + 48, hop_field.mac().bits());

            let hop_field = ScionPacketOffset::std_path(&pck).hop_field(1);
            let base = hop_field.base().bits();
            assert_eq!(
                expected_hop_field_base + HopFieldLayout::HOP_FIELD_SIZE,
                base
            );
            assert_eq!(base, hop_field.flags().bits());
            assert_eq!(base + 6, hop_field.ingress_router_alert().bits());
            assert_eq!(base + 7, hop_field.egress_router_alert().bits());
            assert_eq!(base + 8, hop_field.exp_time().bits());
            assert_eq!(base + 16, hop_field.cons_ingress().bits());
            assert_eq!(base + 32, hop_field.cons_egress().bits());
            assert_eq!(base + 48, hop_field.mac().bits());
        }
    }

    /// Tests for the helper calculations
    mod helper {
        use super::*;
        use crate::{
            packet::{ByEndpoint, CommonHeader},
            path::MetaHeader,
            wire_encoding::WireEncode,
        };

        #[test]
        fn should_get_correct_address_field_lengths() {
            let mut base_common_header = CommonHeader {
                version: 0.into(),
                traffic_class: 0,
                flow_id: 0.into(),
                next_header: 0,
                header_length_factor: 9.try_into().unwrap(),
                payload_length: 9.try_into().unwrap(),
                path_type: crate::path::PathType::Empty,
                address_info: ByEndpoint {
                    source: 0b0000.into(),
                    destination: 0b0000.into(),
                },
                reserved: 0,
            };

            let (src, dst) =
                CommonHeaderLayout::addr_lengths(&base_common_header.encode_to_bytes());
            assert_eq!(src, 32);
            assert_eq!(dst, 32);

            base_common_header.address_info = ByEndpoint {
                source: 0b0001.into(),
                destination: 0b0001.into(),
            };

            let (src, dst) =
                CommonHeaderLayout::addr_lengths(&base_common_header.encode_to_bytes());
            assert_eq!(src, 64);
            assert_eq!(dst, 64);

            base_common_header.address_info = ByEndpoint {
                source: 0b0010.into(),
                destination: 0b0010.into(),
            };

            let (src, dst) =
                CommonHeaderLayout::addr_lengths(&base_common_header.encode_to_bytes());
            assert_eq!(src, 96);
            assert_eq!(dst, 96);

            base_common_header.address_info = ByEndpoint {
                source: 0b0001.into(),
                destination: 0b0011.into(),
            };

            let (src, dst) =
                CommonHeaderLayout::addr_lengths(&base_common_header.encode_to_bytes());
            assert_eq!(src, 64);
            assert_eq!(dst, 128);
        }

        #[test]
        fn should_get_correct_info_field_count() {
            let mut base_header = MetaHeader {
                current_info_field: 0.into(),
                current_hop_field: 0.into(),
                reserved: 0.into(),
                segment_lengths: [0.into(), 0.into(), 0.into()],
            };
            assert_eq!(
                PathMetaHeaderLayout::info_field_count(0, &base_header.encode_to_bytes()),
                0
            );

            base_header.segment_lengths = [3.into(), 0.into(), 0.into()];
            assert_eq!(
                PathMetaHeaderLayout::info_field_count(0, &base_header.encode_to_bytes()),
                1
            );

            base_header.segment_lengths = [3.into(), 7.into(), 0.into()];
            assert_eq!(
                PathMetaHeaderLayout::info_field_count(0, &base_header.encode_to_bytes()),
                2
            );

            base_header.segment_lengths = [3.into(), 7.into(), 1.into()];
            assert_eq!(
                PathMetaHeaderLayout::info_field_count(0, &base_header.encode_to_bytes()),
                3
            );

            // With Offset
            let padding = 24;
            let mut encoded_packet = vec![0; padding];
            base_header.segment_lengths = [3.into(), 7.into(), 0.into()];
            encoded_packet.extend_from_slice(&base_header.encode_to_bytes());
            assert_eq!(
                PathMetaHeaderLayout::info_field_count((padding * 8) as u16, &encoded_packet),
                2
            );
        }

        #[test]
        fn should_byte_into_bit() {
            let offset = BitOffset(16);
            assert_eq!(offset.bytes(), 2);
            assert_eq!(offset.bits(), 16);

            let offset = BitOffset(7);
            assert_eq!(offset.bytes(), 0);
            assert_eq!(offset.bits(), 7);
        }
    }
}
