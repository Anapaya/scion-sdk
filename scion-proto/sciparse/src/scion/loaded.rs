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

//! Loaded SCION Packet Representation
//!
//! These structures represent SCION packet headers after having been fully parsed and loaded into
//! memory.
//!
//! These structures are intended for creating or manipulating SCION packet headers
//! programmatically.
//!
//! If a read only view is sufficient or you only need minimal changes on an existing buffer, prefer
//! using Views.

use crate::{
    helper::write::unchecked_bit_range_be_write,
    layout::{AddressHeaderLayout, CommonHeaderLayout, Layout},
    loaded::standard_path::StandardPath,
    traits::{InvalidStructureError, WireEncode},
    types::{
        address::{IsdAsn, ScionHostAddr, ScionHostAddrType},
        path::PathType,
    },
    views::{ScionHeaderView, ScionPacketView, ScionPathView, View, ViewConversionError},
};

/// A Complete SCION Packet
pub struct ScionPacket {
    /// SCION Packet Header
    pub header: ScionPacketHeader,
    /// Payload
    pub payload: Vec<u8>,
}

impl ScionPacket {
    /// Constructs a `ScionPacket` from a `ScionHeaderView` and payload slice
    pub fn from_view(view: &ScionPacketView) -> Self {
        ScionPacket {
            header: ScionPacketHeader::from_view(view.header()),
            payload: view.payload().to_vec(),
        }
    }

    /// Attempts to construct a `ScionPacket` from a byte slice
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (header, rest) = ScionPacketHeader::from_slice(buf)?;
        let (payload, rest) = rest
            .split_at_checked(header.common.payload_size as usize)
            .ok_or(ViewConversionError::BufferTooSmall {
                at: "Payload",
                required: header.common.payload_size as usize,
                actual: rest.len(),
            })?;

        Ok((
            ScionPacket {
                header,
                payload: payload.to_vec(),
            },
            rest,
        ))
    }
}
impl WireEncode for ScionPacket {
    fn required_size(&self) -> usize {
        self.header.required_size() + self.payload.len()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.header.wire_valid()?;

        if self.payload.len() != self.header.common.payload_size as usize {
            return Err("Payload size does not match header's payload_size field".into());
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        let header_size = self.header.required_size();

        unsafe {
            // Encode header
            {
                let header_buf = buf.get_unchecked_mut(0..header_size);
                self.header.encode_unchecked(header_buf);
            }
            // Encode payload
            buf.get_unchecked_mut(header_size..(header_size + self.payload.len()))
                .copy_from_slice(&self.payload);
        }

        self.required_size()
    }
}

/// Represents a SCION packet header
///
/// This structure contains all the fields of a SCION packet header,
/// including the common header, address header, and path information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScionPacketHeader {
    /// The common header of the SCION packet
    pub common: CommonHeader,
    /// The address header of the SCION packet
    pub address: AddressHeader,
    /// The path information of the SCION packet
    pub path: Path,
}

impl ScionPacketHeader {
    /// Constructs a `ScionPacketHeader` from a `ScionHeaderView`
    pub fn from_view(view: &ScionHeaderView) -> Self {
        ScionPacketHeader {
            common: CommonHeader::from_view(view),
            address: AddressHeader::from_view(view),
            path: Path::from_view(&view.path()),
        }
    }

    /// Attempts to construct a `ScionPacketHeader` from a byte slice
    ///
    /// Returns a tuple containing the `ScionPacketHeader` and the remaining slice after the header.
    /// On failure, returns a `ViewConversionError`.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (view, rest) = ScionHeaderView::from_slice(buf)?;
        Ok((Self::from_view(view), rest))
    }

    /// Returns the size of the SCION packet header in 4-byte units used in the header length field.
    fn size_units(&self) -> u8 {
        (self.required_size() / 4) as u8
    }
}

impl WireEncode for ScionPacketHeader {
    fn required_size(&self) -> usize {
        CommonHeaderLayout::SIZE_BYTES + self.address.required_size() + self.path.required_size()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.common.valid()?;
        self.address.wire_valid()?;
        self.path.wire_valid()?;
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use CommonHeaderLayout as CHL;
            // Encode common header
            self.common.encode(
                buf,
                self.size_units(),
                self.path.path_type(),
                self.address.dst_addr_type(),
                self.address.src_addr_type(),
            );

            // Encode address header
            let offset = CHL::SIZE_BYTES;
            let address_buf = buf.split_at_mut_unchecked(offset).1;
            self.address.encode_unchecked(address_buf);

            // Encode path
            let offset = offset + self.address.required_size();
            let path_buf = buf.split_at_mut_unchecked(offset).1;
            self.path.encode_unchecked(path_buf);
        }

        self.required_size()
    }
}

/// Represents the common header of a SCION packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonHeader {
    /// Traffic class of the SCION packet
    pub traffic_class: u8,
    /// Flow ID of the SCION packet
    pub flow_id: u32,
    /// Next header type
    ///
    /// Indicates the type of header that follows the SCION header. E.g., UDP, TCP, etc.
    pub next_header: u8,
    /// Payload size in bytes
    pub payload_size: u16,
}

impl CommonHeader {
    /// Constructs a `CommonHeader` from a `ScionHeaderView`
    pub fn from_view(view: &ScionHeaderView) -> Self {
        debug_assert!(view.version() == Self::VERSION, "Unsupported SCION version");
        CommonHeader {
            traffic_class: view.traffic_class(),
            flow_id: view.flow_id(),
            next_header: view.next_header(),
            payload_size: view.payload_len(),
        }
    }
}
// Wire Encode (needs size, so can't use trait)
impl CommonHeader {
    /// Validates that all fields in the `CommonHeader` are valid for encoding
    pub fn valid(&self) -> Result<(), InvalidStructureError> {
        use CommonHeaderLayout as CHL;

        if self.flow_id > CHL::FLOW_ID_RNG.max_uint() as u32 {
            return Err("flow_id exceeds maximum encodeable value".into());
        }

        // Payload size is u16, so all values are valid
        // Next header is a u8, so all values are valid

        Ok(())
    }

    const VERSION: u8 = 0;
    /// Encodes the `CommonHeader` into the provided buffer
    pub fn encode(
        &self,
        buf: &mut [u8],
        header_len_units: u8,
        path_type: PathType,
        dst_addr_type: ScionHostAddrType,
        src_addr_type: ScionHostAddrType,
    ) -> usize {
        unsafe {
            use CommonHeaderLayout as CHL;
            // Encode common header
            unchecked_bit_range_be_write(buf, CHL::VERSION_RNG, Self::VERSION);
            unchecked_bit_range_be_write(buf, CHL::TRAFFIC_CLASS_RNG, self.traffic_class);
            unchecked_bit_range_be_write(buf, CHL::FLOW_ID_RNG, self.flow_id);
            unchecked_bit_range_be_write(buf, CHL::NEXT_HEADER_RNG, self.next_header);
            unchecked_bit_range_be_write(buf, CHL::HEADER_LEN_RNG, header_len_units);
            unchecked_bit_range_be_write(buf, CHL::PAYLOAD_LEN_RNG, self.payload_size);
            unchecked_bit_range_be_write::<u8>(buf, CHL::PATH_TYPE_RNG, path_type.into());
            let dst_addr_info: u8 = dst_addr_type.into();
            unchecked_bit_range_be_write::<u8>(buf, CHL::DST_ADDR_INFO_RNG, dst_addr_info);
            let src_addr_info: u8 = src_addr_type.into();
            unchecked_bit_range_be_write::<u8>(buf, CHL::SRC_ADDR_INFO_RNG, src_addr_info);
            unchecked_bit_range_be_write(buf, CHL::RSV_RNG, 0u16); // Reserved
        }

        CommonHeaderLayout::SIZE_BYTES
    }
}

/// Represents the address header of a SCION packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressHeader {
    /// Destination ISD
    pub dst_ia: IsdAsn,
    /// Source ISD
    pub src_ia: IsdAsn,
    /// Destination host address
    pub dst_host_addr: ScionHostAddr,
    /// Source host address
    pub src_host_addr: ScionHostAddr,
}

impl AddressHeader {
    /// Constructs an `AddressHeader` from a `ScionHeaderView`
    pub fn from_view(view: &ScionHeaderView) -> Self {
        AddressHeader {
            dst_ia: IsdAsn::new(view.dst_isd(), view.dst_as()),
            src_ia: IsdAsn::new(view.src_isd(), view.src_as()),
            dst_host_addr: view.dst_host_addr().unwrap(),
            src_host_addr: view.src_host_addr().unwrap(),
        }
    }

    /// Returns the destination address type
    pub fn dst_addr_type(&self) -> ScionHostAddrType {
        self.dst_host_addr.addr_type()
    }

    /// Returns the source address type
    pub fn src_addr_type(&self) -> ScionHostAddrType {
        self.src_host_addr.addr_type()
    }
}

impl WireEncode for AddressHeader {
    fn required_size(&self) -> usize {
        AddressHeaderLayout::new(
            self.dst_host_addr.required_size() as u8,
            self.src_host_addr.required_size() as u8,
        )
        .size_bytes()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // ISD and ASN are newtypes, so assumed valid

        self.dst_host_addr.wire_valid()?;
        self.src_host_addr.wire_valid()?;

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use AddressHeaderLayout as AHL;
            unchecked_bit_range_be_write(buf, AHL::DST_ISD_RNG, self.dst_ia.isd().0);
            unchecked_bit_range_be_write(buf, AHL::DST_AS_RNG, self.dst_ia.asn().0);
            unchecked_bit_range_be_write(buf, AHL::SRC_ISD_RNG, self.src_ia.isd().0);
            unchecked_bit_range_be_write(buf, AHL::SRC_AS_RNG, self.src_ia.asn().0);

            let layout = AddressHeaderLayout::new(
                self.src_host_addr.required_size() as u8,
                self.dst_host_addr.required_size() as u8,
            );

            {
                let dst_host_buf =
                    buf.get_unchecked_mut(layout.dst_host_addr_range().aligned_byte_range());
                self.dst_host_addr.encode_unchecked(dst_host_buf);
            }

            {
                let src_host_buf =
                    buf.get_unchecked_mut(layout.src_host_addr_range().aligned_byte_range());
                self.src_host_addr.encode_unchecked(src_host_buf);
            }
        }

        self.required_size()
    }
}

/// Represents the path information of a SCION packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    /// Standard SCION path
    Standard(StandardPath),
    /// Empty path
    Empty,
    /// Unsupported path type with raw data
    Unsupported {
        /// The type of the unsupported path
        path_type: PathType,
        /// Raw path data
        data: Vec<u8>,
    },
}

impl Path {
    /// Constructs a `Path` from a `ScionPathView`
    pub fn from_view(view: &ScionPathView) -> Self {
        match *view {
            ScionPathView::Standard(standard_view) => {
                Path::Standard(StandardPath::from_view(standard_view))
            }
            ScionPathView::Empty => Path::Empty,
            ScionPathView::Unsupported {
                path_type,
                data: buf,
            } => {
                Path::Unsupported {
                    path_type,
                    data: buf.to_vec(),
                }
            }
        }
    }
}
impl Path {
    /// Returns the type of the path
    pub fn path_type(&self) -> PathType {
        match self {
            Path::Standard(_) => PathType::Scion,
            Path::Empty => PathType::Empty,
            Path::Unsupported { path_type, .. } => PathType::Other((*path_type).into()),
        }
    }

    /// Returns a reference to the standard path if it is of that type
    pub fn standard(&self) -> Option<&StandardPath> {
        match self {
            Path::Standard(path) => Some(path),
            _ => None,
        }
    }
}

impl WireEncode for Path {
    fn required_size(&self) -> usize {
        match self {
            Path::Standard(path) => path.required_size(),
            Path::Unsupported { data, .. } => data.len(),
            Path::Empty => 0,
        }
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        match self {
            Self::Standard(standard_path) => standard_path.wire_valid()?,
            Self::Empty => {}
            Self::Unsupported { path_type: _, data } => {
                if !data.len().is_multiple_of(4) {
                    return Err("Path data must be a multiple of 4 bytes".into());
                }
            }
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        match self {
            Path::Standard(path) => unsafe { path.encode_unchecked(buf) },
            Path::Empty => 0,
            Path::Unsupported { data, .. } => {
                let len = data.len();

                unsafe {
                    buf.get_unchecked_mut(..len).copy_from_slice(data);
                }

                len
            }
        }
    }
}

/// Module for standard SCION path representation
pub mod standard_path {

    use crate::{
        helper::write::unchecked_bit_range_be_write,
        layout::{HopFieldLayout, InfoFieldLayout, Layout, StdPathDataLayout, StdPathMetaLayout},
        traits::{InvalidStructureError, WireEncode},
        types::path::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
        views::{HopFieldView, InfoFieldView, StandardPathView},
    };

    /// Represents a standard SCION path
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StandardPath {
        /// The current info field index
        pub current_info_field: u8,
        /// The current hop field index
        pub curr_hop_field: u8,
        /// The segments of the path
        pub segments: Vec<Segment>,
    }

    impl StandardPath {
        /// Constructs a `StandardPath` from a `StandardPathView`
        pub fn from_view(view: &StandardPathView) -> Self {
            let info_fields = view.info_fields();
            let hop_fields = view.hop_fields();
            let segment_sizes = [view.seg0_len(), view.seg1_len(), view.seg2_len()];

            let mut segments = Vec::with_capacity(info_fields.len());
            let mut hop_fields_iter = hop_fields.iter();

            for (info_field, segment_size) in info_fields.iter().zip(segment_sizes.iter()) {
                let segment = Segment {
                    info_field: InfoField::from_view(info_field),
                    hop_fields: hop_fields_iter
                        .by_ref()
                        .take(*segment_size as usize)
                        .map(HopField::from_view)
                        .collect(),
                };

                segments.push(segment);
            }

            StandardPath {
                current_info_field: view.curr_info_field(),
                curr_hop_field: view.curr_hop_field(),
                segments,
            }
        }
    }

    // Utility
    impl StandardPath {
        /// Returns the total number of hop fields in the path
        pub fn hop_field_count(&self) -> usize {
            self.segments
                .iter()
                .map(|segment| segment.hop_fields.len())
                .sum()
        }

        /// Returns the total number of info fields in the path
        pub fn info_field_count(&self) -> usize {
            self.segments.len()
        }

        /// Returns the lengths of each segment in the path as a tuple
        pub fn segment_lengths(&self) -> (u8, u8, u8) {
            let seg0 = self.segments.first().map_or(0, |s| s.hop_fields.len()) as u8;
            let seg1 = self.segments.get(1).map_or(0, |s| s.hop_fields.len()) as u8;
            let seg2 = self.segments.get(2).map_or(0, |s| s.hop_fields.len()) as u8;
            (seg0, seg1, seg2)
        }

        /// Returns an iterator over all hop fields in the path
        pub fn iter_hop_fields(&self) -> impl Iterator<Item = &HopField> {
            self.segments
                .iter()
                .flat_map(|segment| segment.hop_fields.iter())
        }

        /// Returns an iterator over all info fields in the path
        pub fn iter_info_fields(&self) -> impl Iterator<Item = &InfoField> {
            self.segments.iter().map(|segment| &segment.info_field)
        }

        /// Returns the sizes of each segment in the path
        pub fn segment_sizes(&self) -> [u8; 3] {
            let seg0 = self.segments.first().map_or(0, |s| s.hop_fields.len()) as u8;
            let seg1 = self.segments.get(1).map_or(0, |s| s.hop_fields.len()) as u8;
            let seg2 = self.segments.get(2).map_or(0, |s| s.hop_fields.len()) as u8;
            [seg0, seg1, seg2]
        }
    }

    impl WireEncode for StandardPath {
        fn required_size(&self) -> usize {
            let [seg0, seg1, seg2] = self.segment_sizes();
            StdPathMetaLayout::SIZE_BYTES + StdPathDataLayout::new(seg0, seg1, seg2).size_bytes()
        }

        fn wire_valid(&self) -> Result<(), InvalidStructureError> {
            if self.curr_hop_field != 0 && self.curr_hop_field as usize >= self.hop_field_count() {
                return Err("curr_hop_field exceeds total number of hop fields".into());
            }

            if self.current_info_field != 0
                && self.current_info_field as usize >= self.info_field_count()
            {
                return Err("current_info_field exceeds total number of info fields".into());
            }

            if self.segments.is_empty() {
                return Err("Standard path must contain at least one segment".into());
            }

            for segment in &self.segments {
                if segment.hop_fields.len() > StdPathMetaLayout::MAX_SEGMENT_LENGTH {
                    return Err("Number of hop fields in segment exceeds maximum allowed".into());
                }

                if segment.hop_fields.is_empty() {
                    return Err("Segment must contain at least one hop field".into());
                }

                segment.info_field.wire_valid()?;

                for hop_field in &segment.hop_fields {
                    hop_field.wire_valid()?;
                }
            }

            Ok(())
        }

        unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
            use StdPathMetaLayout as SL;

            let [seg0, seg1, seg2] = self.segment_sizes();

            // Encode standard path meta information
            unsafe {
                unchecked_bit_range_be_write(buf, SL::CURR_INFO_FIELD_RNG, self.current_info_field);
                unchecked_bit_range_be_write(buf, SL::CURR_HOP_FIELD_RNG, self.curr_hop_field);
                unchecked_bit_range_be_write(buf, SL::SEG0_LEN_RNG, seg0);
                unchecked_bit_range_be_write(buf, SL::SEG1_LEN_RNG, seg1);
                unchecked_bit_range_be_write(buf, SL::SEG2_LEN_RNG, seg2);
            }

            // Advance offset to path data
            let data_buf = unsafe { buf.get_unchecked_mut(SL::SIZE_BYTES..) };
            let data_layout = StdPathDataLayout::new(seg0, seg1, seg2);

            // Encode standard path data
            // Encode info fields
            for (i, info_field) in self.iter_info_fields().enumerate() {
                let range = data_layout.info_field_range(i).aligned_byte_range();
                unsafe {
                    let info_field_buf = data_buf.get_unchecked_mut(range);
                    info_field.encode_unchecked(info_field_buf);
                }
            }

            // Encode hop fields
            for (i, hop_field) in self.iter_hop_fields().enumerate() {
                let range = data_layout.hop_field_range(i).aligned_byte_range();
                unsafe {
                    let hop_field_buf = data_buf.get_unchecked_mut(range);
                    hop_field.encode_unchecked(hop_field_buf);
                }
            }

            SL::SIZE_BYTES + data_layout.size_bytes()
        }
    }

    /// Represents a segment in a standard SCION path
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Segment {
        /// Info field containing metadata about the segment
        pub info_field: InfoField,
        /// Hop fields representing the hops in the segment
        pub hop_fields: Vec<HopField>,
    }

    /// Represents an info field in a standard SCION path
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InfoField {
        /// Info field flags
        pub flags: InfoFieldFlags,
        /// Segment ID
        ///
        /// Segment IDs are part of the MAC computation for hop fields.
        ///
        /// Each position in the path, has a segment ID which is computed and modified while the
        /// path is being traversed.
        pub segment_id: u16,
        /// Timestamp when the segment was created
        ///
        /// Used to determine if this segment currently valid.
        pub timestamp: u32,
    }

    impl InfoField {
        /// Constructs a `InfoField` from a `InfoFieldView`
        pub fn from_view(view: &InfoFieldView) -> Self {
            InfoField {
                flags: view.flags(),
                segment_id: view.segment_id(),
                timestamp: view.timestamp(),
            }
        }
    }

    impl WireEncode for InfoField {
        fn required_size(&self) -> usize {
            InfoFieldLayout::SIZE_BYTES
        }

        fn wire_valid(&self) -> Result<(), InvalidStructureError> {
            // All values are full range, so always valid
            Ok(())
        }

        unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
            unsafe {
                use InfoFieldLayout as IFL;
                unchecked_bit_range_be_write(buf, IFL::FLAGS_RNG, self.flags.bits());
                unchecked_bit_range_be_write(buf, IFL::RSV_RNG, 0u8);
                unchecked_bit_range_be_write(buf, IFL::SEGMENT_ID_RNG, self.segment_id);
                unchecked_bit_range_be_write(buf, IFL::TIMESTAMP_RNG, self.timestamp);
            }
            self.required_size()
        }
    }

    /// Represents a hop field in a standard SCION path
    ///
    /// Hop fields contain information about individual hops in a SCION path.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HopField {
        /// Hop field flags
        pub flags: HopFieldFlags,
        /// Hop field expiration units
        ///
        /// The expiration time of a hop field is determined by multiplying the value in this field
        /// by [`EXP_TIME_UNIT`](crate::types::path::EXP_TIME_UNIT)
        ///
        /// After this duration has passed since the segment creation time (found in the info
        /// field), the hop field is considered expired and may not be used for forwarding.
        pub expiration_units: u8,
        /// Hop field construction ingress interface
        ///
        /// A value of 0 indicates that the hop is at the start of the path segment.
        /// The interface number corresponds to the ingress interface used when constructing the
        /// path.
        ///
        /// The construction always starts at a Core router and proceeds towards the Child.
        ///
        /// When traversing the path in the reverse direction from construction (e.g. in a UP
        /// segment to a Core router), this field indicates the egress interface instead.
        pub cons_ingress: u16,
        /// Hop field construction egress interface
        ///
        /// A value of 0 indicates that the hop is at the end of the path segment.
        /// The interface number corresponds to the egress interface used when constructing the
        /// path.
        ///
        /// The construction always starts at a Core router and proceeds towards the Child.
        ///
        /// When traversing the path in the reverse direction from construction (e.g. in a UP
        /// segment to a Core router), this field indicates the ingress interface instead.
        pub cons_egress: u16,
        /// Hop field message authentication code (MAC)
        ///
        /// The MAC is used to ensure the integrity and authenticity of the hop field.
        /// It is computed when a segment is created and verified at each hop.
        pub mac: HopFieldMac,
    }

    impl HopField {
        /// Constructs a `HopField` from a `HopFieldView`
        pub fn from_view(view: &HopFieldView) -> Self {
            HopField {
                flags: view.flags(),
                expiration_units: view.exp_time(),
                cons_ingress: view.cons_ingress(),
                cons_egress: view.cons_egress(),
                mac: view.mac(),
            }
        }
    }

    impl WireEncode for HopField {
        fn required_size(&self) -> usize {
            HopFieldLayout::SIZE_BYTES
        }

        fn wire_valid(&self) -> Result<(), InvalidStructureError> {
            // All values are full range, so always valid
            Ok(())
        }

        unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
            unsafe {
                use HopFieldLayout as HFL;
                unchecked_bit_range_be_write(buf, HFL::FLAGS_RNG, self.flags.bits());
                unchecked_bit_range_be_write(buf, HFL::EXP_TIME_RNG, self.expiration_units);
                unchecked_bit_range_be_write(buf, HFL::CONS_INGRESS_RNG, self.cons_ingress);
                unchecked_bit_range_be_write(buf, HFL::CONS_EGRESS_RNG, self.cons_egress);
                buf.get_unchecked_mut(HFL::MAC_RNG.aligned_byte_range())
                    .copy_from_slice(&self.mac.0);
            }
            self.required_size()
        }
    }
}
