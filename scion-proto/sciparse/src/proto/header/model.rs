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

//! SCION header models

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        layout::Layout,
        view::{View, ViewConversionError},
        write::unchecked_bit_range_be_write,
    },
    header::{
        layout::{AddressHeaderLayout, CommonHeaderLayout},
        view::{ScionHeaderView, ScionPathView},
    },
    path::standard::{model::StandardPath, types::PathType},
    types::address::{IsdAsn, ScionHostAddr, ScionHostAddrType},
};

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
