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
    address::addr::ScionAddr,
    core::{
        encode::{EncodeError, InvalidStructureError, WireEncode},
        layout::Layout,
        view::{View, ViewConversionError},
        write::unchecked_bit_range_be_write,
    },
    header::{
        layout::{AddressHeaderLayout, CommonHeaderLayout, ScionHeaderLayout},
        view::ScionHeaderView,
    },
    path::{model::Path, types::PathType},
    scion::{
        address::host_addr::{WireHostAddr, WireHostAddrType},
        identifier::isd_asn::IsdAsn,
    },
};

/// Represents a SCION packet header
///
/// This structure contains all the fields of a SCION packet header,
/// including the common header, address header, and path information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub fn from_view(view: &ScionHeaderView) -> Result<Self, ViewConversionError> {
        Ok(ScionPacketHeader {
            common: CommonHeader::from_view(view),
            address: AddressHeader::from_view(view)?,
            path: Path::from_view(&view.path()),
        })
    }

    /// Attempts to construct a `ScionPacketHeader` from a byte slice
    ///
    /// Returns a tuple containing the `ScionPacketHeader` and the remaining slice after the header.
    /// On failure, returns a `ViewConversionError`.
    pub fn from_slice(buf: &[u8]) -> Result<(Self, &[u8]), ViewConversionError> {
        let (view, rest) = ScionHeaderView::from_slice(buf)?;
        Ok((Self::from_view(view)?, rest))
    }

    /// Returns the size of the SCION packet header in 4-byte units used in the header length field.
    fn size_units(&self) -> u8 {
        (self.required_size() / 4) as u8
    }
}
// Wire Encode (needs size, so can't use trait)
impl ScionPacketHeader {
    /// Returns the size required for the wire encoding.
    ///
    /// ## Safety
    /// This size must be correct, it is used to validate buffer sizes in `encode`.
    /// If this size is smaller than the actual encoded size, undefined behavior will occur.
    pub fn required_size(&self) -> usize {
        CommonHeaderLayout::SIZE_BYTES + self.address.required_size() + self.path.required_size()
    }

    /// Validates that all fields in the structure are valid for encoding.
    ///
    /// Note: This only checks the minimal set of fields required for encoding, do not expect
    /// comprehensive validation.
    ///
    /// Returns Ok(()) if valid, otherwise a static error reference.
    pub fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        let required_size = self.required_size();
        if !required_size.is_multiple_of(4) {
            return Err(InvalidStructureError::from(
                "header size must be a multiple of 4 bytes",
            ));
        }

        if required_size > ScionHeaderLayout::MAX_SIZE_BYTES {
            return Err(InvalidStructureError::from(
                "header size exceeds maximum encodeable value of 1020 bytes",
            ));
        }

        self.common.valid()?;
        self.address.wire_valid()?;
        self.path.wire_valid()?;
        Ok(())
    }

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// 1. The buffer must be at least `self.required_size()` bytes long
    /// 2. The structure must be valid for encoding, i.e., `self.valid()` must return `Ok(())`
    pub unsafe fn encode_unchecked(&self, buf: &mut [u8], payload_size: u16) -> usize {
        unsafe {
            use CommonHeaderLayout as CHL;
            // Encode common header
            self.common.encode_unchecked(
                buf,
                self.size_units(),
                self.path.path_type(),
                self.address.dst_addr_type(),
                self.address.src_addr_type(),
                payload_size,
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

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written on success, or `Err(usize)` of the required size if the
    /// buffer is too small or the packet.
    ///
    /// The buffer must be at least `self.required_size()` bytes long.
    pub fn encode(&self, buf: &mut [u8], payload_size: u16) -> Result<usize, EncodeError> {
        self.wire_valid()?;

        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }

        // SAFETY: buffer length is checked above
        Ok(unsafe { self.encode_unchecked(buf, payload_size) })
    }
}

/// Represents the common header of a SCION packet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommonHeader {
    /// Traffic class of the SCION packet
    pub traffic_class: u8,
    /// Flow ID of the SCION packet
    pub flow_id: u32,
    /// Next header type
    ///
    /// Indicates the type of header that follows the SCION header. E.g., UDP, TCP, etc.
    pub next_header: u8,
}

impl CommonHeader {
    /// Constructs a `CommonHeader` from a `ScionHeaderView`
    pub fn from_view(view: &ScionHeaderView) -> Self {
        debug_assert!(view.version() == Self::VERSION, "Unsupported SCION version");
        CommonHeader {
            traffic_class: view.traffic_class(),
            flow_id: view.flow_id(),
            next_header: view.next_header(),
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
    /// # Safety
    /// - The implementation may use unchecked indexing operations and relies on the caller to
    ///   provide a sufficiently large buffer (at least `CommonHeaderLayout::SIZE_BYTES` bytes).
    pub unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        header_len_units: u8,
        path_type: PathType,
        dst_addr_type: WireHostAddrType,
        src_addr_type: WireHostAddrType,
        payload_size: u16,
    ) -> usize {
        unsafe {
            use CommonHeaderLayout as CHL;
            // Encode common header
            unchecked_bit_range_be_write(buf, CHL::VERSION_RNG, Self::VERSION);
            unchecked_bit_range_be_write(buf, CHL::TRAFFIC_CLASS_RNG, self.traffic_class);
            unchecked_bit_range_be_write(buf, CHL::FLOW_ID_RNG, self.flow_id);
            unchecked_bit_range_be_write(buf, CHL::NEXT_HEADER_RNG, self.next_header);
            unchecked_bit_range_be_write(buf, CHL::HEADER_LEN_RNG, header_len_units);
            unchecked_bit_range_be_write(buf, CHL::PAYLOAD_LEN_RNG, payload_size);
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressHeader {
    /// Destination ISD
    pub dst_ia: IsdAsn,
    /// Source ISD
    pub src_ia: IsdAsn,
    /// Destination host address
    pub dst_host_addr: WireHostAddr,
    /// Source host address
    pub src_host_addr: WireHostAddr,
}
impl AddressHeader {
    /// Constructs an `AddressHeader` from the given source and destination `ScionAddr`
    pub fn new(src: ScionAddr, dst: ScionAddr) -> Self {
        AddressHeader {
            dst_ia: dst.isd_asn(),
            src_ia: src.isd_asn(),
            dst_host_addr: dst.host().into(),
            src_host_addr: src.host().into(),
        }
    }

    /// Constructs an `AddressHeader` from a `ScionHeaderView`
    pub fn from_view(view: &ScionHeaderView) -> Result<Self, ViewConversionError> {
        Ok(AddressHeader {
            dst_ia: IsdAsn::new(view.dst_isd(), view.dst_as()),
            src_ia: IsdAsn::new(view.src_isd(), view.src_as()),
            dst_host_addr: view
                .dst_host_addr()
                .map_err(|_| ViewConversionError::Other("invalid dst_host_addr"))?,
            src_host_addr: view
                .src_host_addr()
                .map_err(|_| ViewConversionError::Other("invalid src_host_addr"))?,
        })
    }

    /// Returns the destination address type
    pub fn dst_addr_type(&self) -> WireHostAddrType {
        self.dst_host_addr.addr_type()
    }

    /// Returns the source address type
    pub fn src_addr_type(&self) -> WireHostAddrType {
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

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;
    use crate::path::model::Path;

    /// Configuration for generating arbitrary [`ScionPacketHeader`] values.
    ///
    /// Composes sub-parameters for the address header (host address variant weights)
    /// and the path.
    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryScionPacketHeaderParams {
        /// Parameters for generating destination host addresses.
        pub dst_host_addr: <WireHostAddr as Arbitrary>::Parameters,
        /// Parameters for generating source host addresses.
        pub src_host_addr: <WireHostAddr as Arbitrary>::Parameters,
        /// Parameters for generating paths.
        pub path: <Path as Arbitrary>::Parameters,
    }

    impl Arbitrary for ScionPacketHeader {
        type Parameters = ArbitraryScionPacketHeaderParams;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
            let traffic_class = any::<u8>();
            let flow_id = 0u32..=0xF_FFFFu32;
            let next_header = any::<u8>();

            let dst_ia = any::<IsdAsn>();
            let src_ia = any::<IsdAsn>();

            let dst_host_addr = WireHostAddr::arbitrary_with(params.dst_host_addr);
            let src_host_addr = WireHostAddr::arbitrary_with(params.src_host_addr);

            let path = Path::arbitrary_with(params.path);

            (
                traffic_class,
                flow_id,
                next_header,
                dst_ia,
                src_ia,
                dst_host_addr,
                src_host_addr,
                path,
            )
                .prop_map(
                    |(
                        traffic_class,
                        flow_id,
                        next_header,
                        dst_ia,
                        src_ia,
                        dst_host_addr,
                        src_host_addr,
                        path,
                    )| {
                        Self {
                            common: CommonHeader {
                                traffic_class,
                                flow_id,
                                next_header,
                            },
                            address: AddressHeader {
                                dst_ia,
                                src_ia,
                                dst_host_addr,
                                src_host_addr,
                            },
                            path,
                        }
                    },
                )
                .boxed()
        }
    }
}
