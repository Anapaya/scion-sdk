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

//! UDP payload models.

use std::fmt::Debug;

use crate::{
    checksum::ChecksumDigest,
    core::{
        encode::InvalidStructureError,
        view::{View, ViewConversionError},
        write::unchecked_bit_range_be_write,
    },
    header::model::AddressHeader,
    payload::{
        ProtocolNumber,
        encode::PayloadEncode,
        udp::{layout::UdpDatagramLayout, view::UdpDatagramView},
    },
};

/// A UDP message.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpDatagram {
    /// The source port.
    pub src_port: u16,
    /// The destination port.
    pub dst_port: u16,
    /// The payload.
    pub payload: Vec<u8>,
}
impl UdpDatagram {
    /// Creates a new UDP message.
    #[inline]
    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        Self {
            src_port,
            dst_port,
            payload,
        }
    }

    /// Attempts to parse a UDP message from a byte slice.
    ///
    /// This method does not validate the checksum of the UDP datagram.
    ///
    /// Returns the parsed UDP datagram and the remaining byte slice after the UDP datagram, or an
    /// error if parsing fails.
    #[inline]
    pub fn try_from_slice(data: &[u8]) -> Result<(UdpDatagram, &[u8]), ViewConversionError> {
        let (view, rest) = UdpDatagramView::try_from_slice(data)?;
        Ok((Self::from_view(view), rest))
    }

    /// Creates a new UDP message from a view.
    #[inline]
    pub fn from_view(view: &UdpDatagramView) -> Self {
        Self {
            src_port: view.src_port(),
            dst_port: view.dst_port(),
            payload: view.payload().to_vec(),
        }
    }

    /// Returns a [`UdpDatagramRef`] that borrows the payload of this datagram.
    #[inline]
    pub fn to_ref(&self) -> UdpDatagramRef<'_> {
        UdpDatagramRef {
            src_port: self.src_port,
            dst_port: self.dst_port,
            payload: &self.payload,
        }
    }
}
impl From<&UdpDatagramView> for UdpDatagram {
    #[inline]
    fn from(view: &UdpDatagramView) -> Self {
        Self::from_view(view)
    }
}
impl Debug for UdpDatagram {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpDatagram")
            .field("src_port", &self.src_port)
            .field("dst_port", &self.dst_port)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
impl PayloadEncode for &UdpDatagram {
    #[inline]
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        self.to_ref().required_size(header_and_extensions_size)
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.to_ref().wire_valid()
    }

    #[inline]
    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        // SAFETY: the caller upholds the same contract for the borrowed datagram.
        unsafe {
            self.to_ref()
                .encode_unchecked(buf, address_header, header_and_extensions_size)
        }
    }
}
impl PayloadEncode for UdpDatagram {
    #[inline]
    fn required_size(&self, header_and_extensions_size: usize) -> usize {
        self.to_ref().required_size(header_and_extensions_size)
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        self.to_ref().wire_valid()
    }

    #[inline]
    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        // SAFETY: the caller upholds the same contract for the borrowed datagram.
        unsafe {
            self.to_ref()
                .encode_unchecked(buf, address_header, header_and_extensions_size)
        }
    }
}
impl AsRef<UdpDatagram> for UdpDatagram {
    #[inline]
    fn as_ref(&self) -> &UdpDatagram {
        self
    }
}
impl AsMut<UdpDatagram> for UdpDatagram {
    #[inline]
    fn as_mut(&mut self) -> &mut UdpDatagram {
        self
    }
}

/// A UDP message that borrows its payload.
///
/// [`UdpDatagramRef`] writes the same bytes as [`UdpDatagram`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpDatagramRef<'a> {
    /// The source port.
    pub src_port: u16,
    /// The destination port.
    pub dst_port: u16,
    /// The payload.
    pub payload: &'a [u8],
}
impl Debug for UdpDatagramRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpDatagramRef")
            .field("src_port", &self.src_port)
            .field("dst_port", &self.dst_port)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}
impl PayloadEncode for UdpDatagramRef<'_> {
    #[inline]
    fn required_size(&self, _header_and_extensions_size: usize) -> usize {
        UdpDatagramLayout::HEADER_SIZE_BYTES + self.payload.len()
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // The length field of the UDP header has 16 bits.
        if UdpDatagramLayout::HEADER_SIZE_BYTES + self.payload.len() > usize::from(u16::MAX) {
            return Err("UDP datagram size exceeds maximum encodable value of 65535 bytes".into());
        }

        Ok(())
    }

    #[inline]
    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        header_and_extensions_size: usize,
    ) -> usize {
        use UdpDatagramLayout as L;
        unsafe {
            unchecked_bit_range_be_write::<u16>(buf, L::SRC_PORT_RNG, self.src_port);
            unchecked_bit_range_be_write::<u16>(buf, L::DST_PORT_RNG, self.dst_port);
            unchecked_bit_range_be_write::<u16>(
                buf,
                L::LENGTH_RNG,
                (L::HEADER_SIZE_BYTES + self.payload.len()) as u16,
            );
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, 0u16);

            let payload_buf = buf.get_unchecked_mut(
                L::HEADER_SIZE_BYTES..(L::HEADER_SIZE_BYTES + self.payload.len()),
            );
            std::ptr::copy_nonoverlapping(
                self.payload.as_ptr(),
                payload_buf.as_mut_ptr(),
                self.payload.len(),
            );

            let checksum = ChecksumDigest::with_pseudoheader(
                address_header,
                ProtocolNumber::Udp.into(),
                &buf[0..self.required_size(header_and_extensions_size)],
            )
            .checksum();
            unchecked_bit_range_be_write::<u16>(buf, L::CHECKSUM_RNG, checksum);
        }

        self.required_size(header_and_extensions_size)
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;

    impl Arbitrary for UdpDatagram {
        type Parameters = ();

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (
                any::<u16>(),
                any::<u16>(),
                ::proptest::collection::vec(any::<u8>(), 0..1500),
            )
                .prop_map(|(src_port, dst_port, payload)| {
                    Self {
                        src_port,
                        dst_port,
                        payload,
                    }
                })
                .boxed()
        }

        type Strategy = BoxedStrategy<Self>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::addr::ScionAddr;

    mod wire_valid {
        use super::*;

        #[test]
        fn should_accept_a_datagram_of_exactly_65535_bytes() {
            let payload = vec![0u8; usize::from(u16::MAX) - UdpDatagramLayout::HEADER_SIZE_BYTES];
            let datagram = UdpDatagram::new(1, 2, payload);

            assert!(datagram.to_ref().wire_valid().is_ok());
            assert!(datagram.wire_valid().is_ok());
        }

        #[test]
        fn should_reject_a_datagram_larger_than_65535_bytes() {
            let payload =
                vec![0u8; usize::from(u16::MAX) - UdpDatagramLayout::HEADER_SIZE_BYTES + 1];
            let datagram = UdpDatagram::new(1, 2, payload);

            assert!(datagram.to_ref().wire_valid().is_err());
            assert!(datagram.wire_valid().is_err());
        }
    }

    mod payload_encode_for_reference_to_udp_datagram {
        use super::*;

        #[test]
        fn should_give_the_same_size_and_bytes_as_the_owned_datagram() {
            let src: ScionAddr = "1-ff00:0:110,10.0.0.1".parse().unwrap();
            let dst: ScionAddr = "1-ff00:0:111,10.0.0.2".parse().unwrap();
            let address = AddressHeader::new(src, dst);
            let datagram = UdpDatagram::new(12345, 54321, b"data".to_vec());
            let header_size = 36;

            // A method call on `&datagram` picks the impl for `UdpDatagram`, so the impl for
            // `&UdpDatagram` needs the full path.
            let by_ref_datagram = &datagram;
            let owned_size = datagram.required_size(header_size);
            let ref_size =
                <&UdpDatagram as PayloadEncode>::required_size(&by_ref_datagram, header_size);
            let mut owned = vec![0u8; owned_size];
            let mut by_ref = vec![0xAAu8; ref_size];
            datagram
                .try_encode(&mut owned, &address, header_size)
                .unwrap();
            <&UdpDatagram as PayloadEncode>::try_encode(
                &by_ref_datagram,
                &mut by_ref,
                &address,
                header_size,
            )
            .unwrap();

            assert_eq!(ref_size, owned_size);
            assert_eq!(by_ref, owned);
        }
    }
}
