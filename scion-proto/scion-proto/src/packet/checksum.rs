// Copyright 2025 Mysten Labs
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

use std::slice;

use super::{AddressHeader, AddressInfo, RawHostAddress};
use crate::{
    address::HostAddr,
    wire_encoding::{MaybeEncoded, WireEncode},
};

/// Trait implemented by all higher-layer messages that use 2-byte checksums.
pub trait MessageChecksum {
    /// Returns the currently stored checksum of the message.
    fn checksum(&self) -> u16;

    /// Clears then sets the checksum to the value returned by [`Self::calculate_checksum()`].
    fn set_checksum(&mut self, address_header: &AddressHeader);

    /// Compute the checksum for this message using the provided address header.
    fn calculate_checksum(&self, address_header: &AddressHeader) -> u16;

    /// Returns true if the checksum successfully verifies, otherwise false.
    fn verify_checksum(&self, address_header: &AddressHeader) -> bool {
        self.calculate_checksum(address_header) == 0
    }
}

/// Incrementally computes the 16-bit checksum for upper layer protocols.
///
/// A new, empty digest can be created with [`ChecksumDigest::new()`], or
/// [`ChecksumDigest::with_pseudoheader()`] can be used to create a new digest
/// already initialized with a partial checksum over the SCION pseudoheader.
///
/// The final checksum value can then be retrieved with
/// [`ChecksumDigest::checksum()`], and is in the host's native endianness.
///
/// # Example
///
/// ```
/// # use scion_proto::packet::ChecksumDigest;
/// let checksum = ChecksumDigest::new()
///     .add_u32(0x0001f203)
///     .add_u32(0xf4f5f6f7)
///     .checksum();
///
/// assert_eq!(checksum, 0x220d);
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumDigest {
    checksum_with_overflow: u32,
}

impl ChecksumDigest {
    /// Creates a new empty digest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new digest initialized with the contents of the pseudoheader
    /// constructed from the packet addresses, length, and protocol.
    ///
    /// The length is the length of the upper-layer header and data. For protocols
    /// that carry this information, such as UDP, that value can be used directly.
    /// Other protocols use a value derived from the packet length. See the [RFC]
    /// for details.
    ///
    /// Protocol is the IANA number of the upper-layer protocol, which may be
    /// different from the next-header field in a SCION packet header with extensions.
    ///
    /// [RFC]: https://datatracker.ietf.org/doc/draft-dekater-scion-dataplane/
    pub fn with_pseudoheader(addresses: &AddressHeader, protocol: u8, length: u32) -> Self {
        let mut digest = Self::default();
        digest
            .add_u64(addresses.ia.destination.into())
            .add_u64(addresses.ia.source.into())
            .add_host(addresses.host.destination)
            .add_host(addresses.host.source)
            .add_u32(length)
            .add_u32(protocol as u32);
        digest
    }

    #[inline]
    fn add_host(
        &mut self,
        host: MaybeEncoded<HostAddr, (AddressInfo, RawHostAddress)>,
    ) -> &mut Self {
        let mut buffer = [0_u8; 16];
        host.encode_to_unchecked(&mut buffer.as_mut());
        self.add_slice(&buffer[..host.encoded_length()]);
        self
    }

    /// Adds a u64 value to the checksum computation.
    pub fn add_u64(&mut self, value: u64) -> &mut Self {
        const MASK: u64 = 0xffff;
        let sum = (value & MASK)
            + ((value >> u16::BITS) & MASK)
            + ((value >> (2 * u16::BITS)) & MASK)
            + ((value >> (3 * u16::BITS)) & MASK);

        self.checksum_with_overflow += sum as u32;
        self
    }

    /// Adds a u32 value to the checksum computation.
    pub fn add_u32(&mut self, value: u32) -> &mut Self {
        const MASK: u32 = 0xffff;
        self.checksum_with_overflow += (value & MASK) + ((value >> u16::BITS) & MASK);
        self
    }

    /// Adds a u16 value to the checksum computation.
    pub fn add_u16(&mut self, value: u16) -> &mut Self {
        self.checksum_with_overflow += value as u32;
        self
    }

    /// Adds the data contained in the slice to the checksum computation.
    ///
    /// If the slice is not a multiple of 2-bytes, then it is zero-padded
    /// before being added to the checksum.
    pub fn add_slice(&mut self, mut data: &[u8]) -> &mut Self {
        if data.is_empty() {
            return self;
        }
        let mut initial_sum = 0;

        // Before converting to a `&[u16]` we need to make sure the slice is aligned.
        let is_aligned = data.as_ptr().align_offset(2) == 0;
        if !is_aligned {
            // We want to zero-prepend the value, i.e., for slice where we pair the elements, we
            // have [0, A], [B, C], ... Storing [0, X] on a little endian architecture gets written
            // as [X, 0] to memory, so we need to swap it with `to_be()`.
            initial_sum = (data[0] as u16).to_be() as u32;
            data = &data[1..];
        };
        let ptr: *const u8 = data.as_ptr();

        // Converting to a `&[u16]` requires an even number of elements in the slice.
        if !data.len().is_multiple_of(2) {
            // We want to zero pad the value, i.e., for slice where we pair the elements,
            // we have [A, B], [C, D], ... [X, 0]. Since all the values are currently in
            // memory in the order [A, B] storing [0, X] on a little endian architecture
            // gets written as [X, 0] to memory. On big-endian this would get written as
            // [0, X] so we swap it only on that big-endian architectures with to_le().
            initial_sum += (data[data.len() - 1] as u16).to_le() as u32;
            data = &data[..data.len() - 1];
        };

        let data_u16 = unsafe { slice::from_raw_parts(ptr as *const u16, data.len() / 2) };

        let sum_with_overflow = data_u16
            .iter()
            .fold(initial_sum, |sum, value| sum + (*value as u32));

        // Already incorporate the overflow, as it simplifies the endian conversion below
        let mut sum = Self::fold_checksum(sum_with_overflow) as u16;

        // If the original slice was not aligned, we need to swap the bytes to get the correct
        // checksum.
        if !is_aligned {
            sum = sum.swap_bytes();
        }

        // The above sum is actually in big-endian but stored in big/little endian depending
        // on the platform. If the platform is little endian, this call will swap the byte-order
        // so that the result is truly little endian. If the platform is big-endian, this is a noop.
        // The result is the value in native endian.
        self.checksum_with_overflow += sum.to_be() as u32;
        self
    }

    #[inline]
    fn fold_checksum(mut checksum: u32) -> u32 {
        // This needs to be done at most twice to fold the overflow into the checksum,
        // since the value is at most 0xffff_ffff -> 0x0001_fffe -> 0x0000_ffff
        for _ in 0..2 {
            checksum = (checksum >> u16::BITS) + (checksum & 0xffff);
        }
        checksum
    }

    /// Returns the computed checksum value.
    pub fn checksum(&self) -> u16 {
        !(Self::fold_checksum(self.checksum_with_overflow) as u16)
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};

    use super::*;
    use crate::{
        address::{HostAddr, ServiceAddr},
        packet::ByEndpoint,
        wire_encoding::WireEncode,
    };

    fn pseudoheader_with_data(addresses: &AddressHeader, protocol: u8, data: &[u8]) -> BytesMut {
        let mut buffer = BytesMut::new();
        addresses.encode_to(&mut buffer).unwrap();

        buffer.put_u32(data.len() as u32);
        buffer.put_u32(protocol as u32);
        buffer.put_slice(data);

        buffer
    }

    fn reference_checksum(data: &[u8]) -> u16 {
        let mut cumsum = 0u32;
        let mut i = 0usize;

        let (data, leftover) = if data.len().is_multiple_of(2) {
            (data, 0u8)
        } else {
            (&data[..data.len() - 1], data[data.len() - 1])
        };

        while i + 1 < data.len() {
            cumsum += ((data[i] as u32) << 8) + (data[i + 1] as u32);
            i += 2;
        }
        cumsum += (leftover as u32) << 8;

        while cumsum > 0xffff {
            cumsum = (cumsum >> 16) + (cumsum & 0xffff);
        }

        !(cumsum as u16)
    }

    #[test]
    fn checksum_with_overflow() {
        let checksum = ChecksumDigest::default()
            .add_u16(0xffff)
            .add_u16(0xffff)
            .add_u16(0x1)
            .checksum();
        assert_eq!(checksum, !0x1_u16);
    }

    #[test]
    fn checksum_with_repeated_overflow() {
        let checksum = ChecksumDigest {
            checksum_with_overflow: 0xffff_ffff,
        }
        .checksum();
        assert_eq!(checksum, !0xffff_u16);
    }

    #[test]
    fn rfc1071_example() {
        let checksum = ChecksumDigest::default()
            .add_u64(0x1_f203_f4f5_f6f7)
            .checksum();
        assert_eq!(checksum, !0xddf2);
    }

    #[test]
    fn rfc1071_example_binary_data() {
        let checksum = ChecksumDigest::default()
            .add_slice(b"\0\x01\xf2\x03\xf4\xf5\xf6\xf7")
            .checksum();
        assert_eq!(checksum, !0xddf2);
    }

    #[test]
    fn rfc1071_example_slice_unaligned() {
        // Construct a slice that is not 2B aligned.
        let mut data = b"\0\0\x01\xf2\x03\xf4\xf5\xf6\xf7".to_vec();
        let slice = if data.as_ptr().align_offset(2) == 0 {
            &data[1..]
        } else {
            data.rotate_left(1);
            &data[..data.len() - 1]
        };

        assert_eq!(slice.as_ptr().align_offset(2), 1);
        assert_eq!(
            ChecksumDigest::default().add_slice(slice).checksum(),
            !0xddf2
        );
    }

    macro_rules! test_checksum {
        (
            name: $name:ident,
            destination: {ia: $dst_ia:expr, host: $dst_host:expr},
            source: {ia: $src_ia:expr, host: $src_host:expr},
            data: $data:expr,
            protocol: $protocol:expr,
            checksum: $checksum:expr
        ) => {
            test_checksum!(
                $name,
                AddressHeader {
                    ia: ByEndpoint {
                        destination: $dst_ia.parse()?,
                        source: $src_ia.parse()?
                    },
                    host: ByEndpoint {
                        destination: MaybeEncoded::Decoded($dst_host),
                        source: MaybeEncoded::Decoded($src_host)
                    },
                },
                $data,
                $protocol,
                $checksum
            );
        };
        ($name:ident, $addresses:expr, $data:expr, $protocol:expr, $checksum:expr) => {
            mod $name {
                use super::*;

                /// Test the checksum using the reference method from
                /// scionproto/scion/pkg/slayers/scion_test.go. If this fails, there is likely
                /// an issue with the inputs.
                #[test]
                fn checksum_using_reference() -> Result<(), Box<dyn std::error::Error>> {
                    let address_header = $addresses;
                    let data = $data;
                    let input_data = pseudoheader_with_data(&address_header, $protocol, data);

                    let reference_checksum = reference_checksum(&input_data);

                    assert_eq!($checksum, reference_checksum);

                    Ok(())
                }

                #[test]
                fn checksum_using_pseudoheader() -> Result<(), Box<dyn std::error::Error>> {
                    let address_header = $addresses;
                    let data = $data;

                    let pseudoheader_checksum = ChecksumDigest::with_pseudoheader(
                        &address_header,
                        $protocol,
                        data.len() as u32,
                    )
                    .add_slice(data)
                    .checksum();

                    assert_eq!(
                        $checksum, pseudoheader_checksum,
                        "invalid checksum using pseudoheader",
                    );
                    Ok(())
                }

                #[test]
                fn checksum_using_add_data() -> Result<(), Box<dyn std::error::Error>> {
                    let address_header = $addresses;
                    let data = $data;
                    let input_data = pseudoheader_with_data(&address_header, $protocol, data);

                    let encoded_checksum =
                        ChecksumDigest::default().add_slice(&input_data).checksum();
                    assert_eq!($checksum, encoded_checksum);
                    Ok(())
                }

                /// Ensure that the checksum of the input with it's own checksum is zero.
                /// i.e., that if x = checksum(input) then checksum(input || x) is 0
                #[test]
                fn checksum_including_checksum() -> Result<(), Box<dyn std::error::Error>> {
                    let address_header = $addresses;
                    let data = $data;
                    let input_data = pseudoheader_with_data(&address_header, $protocol, data);

                    let encoded_checksum = ChecksumDigest::default()
                        .add_slice(&input_data)
                        .add_u16($checksum)
                        .checksum();

                    assert_eq!(encoded_checksum, 0);
                    Ok(())
                }
            }
        };
    }

    test_checksum! {
        name: ipv4_to_ipv4,
        destination: {ia: "1-ff00:0:112", host: HostAddr::V4("174.16.4.2".parse()?)},
        source: {ia: "1-ff00:0:110", host: HostAddr::V4("172.16.4.1".parse()?)},
        data: b"\x00\x00\xaa\xbb\xcc\xdd",
        protocol: 1u8,
        checksum: 0x2615_u16
    }

    test_checksum! {
        name: ipv4_to_ipv4_odd_length,
        destination: {ia: "1-ff00:0:112", host: HostAddr::V4("174.16.4.2".parse()?)},
        source: {ia: "1-ff00:0:110", host: HostAddr::V4("172.16.4.1".parse()?)},
        data: b"\0\0\xaa\xbb\xcc\xdd\xee",
        protocol: 1u8,
        checksum: 0x3813_u16
    }

    test_checksum! {
        name: ipv4_to_ipv6,
        destination: {ia: "1-ff00:0:112", host: HostAddr::V6("dead::beef".parse()?)},
        source: {ia: "1-ff00:0:110", host: HostAddr::V4("174.16.4.1".parse()?)},
        data: b"\0\0\xaa\xbb\xcc\xdd",
        protocol: 17u8,
        checksum: 0x387a_u16
    }

    test_checksum! {
        name: ipv4_to_svc,
        destination: {ia: "1-ff00:0:112", host: HostAddr::Svc(ServiceAddr::CONTROL)},
        source: {ia: "1-ff00:0:110", host: HostAddr::V4("174.16.4.1".parse()?)},
        data: b"\0\0\xaa\xbb\xcc\xdd",
        protocol: 223u8,
        checksum: 0xd547_u16
    }
}
