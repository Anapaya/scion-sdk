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

//! A standard SCION path.
use std::ops::{Deref, DerefMut};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};

pub use super::{
    EncodedHopField, EncodedInfoField, EncodedSegment, EncodedSegments, HopFields, InfoFields,
};
use crate::{
    packet::DecodeError,
    path::{InfoField, MetaHeader},
    wire_encoding::{WireDecode, WireEncode},
};

/// The standard SCION path header.
///
/// Consists of a [`MetaHeader`] along with one or more info fields and hop fields.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedStandardPath<T = Bytes> {
    /// The meta information about the stored path.
    pub(crate) meta_header: MetaHeader,
    /// The raw data containing the meta_header, info, and hop fields.
    pub(crate) encoded_path: T,
}

/// The standard SCION path header with a mutable encoded path.
pub type EncodedStandardPathMut = EncodedStandardPath<BytesMut>;

impl<T> EncodedStandardPath<T> {
    /// Returns the metadata about the stored path.
    pub fn meta_header(&self) -> &MetaHeader {
        &self.meta_header
    }
}

impl<T> EncodedStandardPath<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns the encoded raw path.
    pub fn raw(&self) -> &[u8] {
        &self.encoded_path
    }

    /// Creates new StandardPath, backed by the provided buffer, by copying this one.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as self.raw().
    pub fn copy_to_slice<'b>(&self, buffer: &'b mut [u8]) -> EncodedStandardPath<&'b mut [u8]> {
        buffer.copy_from_slice(&self.encoded_path);
        EncodedStandardPath {
            meta_header: self.meta_header.clone(),
            encoded_path: buffer,
        }
    }

    /// Creates a new, reversed StandardPath with the provided buffer.
    ///
    /// Indices are carried over to their current position in reverse.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as self.raw().
    pub fn reverse_to_slice<'b>(&self, buffer: &'b mut [u8]) -> EncodedStandardPath<&'b mut [u8]> {
        assert_eq!(
            buffer.len(),
            self.encoded_path.len(),
            "destination buffer length is not the same as this path's"
        );

        let mut buf_mut: &mut [u8] = buffer;

        let meta_header = self.meta_header.to_reversed();

        meta_header.encode_to_unchecked(&mut buf_mut);
        self.write_reversed_info_fields_to(&mut buf_mut);
        self.write_reversed_hop_fields_to(&mut buf_mut);

        EncodedStandardPath {
            meta_header,
            encoded_path: buffer,
        }
    }

    /// Reverses both the raw path and the metadata in the [`Self::meta_header`].
    ///
    /// The reversed path is suitable for use from an end-host: its current hop and info field
    /// indices are set to 0.
    pub fn to_reversed(&self) -> EncodedStandardPath<Bytes> {
        let mut encoded_path = vec![0u8; self.encoded_path.len()];
        let EncodedStandardPath { meta_header, .. } = self.reverse_to_slice(&mut encoded_path);

        EncodedStandardPath {
            meta_header,
            encoded_path: encoded_path.into(),
        }
    }

    /// Returns the [`EncodedInfoField`] at the specified index, if within range.
    ///
    /// The index is the index into the path's info fields, and can be at most 3.
    pub fn info_field(&self, index: usize) -> Option<&EncodedInfoField> {
        if index < self.meta_header.info_fields_count() {
            let start = MetaHeader::info_field_offset(index);
            let slice = &self.encoded_path[start..(start + EncodedInfoField::LENGTH)];
            Some(EncodedInfoField::new(slice))
        } else {
            None
        }
    }

    /// Returns the segment at the specified index, if any.
    ///
    /// There are always at most 3 segments.
    pub fn segment(&self, segment_index: usize) -> Option<EncodedSegment<'_>> {
        let info_field = self.info_field(segment_index)?;

        // Get the index of the first hop field in the segment.
        // This is equivalent to the index after all preceding hop fields.
        let hop_index = self.meta_header.segment_lengths[..segment_index]
            .iter()
            .fold(0usize, |sum, seglen| sum + usize::from(seglen.get()));

        let n_hop_fields: usize = self.meta_header.segment_lengths[segment_index].get().into();
        debug_assert_ne!(n_hop_fields, 0);

        Some(EncodedSegment::new(
            info_field,
            self.hop_fields_subset(hop_index, n_hop_fields),
        ))
    }

    /// Returns an iterator over the segments of this path.
    pub fn segments(&self) -> EncodedSegments<'_> {
        EncodedSegments::new([self.segment(0), self.segment(1), self.segment(2)])
    }

    /// Returns the expiry time of the path.
    ///
    /// This is the minimum expiry time of each of its segments.
    pub fn expiry_time(&self) -> DateTime<Utc> {
        self.segments()
            .map(|seg| seg.expiry_time())
            .min()
            .expect("at least 1 segment")
    }

    fn hop_fields_subset(&self, hop_index: usize, n_hop_fields: usize) -> HopFields<'_> {
        let start = self.meta_header.hop_field_offset(hop_index);
        let stop = start + n_hop_fields * EncodedHopField::LENGTH;

        HopFields::new(&self.encoded_path[start..stop])
    }

    /// Returns an iterator over all the [`EncodedInfoField`]s in the SCION path.
    pub fn info_fields(&self) -> InfoFields<'_> {
        let start = MetaHeader::info_field_offset(0);
        let stop = start + self.meta_header.info_fields_count() * EncodedInfoField::LENGTH;

        InfoFields::new(&self.encoded_path[start..stop])
    }

    /// Returns an iterator over all of the [`EncodedHopField`]s in the SCION path.
    pub fn hop_fields(&self) -> HopFields<'_> {
        self.hop_fields_subset(0, self.meta_header.hop_fields_count())
    }

    /// Writes the info fields to the provided buffer in reversed order.
    ///
    /// This also flips the "construction direction flag" for all info fields.
    fn write_reversed_info_fields_to(&self, buffer: &mut &mut [u8]) {
        for info_field in self.info_fields().rev() {
            let data = info_field.as_ref();
            buffer.put_u8(data[0] ^ InfoField::FLAGS_CONS_DIR);
            buffer.put_slice(&data[1..]);
        }
    }

    /// Returns an iterator over the path's interfaces in order of traversal.
    pub fn iter_interfaces(&self) -> impl Iterator<Item = std::num::NonZeroU16> {
        self.segments().flat_map(|seg| {
            let info_field = seg.info_field();
            let cons_dir = info_field.is_constructed_dir();

            seg.hop_fields()
                .flat_map(move |hop_field| {
                    match cons_dir {
                        true => {
                            [
                                hop_field.cons_ingress_interface(),
                                hop_field.cons_egress_interface(),
                            ]
                            .into_iter()
                        }
                        false => {
                            [
                                hop_field.cons_egress_interface(),
                                hop_field.cons_ingress_interface(),
                            ]
                            .into_iter()
                        }
                    }
                })
                .flatten()
        })
    }

    /// Writes the hop fields to the provided buffer in reversed order.
    fn write_reversed_hop_fields_to(&self, buffer: &mut &mut [u8]) {
        for hop_field in self.hop_fields().rev() {
            buffer.put_slice(hop_field.as_ref())
        }
    }
}

impl<T> EncodedStandardPath<T>
where
    T: DerefMut<Target = [u8]>,
{
    /// Returns the [`EncodedHopField`] at the specified index as a mutable reference, if within
    /// range.
    pub fn hop_field_mut(&mut self, index: usize) -> Option<&mut EncodedHopField> {
        if index < self.meta_header.hop_fields_count() {
            let start = self.meta_header.hop_field_offset(index);
            let slice = &mut self.encoded_path[start..(start + EncodedHopField::LENGTH)];
            Some(EncodedHopField::new_mut(slice))
        } else {
            None
        }
    }
}

impl EncodedStandardPath {
    /// Converts a standard path over an immutable reference to one over an mutable reference.
    ///
    /// This requires copying the encoded path.
    pub fn to_mut(&self) -> EncodedStandardPathMut {
        let mut encoded_path = BytesMut::zeroed(self.encoded_path.len());
        encoded_path.copy_from_slice(self.encoded_path.as_ref());
        EncodedStandardPath {
            meta_header: self.meta_header.clone(),
            encoded_path,
        }
    }
}

impl EncodedStandardPathMut {
    /// Converts a standard path over a mutable reference to one over an immutable reference.
    pub fn freeze(self) -> EncodedStandardPath {
        EncodedStandardPath {
            meta_header: self.meta_header,
            encoded_path: self.encoded_path.freeze(),
        }
    }
}

impl<'b> EncodedStandardPath<&'b mut [u8]> {
    /// Converts a standard path over a mutable reference to one over an immutable reference.
    pub fn freeze(self) -> EncodedStandardPath<&'b [u8]> {
        EncodedStandardPath {
            meta_header: self.meta_header,
            encoded_path: &*self.encoded_path,
        }
    }
}

impl EncodedStandardPath<Bytes> {
    /// Creates a deep copy of this path.
    pub fn deep_copy(&self) -> Self {
        Self {
            meta_header: self.meta_header.clone(),
            encoded_path: Bytes::copy_from_slice(&self.encoded_path),
        }
    }

    /// Creates a new path using the Bytes of this path as backing storage
    pub fn to_slice_path(&self) -> EncodedStandardPath<&[u8]> {
        EncodedStandardPath {
            meta_header: self.meta_header.clone(),
            encoded_path: self.encoded_path.as_ref(),
        }
    }
}
impl<T: AsRef<[u8]>> EncodedStandardPath<T> {
    /// Transforms the path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> EncodedStandardPath<Bytes> {
        EncodedStandardPath {
            meta_header: self.meta_header.clone(),
            encoded_path: Bytes::copy_from_slice(self.encoded_path.as_ref()),
        }
    }
}

impl WireDecode<Bytes> for EncodedStandardPath {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        let mut view: &[u8] = data.as_ref();
        let meta_header = MetaHeader::decode(&mut view)?;

        if data.remaining() < meta_header.encoded_path_length() {
            Err(Self::Error::PacketEmptyOrTruncated)
        } else {
            let encoded_path = data.split_to(meta_header.encoded_path_length());
            Ok(Self {
                meta_header,
                encoded_path,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use bytes::BufMut;

    use super::*;
    use crate::path::{
        DataPlanePathErrorKind, HopFieldIndex, InfoFieldIndex, MetaReserved, SegmentLength,
    };

    macro_rules! path_bytes {
        (info: $info:expr, hop: $hop:expr, seg_lengths: $segs:expr, field_len: $field_len:expr) => {{
            const MASK: u32 = 0b11_1111;
            let meta_bytes = ($info << 30)
                | (($hop & MASK) << 24)
                | (($segs[0] & MASK) << 12)
                | (($segs[1] & MASK) << 6)
                | ($segs[2] & MASK);

            let mut data = vec![7u8; $field_len + MetaHeader::LENGTH];
            data.as_mut_slice().put_u32(meta_bytes);
            Bytes::from(data)
        }};
        (info: $info:expr, hop: $hop:expr, seg_lengths: $segs:expr) => {
            path_bytes! {
                info: $info, hop: $hop, seg_lengths: $segs,
                field_len: (
                    ($segs[0] + $segs[1] + $segs[2]) * 12
                    + $segs.iter().filter(|x| **x != 0).count() * 8
                )
            }
        };
    }

    macro_rules! test_valid_decode_encode_reverse {
        ($name:ident, $encoded_path:expr, $decoded_header:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn decode() {
                    let mut data = $encoded_path;
                    let header = EncodedStandardPath::decode(&mut data).expect("valid decode");

                    assert_eq!(*header.meta_header(), $decoded_header);
                }

                #[test]
                fn encode() {
                    let encoded_header = $decoded_header.encode_to_bytes();

                    assert_eq!(
                        encoded_header.slice(..),
                        $encoded_path[..MetaHeader::LENGTH]
                    );
                }

                #[test]
                fn reverse_twice_field_identity() {
                    let mut data = $encoded_path;
                    let path = EncodedStandardPath::decode(&mut data).expect("valid decode");

                    let twice_reversed = path.to_reversed().to_reversed();
                    assert!(path.hop_fields().eq(twice_reversed.hop_fields()));
                    assert!(path.info_fields().eq(twice_reversed.info_fields()));
                    assert_eq!(
                        path.meta_header.segment_lengths,
                        twice_reversed.meta_header.segment_lengths
                    );
                }
            }
        };
    }

    test_valid_decode_encode_reverse!(
        valid_no_zero_index,
        path_bytes! {info: 0, hop: 0, seg_lengths: [3, 0, 0], field_len: 44},
        MetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(0),
            current_hop_field: HopFieldIndex::new_unchecked(0),
            reserved: MetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(3),
                SegmentLength::new_unchecked(0),
                SegmentLength::new_unchecked(0)
            ]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_minimal,
        path_bytes! {info: 0, hop: 0, seg_lengths: [1, 0, 0]},
        MetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(0),
            current_hop_field: HopFieldIndex::new_unchecked(0),
            reserved: MetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(1),
                SegmentLength::new_unchecked(0),
                SegmentLength::new_unchecked(0)
            ]
        }
    );

    test_valid_decode_encode_reverse!(
        valid_with_index,
        path_bytes! {info: 1, hop: 8, seg_lengths: [5, 4, 0], field_len: 124},
        MetaHeader {
            current_info_field: InfoFieldIndex::new_unchecked(1),
            current_hop_field: HopFieldIndex::new_unchecked(8),
            reserved: MetaReserved::new_unchecked(0),
            segment_lengths: [
                SegmentLength::new_unchecked(5),
                SegmentLength::new_unchecked(4),
                SegmentLength::new_unchecked(0)
            ]
        }
    );

    macro_rules! decode_errs {
        ($name:ident, $path:expr, $err:expr) => {
            #[test]
            fn $name() {
                let mut data = $path;
                let expected_err: DecodeError = $err.into();
                let err = EncodedStandardPath::decode(&mut data).expect_err("should fail");
                assert_eq!(expected_err, err);
            }
        };
    }

    decode_errs!(
        fields_truncated,
        path_bytes! {info: 1, hop: 8, seg_lengths: [5, 4, 0], field_len: 8},
        DecodeError::PacketEmptyOrTruncated
    );
    decode_errs!(
        invalid_segment_len,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 1, 1]},
        DataPlanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        invalid_segment_len2,
        path_bytes! {info: 0, hop: 0, seg_lengths: [1, 0, 1]},
        DataPlanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        invalid_segment_len3,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 1, 0]},
        DataPlanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        no_segment_len,
        path_bytes! {info: 0, hop: 0, seg_lengths: [0, 0, 0]},
        DataPlanePathErrorKind::InvalidSegmentLengths
    );
    decode_errs!(
        info_index_too_large,
        path_bytes! {info: 3, hop: 0, seg_lengths: [5, 4, 3]},
        DataPlanePathErrorKind::InfoFieldOutOfRange
    );
    decode_errs!(
        info_index_out_of_range,
        path_bytes! {info: 2, hop: 0, seg_lengths: [5, 4, 0]},
        DataPlanePathErrorKind::InfoFieldOutOfRange
    );
    decode_errs!(
        hop_field_out_of_range,
        path_bytes! {info: 0, hop: 10, seg_lengths: [9, 0, 0]},
        DataPlanePathErrorKind::HopFieldOutOfRange
    );
    decode_errs!(
        hop_field_points_to_wrong_info,
        path_bytes! {info: 0, hop: 6, seg_lengths: [3, 7, 0]},
        DataPlanePathErrorKind::HopFieldOutOfRange
    );
    decode_errs!(
        hop_field_points_to_wrong_info2,
        path_bytes! {info: 0, hop: 3, seg_lengths: [3, 7, 0]},
        DataPlanePathErrorKind::HopFieldOutOfRange
    );

    fn assert_ifaces_eq(hop_fields: HopFields<'_>, hops: &[(u16, u16)]) {
        fn interface_or_zero(iface: Option<NonZeroU16>) -> u16 {
            iface.map(NonZeroU16::get).unwrap_or_default()
        }

        let hop_field_hops: Vec<_> = hop_fields
            .map(|hop| {
                (
                    interface_or_zero(hop.cons_ingress_interface()),
                    interface_or_zero(hop.cons_egress_interface()),
                )
            })
            .collect();
        assert_eq!(hop_field_hops, hops);
    }

    macro_rules! test_iterators {
        ($name:ident: { path: $path_bytes:expr, times: $times:expr, hops: $hops:expr, interfaces: $interfaces:expr }) => {
            mod $name {
                use super::*;

                type TestResult = Result<(), Box<dyn std::error::Error>>;

                #[test]
                fn info_fields() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = EncodedStandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;
                    let times: &[i64] = &$times;

                    let info_field_times: Vec<_> = path
                        .info_fields()
                        .map(|info| info.timestamp().timestamp())
                        .collect();
                    assert_eq!(times, info_field_times);

                    Ok(())
                }

                #[test]
                fn hop_fields() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = EncodedStandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;

                    let hops: &[&[(u16, u16)]] = &$hops;
                    let hops: Vec<(u16, u16)> =
                        hops.iter().map(|l| l.iter()).flatten().cloned().collect();

                    assert_ifaces_eq(path.hop_fields(), &hops);

                    Ok(())
                }

                #[test]
                fn segments() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = EncodedStandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;
                    let times: &[i64] = &$times;
                    let hops: &[&[(u16, u16)]] = &$hops;

                    assert_eq!(path.segments().len(), times.len());
                    for (i, segment) in path.segments().enumerate() {
                        assert_eq!(segment.info_field().timestamp().timestamp(), times[i]);
                        assert_ifaces_eq(segment.hop_fields(), hops[i]);
                    }

                    Ok(())
                }

                #[test]
                fn interfaces() -> TestResult {
                    let path_bytes: Vec<&[u8]> = $path_bytes;
                    let path = EncodedStandardPath::decode(&mut Bytes::from(path_bytes.concat()))?;
                    let interfaces: Vec<u16> = $interfaces;
                    assert_eq!(
                        interfaces,
                        path.iter_interfaces()
                            .map(NonZeroU16::get)
                            .collect::<Vec<_>>()
                    );

                    Ok(())
                }
            }
        };
    }

    test_iterators! {
        one_segment_path: {
            path: vec![
                b"\x00\x00\x10\x00",
                // Info
                b"\x3c\x84\x86\x84",
                b"\xa9\xf0\x7c\xce",
                // Hop
                b"\x13\xf7\xb4\x8a",
                b"\xc4\x8a\xc6\x3c",
                b"\xb7\xb1\x94\x9c",
            ],
            times: [0xa9f07cce],
            hops: [&[(0xb48a, 0xc48a)]],
            interfaces: vec![0xc48a, 0xb48a]
        }
    }

    test_iterators! {
        two_segment_path: {
            path: vec![
                b"\x00\x00\x10\x80",
                // Info-1
                b"\x07\x2d\x19\xcd",
                b"\x76\x5d\xd0\xdf",
                // Info-2
                b"\xfb\xc7\xe6\xbd",
                b"\x2a\xb4\x7c\x18",
                // Hop-1-1
                b"\x0f\xb8\x40\x22\x19\x90\xb7\x06\xb3\xe1\x97\x66",
                // Hop-2-1, Hop-2-2
                b"\x66\xba\x03\x8d\xdd\x4e\xd0\x7f\xda\xce\xfe\x81",
                b"\xce\x4e\x99\x9e\x52\x74\xc1\x52\xfc\x72\x0c\x35",
            ],
            times: [0x765dd0df, 0x2ab47c18],
            hops: [&[(0x4022, 0x1990)], &[(0x038d, 0xdd4e), (0x999e, 0x5274)]],
            interfaces: vec![0x4022, 0x1990, 0x038d, 0xdd4e, 0x999e, 0x5274]
        }
    }

    test_iterators! {
        three_segment_path: {
            path: vec![
                b"\x00\x00\x10\x83",
                // Info-1
                b"\x2e\x48\x83\xd9",
                b"\xa3\x1a\xb4\x21",
                // Info-2
                b"\x81\xbc\xbe\xfd",
                b"\xd7\x76\x72\xf2",
                // Info-3
                b"\x1c\x40\x75\xf3",
                b"\xd3\x48\x21\x61",
                // Hop-1-1
                b"\x6b\x80\xa9\xb7\x25\x58\xbe\xa8\x7c\x1e\x93\x71",
                // Hop-2-1, Hop-2-2
                b"\x97\xca\xc2\xb6\x91\x99\x75\x2d\x7a\x6a\xa4\x9f",
                b"\x67\x83\xea\x67\x39\x02\x05\x49\xe6\x0a\xe7\x36",
                // Hop-3-1, Hop-3-2, Hop-3-3
                b"\xb5\x83\xd1\xf7\x27\xbf\xc2\x95\x1a\xdc\x05\x5f",
                b"\xcb\x66\x78\xca\xa6\xb0\x8e\x1b\x92\x4c\x79\xa5",
                b"\xf9\x77\x08\xde\xdf\x39\xef\xa9\x10\x40\x23\xca",
            ],
            times: [0xa31ab421, 0xd77672f2, 0xd3482161],
            hops: [
                &[(0xa9b7, 0x2558)],
                &[(0xc2b6, 0x9199), (0xea67, 0x3902)],
                &[(0xd1f7, 0x27bf), (0x78ca, 0xa6b0), (0x08de, 0xdf39)]
            ],
            interfaces: vec![
                0x2558, 0xa9b7, 0xc2b6, 0x9199, 0xea67, 0x3902, 0x27bf, 0xd1f7, 0xa6b0, 0x78ca, 0xdf39, 0x08de,
            ]
        }
    }
}
