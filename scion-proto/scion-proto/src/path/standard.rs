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
//! Standard SCION path.

use std::time::Duration;

use bytes::{Buf as _, BufMut, Bytes};
use chrono::{DateTime, Utc};
use sciparse::path::standard::types::{HopFieldFlags, InfoFieldFlags};

use super::{HopFieldIndex, InfoFieldIndex, MetaHeader, MetaReserved, SegmentLength, encoded};
use crate::{
    packet::{DecodeError, InadequateBufferSize},
    wire_encoding::{WireDecode, WireEncode},
};

/// A fully decoded data plane path. It can be used to build new paths or to modify existing ones.
/// If you only need to read information, use [`encoded::EncodedStandardPath`] instead for better
/// performance.
#[derive(Debug, Clone)]
pub struct StandardPath {
    /// Path meta data.
    pub path_meta: MetaHeader,
    /// Info fields of the path.
    pub info_fields: Vec<InfoField>,
    /// Hop fields of the path.
    pub hop_fields: Vec<HopField>,
}

/// Data plane path builder errors.
#[derive(Debug, thiserror::Error)]
pub enum DataPlanePathBuilderError {
    /// Error when trying to add too many segments to a path.
    #[error("A path can only be constructed with up to 3 segments")]
    TooManySegments,
}

impl StandardPath {
    /// Creates a new empty path.
    pub fn new() -> Self {
        Self {
            path_meta: MetaHeader {
                current_info_field: InfoFieldIndex::new_unchecked(0),
                current_hop_field: HopFieldIndex::new_unchecked(0),
                reserved: MetaReserved::new_unchecked(0),
                segment_lengths: [SegmentLength::new_unchecked(0); 3],
            },
            info_fields: Vec::new(),
            hop_fields: Vec::new(),
        }
    }

    /// Add a segment to the path .
    pub fn add_segment(
        &mut self,
        info_field: InfoField,
        hop_fields: Vec<HopField>,
    ) -> Result<(), DataPlanePathBuilderError> {
        if self.info_fields.len() >= 3 {
            return Err(DataPlanePathBuilderError::TooManySegments);
        }
        let seg_idx = self.info_fields.len();
        self.path_meta.segment_lengths[seg_idx] =
            SegmentLength::new_unchecked(hop_fields.len() as u8);
        self.info_fields.push(info_field);
        self.hop_fields.extend(hop_fields);
        Ok(())
    }

    /// Creates a StandardPath from a sciparse standard path.
    #[doc(hidden)]
    pub fn from_sciparse_standard_path(
        sciparse_path: sciparse::path::standard::model::StandardPath,
    ) -> Self {
        let info_fields = sciparse_path
            .iter_info_fields()
            .map(|f| {
                InfoField {
                    peer: f.flags.contains(InfoFieldFlags::PEERING),
                    cons_dir: f.flags.contains(InfoFieldFlags::CONS_DIR),
                    seg_id: f.segment_id,
                    timestamp_epoch: f.timestamp,
                }
            })
            .collect();

        let hop_fields = sciparse_path
            .iter_hop_fields()
            .map(|f| {
                HopField {
                    ingress_router_alert: f
                        .flags
                        .contains(HopFieldFlags::CONS_INGRESS_ROUTER_ALERT),
                    egress_router_alert: f.flags.contains(HopFieldFlags::CONS_EGRESS_ROUTER_ALERT),
                    exp_time: f.expiration_units,
                    cons_ingress: f.cons_ingress,
                    cons_egress: f.cons_egress,
                    mac: f.mac.0,
                }
            })
            .collect();

        let (seg1, seg2, seg3) = sciparse_path.segment_lengths();

        Self {
            path_meta: MetaHeader {
                current_info_field: InfoFieldIndex::new_unchecked(sciparse_path.current_info_field),
                current_hop_field: HopFieldIndex::new_unchecked(sciparse_path.curr_hop_field),
                reserved: MetaReserved::new_unchecked(0),
                segment_lengths: [
                    SegmentLength::new_unchecked(seg1),
                    SegmentLength::new_unchecked(seg2),
                    SegmentLength::new_unchecked(seg3),
                ],
            },
            info_fields,
            hop_fields,
        }
    }
}

impl Default for StandardPath {
    fn default() -> Self {
        Self::new()
    }
}

impl From<StandardPath> for encoded::EncodedStandardPath<Bytes> {
    fn from(value: StandardPath) -> Self {
        encoded::EncodedStandardPath {
            meta_header: value.path_meta.clone(),
            encoded_path: value.encode_to_bytes(),
        }
    }
}

impl TryFrom<encoded::EncodedStandardPath<Bytes>> for StandardPath {
    type Error = DecodeError;

    fn try_from(mut value: encoded::EncodedStandardPath<Bytes>) -> Result<Self, Self::Error> {
        Self::decode(&mut value.encoded_path)
    }
}

impl WireEncode for StandardPath {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        self.path_meta.encoded_length()
            + self
                .info_fields
                .iter()
                .map(|f| f.encoded_length())
                .sum::<usize>()
            + self
                .hop_fields
                .iter()
                .map(|f| f.encoded_length())
                .sum::<usize>()
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        self.path_meta.encode_to_unchecked(buffer);
        for info in self.info_fields.iter() {
            info.encode_to_unchecked(buffer);
        }
        for hop in self.hop_fields.iter() {
            hop.encode_to_unchecked(buffer);
        }
    }
}

impl WireDecode<Bytes> for StandardPath {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        let meta_header = MetaHeader::decode(data)?;

        let mut info_fields = Vec::new();
        let mut hop_fields = Vec::new();

        for _ in 0..meta_header.info_fields_count() {
            let info_field = InfoField::decode(data)?;
            info_fields.push(info_field);
        }

        for _ in 0..meta_header.hop_fields_count() {
            let hop_field = HopField::decode(data)?;
            hop_fields.push(hop_field);
        }

        Ok(Self {
            path_meta: meta_header,
            info_fields,
            hop_fields,
        })
    }
}

/// InfoField is the InfoField used in the SCION and OneHop path types.
///
/// InfoField has the following format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |r r r r r r P C|      RSV      |             SegID             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone, Copy, Default)]
pub struct InfoField {
    /// Peer is the peering flag. If set to true, then the forwarding path is built as a peering
    /// path, which requires special processing on the data plane.
    pub peer: bool,
    /// ConsDir is the construction direction flag. If set to true then the hop fields are arranged
    /// in the direction they have been constructed during beaconing.
    pub cons_dir: bool,
    /// SegID is a updatable field that is required for the MAC-chaining mechanism.
    pub seg_id: u16,
    /// Timestamp created by the initiator of the corresponding beacon. The timestamp is expressed
    /// in Unix time, and is encoded as an unsigned integer within 4 bytes with 1-second time
    /// granularity.  This timestamp enables validation of the hop field by verification of the
    /// expiration time and MAC.
    pub timestamp_epoch: u32,
}

impl InfoField {
    /// The encoded size of an InfoField.
    pub const ENCODED_SIZE: usize = 8;
    pub(super) const FLAGS_CONS_DIR: u8 = 0b01;
    pub(super) const FLAGS_PEER: u8 = 0b10;

    /// Returns the info field timestamp as [`DateTime<Utc>`].
    pub fn timestamp(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.timestamp_epoch as i64, 0)
            .expect("u32 can not be out of range")
    }
}

impl WireEncode for InfoField {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        let mut flags: u8 = 0;
        if self.cons_dir {
            flags |= Self::FLAGS_CONS_DIR;
        }
        if self.peer {
            flags |= Self::FLAGS_PEER;
        }
        buffer.put_u8(flags);
        buffer.put_u8(0);
        buffer.put_u16(self.seg_id);
        buffer.put_u32(self.timestamp_epoch);
    }
}

impl WireDecode<Bytes> for InfoField {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_SIZE {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        let flags = data.get_u8();
        let peer = flags & Self::FLAGS_PEER != 0;
        let cons_dir = flags & Self::FLAGS_CONS_DIR != 0;
        // skip reserved
        data.advance(1);
        let seg_id = data.get_u16();
        let timestamp = data.get_u32();

        Ok(Self {
            peer,
            cons_dir,
            seg_id,
            timestamp_epoch: timestamp,
        })
    }
}

/// HopField is the HopField used in the SCION and OneHop path types.
///
/// The Hop Field has the following format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |r r r r r r I E|    ExpTime    |           ConsIngress         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        ConsEgress             |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                              MAC                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, Clone)]
pub struct HopField {
    /// IngressRouterAlert flag. If the IngressRouterAlert is set, the ingress router (in
    /// construction direction) will process the L4 payload in the packet.
    pub ingress_router_alert: bool,
    /// EgressRouterAlert flag. If the EgressRouterAlert is set, the egress router (in
    /// construction direction) will process the L4 payload in the packet.
    pub egress_router_alert: bool,
    /// Exptime is the expiry time of a HopField. The field is 1-byte long, thus there are 256
    /// different values available to express an expiration time. The expiration time expressed by
    /// the value of this field is relative, and an absolute expiration time in seconds is computed
    /// in combination with the timestamp field (from the corresponding info field) as follows
    ///
    /// Timestamp + (1 + ExpTime) * (24*60*60)/256
    pub exp_time: u8,
    /// ConsIngress is the ingress interface ID in construction direction.
    pub cons_ingress: u16,
    /// ConsEgress is the egress interface ID in construction direction.
    pub cons_egress: u16,
    /// Mac is the 6-byte Message Authentication Code to authenticate the HopField.
    pub mac: [u8; 6],
}

impl HopField {
    /// The encoded size of a HopField.
    pub const ENCODED_SIZE: usize = 12;
    pub(super) const FLAGS_EGRESS_ROUTER_ALERT: u8 = 0b01;
    pub(super) const FLAGS_INGRESS_ROUTER_ALERT: u8 = 0b10;

    pub(super) const DURATION_PER_EXP_UNIT: Duration = Duration::from_millis(337_500);

    /// Returns the normalized interfaces of the HopField. \
    /// (ingress, egress)
    pub fn interfaces(&self, is_construction_dir: bool) -> (u16, u16) {
        if is_construction_dir {
            (self.cons_ingress, self.cons_egress)
        } else {
            (self.cons_egress, self.cons_ingress)
        }
    }

    /// Returns the normalized SCMP alerts of the HopField. \
    /// (ingress, egress)
    pub fn alerts(&self, is_construction_dir: bool) -> (bool, bool) {
        if is_construction_dir {
            (self.ingress_router_alert, self.egress_router_alert)
        } else {
            (self.egress_router_alert, self.ingress_router_alert)
        }
    }

    /// Returns expiry offset of packet in seconds.
    pub fn expiry_offset(&self) -> Duration {
        Self::DURATION_PER_EXP_UNIT * (1 + self.exp_time as u32)
    }

    /// Returns the unix epoch in seconds of when the HopField expires.
    pub fn expiry_time(&self, info_field: &InfoField) -> DateTime<Utc> {
        info_field.timestamp() + self.expiry_offset()
    }
}

impl WireEncode for HopField {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        let mut flags: u8 = 0;
        if self.ingress_router_alert {
            flags |= Self::FLAGS_INGRESS_ROUTER_ALERT;
        }
        if self.egress_router_alert {
            flags |= Self::FLAGS_EGRESS_ROUTER_ALERT;
        }
        buffer.put_u8(flags);
        buffer.put_u8(self.exp_time);
        buffer.put_u16(self.cons_ingress);
        buffer.put_u16(self.cons_egress);
        buffer.put_slice(&self.mac);
    }
}

impl WireDecode<Bytes> for HopField {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_SIZE {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        let flags = data.get_u8();
        let ingress_router_alert = flags & Self::FLAGS_INGRESS_ROUTER_ALERT != 0;
        let egress_router_alert = flags & Self::FLAGS_EGRESS_ROUTER_ALERT != 0;
        let exp_time = data.get_u8();
        let cons_ingress = data.get_u16();
        let cons_egress = data.get_u16();
        let mac = data.split_to(6);

        Ok(Self {
            ingress_router_alert,
            egress_router_alert,
            exp_time,
            cons_ingress,
            cons_egress,
            mac: mac.slice(..6).to_vec().try_into().unwrap(),
        })
    }
}
