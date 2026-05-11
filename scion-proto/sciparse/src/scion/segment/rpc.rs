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

//! Segment RPC types and conversions.

use prost::Message;

use crate::{
    path::standard::types::HopFieldMac,
    segment::{
        AsEntry, HopEntry, PeerEntry, SegmentHopField, SegmentInfo, Segments, SegmentsPage,
        SignedAsEntry, SignedPathSegment,
    },
};

/// Invalid segment error.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("invalid segment: {0}")]
pub struct InvalidSegmentError(pub &'static str);
impl From<&'static str> for InvalidSegmentError {
    fn from(value: &'static str) -> Self {
        InvalidSegmentError(value)
    }
}

impl SegmentHopField {
    /// Converts to a protobuf hop field message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::HopField {
        scion_protobuf::control_plane::v1::HopField {
            exp_time: self.exp_time as u32,
            ingress: self.cons_ingress as u64,
            egress: self.cons_egress as u64,
            mac: self.mac.to_vec(),
        }
    }

    /// Tries to convert from a protobuf hop field message.
    pub fn try_from_rpc(
        hop_field: scion_protobuf::control_plane::v1::HopField,
    ) -> Result<Self, InvalidSegmentError> {
        if hop_field.mac.len() != 6 {
            return Err("Invalid MAC length in HopField".into());
        }

        Ok(SegmentHopField {
            exp_time: hop_field
                .exp_time
                .try_into()
                .map_err(|_| "Exp Time in HopField is not a valid u8")?,
            cons_ingress: hop_field
                .ingress
                .try_into()
                .map_err(|_| "Ingress in HopField is not a valid u16")?,
            cons_egress: hop_field
                .egress
                .try_into()
                .map_err(|_| "Egress in HopField is not a valid u16")?,
            mac: HopFieldMac(
                hop_field.mac[..6]
                    .try_into()
                    .expect("MAC length checked above, should be 6"),
            ),
        })
    }
}
impl From<SegmentHopField> for scion_protobuf::control_plane::v1::HopField {
    fn from(hop_field: SegmentHopField) -> Self {
        hop_field.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::HopField> for SegmentHopField {
    type Error = InvalidSegmentError;
    fn try_from(
        hop_field: scion_protobuf::control_plane::v1::HopField,
    ) -> Result<Self, Self::Error> {
        SegmentHopField::try_from_rpc(hop_field)
    }
}

impl HopEntry {
    /// Converts to a protobuf hop entry message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::HopEntry {
        scion_protobuf::control_plane::v1::HopEntry {
            ingress_mtu: self.ingress_mtu as u32,
            hop_field: Some(self.hop_field.into_rpc()),
        }
    }

    /// Tries to convert from a protobuf hop entry message.
    pub fn try_from_rpc(
        entry: scion_protobuf::control_plane::v1::HopEntry,
    ) -> Result<Self, InvalidSegmentError> {
        Ok(HopEntry {
            ingress_mtu: entry
                .ingress_mtu
                .try_into()
                .map_err(|_| "Ingress MTU in HopEntry is not a valid u16")?,
            hop_field: entry
                .hop_field
                .ok_or("Missing hop field in HopEntry")?
                .try_into()?,
        })
    }
}
impl From<HopEntry> for scion_protobuf::control_plane::v1::HopEntry {
    fn from(entry: HopEntry) -> Self {
        entry.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::HopEntry> for HopEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::HopEntry) -> Result<Self, Self::Error> {
        HopEntry::try_from_rpc(entry)
    }
}

impl PeerEntry {
    /// Converts to a protobuf peer entry message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::PeerEntry {
        scion_protobuf::control_plane::v1::PeerEntry {
            peer_isd_as: self.peer.into(),
            peer_interface: self.peer_interface as u64,
            peer_mtu: self.peer_mtu as u32,
            hop_field: Some(self.hop_field.into_rpc()),
        }
    }

    /// Tries to convert from a protobuf peer entry message.
    pub fn try_from_rpc(
        entry: scion_protobuf::control_plane::v1::PeerEntry,
    ) -> Result<Self, InvalidSegmentError> {
        Ok(PeerEntry {
            peer: entry.peer_isd_as.into(),
            peer_interface: entry
                .peer_interface
                .try_into()
                .map_err(|_| "Peer interface in PeerEntry exceeds u16 maximum")?,
            peer_mtu: entry
                .peer_mtu
                .try_into()
                .map_err(|_| "Peer MTU in PeerEntry exceeds u16 maximum")?,
            hop_field: entry
                .hop_field
                .ok_or("Missing Hop Field in Peer Entry")?
                .try_into()?,
        })
    }
}
impl From<PeerEntry> for scion_protobuf::control_plane::v1::PeerEntry {
    fn from(entry: PeerEntry) -> Self {
        entry.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::PeerEntry> for PeerEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::PeerEntry) -> Result<Self, Self::Error> {
        PeerEntry::try_from_rpc(entry)
    }
}

impl SegmentInfo {
    /// Converts to a protobuf segment information message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::SegmentInformation {
        scion_protobuf::control_plane::v1::SegmentInformation {
            timestamp: self.timestamp as i64,
            segment_id: self.segment_id as u32,
        }
    }

    /// Tries to convert from a protobuf segment information message.
    pub fn try_from_rpc(
        info: scion_protobuf::control_plane::v1::SegmentInformation,
    ) -> Result<Self, InvalidSegmentError> {
        Ok(SegmentInfo::new(
            info.timestamp
                .try_into()
                .map_err(|_| "Timestamp is not a valid u32")?,
            info.segment_id
                .try_into()
                .map_err(|_| "Segment ID is not a valid u16")?,
        ))
    }
}
impl From<SegmentInfo> for scion_protobuf::control_plane::v1::SegmentInformation {
    fn from(info: SegmentInfo) -> Self {
        info.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::SegmentInformation> for SegmentInfo {
    type Error = InvalidSegmentError;
    fn try_from(
        info: scion_protobuf::control_plane::v1::SegmentInformation,
    ) -> Result<Self, Self::Error> {
        SegmentInfo::try_from_rpc(info)
    }
}

impl SignedAsEntry {
    /// Converts to a protobuf AS entry message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::AsEntry {
        scion_protobuf::control_plane::v1::AsEntry {
            signed: Some(self.signed.into_rpc()),
            // Todo: We should be able to fill this in
            unsigned: None,
        }
    }

    /// Tries to convert from a protobuf AS entry message.
    pub fn try_from_rpc(
        entry: scion_protobuf::control_plane::v1::AsEntry,
    ) -> Result<Self, InvalidSegmentError> {
        let signed = entry.signed.ok_or("Missing Signed Message")?;
        let hdr_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
            signed.header_and_body.as_ref(),
        )
        .map_err(|_| "Failed to decode Signed Header and Body")?;
        let unverified_body = hdr_and_body.body;
        let entry =
            scion_protobuf::control_plane::v1::AsEntrySignedBody::decode(unverified_body.as_ref())
                .map_err(|_| "Failed to decode AsEntrySignedBody")?;

        Ok(SignedAsEntry {
            entry: AsEntry {
                local: entry.isd_as.into(),
                mtu: entry.mtu,
                next: entry.next_isd_as.into(),
                hop_entry: entry.hop_entry.ok_or("missing Hop Entry")?.try_into()?,
                peer_entries: entry
                    .peer_entries
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, _>>()?,
                extensions: Vec::new(),
                unsigned_extensions: Vec::new(),
            },
            signed: signed.into(),
        })
    }
}
impl From<SignedAsEntry> for scion_protobuf::control_plane::v1::AsEntry {
    fn from(as_entry: SignedAsEntry) -> Self {
        as_entry.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::AsEntry> for SignedAsEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::AsEntry) -> Result<Self, Self::Error> {
        SignedAsEntry::try_from_rpc(entry)
    }
}

impl SignedPathSegment {
    /// Converts to a protobuf path segment message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::PathSegment {
        scion_protobuf::control_plane::v1::PathSegment {
            segment_info: self.info.into_rpc().encode_to_vec(),
            as_entries: self.as_entries.into_iter().map(Into::into).collect(),
        }
    }

    /// Tries to convert from a protobuf path segment message.
    pub fn try_from_rpc(
        segment: scion_protobuf::control_plane::v1::PathSegment,
    ) -> Result<Self, InvalidSegmentError> {
        let segment_info = scion_protobuf::control_plane::v1::SegmentInformation::decode(
            segment.segment_info.as_slice(),
        )
        .map_err(|_| "Failed to decode segment info")?;

        Ok(Self {
            info: segment_info.try_into()?,
            as_entries: segment
                .as_entries
                .into_iter()
                .map(SignedAsEntry::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}
impl From<SignedPathSegment> for scion_protobuf::control_plane::v1::PathSegment {
    fn from(value: SignedPathSegment) -> Self {
        value.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::PathSegment> for SignedPathSegment {
    type Error = InvalidSegmentError;
    fn try_from(
        segment: scion_protobuf::control_plane::v1::PathSegment,
    ) -> Result<Self, Self::Error> {
        SignedPathSegment::try_from_rpc(segment)
    }
}

type RpcSegments =
    std::collections::HashMap<i32, scion_protobuf::control_plane::v1::segments_response::Segments>;

impl Segments {
    /// Converts to protobuf segments grouped by type.
    pub fn into_rpc(
        self,
    ) -> std::collections::HashMap<
        i32,
        scion_protobuf::control_plane::v1::segments_response::Segments,
    > {
        use scion_protobuf::control_plane::v1::{SegmentType, segments_response};
        let mut segments = std::collections::HashMap::new();
        if !self.up_segments.is_empty() {
            segments.insert(
                SegmentType::Up as i32,
                segments_response::Segments {
                    segments: self.up_segments.into_iter().map(Into::into).collect(),
                },
            );
        }
        if !self.down_segments.is_empty() {
            segments.insert(
                SegmentType::Down as i32,
                segments_response::Segments {
                    segments: self.down_segments.into_iter().map(Into::into).collect(),
                },
            );
        }
        if !self.core_segments.is_empty() {
            segments.insert(
                SegmentType::Core as i32,
                segments_response::Segments {
                    segments: self.core_segments.into_iter().map(Into::into).collect(),
                },
            );
        }
        segments
    }

    /// Tries to convert from a protobuf segments response message.
    pub fn try_from_rpc(value: RpcSegments) -> Result<Self, InvalidSegmentError> {
        let mut up_segments = Vec::new();
        let mut down_segments = Vec::new();
        let mut core_segments = Vec::new();
        for (segment_type, segments) in value {
            let segment_type =
                match scion_protobuf::control_plane::v1::SegmentType::try_from(segment_type) {
                    Ok(t) => t,
                    Err(_err) => {
                        // Skip unrecognized segment types
                        continue;
                    }
                };
            for path_segment in segments.segments {
                let segment = path_segment.try_into()?;
                match segment_type {
                    scion_protobuf::control_plane::v1::SegmentType::Up => {
                        up_segments.push(segment);
                    }
                    scion_protobuf::control_plane::v1::SegmentType::Core => {
                        core_segments.push(segment);
                    }
                    scion_protobuf::control_plane::v1::SegmentType::Down => {
                        down_segments.push(segment);
                    }
                    scion_protobuf::control_plane::v1::SegmentType::Unspecified => {
                        // Skip unrecognized segment types
                        continue;
                    }
                }
            }
        }
        Ok(Self {
            up_segments,
            down_segments,
            core_segments,
        })
    }
}
impl From<Segments> for RpcSegments {
    fn from(segments: Segments) -> Self {
        segments.into_rpc()
    }
}
impl TryFrom<RpcSegments> for Segments {
    type Error = InvalidSegmentError;
    fn try_from(
        value: std::collections::HashMap<
            i32,
            scion_protobuf::control_plane::v1::segments_response::Segments,
        >,
    ) -> Result<Self, Self::Error> {
        Segments::try_from_rpc(value)
    }
}

impl SegmentsPage {
    /// Converts to a protobuf segments response message.
    pub fn into_rpc(self) -> scion_protobuf::control_plane::v1::SegmentsResponse {
        scion_protobuf::control_plane::v1::SegmentsResponse {
            segments: self.segments.into_rpc(),
            deprecated_signed_revocations: Vec::new(),
        }
    }

    /// Tries to convert from a protobuf segments response message.
    pub fn try_from_rpc(
        value: scion_protobuf::control_plane::v1::SegmentsResponse,
    ) -> Result<Self, InvalidSegmentError> {
        Ok(Self {
            segments: Segments::try_from_rpc(value.segments)?,
            // TODO(pagination): There is no pagination in the control service.
            next_page_token: "".to_string(),
        })
    }
}
impl From<SegmentsPage> for scion_protobuf::control_plane::v1::SegmentsResponse {
    fn from(page: SegmentsPage) -> Self {
        page.into_rpc()
    }
}
impl TryFrom<scion_protobuf::control_plane::v1::SegmentsResponse> for SegmentsPage {
    type Error = InvalidSegmentError;
    fn try_from(
        value: scion_protobuf::control_plane::v1::SegmentsResponse,
    ) -> Result<Self, Self::Error> {
        SegmentsPage::try_from_rpc(value)
    }
}
