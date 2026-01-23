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
//! Conversion between path segment model and protobuf.

use prost::Message;

use crate::path::{
    ASEntry, HopEntry, Info, PathSegment, PeerEntry, SegmentHopField, Segments, SegmentsPage,
    SignedMessage,
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

// Protobuf Conversion
impl ASEntry {
    fn unsound_into_rpc(self) -> scion_protobuf::control_plane::v1::AsEntry {
        // TODO: Needs to be properly implemented
        use scion_protobuf::Message;

        scion_protobuf::control_plane::v1::AsEntry {
            signed: Some(scion_protobuf::crypto::v1::SignedMessage {
                header_and_body: scion_protobuf::crypto::v1::HeaderAndBodyInternal {
                    header: scion_protobuf::crypto::v1::Header {
                        signature_algorithm:
                            scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha256 as i32,
                        verification_key_id: vec![],
                        timestamp: None,
                        metadata: vec![],
                        associated_data_length: 0,
                    }
                    .encode_to_vec(),
                    body: scion_protobuf::control_plane::v1::AsEntrySignedBody {
                        hop_entry: Some(scion_protobuf::control_plane::v1::HopEntry {
                            ingress_mtu: self.hop_entry.ingress_mtu as u32,
                            hop_field: Some(scion_protobuf::control_plane::v1::HopField {
                                exp_time: self.hop_entry.hop_field.exp_time as u32,
                                ingress: self.hop_entry.hop_field.cons_ingress as u64,
                                egress: self.hop_entry.hop_field.cons_egress as u64,
                                mac: self.hop_entry.hop_field.mac.to_vec(),
                            }),
                        }),
                        isd_as: self.local.into(),
                        next_isd_as: self.next.into(),
                        mtu: self.mtu,
                        peer_entries: self
                            .peer_entries
                            .iter()
                            .map(|p| {
                                scion_protobuf::control_plane::v1::PeerEntry {
                                    peer_isd_as: p.peer.into(),
                                    peer_interface: p.peer_interface as u64,
                                    peer_mtu: p.peer_mtu as u32,
                                    hop_field: Some(scion_protobuf::control_plane::v1::HopField {
                                        exp_time: p.hop_field.exp_time as u32,
                                        ingress: p.hop_field.cons_ingress as u64,
                                        egress: p.hop_field.cons_egress as u64,
                                        mac: p.hop_field.mac.to_vec(),
                                    }),
                                }
                            })
                            .collect(),
                        extensions: None,
                    }
                    .encode_to_vec(),
                }
                .encode_to_vec(),
                signature: vec![],
            }),
            unsigned: None,
        }
    }
}

// Model to Protobuf
//

impl From<PathSegment> for scion_protobuf::control_plane::v1::PathSegment {
    fn from(value: PathSegment) -> Self {
        Self {
            segment_info: scion_protobuf::control_plane::v1::SegmentInformation::from(value.info)
                .encode_to_vec(),
            as_entries: value.as_entries.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Info> for scion_protobuf::control_plane::v1::SegmentInformation {
    fn from(info: Info) -> Self {
        scion_protobuf::control_plane::v1::SegmentInformation {
            timestamp: info.timestamp.timestamp(),
            segment_id: info.segment_id as u32,
        }
    }
}

/// WARNING: This function is not correctly implementing the conversion!
impl From<ASEntry> for scion_protobuf::control_plane::v1::AsEntry {
    fn from(as_entry: ASEntry) -> Self {
        if as_entry.signed.header_and_body.is_empty() {
            // If we created the segment locally, we do not have the signed message
            // available. So we use the unsound conversion that which creates it without a signature
            as_entry.unsound_into_rpc()
        } else {
            Self {
                signed: Some(as_entry.signed.into()),
                unsigned: None,
            }
        }
    }
}

impl From<SignedMessage> for scion_protobuf::crypto::v1::SignedMessage {
    fn from(signed: SignedMessage) -> Self {
        Self {
            header_and_body: signed.header_and_body,
            signature: signed.signature,
        }
    }
}

impl From<HopEntry> for scion_protobuf::control_plane::v1::HopEntry {
    fn from(entry: HopEntry) -> Self {
        Self {
            ingress_mtu: entry.ingress_mtu as u32,
            hop_field: Some(entry.hop_field.into()),
        }
    }
}

impl From<SegmentHopField> for scion_protobuf::control_plane::v1::HopField {
    fn from(hop_field: SegmentHopField) -> Self {
        Self {
            exp_time: hop_field.exp_time as u32,
            ingress: hop_field.cons_ingress as u64,
            egress: hop_field.cons_egress as u64,
            mac: hop_field.mac.to_vec(),
        }
    }
}

// Protobuf to Model
//

impl TryFrom<scion_protobuf::control_plane::v1::SegmentsResponse> for SegmentsPage {
    type Error = InvalidSegmentError;
    fn try_from(
        value: scion_protobuf::control_plane::v1::SegmentsResponse,
    ) -> Result<Self, Self::Error> {
        let mut up_segments = Vec::new();
        let mut down_segments = Vec::new();
        let mut core_segments = Vec::new();
        for (segment_type, segments) in value.segments {
            let segment_type =
                match scion_protobuf::control_plane::v1::SegmentType::try_from(segment_type) {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::debug!(
                            ?err,
                            "Invalid segment type in segments response, skipping"
                        );
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
                        tracing::debug!("Unspecified segment type in segments response, skipping");
                        continue;
                    }
                }
            }
        }

        Ok(Self {
            segments: Segments {
                up_segments,
                down_segments,
                core_segments,
            },
            // TODO(pagination): There is no pagination in the control service.
            next_page_token: "".to_string(),
        })
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::PathSegment> for PathSegment {
    type Error = InvalidSegmentError;
    fn try_from(
        segment: scion_protobuf::control_plane::v1::PathSegment,
    ) -> Result<Self, Self::Error> {
        let segment_info = scion_protobuf::control_plane::v1::SegmentInformation::decode(
            segment.segment_info.as_slice(),
        )
        .map_err(|_| "Failed to decode segment info")?;

        Ok(Self {
            info: segment_info.try_into()?,
            as_entries: segment
                .as_entries
                .into_iter()
                .map(ASEntry::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::SegmentInformation> for Info {
    type Error = InvalidSegmentError;
    fn try_from(
        info: scion_protobuf::control_plane::v1::SegmentInformation,
    ) -> Result<Self, Self::Error> {
        let timestamp = chrono::DateTime::from_timestamp(info.timestamp, 0)
            .ok_or("Invalid timestamp in segment info")?;
        Ok(Info::new(timestamp, info.segment_id as u16))
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::AsEntry> for ASEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::AsEntry) -> Result<Self, Self::Error> {
        let signed = entry.signed.as_ref().ok_or("Missing Signed Message")?;
        let hdr_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
            signed.header_and_body.as_ref(),
        )
        .map_err(|_| "Failed to decode Signed Header and Body")?;
        let unverified_body = hdr_and_body.body;
        let entry =
            scion_protobuf::control_plane::v1::AsEntrySignedBody::decode(unverified_body.as_ref())
                .map_err(|_| "Failed to decode AsEntrySignedBody")?;

        Ok(ASEntry {
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
            signed: signed.clone().into(),
        })
    }
}

impl From<scion_protobuf::crypto::v1::SignedMessage> for SignedMessage {
    fn from(value: scion_protobuf::crypto::v1::SignedMessage) -> Self {
        Self {
            header_and_body: value.header_and_body,
            signature: value.signature,
        }
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::PeerEntry> for PeerEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::PeerEntry) -> Result<Self, Self::Error> {
        Ok(PeerEntry {
            peer: entry.peer_isd_as.into(),
            peer_interface: entry.peer_interface as u16,
            peer_mtu: entry.peer_mtu as u16,
            hop_field: entry
                .hop_field
                .ok_or("Missing Hop Field in Peer Entry")?
                .try_into()?,
        })
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::HopEntry> for HopEntry {
    type Error = InvalidSegmentError;
    fn try_from(entry: scion_protobuf::control_plane::v1::HopEntry) -> Result<Self, Self::Error> {
        Ok(HopEntry {
            ingress_mtu: entry.ingress_mtu as u16,
            hop_field: entry
                .hop_field
                .ok_or("Missing hop field in HopEntry")?
                .try_into()?,
        })
    }
}

impl TryFrom<scion_protobuf::control_plane::v1::HopField> for SegmentHopField {
    type Error = InvalidSegmentError;
    fn try_from(
        hop_field: scion_protobuf::control_plane::v1::HopField,
    ) -> Result<Self, Self::Error> {
        Ok(SegmentHopField {
            exp_time: hop_field.exp_time as u8,
            cons_ingress: hop_field.ingress as u16,
            cons_egress: hop_field.egress as u16,
            mac: hop_field.mac[..6]
                .try_into()
                .map_err(|_| "Invalid MAC length")?,
        })
    }
}
