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

//! SCION path segment types.
//!
//! This module contains types for SCION path segments used in the control plane.
//! Path segments are used during the beaconing process and stored in path servers.
//! They can be combined to form end-to-end paths used for data plane forwarding.

use std::{
    fmt,
    hash::Hasher,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use ecdsa::signature;
use scion_protobuf::control_plane::v1::VerificationKeyId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    address::IsdAsn,
    path::signed_message::{DigestAlgorithm, SignedMessage, ValidateError},
};

// MaxTTL is the maximum age of a HopField (24h).
const MAX_TTL: Duration = Duration::from_secs(86400);

// MaxTTL / 256 (5m38.5s) see the following for reference:
// https://datatracker.ietf.org/doc/html/draft-dekater-scion-dataplane#name-hop-field
/// Expiration Duration per ExpTime unit on a HopField.
pub const EXP_TIME_UNIT: Duration = Duration::new(337, 500_000_000);

/// Path segment error.
#[derive(Debug)]
pub enum SegmentsError {
    /// Invalid argument.
    InvalidArgument(String),
    /// Internal error.
    InternalError(String),
}

/// Segments containing up, down, and core segments along with a next page token.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Segments {
    /// Up segments.
    pub up_segments: Vec<PathSegment>,
    /// Down segments.
    pub down_segments: Vec<PathSegment>,
    /// Core segments.
    pub core_segments: Vec<PathSegment>,
}

impl Segments {
    /// Returns an iterator over vectors of path segments by type.
    pub fn iter_with_type(&self) -> impl Iterator<Item = (&'static str, &Vec<PathSegment>)> {
        [
            ("up", &self.up_segments),
            ("down", &self.down_segments),
            ("core", &self.core_segments),
        ]
        .into_iter()
    }

    /// Splits the segments into core and non-core segments.
    ///
    /// Returns (core_segments, non_core_segments)
    pub fn split_parts(self) -> (Vec<PathSegment>, Vec<PathSegment>) {
        (
            self.core_segments,
            [self.up_segments, self.down_segments].concat(),
        )
    }
}

impl std::fmt::Display for Segments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format_vec = |v: &Vec<PathSegment>| {
            let shown = v
                .iter()
                .take(10)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            if v.len() > 10 {
                format!("{}, {} more...", shown, v.len() - 10)
            } else {
                shown
            }
        };
        write!(
            f,
            "Segments[up: [{}], down: [{}], core: [{}]]",
            format_vec(&self.up_segments),
            format_vec(&self.down_segments),
            format_vec(&self.core_segments)
        )
    }
}

/// Segments containing up, down, and core segments along with a next page token.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SegmentsPage {
    /// Segments.
    pub segments: Segments,
    /// Next page token.
    pub next_page_token: String,
}

impl std::fmt::Display for SegmentsPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SegmentsPage[{}, next_page_token: {}]",
            self.segments, self.next_page_token
        )
    }
}

/// A SCION control plane path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathSegment {
    /// Segment information.
    pub info: Info,
    /// AS entries of the segment.
    pub as_entries: Vec<ASEntry>,
}

/// A hash of a path segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentID([u8; 32]);

impl From<[u8; 32]> for SegmentID {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl SegmentID {
    fn logging_id(&self) -> String {
        self.0[0..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

impl std::hash::Hash for SegmentID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl PathSegment {
    /// Creates a new path segment with the given timestamp and segment ID.
    pub fn new(timestamp: DateTime<Utc>, segment_id: u16, as_entries: Vec<ASEntry>) -> Self {
        Self {
            info: Info::new(timestamp, segment_id),
            as_entries,
        }
    }

    /// Returns a hash of the segment covering all hops, except for peerings.
    pub fn id(&self) -> SegmentID {
        let mut hasher = Sha256::new();

        for ase in &self.as_entries {
            // Add local ISD-AS
            hasher.update(ase.local.to_be_bytes());
            // Add hop field interfaces
            hasher.update(ase.hop_entry.hop_field.cons_ingress.to_be_bytes());
            hasher.update(ase.hop_entry.hop_field.cons_egress.to_be_bytes());
        }

        SegmentID(hasher.finalize().into())
    }

    /// Returns a hash of the segment covering all hops including peerings.
    pub fn full_id(&self) -> SegmentID {
        let mut hasher = Sha256::new();

        for ase in &self.as_entries {
            // Add local ISD-AS
            hasher.update(ase.local.to_be_bytes());

            // Add hop field interfaces
            hasher.update(ase.hop_entry.hop_field.cons_ingress.to_be_bytes());
            hasher.update(ase.hop_entry.hop_field.cons_egress.to_be_bytes());

            // Add peer entries
            for peer in &ase.peer_entries {
                hasher.update(peer.peer.to_be_bytes());
                hasher.update(peer.hop_field.cons_ingress.to_be_bytes());
                hasher.update(peer.hop_field.cons_egress.to_be_bytes());
            }
        }

        SegmentID(hasher.finalize().into())
    }

    /// Returns the first IA in the path segment.
    pub fn first_ia(&self) -> IsdAsn {
        self.as_entries.first().unwrap().local
    }

    /// Returns the last IA in the path segment.
    pub fn last_ia(&self) -> IsdAsn {
        self.as_entries.last().unwrap().local
    }

    /// Returns the number of AS entries in the path segment.
    pub fn len(&self) -> usize {
        self.as_entries.len()
    }

    /// Returns true if the path segment is empty.
    pub fn is_empty(&self) -> bool {
        self.as_entries.is_empty()
    }

    /// Returns an iterator over the AS entries in the path segment
    /// in the order of the path segment.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ASEntry> + DoubleEndedIterator {
        self.as_entries.iter()
    }

    /// Adds an AS entry to the path segment
    pub fn add_as_entry(mut self, as_entry: ASEntry) -> Self {
        self.as_entries.push(as_entry);
        self
    }

    /// Returns the maximum index of AS entries.
    pub fn max_idx(&self) -> usize {
        self.as_entries.len() - 1
    }

    /// Returns the maximum expiry time of the segment.
    pub fn max_expiry(&self) -> DateTime<Utc> {
        self.expiry(Duration::ZERO, |hf_ttl, ttl| hf_ttl > ttl)
    }

    /// Returns the minimum expiry time of the segment.
    pub fn min_expiry(&self) -> DateTime<Utc> {
        self.expiry(Duration::MAX, |hf_ttl, ttl| hf_ttl < ttl)
    }

    fn expiry(
        &self,
        init_ttl: Duration,
        compare: impl Fn(Duration, Duration) -> bool,
    ) -> DateTime<Utc> {
        let mut ttl = init_ttl;
        for ase in &self.as_entries {
            let hf_ttl = exp_time_to_duration(ase.hop_entry.hop_field.exp_time);
            if compare(hf_ttl, ttl) {
                ttl = hf_ttl;
            }
            for peer in &ase.peer_entries {
                let hf_ttl = exp_time_to_duration(peer.hop_field.exp_time);
                if compare(hf_ttl, ttl) {
                    ttl = hf_ttl;
                }
            }
        }
        self.info.timestamp + ttl
    }

    /// Returns a description of the hops in the path segment.
    fn get_hops_description(&self) -> String {
        let mut interfaces = Vec::new();
        for e in &self.as_entries {
            if e.hop_entry.hop_field.cons_ingress > 0 {
                interfaces.push(format!(
                    "{}#{}",
                    e.local, e.hop_entry.hop_field.cons_ingress
                ));
            }
            if e.hop_entry.hop_field.cons_egress > 0 {
                interfaces.push(format!("{}#{}", e.local, e.hop_entry.hop_field.cons_egress));
            }
        }
        interfaces.join(", ")
    }
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathSegment[id: {} ts:{} hops: {}]",
            self.id().logging_id(),
            self.info.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.get_hops_description()
        )
    }
}

impl std::hash::Hash for PathSegment {
    /// Hash of the path segment to be used as hash table key.
    fn hash<H: Hasher>(&self, state: &mut H) {
        for ase in &self.as_entries {
            // Add local ISD-AS
            ase.local.hash(state);
            // Add hop field interfaces
            ase.hop_entry.hop_field.cons_ingress.hash(state);
            ase.hop_entry.hop_field.cons_egress.hash(state);
            // Add peer entries
            for peer in &ase.peer_entries {
                peer.peer.hash(state);
                peer.hop_field.cons_ingress.hash(state);
                peer.hop_field.cons_egress.hash(state);
            }
        }
    }
}

/// ASEntry is one AS Entry in a path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ASEntry {
    /// ISD-AS of the AS corresponding to this entry.
    pub local: IsdAsn,
    /// ISD-AS of the downstream AS.
    pub next: IsdAsn,
    /// AS internal MTU.
    pub mtu: u32,
    /// Hop entry to create regular data plane paths.
    pub hop_entry: HopEntry,
    /// List of entries to create peering data plane paths.
    pub peer_entries: Vec<PeerEntry>,
    /// Raw signed extensions. We currently do not support parsing these.
    pub extensions: Vec<u8>,
    /// Raw unsigned extensions. We currently do not support parsing these.
    pub unsigned_extensions: Vec<u8>,
    /// Signed message containing the AS entry. It is used for signature input.
    pub signed: SignedMessage,
}

impl ASEntry {
    /// Returns the AS entry's associated data for signing/verification.
    ///
    /// The associated data includes the raw protobuf encoded info of the path segment and all
    /// previous AS entries in the path segment.
    ///
    /// Returns the total length of the associated data and an iterator over the associated data
    /// slices.
    pub fn associated_data<'seg>(
        &self,
        path_segment: &'seg PathSegment,
    ) -> (usize, impl Iterator<Item = &'seg [u8]>) {
        let entry_iter = path_segment
            .as_entries
            .iter()
            // Take all entries before the current one in the path segment.
            .take_while(|e| **e != *self)
            .flat_map(|entry| {
                [
                    entry.signed.header_and_body.as_slice(),
                    entry.signed.signature.as_slice(),
                ]
            });

        let final_iter = std::iter::once(path_segment.info.raw.as_slice()).chain(entry_iter);

        // Calculate the total length of the associated data by summing the lengths of all slices.
        let len = final_iter.clone().map(|slice| slice.len()).sum();

        (len, final_iter)
    }

    /// Creates a signature for the AS entry using the provided signing key, key ID, timestamp, and
    /// path segment.
    ///
    /// All entries before the AS entry must be signed before calling this method, as the signature
    /// covers all previous entries in the path segment.
    ///
    /// The signature can not be reused indiscriminately across different path segments, as the
    /// associated data includes the SignedMessage of all previous AS entries in the path segment.
    /// Reusing a signature across different path segments would require that all previous AS
    /// entries in those segments are identical, which is unlikely in practice.
    pub fn signature(
        &self,
        key: &p256::ecdsa::SigningKey,
        key_id: Option<VerificationKeyId>,
        timestamp: SystemTime,
        path_segment: &PathSegment,
    ) -> Result<SignedMessage, signature::Error> {
        let body = scion_protobuf::control_plane::v1::AsEntrySignedBody {
            isd_as: self.local.to_u64(),
            next_isd_as: self.next.to_u64(),
            hop_entry: Some(scion_protobuf::control_plane::v1::HopEntry {
                hop_field: Some(scion_protobuf::control_plane::v1::HopField {
                    ingress: self.hop_entry.hop_field.cons_ingress as u64,
                    egress: self.hop_entry.hop_field.cons_egress as u64,
                    exp_time: self.hop_entry.hop_field.exp_time as u32,
                    mac: self.hop_entry.hop_field.mac.to_vec(),
                }),
                ingress_mtu: self.hop_entry.ingress_mtu as u32,
            }),
            peer_entries: self
                .peer_entries
                .iter()
                .map(|peer| {
                    scion_protobuf::control_plane::v1::PeerEntry {
                        peer_isd_as: peer.peer.to_u64(),
                        peer_interface: peer.peer_interface as u64,
                        peer_mtu: peer.peer_mtu as u32,
                        hop_field: Some(scion_protobuf::control_plane::v1::HopField {
                            ingress: peer.hop_field.cons_ingress as u64,
                            egress: peer.hop_field.cons_egress as u64,
                            exp_time: peer.hop_field.exp_time as u32,
                            mac: peer.hop_field.mac.to_vec(),
                        }),
                    }
                })
                .collect(),
            mtu: self.mtu,
            extensions: None, // Todo: support extensions
        };

        let associated_data = self.associated_data(path_segment);

        SignedMessage::sign(
            key,
            DigestAlgorithm::Sha256,
            timestamp,
            key_id,
            associated_data,
            &body,
            &(),
        )
    }

    /// Validates the AS entry's signature using the provided path segment.
    ///
    /// ## Parameters
    /// * `key_provider`: A function which takes the slice contained in `header.key_id` and returns
    ///   the corresponding `p256::ecdsa::VerifyingKey` if available.
    /// * `path_segment`: The `PathSegment` containing the AS entry. All entries before the AS entry
    ///   in the path segment must be included, as the signature covers all previous entries.
    pub fn validate_signature(
        &self,
        key_provider: impl Fn(&[u8]) -> Result<p256::ecdsa::VerifyingKey, ValidateError>,
        path_segment: &PathSegment,
    ) -> Result<(), ValidateError> {
        self.signed
            .validate(key_provider, self.associated_data(path_segment))
            .map(|_| ())
    }
}

impl std::fmt::Display for ASEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ASEntry[local: {}, next: {}, mtu: {}, hop: {}, peers: {}]",
            self.local,
            self.next,
            self.mtu,
            self.hop_entry,
            self.peer_entries.len()
        )
    }
}

/// Info contains the immutable parts of a path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Info {
    /// Creation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Segment identifier.
    pub segment_id: u16,
    /// Raw protobuf encoded info used for signature input.
    pub raw: Vec<u8>,
}

impl Info {
    /// Creates a new Info with the given timestamp and segment ID.
    pub fn new(timestamp: DateTime<Utc>, segment_id: u16) -> Self {
        use prost::Message;
        Self {
            timestamp,
            segment_id,
            raw: scion_protobuf::control_plane::v1::SegmentInformation {
                timestamp: timestamp.timestamp(),
                segment_id: segment_id as u32,
            }
            .encode_to_vec(),
        }
    }
}

impl std::fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Info[ts: {}, seg_id: {}, raw_len: {}]",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.segment_id,
            self.raw.len()
        )
    }
}

/// HopEntry defines an AS hop entry in the path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HopEntry {
    /// Ingress MTU of the hop.
    pub ingress_mtu: u16,
    /// The hop field.
    pub hop_field: SegmentHopField,
}

impl std::fmt::Display for HopEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HopEntry[ingress_mtu: {}, {}]",
            self.ingress_mtu, self.hop_field
        )
    }
}

/// PeerEntry defines a peering entry at a specific AS hop in a path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEntry {
    /// The peer's ISD-AS identifier.
    pub peer: IsdAsn,
    /// The peer's ingress interface identifier.
    pub peer_interface: u16,
    /// The peer's MTU.
    pub peer_mtu: u16,
    /// The hop field.
    pub hop_field: SegmentHopField,
}

impl std::fmt::Display for PeerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerEntry[peer: {}, peer_if: {}, peer_mtu: {}, {}]",
            self.peer, self.peer_interface, self.peer_mtu, self.hop_field
        )
    }
}

/// HopField contains the information required for routing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentHopField {
    /// Expiration time of the hop field.
    pub exp_time: u8,
    /// Ingress interface ID.
    pub cons_ingress: u16,
    /// Egress interface ID.
    pub cons_egress: u16,
    /// MAC of the hop field.
    pub mac: [u8; 6],
}

impl std::fmt::Display for SegmentHopField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HopField[ingress: {}, egress: {}, exp_time: {}, mac: {:02x?}]",
            self.cons_ingress, self.cons_egress, self.exp_time, self.mac
        )
    }
}

/// ExpTimeToDuration calculates the relative expiration time in seconds.
/// Note that for a 0 value ExpTime, the minimal duration is expTimeUnit.
/// ExpTimeToDuration is pure: it does not modify any memory locations and
/// does not produce any side effects.
/// Calls to ExpTimeToDuration are guaranteed to always terminate.
pub fn exp_time_to_duration(exp_time: u8) -> Duration {
    EXP_TIME_UNIT.saturating_mul(exp_time as u32 + 1)
}

/// Expiration time errors.
pub enum ExpTimeError {
    /// Duration is too small.
    DurationTooSmall,
    /// Duration is too large.
    DurationTooLarge,
}

/// ExpTimeFromDuration calculates the largest relative expiration time that
/// represents a duration <= the provided duration, that is:
/// d <= ExpTimeToDuration(ExpTimeFromDuration(d)).
/// The returned value is the ExpTime that can be used in a HopField.
/// For durations that are out of range, an error is returned.
pub fn exp_time_from_duration(d: Duration) -> Result<u8, ExpTimeError> {
    if d < EXP_TIME_UNIT {
        return Err(ExpTimeError::DurationTooSmall);
    }
    if d > MAX_TTL {
        return Err(ExpTimeError::DurationTooLarge);
    }
    Ok(((d.as_nanos() * 256) / MAX_TTL.as_nanos() - 1) as u8)
}

#[cfg(test)]
mod tests {

    use std::time::SystemTime;

    use base64::prelude::BASE64_STANDARD;
    use chrono::DateTime;
    use ecdsa::signature::rand_core::OsRng;
    use p256::pkcs8::DecodePublicKey;
    use prost::Message;

    use crate::{
        address::{Asn, Isd, IsdAsn},
        path::{ASEntry, HopEntry, PathSegment, SegmentHopField, signed_message::SignedMessage},
    };

    const PUB_KEY_1_BASE64_DER: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQUUW2ZQaiYHsKgz1ow404XaMK2QSeB622LqyoMbU6NbJaUe9uJCkup5aqLJBMpgopXAWtFoK+hljpeTflwdvag==";
    const PUB_KEY_2_BASE64_DER: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4ef6rUbpCrI3uzMA14HnbSbZUXil5fI/OR+ztE4QHkh3OEcSrf4GmghWp0f/MLpbhkzwZS41nCYh3Iyo0VWLAw==";
    const PATH_SEGMENT_BASE64: &str = "CgkIntqgzQYQuQoSlAEKkQEKRQoeCAESCr3ltqGkjVLLRB0aDAie2qDNBhD+wuiKAigJEiMIkIKAgIDgfxCRgoCAgOB/Gg4KDBABGD8iBhERERERESjcCxJIMEYCIQCVJj3K7blapL979ZwlmJQcdFPjz6HaJm2+Of97+Sq2vAIhAP52eTIgXBHjcCoCtdllIzXIE4yLzwxL3XikgQC5gzw8EpkBCpYBCksKHwgBEgpBl2HLMkBdrr1vGgwIntqgzQYQzdvwigIolgESKAiRgoCAgOB/EJKCgICA4H8aEwoOCAoQCxg/IgYiIiIiIiIQuQoo3AsSRzBFAiBC871fskieS/DmKRoPI703gDFb31Ledu15zviB0RrzVAIhANMQXTnfQCQhoyUfMvjKb0soDtDSgwndSxeLId3JxZSZ";

    /// Validates signatures of a real path segment protobuf message using the provided public
    /// keys.
    #[test]
    fn validate_real_path_segment() {
        use base64::Engine;

        let path_segment = BASE64_STANDARD
            .decode(PATH_SEGMENT_BASE64)
            .expect("failed to decode path segment");
        let path_segment =
            scion_protobuf::control_plane::v1::PathSegment::decode(&path_segment[..])
                .expect("failed to decode path segment protobuf");
        let path_segment: PathSegment = path_segment
            .try_into()
            .expect("failed to convert path segment");

        let key_1 = BASE64_STANDARD
            .decode(PUB_KEY_1_BASE64_DER)
            .expect("failed to decode public key 1");
        let key_1 = p256::ecdsa::VerifyingKey::from_public_key_der(&key_1)
            .expect("failed to parse public key 1");

        let entry_1 = path_segment.as_entries.first().expect("missing entry 1");

        entry_1
            .validate_signature(|_: &[u8]| Ok(key_1), &path_segment)
            .expect("failed to validate entry 1 signature");

        let key_2 = BASE64_STANDARD
            .decode(PUB_KEY_2_BASE64_DER)
            .expect("failed to decode public key 2");
        let key_2 = p256::ecdsa::VerifyingKey::from_public_key_der(&key_2)
            .expect("failed to parse public key 2");

        let entry_2 = path_segment.as_entries.get(1).expect("missing entry 2");

        entry_2
            .validate_signature(|_: &[u8]| Ok(key_2), &path_segment)
            .expect("failed to validate entry 2 signature");
    }

    #[test]
    fn roundtrip_validation() {
        let path_segment = PathSegment::new(DateTime::from_timestamp_nanos(0), 0, vec![]);
        let sign_key_1 = p256::ecdsa::SigningKey::random(&mut OsRng);
        let sign_key_2 = p256::ecdsa::SigningKey::random(&mut OsRng);

        let mut entry1 = ASEntry {
            local: IsdAsn::new(Isd(1), Asn(1)),
            next: IsdAsn::new(Isd(1), Asn(2)),
            mtu: 1500,
            hop_entry: HopEntry {
                ingress_mtu: 1500,
                hop_field: SegmentHopField {
                    exp_time: 10,
                    cons_ingress: 1,
                    cons_egress: 2,
                    mac: [0; 6],
                },
            },
            peer_entries: vec![],
            extensions: vec![],
            unsigned_extensions: vec![],
            signed: SignedMessage {
                header_and_body: vec![],
                signature: vec![],
            },
        };

        let sign = entry1
            .signature(&sign_key_1, None, SystemTime::now(), &path_segment)
            .unwrap();
        entry1.signed = sign;

        let path_segment = path_segment.add_as_entry(entry1);

        let mut entry2 = ASEntry {
            local: IsdAsn::new(Isd(1), Asn(2)),
            next: IsdAsn::new(Isd(1), Asn(3)),
            mtu: 1500,
            hop_entry: HopEntry {
                ingress_mtu: 1500,
                hop_field: SegmentHopField {
                    exp_time: 10,
                    cons_ingress: 2,
                    cons_egress: 3,
                    mac: [0; 6],
                },
            },
            peer_entries: vec![],
            extensions: vec![],
            unsigned_extensions: vec![],
            signed: SignedMessage {
                header_and_body: vec![],
                signature: vec![],
            },
        };

        let sign = entry2
            .signature(&sign_key_2, None, SystemTime::now(), &path_segment)
            .unwrap();
        entry2.signed = sign;

        let path_segment = path_segment.add_as_entry(entry2);

        // Validate signatures
        for entry in &path_segment.as_entries {
            let key_provider = |_: &[u8]| {
                if entry.local == IsdAsn::new(Isd(1), Asn(1)) {
                    Ok(*sign_key_1.verifying_key())
                } else if entry.local == IsdAsn::new(Isd(1), Asn(2)) {
                    Ok(*sign_key_2.verifying_key())
                } else {
                    panic!("unknown ISD-AS")
                }
            };
            entry
                .validate_signature(key_provider, &path_segment)
                .unwrap();
        }
    }
}
