// Copyright 2025 Mysten Labs
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

//! SCION control plane segment types.
//!
//! The contained types represent SCION control plane path segments. These types are communicated
//! when using the SCION control plane APIs.
//!
//! Main type is: [SignedPathSegment]
use std::{
    fmt,
    hash::Hasher,
    ops::Deref,
    time::{Duration, SystemTime},
};

use ecdsa::signature;
use scion_protobuf::control_plane::v1::VerificationKeyId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    identifier::isd_asn::IsdAsn,
    path::standard::{
        mac::{
            ForwardingKey, HopMacCalculate, HopMacInput, HopMacInputSource, algo::mac_chaining_beta,
        },
        types::{HopFieldMac, exp_time_to_duration},
    },
    signed_message::{DigestAlgorithm, SignedMessage, ValidateError},
};

pub mod rpc;

/// Trait for AS entries in a path segment, allowing for both signed and unsigned AS entries to be
/// treated uniformly.
pub trait Entry: Sized + Send + Sync + 'static {
    /// Returns a reference to the underlying AS entry.
    fn get(&self) -> &AsEntry;
}

/// A SCION control plane path segment.
///
/// Prefer using the type aliases [UnsignedPathSegment] and [SignedPathSegment].\
/// For generic functions, use `PathSegment<impl Entry>` to allow both signed and unsigned path
/// segments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathSegment<E: Entry> {
    /// Segment information.
    info: SegmentInfo,
    /// AS entries of the segment.
    pub as_entries: Vec<E>,
}
impl<E: Entry + Sized> PathSegment<E> {
    /// Returns a reference to the segment info of the path segment.
    pub fn info(&self) -> &SegmentInfo {
        &self.info
    }

    /// Returns a hash of the segment covering all hops, except for peerings.
    pub fn id(&self) -> SegmentID {
        let mut hasher = Sha256::new();

        for ase in &self.as_entries {
            let ase = ase.get();
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
            let ase = ase.get();
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
    pub fn first_ia(&self) -> Option<IsdAsn> {
        self.as_entries.first().map(|e| e.get().local)
    }

    /// Returns the last IA in the path segment.
    pub fn last_ia(&self) -> Option<IsdAsn> {
        self.as_entries.last().map(|e| e.get().local)
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
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &AsEntry> + DoubleEndedIterator {
        self.as_entries.iter().map(Entry::get)
    }

    /// Returns the latest expiry time of the segment.
    pub fn expires_latest(&self) -> SystemTime {
        self.expiry(Duration::ZERO, |hf_ttl, ttl| hf_ttl > ttl)
    }

    /// Returns the earliest expiry time of the segment.
    pub fn expires_earliest(&self) -> SystemTime {
        self.expiry(Duration::MAX, |hf_ttl, ttl| hf_ttl < ttl)
    }

    fn expiry(
        &self,
        init_ttl: Duration,
        compare: impl Fn(Duration, Duration) -> bool,
    ) -> SystemTime {
        let mut ttl = init_ttl;
        for ase in &self.as_entries {
            let ase = ase.get();

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

        SystemTime::UNIX_EPOCH + Duration::from_secs(self.info.timestamp as u64) + ttl
    }

    /// Formats the hops of the path segment as a string.
    ///
    /// Example: `"1-ff00:0:110 13>21 1-ff00:0:111 2>3 1-ff00:0:112"`.
    ///
    /// Invalid Segments will be printed as best effort
    fn format_hops(&self, writer: &mut dyn std::fmt::Write) -> std::fmt::Result {
        match self.as_entries[..].as_ref() {
            [] => write!(writer, "<empty>")?,
            [single] => {
                // Invalid segment, but still format the single hop
                let ase = single.get();
                let ingress = ase.hop_entry.hop_field.cons_ingress;
                let local = ase.local;
                let egress = ase.hop_entry.hop_field.cons_egress;
                write!(writer, "{ingress} {local} {egress}")?;
            }
            [head, mid @ .., tail] => {
                let head = head.get();
                let mid = mid.iter().map(Entry::get);
                let tail = tail.get();

                // Write entry hop if it's not 0
                if head.hop_entry.hop_field.cons_ingress != 0 {
                    write!(writer, "{} ", head.hop_entry.hop_field.cons_ingress)?;
                }

                write!(
                    writer,
                    "{} {}",
                    head.local, head.hop_entry.hop_field.cons_egress,
                )?;

                for ase in mid {
                    let ingress = ase.hop_entry.hop_field.cons_ingress;
                    let local = ase.local;
                    let egress = ase.hop_entry.hop_field.cons_egress;
                    write!(writer, ">{ingress} {local} {egress}")?;
                }

                write!(
                    writer,
                    ">{} {}",
                    tail.hop_entry.hop_field.cons_ingress, tail.local
                )?;

                // Write tail egress if it's not 0
                if tail.hop_entry.hop_field.cons_egress != 0 {
                    write!(writer, " {}", tail.hop_entry.hop_field.cons_egress)?;
                }
            }
        }

        Ok(())
    }
}
impl<E: Entry> fmt::Display for PathSegment<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathSegment[id: {} ts: {:?} hops: ",
            self.id().logging_id(),
            self.info.timestamp, // TODO: format timestamp in human readable format
        )?;
        self.format_hops(f)?;
        write!(f, "]")
    }
}
impl<E: Entry> std::hash::Hash for PathSegment<E> {
    /// Hash of the path segment to be used as hash table key.
    fn hash<H: Hasher>(&self, state: &mut H) {
        for ase in &self.as_entries {
            let ase = ase.get();
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

/// A unsigned path segment, containing AS entries without signatures.
///
/// For generic functions, use `PathSegment<impl Entry>` to allow both signed and unsigned path
/// segments.
///
/// This can be used to build a path segment without requiring signing keys.
/// Unsigned path segments can not be converted into protobuf messages.
pub type UnsignedPathSegment = PathSegment<AsEntry>;
impl UnsignedPathSegment {
    /// Creates an new unsigned path segment with the given timestamp and segment ID.
    pub fn new(timestamp: u32, segment_id: u16, as_entries: Vec<AsEntry>) -> Self {
        Self {
            info: SegmentInfo::new(timestamp, segment_id),
            as_entries,
        }
    }

    /// Adds an AS entry to the path segment.
    ///
    /// This does not require a valid MAC, as the MAC will be recalculated for each entry using the
    /// provided MAC key.
    pub fn add_unsigned_entry(&mut self, mut entry: AsEntry, mac_key: &ForwardingKey) {
        entry.update_macs(mac_key, self);
        self.as_entries.push(entry);
    }

    /// Converts the unsigned path segment into a signed path segment by signing each AS entry.
    ///
    /// ### Parameters
    /// * `key_provider`: A function taking the local ISD-AS of an ASEntry and returning the signing
    ///   key and optional key ID to sign the entry.
    /// * `timestamp`: The timestamp to include in the signature header of each AS entry.
    pub fn into_signed_segment(
        self,
        key_provider: impl Fn(IsdAsn) -> Option<(p256::ecdsa::SigningKey, Option<VerificationKeyId>)>,
        timestamp: u32,
    ) -> Result<PathSegment<SignedAsEntry>, signature::Error> {
        let mut signed_segment = PathSegment::<SignedAsEntry> {
            info: self.info,
            as_entries: Vec::with_capacity(self.as_entries.len()),
        };

        for entry in self.as_entries {
            let (key, key_id) = key_provider(entry.local).ok_or_else(|| {
                signature::Error::from_source(format!(
                    "No signing key found for ISD-AS {}",
                    entry.local
                ))
            })?;

            signed_segment.add_entry_no_mac_update(entry, &key, key_id, timestamp)?;
        }

        Ok(signed_segment)
    }
}

/// A signed path segment, containing AS entries with signatures.
///
/// For generic functions, use `PathSegment<impl Entry>` to allow both signed and unsigned path
/// segments.
pub type SignedPathSegment = PathSegment<SignedAsEntry>;
impl SignedPathSegment {
    /// Creates and signs a new path segment with the given timestamp, segment ID, and AS entries.
    ///
    /// The given AS entries do not require a valid MAC, as the MAC will be recalculated for each
    /// entry using the provided MAC key.
    ///
    /// ### Parameters
    /// * `timestamp`: The timestamp to include in the segment info
    /// * `segment_id`: The segment ID to include in the segment info
    /// * `as_entries`: The AS entries to include in the path segment. These will be signed using
    ///   the provided key provider.
    /// * `key_provider`: A function taking the local ISD-AS of an ASEntry and returning the signing
    ///   key, optional key ID, and MAC key to sign the entry.
    pub fn new(
        timestamp: u32,
        segment_id: u16,
        as_entries: Vec<AsEntry>,
        key_provider: impl Fn(IsdAsn) -> Option<EntryKeyInfo>,
    ) -> Result<Self, signature::Error> {
        let mut signed_segment = PathSegment::<SignedAsEntry> {
            info: SegmentInfo::new(timestamp, segment_id),
            as_entries: Vec::with_capacity(as_entries.len()),
        };

        for entry in as_entries {
            let EntryKeyInfo {
                key,
                key_id,
                mac_key,
            } = key_provider(entry.local).ok_or_else(|| {
                signature::Error::from_source(format!(
                    "No signing key found for ISD-AS {}",
                    entry.local
                ))
            })?;

            signed_segment.add_entry(entry, &key, key_id, &mac_key, timestamp)?;
        }

        Ok(signed_segment)
    }

    /// Creates an empty signed path segment with the given timestamp and segment ID.
    pub fn empty(timestamp: u32, segment_id: u16) -> Self {
        Self {
            info: SegmentInfo::new(timestamp, segment_id),
            as_entries: Vec::new(),
        }
    }

    /// Creates an empty signed path segment with the given timestamp, segment ID, and capacity for
    /// AS entries.
    pub fn with_capacity(timestamp: u32, segment_id: u16, capacity: usize) -> Self {
        Self {
            info: SegmentInfo::new(timestamp, segment_id),
            as_entries: Vec::with_capacity(capacity),
        }
    }

    /// Adds a entry to the Path Segment.
    ///
    /// This will update the entries MAC, and create a signature for the entry using the provided
    /// signing key, key ID, and timestamp.
    pub fn add_entry(
        &mut self,
        mut entry: AsEntry,
        key: &p256::ecdsa::SigningKey,
        key_id: Option<VerificationKeyId>,
        mac_key: &ForwardingKey,
        timestamp: u32,
    ) -> Result<(), signature::Error> {
        // Update the entry's hop field MACs
        entry.update_macs(mac_key, self);
        self.add_entry_no_mac_update(entry, key, key_id, timestamp)
    }

    /// Adds a entry to the Path Segment without updating the entry's MAC.
    ///
    /// Private as misuse would create invalid segments
    fn add_entry_no_mac_update(
        &mut self,
        entry: AsEntry,
        key: &p256::ecdsa::SigningKey,
        key_id: Option<VerificationKeyId>,
        timestamp: u32,
    ) -> Result<(), signature::Error> {
        // Create a signature for the AS entry using the provided signing key, key ID, timestamp,
        // and path
        let signature = entry.signature(key, key_id, timestamp, self)?;

        self.as_entries.push(SignedAsEntry {
            entry,
            signed: signature,
        });

        Ok(())
    }

    /// Converts the signed path segment into an unsigned path segment.
    ///
    /// This strips the signatures from all AS entries, so the resulting unsigned path segment will
    /// not be verifiable.
    pub fn into_unsigned_segment(self) -> PathSegment<AsEntry> {
        PathSegment::<AsEntry> {
            info: self.info,
            as_entries: self
                .as_entries
                .into_iter()
                .map(|signed_entry| signed_entry.entry)
                .collect(),
        }
    }
}

/// Segment ID, which is a hash of a path segment.
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

/// Key material required to calculate the signature and MAC for an AS entry in a path segment.
pub struct EntryKeyInfo {
    /// The signing key to use for creating the signature of the AS entry.
    pub key: p256::ecdsa::SigningKey,
    /// An optional key ID to include in the signature header. This can be used by the verifier to
    /// select the correct key for verification.
    pub key_id: Option<VerificationKeyId>,
    /// The MAC key to use for calculating the MAC of the AS entry.
    pub mac_key: ForwardingKey,
}

/// A entry for a PathSegment, describing a single AS hop and multiple peering hops.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsEntry {
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
    /// Raw signed extensions. Unsupported.
    pub extensions: Vec<u8>,
    /// Raw unsigned extensions. Unsupported.
    pub unsigned_extensions: Vec<u8>,
}
impl AsEntry {
    /// Returns the AS entry's associated data for signing/verification.
    ///
    /// The associated data includes the raw protobuf encoded info of the path segment and all
    /// previous AS entries in the path segment.
    ///
    /// Returns the total length of the associated data and an iterator over the associated data
    /// slices.
    pub fn associated_data<'seg>(
        &self,
        path_segment: &'seg PathSegment<SignedAsEntry>,
    ) -> (usize, impl Iterator<Item = &'seg [u8]>) {
        let entry_iter = path_segment
            .as_entries
            .iter()
            // Take all entries before the current one in the path segment.
            .take_while(|e| e.entry != *self)
            .flat_map(|entry| {
                [
                    entry.signed.header_and_body.as_slice(),
                    entry.signed.signature.as_slice(),
                ]
            });

        let final_iter = std::iter::once(path_segment.info.encoded.as_slice()).chain(entry_iter);

        // Calculate the total length of the associated data by summing the lengths of all slices.
        let len = final_iter.clone().map(|slice: &[u8]| slice.len()).sum();

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
    ///
    /// ### Parameters
    /// * `key`: The signing key to use for creating the signature.
    /// * `key_id`: An optional key ID to include in the signature header. This can be used by the
    ///   verifier to select the correct key for verification.
    /// * `timestamp`: The timestamp to include in the signature header.
    /// * `path_segment`: The path segment containing the AS entry.
    /// * `encoded_segment_info`: Optional pre-encoded segment info to use for the associated data.
    pub fn signature(
        &self,
        key: &p256::ecdsa::SigningKey,
        key_id: Option<VerificationKeyId>,
        timestamp: u32,
        path_segment: &PathSegment<SignedAsEntry>,
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

        SignedMessage::sign(
            key,
            DigestAlgorithm::Sha256,
            timestamp,
            key_id,
            self.associated_data(path_segment),
            &body,
            &(),
        )
    }

    /// Updates the MACs of the AS entry and its peer entries using the provided MAC key and path
    /// segment.
    ///
    /// Usually you do not need to call this method directly, as the MACs are automatically updated
    /// when adding an entry to a path segment.
    ///
    /// The MACs are updated based on the current path segment, so all previous entries in the path
    /// segment must be included in the path segment.
    ///
    /// The MAC beta value is calculated based on the segment ID and the hop field MACs of all
    /// previous entries in the path segment.
    pub fn update_macs(&mut self, mac_key: &ForwardingKey, path_segment: &PathSegment<impl Entry>) {
        let mac_beta = mac_chaining_beta(
            path_segment.info.segment_id,
            path_segment
                .as_entries
                .iter()
                .take_while(|e| e.get().hop_entry != self.hop_entry)
                .map(|e| *e.get().hop_entry.hop_field.mac.as_bytes()),
        );

        self.hop_entry.hop_field.mac =
            self.hop_entry
                .hop_field
                .calculate_mac(mac_beta, path_segment.info.timestamp, mac_key);

        for peer in &mut self.peer_entries {
            peer.hop_field.mac =
                peer.hop_field
                    .calculate_mac(mac_beta, path_segment.info.timestamp, mac_key);
        }
    }
}
impl std::fmt::Display for AsEntry {
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
impl Entry for AsEntry {
    fn get(&self) -> &AsEntry {
        self
    }
}

/// A signed entry for a PathSegment, describing a single AS hop and multiple peering hops.
///
/// The signed entry is immutable, as any modification would invalidate the signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAsEntry {
    entry: AsEntry,
    signed: SignedMessage,
}
impl SignedAsEntry {
    /// Returns the AS entry
    pub fn entry(&self) -> &AsEntry {
        &self.entry
    }

    /// Returns the signature of the AS entry.
    pub fn signature(&self) -> &SignedMessage {
        &self.signed
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
        path_segment: &PathSegment<SignedAsEntry>,
    ) -> Result<(), ValidateError> {
        let assoc_data = self.entry.associated_data(path_segment);

        self.signed.validate(key_provider, assoc_data)?;

        Ok(())
    }
}
impl Entry for SignedAsEntry {
    fn get(&self) -> &AsEntry {
        self.entry.get()
    }
}
impl Deref for SignedAsEntry {
    type Target = AsEntry;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

/// Immutable information about a path segment, used for signing and verification of AS entries in
/// the path segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentInfo {
    /// Creation timestamp.
    timestamp: u32,
    /// Segment identifier.
    segment_id: u16,
    /// Raw protobuf encoded info. This is used for signing AS entries.
    encoded: Vec<u8>,
}
impl SegmentInfo {
    /// Creates a new Info with the given timestamp and segment ID.
    pub fn new(timestamp: u32, segment_id: u16) -> Self {
        use prost::Message;

        let proto_info = scion_protobuf::control_plane::v1::SegmentInformation {
            timestamp: timestamp as i64,
            segment_id: segment_id as u32,
        }
        .encode_to_vec();

        Self {
            timestamp,
            segment_id,
            encoded: proto_info,
        }
    }

    /// Returns the timestamp of the segment info.
    ///
    /// The timestamp is represented as seconds since the UNIX epoch.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the segment ID of the segment info.
    pub fn segment_id(&self) -> u16 {
        self.segment_id
    }

    /// Returns the protobuf encoded segment info.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}
impl std::fmt::Display for SegmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Info[ts: {:?}, seg_id: {}, raw_len: {}]",
            self.timestamp, // TODO: format timestamp in human readable format
            self.segment_id,
            self.encoded.len()
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
    /// The hop used for the peering link.
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
    pub mac: HopFieldMac,
}
impl SegmentHopField {
    /// Recalculates the MAC for this hop field and updates the `mac` field with the new value.
    ///
    /// See [`HopMacCalculate::calculate_mac`](crate::path::standard::mac::HopMacCalculate::calculate_mac) for details on how the MAC is calculated.
    pub fn with_calculated_mac(
        mut self,
        mac_chain_beta: u16,
        timestamp_epoch: u32,
        forwarding_key: &ForwardingKey,
    ) -> Self {
        self.mac = self.calculate_mac(mac_chain_beta, timestamp_epoch, forwarding_key);
        self
    }
}
impl HopMacInputSource for SegmentHopField {
    fn get_mac_input(&self) -> HopMacInput {
        HopMacInput {
            exp_time: self.exp_time,
            cons_ingress: self.cons_ingress,
            cons_egress: self.cons_egress,
        }
    }
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

/// Segments containing up, down, and core segments along with a next page token.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Segments {
    /// Up segments.
    pub up_segments: Vec<SignedPathSegment>,
    /// Down segments.
    pub down_segments: Vec<SignedPathSegment>,
    /// Core segments.
    pub core_segments: Vec<SignedPathSegment>,
}
impl Segments {
    /// Returns an iterator over vectors of path segments by type.
    pub fn iter_with_type(&self) -> impl Iterator<Item = (&'static str, &Vec<SignedPathSegment>)> {
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
    pub fn split_parts(self) -> (Vec<SignedPathSegment>, Vec<SignedPathSegment>) {
        (
            self.core_segments,
            [self.up_segments, self.down_segments].concat(),
        )
    }
}
impl std::fmt::Display for Segments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format_vec = |v: &Vec<SignedPathSegment>| {
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
#[cfg(test)]
mod tests {

    use base64::prelude::BASE64_STANDARD;
    use ecdsa::signature::rand_core::OsRng;
    use p256::pkcs8::DecodePublicKey;
    use prost::Message;

    use super::*;
    use crate::scion::identifier::{asn::Asn, isd::Isd};

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
        let path_segment =
            SignedPathSegment::try_from_rpc(path_segment).expect("failed to convert path segment");

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
        use aes::cipher::generic_array::GenericArray;

        let timestamp: u32 = 0;
        let segment_id: u16 = 0;
        let mut path_segment = SignedPathSegment::empty(timestamp, segment_id);
        let sign_key_1 = p256::ecdsa::SigningKey::random(&mut OsRng);
        let sign_key_2 = p256::ecdsa::SigningKey::random(&mut OsRng);
        let mac_key: ForwardingKey = GenericArray::default();

        let entry1 = AsEntry {
            local: IsdAsn::new(Isd(1), Asn(1)),
            next: IsdAsn::new(Isd(1), Asn(2)),
            mtu: 1500,
            hop_entry: HopEntry {
                ingress_mtu: 1500,
                hop_field: SegmentHopField {
                    exp_time: 10,
                    cons_ingress: 1,
                    cons_egress: 2,
                    mac: HopFieldMac([0; 6]),
                },
            },
            peer_entries: vec![],
            extensions: vec![],
            unsigned_extensions: vec![],
        };

        path_segment
            .add_entry(entry1, &sign_key_1, None, &mac_key, timestamp)
            .unwrap();

        let entry2 = AsEntry {
            local: IsdAsn::new(Isd(1), Asn(2)),
            next: IsdAsn::new(Isd(1), Asn(3)),
            mtu: 1500,
            hop_entry: HopEntry {
                ingress_mtu: 1500,
                hop_field: SegmentHopField {
                    exp_time: 10,
                    cons_ingress: 2,
                    cons_egress: 3,
                    mac: HopFieldMac([0; 6]),
                },
            },
            peer_entries: vec![],
            extensions: vec![],
            unsigned_extensions: vec![],
        };

        path_segment
            .add_entry(entry2, &sign_key_2, None, &mac_key, timestamp)
            .unwrap();

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

    #[test]
    fn should_print_segment() {
        let segment = PathSegment::<AsEntry> {
            info: SegmentInfo::new(0, 0),
            as_entries: vec![
                AsEntry {
                    local: IsdAsn::new(Isd(1), Asn(1)),
                    next: IsdAsn::new(Isd(1), Asn(2)),
                    mtu: 1500,
                    hop_entry: HopEntry {
                        ingress_mtu: 1500,
                        hop_field: SegmentHopField {
                            exp_time: 10,
                            cons_ingress: 0,
                            cons_egress: 2,
                            mac: HopFieldMac([0; 6]),
                        },
                    },
                    peer_entries: vec![],
                    extensions: vec![],
                    unsigned_extensions: vec![],
                },
                AsEntry {
                    local: IsdAsn::new(Isd(1), Asn(2)),
                    next: IsdAsn::new(Isd(1), Asn(3)),
                    mtu: 1500,
                    hop_entry: HopEntry {
                        ingress_mtu: 1500,
                        hop_field: SegmentHopField {
                            exp_time: 10,
                            cons_ingress: 2,
                            cons_egress: 3,
                            mac: HopFieldMac([0; 6]),
                        },
                    },
                    peer_entries: vec![],
                    extensions: vec![],
                    unsigned_extensions: vec![],
                },
                AsEntry {
                    local: IsdAsn::new(Isd(1), Asn(2)),
                    next: IsdAsn::new(Isd(1), Asn(3)),
                    mtu: 1500,
                    hop_entry: HopEntry {
                        ingress_mtu: 1500,
                        hop_field: SegmentHopField {
                            exp_time: 10,
                            cons_ingress: 2,
                            cons_egress: 3,
                            mac: HopFieldMac([0; 6]),
                        },
                    },
                    peer_entries: vec![],
                    extensions: vec![],
                    unsigned_extensions: vec![],
                },
            ],
        };

        let expected =
            "PathSegment[id: e6f0dd86a0413116d3c43919 ts: 0 hops: 1-1 2>2 1-2 3>2 1-2 3]";
        assert_eq!(segment.to_string(), expected);
    }
}
