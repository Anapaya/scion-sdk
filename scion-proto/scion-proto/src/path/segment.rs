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

use std::{fmt, hash::Hasher, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::address::IsdAsn;

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

/// New path segment errors.
#[derive(Debug, Error)]
pub enum NewSegmentError {
    /// Empty AS entries.
    #[error("segment must be created with at least one AS entry")]
    EmptyASEntries,
}

impl PathSegment {
    /// Creates a new path segment with the given timestamp and segment ID.
    pub fn new(
        timestamp: DateTime<Utc>,
        segment_id: u16,
        as_entries: Vec<ASEntry>,
    ) -> Result<Self, NewSegmentError> {
        if as_entries.is_empty() {
            return Err(NewSegmentError::EmptyASEntries);
        }
        Ok(Self {
            info: Info::new(timestamp, segment_id),
            as_entries,
        })
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

    /// Adds an AS entry to the path segment and signs it.
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
    /// Raw protobuf encoded info data.
    pub raw: Vec<u8>,
}

impl Info {
    /// Creates a new Info with the given timestamp and segment ID.
    pub fn new(timestamp: DateTime<Utc>, segment_id: u16) -> Self {
        Self {
            timestamp,
            segment_id,
            // TODO: replace this with the protobuf encoded info data.
            raw: Vec::new(),
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

/// Signed message containing header, body, and signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedMessage {
    /// The header and body of the message.
    pub header_and_body: Vec<u8>,
    /// The signature of the message.
    pub signature: Vec<u8>,
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
