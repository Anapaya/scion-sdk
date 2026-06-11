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

//! Standard SCION path
//!
//! A SCION standard path is the primary path type used to forward packets through a
//! SCION network. It encodes the complete forwarding path in the packet header.
//!
//! Each forwarding hop is protected by a message authentication code (MAC)
//! that enables cryptographic validation of the path.
//!
//! For the wire format and forwarding semantics, see:
//! - <https://docs.scion.org/en/latest/protocols/scion-header.html>
//! - <https://scionassociation.github.io/scion-dp_I-D/draft-dekater-scion-dataplane.html>
//!
//!
//!
//!
//! ## Structure
//!
//! A standard path consists of a path meta header followed by one to three path
//! segments.
//!
//! - **Path meta header** ([StandardPath]): tracks the currently active info field and hop field
//!   during forwarding, and records the hop count of each segment.
//! - **Segments** ([Segment]): one to three ordered path segments, each consisting of a single info
//!   field and a sequence of hop fields.
//!   - **Info field** ([InfoField]): per-segment metadata, including the segment creation
//!     timestamp, a segment identifier used for MAC chaining, and, among others, a flag indicating
//!     whether the segment is traversed in its construction direction.
//!   - **Hop field** ([HopField]): per-hop forwarding information, including ingress and egress
//!     interface identifiers, an expiration time, and a MAC protecting the forwarding information.
//!
//! ## Segments
//!
//! A segment is a contiguous sequence of hop fields that share a common info
//! field. Every segment contains at least two hop fields.
//!
//! The first hop field in a segment has an ingress interface identifier of `0`,
//! marking the start of the segment. The last hop field has an egress interface
//! identifier of `0`, marking the end of the segment.
//!
//! Segments are produced by the SCION beaconing process and can be retrieved via
//! the SCION Endhost API, Control Service, or SCION Daemon.
//!
//! End-to-end paths are constructed by combining one or more of these segments. Using e.g.
//! [combine_with_weight_fn](crate::path::combinator::combine_with_weight_fn).
//!
//! ## Hop Fields
//!
//! Each router on the path processes one hop field of a segment. The router verifies
//! that the packet arrived on the expected ingress interface and forwards it via
//! the egress interface encoded in the hop field.
//!
//! In case the router is processing the last hop of a segment, it does a segment-change, where two
//! hop fields are processed: the last hop field of the current segment and the first hop field of
//! the next segment.
//!
//! Hop fields carry an expiration time expressed relative to the segment creation
//! timestamp. They also contain a MAC that protects the forwarding information
//! from modification. The MAC is computed over the hop field contents and the
//! current segment identifier using a router-specific secret key.
//!
//! The segment identifier is updated after each hop using the processed hop field
//! MAC, forming a MAC chain across the segment. This chain allows routers to
//! efficiently validate that the forwarding state has not been tampered with.
//!
//! Hop fields store the ingress and egress interfaces recorded during path
//! construction. Depending on the construction-direction flag in the segment's
//! info field, these interfaces may be interpreted in forward or reverse order
//! during packet forwarding. (e.g. const_ingress is the egress if CONS_DIR is not set)
//!
//!
//! [StandardPath]: model::StandardPath
//! [Segment]: model::Segment
//! [InfoField]: model::InfoField
//! [HopField]: model::HopField

pub mod layout;
pub mod mac;
pub mod model;
pub mod routing;
pub mod types;
pub mod view;
