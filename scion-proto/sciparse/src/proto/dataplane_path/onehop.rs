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

//! SCION one-hop path
//!
//! A SCION one-hop path is a specialized path type used for communication between
//! directly connected Autonomous Systems (ASes). Unlike a standard path, it does
//! not encode a complete end-to-end route. Instead, it contains the forwarding
//! information required to traverse a single inter-AS link.
//!
//! One-hop paths are primarily used during beaconing and path discovery, where a
//! router must forward packets to a neighboring AS before a complete end-to-end
//! path has been constructed.
//!
//! For the wire format and forwarding semantics, see:
//! - <https://docs.scion.org/en/latest/protocols/scion-header.html>
//! - <https://scionassociation.github.io/scion-dp_I-D/draft-dekater-scion-dataplane.html>
//!
//! ## Structure
//!
//! A one-hop path consists of a single info field and two hop fields.
//!
//! - **Info field** ([InfoField]): segment metadata, including a creation timestamp, a segment
//!   identifier used for MAC chaining, and a flag indicating the construction direction.
//! - **First hop field** ([HopField]): forwarding information for the local border router.
//! - **Second hop field** ([HopField]): initially unset, but populated by the receiving border
//!   router with the forwarding information for the second hop.
//!
//! Together, these fields describe a single inter-AS hop between adjacent
//! border routers.
//!
//! ## Hop Fields
//!
//! One-hop paths contain exactly two hop fields. As with standard paths, hop
//! fields encode ingress and egress interface identifiers, an expiration time,
//! and a MAC protecting the forwarding information.
//!
//! The MAC is computed over the hop field contents and the current segment
//! identifier using a router-specific secret key. The segment identifier is
//! updated using the MAC of the processed hop field, forming a MAC chain that
//! allows routers to validate the integrity of the path.
//!
//! Hop fields store the ingress and egress interfaces recorded during path
//! construction. Depending on the construction-direction flag in the info
//! field, these interfaces may be interpreted in forward or reverse order
//! during forwarding.
//!
//! After the one-hop path is processed by the local border router, it can be converted into a
//! standard path, where the onehop path becomes a single segment.
//!
//! ## Forwarding
//!
//! A one-hop path always represents a single inter-AS transition. The first hop
//! field is processed by the local border router, which forwards the packet to
//! the neighboring AS. The second hop field is then processed by the receiving
//! border router.
//!
//! Unlike standard paths, one-hop paths do not contain multiple segments and do
//! not support arbitrary end-to-end forwarding. They are intended only for
//! communication between directly connected ASes.
//!
//! One-hop paths are generated on the fly for directly connected ASes.
//!
//!
//! [StandardPath]: super::standard::model::StandardPath
//! [Segment]: super::standard::model::Segment
//! [InfoField]: super::standard::model::InfoField
//! [HopField]: super::standard::model::HopField

pub mod layout;
pub mod model;
pub mod view;
