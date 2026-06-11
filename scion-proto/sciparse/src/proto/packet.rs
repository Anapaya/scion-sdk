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

//! SCION packet parsing and construction
//!
//! SciParse ships with functionality to parse and construct SCION packets of different types.
//!
//! ## Views
//! Views are zero-copy projections over byte buffers, providing direct access to SCION packet
//! fields without copying the underlying data.
//!
//! [ScionPacketView] is a generic view for SCION packets, providing access
//! to the common SCION header fields and payload.
//!
//! Specialized views for specific packet types are also provided, which build on top of the generic
//! view and provide additional functionality and type safety for working with specific SCION packet
//! variants.
//!
//! * [ScionRawPacketView] for SCION packets with arbitrary payloads,
//! * [ScionUdpPacketView] for SCION packets with UDP payloads.
//!
//! Views can be created from byte buffers using the [View](crate::core::view::View) trait, which
//! performs the necessary validation to ensure that the view is safe to use.
//!
//! Views provide read access and limited write access to SCION packet fields.
//!
//!
//! ## Models
//!
//! For constructing new packets or performing complex modifications, SciParse also provides
//! structured models. These load the relevant fields of a SCION packet into Rust types, allowing
//! for more convenient manipulation and construction of packets.
//!
//! [ScionPacket] is a generic model for SCION packets, providing access to the
//! common SCION header fields and payload.
//!
//! Specialized models are also provided for specific package types.
//! These are based on the generic model and offer additional functionality as well as type safety
//! for working with specific SCION package variants.
//!
//! * [ScionRawPacket]for SCION packets with arbitrary payloads,
//! * [ScionUdpPacket] for SCION packets with UDP payloads.
//!
//! All these packets can be parsed from and serialized to byte buffers.
//!
//! [ScionPacketView]: crate::proto::packet::view::ScionPacketView
//! [ScionRawPacketView]: crate::proto::packet::view::ScionRawPacketView
//! [ScionUdpPacketView]: crate::proto::packet::view::ScionUdpPacketView
//! [ScionPacket]: crate::proto::packet::model::ScionPacket
//! [ScionRawPacket]: crate::proto::packet::model::ScionRawPacket
//! [ScionUdpPacket]: crate::proto::packet::model::ScionUdpPacket

pub mod classify;
pub mod model;
pub mod view;
