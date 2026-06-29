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

//! # SciParse: Zero-Copy SCION Packets
//!
//! This library provides functionality to parse and construct SCION packets.
//!
//! Parsing is performed via zero-copy views over byte buffers, providing direct
//! field access without allocation or data transformation, and with only the
//! validation required to uphold safety.
//!
//! The library is designed to be efficient and flexible, allowing users to work
//! with SCION packets in a straightforward manner.
//!
//! SciParse exposes both view-based and model-based representations of SCION packets.
//!
//! ## Overview
//!
//! * [SCION Packet Types](proto::packet) - SCION packet parsing and construction
//! * [SCION Path Types](proto::dataplane_path) - SCION path parsing and construction
//! * [SCION Header Types](proto::header) - SCION header parsing and construction
//!
//! ## Views
//!
//! Detailed docs: [view](core::view)
//!
//! Views are zero-copy projections over byte buffers.
//!
//! A view provides read access and limited write access to SCION packet fields
//! directly on the underlying buffer, with minimal overhead.
//!
//! Views do not support modification of dynamically sized fields
//! (e.g., addresses, path segments).
//!
//! Most relevant structs include:
//!
//! * [ScionRawPacketView](proto::packet::view::ScionRawPacketView)
//! * [ScionUdpPacketView](proto::packet::view::ScionUdpPacketView)
//! * [ScionHeaderView](proto::header::view::ScionHeaderView)
//! * [ScionDpPathView](proto::dataplane_path::view::ScionDpPathView)
//! * [StandardPathView](proto::dataplane_path::standard::view::StandardPathView)
//! * [OneHopPathView](proto::dataplane_path::onehop::view::OneHopPathView)
//!
//!
//! Most views can be parsed from byte buffers using the [View](crate::core::view::View) trait,
//! which performs the necessary validation to ensure that the view is safe to use.
//!
//! ```no_run
//! # use sciparse::packet::view::ScionRawPacketView;
//! # use sciparse::core::view::View;
//! let buf: Vec<u8> = vec![/* ... */]; // Buffer containing a SCION packet
//! let packet_view = ScionRawPacketView::from_slice(&buf[..]).expect("Failed to parse SCION packet");
//!
//! println!("Parsed view: {:?}", packet_view);
//! ```
//!
//! The View trait also supplies functions for mutable slices, and boxed buffers, as well as unsafe
//! functions for unchecked parsing when the caller can guarantee the validity of the buffer.
//!
//! There are some exceptions where views require information found in other parts of the packet,
//! which can not implement the View trait directly.
//!
//! ## Models
//!
//! Models represent SCION packets as structured Rust types.
//!
//! They are intended for constructing new packets or performing complex
//! modifications that are impractical or unsafe using views alone.
//!
//! Most relevant structs include:
//! * [ScionRawPacket](proto::packet::model::ScionRawPacket)
//! * [ScionUdpPacket](proto::packet::model::ScionUdpPacket)
//! * [ScionHeader](proto::header::model::ScionPacketHeader)
//! * [DpPath](proto::dataplane_path::model::DpPath)
//! * [StandardPath](proto::dataplane_path::standard::model::StandardPath)
//! * [OneHopPath](proto::dataplane_path::onehop::model::OneHopPath)
//!
//! Models allow creating new packets from scratch.
//!
//! Most models can also be created from views or from byte buffers directly, which load the
//! relevant fields of a SCION packet into Rust types.
//!
//! ```no_run
//! # use sciparse::packet::model::ScionRawPacket;
//! # use sciparse::core::convert::TryFromView;
//! # let buf: Vec<u8> = vec![/* ... */]; // Buffer containing a SCION packet
//! let model = ScionRawPacket::try_from_slice(&buf[..]).expect("Failed to parse SCION packet");
//!
//! println!("Parsed model: {:?}", model);
//! ```
//!
//!
//! ## Control Plane Primitives
//!
//! In addition to dataplane packet parsing and construction, SciParse also provides primitives for
//! working with SCION control plane messages, such as path segments and beacons.

/// Core traits and utilities for working with bit-level data
pub mod core;

mod proto;
pub use proto::*;

mod scion;
pub use scion::*;

pub mod util;

/// Re-exports of dependencies for users of this library
pub mod reexport {
    pub use p256;
    #[cfg(feature = "proptest")]
    pub use proptest;
    pub use prost;
    pub use prost_types;
    pub use scion_protobuf as protobuf;
    pub use tinyvec;
}
