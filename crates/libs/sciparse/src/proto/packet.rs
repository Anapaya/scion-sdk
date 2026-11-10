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
//! * [ScionUdpPacketView] for SCION packets with UDP payloads,
//! * [ScionScmpPacketView] for SCION packets with SCMP payloads.
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
//! * [ScionRawPacket] for SCION packets with arbitrary payloads,
//! * [ScionUdpPacket] for SCION packets with UDP payloads,
//! * [ScionScmpPacket] for SCION packets with SCMP payloads.
//!
//! All these packets can be parsed from and serialized to byte buffers.
//!
//! Each specialized model has a `new` constructor that takes the addresses, a [DpPath], and the
//! payload. [TryFromView] parses a model from a view or from a byte buffer.
//!
//! ```
//! # use sciparse::address::socket_addr::ScionSocketAddr;
//! # use sciparse::core::{convert::TryFromView, encode::WireEncode};
//! # use sciparse::dataplane_path::model::DpPath;
//! # use sciparse::packet::model::ScionUdpPacket;
//! let src: ScionSocketAddr = "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap();
//! let dst: ScionSocketAddr = "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap();
//!
//! let packet = ScionUdpPacket::new(src, dst, DpPath::Empty, b"payload".to_vec());
//! let bytes = packet.try_encode_to_vec().unwrap();
//!
//! let (parsed, _rest) = ScionUdpPacket::try_from_slice(&bytes).unwrap();
//! assert_eq!(parsed, packet);
//! ```
//!
//! ## Borrowed models
//!
//! A borrowed model borrows its path and its payload, and writes the same bytes as the matching
//! model. It only encodes.
//!
//! Use a borrowed model to send a payload over a path that you already hold. The encoder copies
//! both straight into the buffer of the caller, without a [DpPath] model and without a copy of the
//! payload.
//!
//! [ScionPacketRef] is the generic borrowed model. Its constructors set `next_header` to match the
//! payload:
//!
//! * [ScionRawPacketRef] for SCION packets with arbitrary payloads,
//! * [ScionUdpPacketRef] for SCION packets with UDP payloads,
//! * [ScionScmpPacketRef] for SCION packets with SCMP payloads.
//!
//! Each borrowed model has a `new` constructor that takes the addresses, a path view, and the
//! payload. The path view comes for example from [ScionPath::dp_path] or from a received packet.
//!
//! ```
//! # use sciparse::address::socket_addr::ScionSocketAddr;
//! # use sciparse::core::{encode::WireEncode, model::Model, view::View};
//! # use sciparse::dataplane_path::{model::DpPath, view::ScionDpPathViewExt};
//! # use sciparse::packet::{model::{ScionUdpPacket, ScionUdpPacketRef}, view::ScionRawPacketView};
//! # let src: ScionSocketAddr = "[1-ff00:0:110,10.0.0.1]:12345".parse().unwrap();
//! # let dst: ScionSocketAddr = "[1-ff00:0:111,10.0.0.2]:54321".parse().unwrap();
//! # let received = ScionUdpPacket::new(dst, src, DpPath::Empty, b"request".to_vec())
//! #     .try_encode_to_vec()
//! #     .unwrap();
//! // Take the path of a received packet
//! let (request, _rest) = ScionRawPacketView::try_from_slice(&received).unwrap();
//! let path = request.header().path();
//!
//! let reply = ScionUdpPacketRef::new(src, dst, path.as_ref(), b"reply");
//! let mut buf = vec![0u8; reply.required_size()];
//! let (view, _rest) = reply.try_encode_to_view(&mut buf).unwrap();
//! assert_eq!(view.udp().payload(), b"reply");
//! ```
//!
//! [ScionPacketView]: crate::proto::packet::view::ScionPacketView
//! [ScionRawPacketView]: crate::proto::packet::view::ScionRawPacketView
//! [ScionUdpPacketView]: crate::proto::packet::view::ScionUdpPacketView
//! [ScionScmpPacketView]: crate::proto::packet::view::ScionScmpPacketView
//! [ScionPacket]: crate::proto::packet::model::ScionPacket
//! [ScionRawPacket]: crate::proto::packet::model::ScionRawPacket
//! [ScionUdpPacket]: crate::proto::packet::model::ScionUdpPacket
//! [ScionScmpPacket]: crate::proto::packet::model::ScionScmpPacket
//! [ScionPacketRef]: crate::proto::packet::model::ScionPacketRef
//! [ScionRawPacketRef]: crate::proto::packet::model::ScionRawPacketRef
//! [ScionUdpPacketRef]: crate::proto::packet::model::ScionUdpPacketRef
//! [ScionScmpPacketRef]: crate::proto::packet::model::ScionScmpPacketRef
//! [DpPath]: crate::proto::dataplane_path::model::DpPath
//! [TryFromView]: crate::core::convert::TryFromView
//! [ScionPath::dp_path]: crate::path::ScionPath::dp_path

pub mod classify;
pub mod model;
pub mod view;
