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

//! Representation of SCION packet and constituent types.
//!
//! This module contains an implementation of the SCION packet representation, its wire
//! format, and errors encountered while decoding the packet.
//!
//! For paths useable in a SCION packet, see the [path module][`crate::path`].
use bytes::Bytes;

mod error;
pub use error::{DecodeError, EncodeError, InadequateBufferSize, ScmpEncodeError};

mod headers;
pub use headers::{
    AddressHeader, AddressInfo, ByEndpoint, CommonHeader, FlowId, RawHostAddress, ScionHeaders,
    Version,
};

mod raw;
pub use raw::ScionPacketRaw;

mod scmp;
pub use scmp::ScionPacketScmp;

mod udp;
pub use udp::ScionPacketUdp;

mod checksum;
pub use checksum::{ChecksumDigest, MessageChecksum};

pub mod dispatch;
pub use dispatch::{
    PacketClassification, PacketClassificationError, classify_scion_packet, scmp_port,
};

pub mod layout;

use crate::wire_encoding::{WireDecode, WireEncodeVec};

/// All SCION packet types must implement this trait.
pub trait ScionPacket<const N: usize>: WireEncodeVec<N> + WireDecode<Bytes> {}
