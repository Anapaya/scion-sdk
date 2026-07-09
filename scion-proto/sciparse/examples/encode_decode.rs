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

//! Example of encoding and decoding a SCION packet.

use sciparse::{
    address::socket_addr::ScionSocketAddr,
    core::{
        convert::{TryFromView, TryToModel},
        encode::WireEncode,
        view::View,
    },
    dataplane_path::model::DpPath,
    packet::{
        model::{ScionRawPacket, ScionUdpPacket},
        view::ScionRawPacketView,
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = ScionUdpPacket::new(
        "[1-1,2.2.2.2]:1234".parse::<ScionSocketAddr>()?,
        "[1-1,3.3.3.3]:5678".parse::<ScionSocketAddr>()?,
        DpPath::Empty, // Paths are usually aquired from the EndhostAPI or the SCION DAEMON
        b"payload".to_vec(),
    );

    let buf = encode_packet(&packet)?;
    decode_slice(&buf)?;

    Ok(())
}

/// How to get a scion packet from a slice of bytes, and convert it to a model.
fn decode_slice(buf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Access slice through a View
    let (packet, _rest): (&ScionRawPacketView, &[u8]) = ScionRawPacketView::try_from_slice(buf)?;
    println!("{:?}", packet);

    // Convert slice to a Model
    let model = packet.try_to_model();
    println!("{:?}", model);

    // Directly decode slice to a Model
    let (packet, _rest): (ScionRawPacket, &[u8]) = ScionRawPacket::try_from_slice(buf)?;
    println!("{:?}", packet);

    Ok(())
}

fn encode_packet(packet: &impl WireEncode) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let required_size = packet.required_size();
    let mut buf = vec![0u8; required_size];

    // Encode the packet into the buffer
    // May fail if the buffer is not large enough, or if the packet is malformed (e.g. too many
    // total hops)
    packet.try_encode(&mut buf[..])?;
    Ok(buf)
}
