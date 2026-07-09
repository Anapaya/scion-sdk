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

//! Example of a simple request-response interaction.

use sciparse::{
    address::socket_addr::ScionSocketAddr,
    core::{encode::WireEncode, view::View},
    dataplane_path::{model::DpPath, view::ScionDpPathViewExt},
    packet::{classify::ClassifiedPacketView, model::ScionUdpPacket, view::ScionRawPacketView},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buf = ScionUdpPacket::new(
        "[1-1,2.2.2.2]:1234".parse::<ScionSocketAddr>()?,
        "[1-1,3.3.3.3]:5678".parse::<ScionSocketAddr>()?,
        DpPath::Empty, // Paths are usually aquired from the EndhostAPI or the SCION DAEMON
        b"payload".to_vec(),
    )
    .try_encode_to_vec()?;

    let response = echo_request(buf)?;

    println!("Received response: {:?}", response);

    Ok(())
}

fn echo_request(pkt: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (packet, _rest): (&ScionRawPacketView, &[u8]) = ScionRawPacketView::try_from_slice(&pkt)?;

    match packet.try_classify()? {
        // Echo the UDP packet back to the sender
        ClassifiedPacketView::Udp(scion_packet_view) => {
            // Reverse the path
            let path = scion_packet_view.header().path().to_model();
            let path = path.try_into_reversed().map_err(|(_, err)| err)?;

            // Create a new packet with the reversed path and swapped source/destination addresses
            let response = ScionUdpPacket::new(
                scion_packet_view.dst_socket_addr()?,
                scion_packet_view.src_socket_addr()?,
                path,
                scion_packet_view.payload().to_vec(),
            )
            .try_encode_to_vec()?;

            Ok(response)
        }
        _ => {
            // Example doesn't handle other packet types, return an error
            Err("Unsupported packet type".into())
        }
    }
}
