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

//! Example of classifying a SCION packet based on its next header.

use sciparse::{
    address::socket_addr::ScionSocketAddr,
    core::{encode::WireEncode, view::View},
    dataplane_path::model::DpPath,
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

    let (packet, _rest): (&ScionRawPacketView, &[u8]) = ScionRawPacketView::try_from_slice(&buf)?;

    // Manually check the next header and handle it accordingly.
    match packet.header().next_header() {
        sciparse::payload::ProtocolNumber::Udp => {
            let udp_packet = packet.try_as_udp()?;
            println!("Received a UDP packet: {:?}", udp_packet);
        }
        sciparse::payload::ProtocolNumber::Scmp => {
            let scmp_packet = packet.try_as_scmp()?;
            println!("Received a SCMP packet: {:?}", scmp_packet);
        }
        sciparse::payload::ProtocolNumber::Tcp => {
            println!("Received a TCP packet: {:?}", packet);
        }
        sciparse::payload::ProtocolNumber::Hbh => {
            println!("Received a HBH packet extension: {:?}", packet);
        }
        sciparse::payload::ProtocolNumber::E2e => {
            println!("Received an E2E packet extension: {:?}", packet);
        }
        sciparse::payload::ProtocolNumber::Bfd => {
            println!("Received a BFD packet extension: {:?}", packet);
        }
        sciparse::payload::ProtocolNumber::Other(_) => {
            println!("Received a packet with unknown next header: {:?}", packet);
        }
    }

    // Use the utility function to classify the packet and handle it accordingly.
    match packet.try_classify()? {
        ClassifiedPacketView::Udp(udp) => {
            println!("Received a UDP packet: {:?}", udp);
        }
        ClassifiedPacketView::Scmp(scmp) => {
            println!("Received a SCMP packet: {:?}", scmp);
        }
        ClassifiedPacketView::Other(scion_packet_view) => {
            println!(
                "Received packet with unexpected next header: {:?}",
                scion_packet_view
            );
        }
    }

    Ok(())
}
