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

//! Development artifact for debugging purposes.
//!
//! Will be removed later.

use std::net::Ipv4Addr;

use sciparse::{
    core::{encode::WireEncode, view::View},
    header::{
        layout::ScionHeaderLayout,
        model::{AddressHeader, CommonHeader, Path, ScionPacketHeader},
        view::ScionHeaderView,
    },
    path::standard::{
        model::{HopField, InfoField, Segment, StandardPath},
        types::{HopFieldFlags, InfoFieldFlags},
    },
    types::address::{IsdAsn, ScionHostAddr},
};

fn main() {
    let header = ScionPacketHeader {
        common: CommonHeader {
            traffic_class: 1,
            flow_id: 2,
            next_header: 3,
            payload_size: 4,
        },
        address: AddressHeader {
            dst_ia: IsdAsn::new_from_raw(2, 141),
            src_ia: IsdAsn::new_from_raw(1, 12),
            dst_host_addr: ScionHostAddr::Ipv4(Ipv4Addr::new(192, 168, 0, 1)),
            src_host_addr: ScionHostAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        },
        path: Path::Standard(StandardPath {
            current_info_field: 0,
            curr_hop_field: 0,
            segments: vec![Segment {
                info_field: InfoField {
                    flags: InfoFieldFlags::empty(),
                    segment_id: 42,
                    timestamp: 1234567890,
                },
                hop_fields: vec![
                    HopField {
                        flags: HopFieldFlags::empty(),
                        expiration_units: 1,
                        cons_ingress: 2,
                        cons_egress: 3,
                        mac: [0u8; 6].into(),
                    },
                    HopField {
                        flags: HopFieldFlags::empty(),
                        expiration_units: 5,
                        cons_ingress: 7,
                        cons_egress: 8,
                        mac: [1u8; 6].into(),
                    },
                    HopField {
                        flags: HopFieldFlags::empty(),
                        expiration_units: 6,
                        cons_ingress: 7,
                        cons_egress: 8,
                        mac: [2u8; 6].into(),
                    },
                ],
            }],
        }),
    };

    println!("Required size: {}", header.required_size());

    let mut buf = vec![0u8; header.required_size()];
    header.encode(&mut buf).unwrap();

    let mut output = String::new();
    let layout = ScionHeaderLayout::from_slice(&buf).unwrap();
    let ann = layout.annotations();

    ann.fmt_on_buffer(&mut output, &buf, 4).unwrap();
    print!("{output}");

    println!("Encoded header: {:x?}", buf);

    let (view, _rest) = ScionHeaderView::from_mut_slice(&mut buf).unwrap();

    println!("Alternative decoded header: {:#?}", view);

    let reconstructed = ScionPacketHeader::from_view(view);
    println!("Reconstructed header: {:#?}", reconstructed);
    assert_eq!(header, reconstructed);
    println!("Success!");
}
