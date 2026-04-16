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
//! Mock segment lister for testing.

use std::{str::FromStr, time::SystemTime};

use endhost_api_models::{SegmentsDiscovery, SegmentsError};
use sciparse::{
    identifier::isd_asn::IsdAsn,
    path::standard::types::HopFieldMac,
    reexport::p256::ecdsa::SigningKey,
    segment::{AsEntry, HopEntry, SegmentHopField, Segments, SegmentsPage, SignedPathSegment},
};
use tonic::async_trait;

/// A mock segment lister that returns segments from the default test graph.
/// It only supports queries from 1-ff00:0:132 to 2-ff00:0:211 and back.
pub struct MockSegmentLister {
    supported_ases: (IsdAsn, IsdAsn),
}

impl Default for MockSegmentLister {
    fn default() -> Self {
        Self {
            supported_ases: (
                IsdAsn::from_str("1-ff00:0:132").unwrap(),
                IsdAsn::from_str("2-ff00:0:212").unwrap(),
            ),
        }
    }
}

#[async_trait]
impl SegmentsDiscovery for MockSegmentLister {
    async fn list_segments(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        _page_size: i32,
        _page_token: String,
    ) -> Result<SegmentsPage, SegmentsError> {
        if self.supported_ases != (src, dst) && self.supported_ases != (dst, src) {
            return Err(SegmentsError::InvalidArgument(
                format!(
                    "Only queries from {} to {} and back are supported",
                    self.supported_ases.0, self.supported_ases.1
                )
                .into(),
            ));
        };

        Ok(SegmentsPage {
            segments: default_segments(self.supported_ases),
            next_page_token: String::new(),
        })
    }
}

fn default_segments((start_as, end_as): (IsdAsn, IsdAsn)) -> Segments {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let key = SigningKey::from_slice(&[0x01; 32]).unwrap();
    let forwarding_key = [0x02u8; 16];

    let mut segment = SignedPathSegment::empty(timestamp, 0);
    segment
        .add_entry(
            AsEntry {
                local: start_as,
                next: end_as,
                mtu: 1480,
                hop_entry: HopEntry {
                    ingress_mtu: 1480,
                    hop_field: SegmentHopField {
                        exp_time: 60,
                        cons_ingress: 0,
                        cons_egress: 2,
                        mac: HopFieldMac::default(),
                    },
                },
                peer_entries: vec![],
                extensions: vec![],
                unsigned_extensions: vec![],
            },
            &key,
            None,
            &forwarding_key,
            timestamp,
        )
        .expect("default segment should be valid");

    segment
        .add_entry(
            AsEntry {
                local: end_as,
                next: IsdAsn::WILDCARD,
                mtu: 1480,
                hop_entry: HopEntry {
                    ingress_mtu: 1480,
                    hop_field: SegmentHopField {
                        exp_time: 60,
                        cons_ingress: 201,
                        cons_egress: 0,
                        mac: HopFieldMac::default(),
                    },
                },
                peer_entries: vec![],
                extensions: vec![],
                unsigned_extensions: vec![],
            },
            &key,
            None,
            &forwarding_key,
            timestamp,
        )
        .expect("default segment should be valid");

    Segments {
        up_segments: vec![],
        core_segments: vec![segment],
        down_segments: vec![],
    }
}
