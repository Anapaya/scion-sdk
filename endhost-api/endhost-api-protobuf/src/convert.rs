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
//! Conversions between endhost API protobuf types and endhost API models.

use scion_proto::path::{Segments, convert::segment::InvalidSegmentError};

use crate::endhost::api_service::v1::{
    ListSegmentsResponse, ListUnderlaysResponse, Router, Snap, SnapUnderlay, UdpUnderlay,
};

impl From<endhost_api_models::underlays::Underlays> for ListUnderlaysResponse {
    fn from(underlays: endhost_api_models::underlays::Underlays) -> Self {
        ListUnderlaysResponse {
            udp: Some(UdpUnderlay::from(underlays.udp_underlay)),
            snap: Some(SnapUnderlay::from(underlays.snap_underlay)),
        }
    }
}

impl TryFrom<ListUnderlaysResponse> for endhost_api_models::underlays::Underlays {
    type Error = url::ParseError;
    fn try_from(response: ListUnderlaysResponse) -> Result<Self, Self::Error> {
        Ok(endhost_api_models::underlays::Underlays {
            udp_underlay: match response.udp {
                Some(udp) => udp.routers.into_iter().map(Into::into).collect(),
                None => Vec::new(),
            },
            snap_underlay: match response.snap {
                Some(snap) => {
                    snap.snaps
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, _>>()?
                }
                None => Vec::new(),
            },
        })
    }
}

impl From<Vec<endhost_api_models::underlays::ScionRouter>> for UdpUnderlay {
    fn from(routers: Vec<endhost_api_models::underlays::ScionRouter>) -> Self {
        UdpUnderlay {
            routers: routers.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<UdpUnderlay> for Vec<endhost_api_models::underlays::ScionRouter> {
    fn from(udp: UdpUnderlay) -> Self {
        udp.routers.into_iter().map(Into::into).collect()
    }
}

impl From<endhost_api_models::underlays::ScionRouter> for Router {
    fn from(r: endhost_api_models::underlays::ScionRouter) -> Self {
        Router {
            isd_as: r.isd_as.into(),
            address: r.internal_interface.to_string(),
            // XXX(bunert): protobuf doesn't support u16
            interfaces: r.interfaces.into_iter().map(|i| i as u32).collect(),
        }
    }
}

impl From<Router> for endhost_api_models::underlays::ScionRouter {
    fn from(r: Router) -> Self {
        endhost_api_models::underlays::ScionRouter {
            isd_as: r.isd_as.into(),
            internal_interface: r.address.parse().unwrap(),
            interfaces: r.interfaces.into_iter().map(|i| i as u16).collect(),
        }
    }
}

impl From<Vec<endhost_api_models::underlays::Snap>> for SnapUnderlay {
    fn from(snaps: Vec<endhost_api_models::underlays::Snap>) -> Self {
        SnapUnderlay {
            snaps: snaps.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<SnapUnderlay> for Vec<endhost_api_models::underlays::Snap> {
    type Error = url::ParseError;
    fn try_from(snap: SnapUnderlay) -> Result<Self, Self::Error> {
        snap.snaps.into_iter().map(TryFrom::try_from).collect()
    }
}

impl From<endhost_api_models::underlays::Snap> for Snap {
    fn from(s: endhost_api_models::underlays::Snap) -> Self {
        Snap {
            address: s.address.to_string(),
            isd_ases: s.isd_ases.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<Snap> for endhost_api_models::underlays::Snap {
    type Error = url::ParseError;
    fn try_from(s: Snap) -> Result<Self, Self::Error> {
        Ok(endhost_api_models::underlays::Snap {
            address: s.address.parse()?,
            isd_ases: s.isd_ases.into_iter().map(Into::into).collect(),
        })
    }
}

impl From<scion_proto::path::segment::SegmentsPage> for ListSegmentsResponse {
    fn from(page: scion_proto::path::segment::SegmentsPage) -> Self {
        Self {
            up_segments: page
                .segments
                .up_segments
                .into_iter()
                .map(Into::into)
                .collect(),
            down_segments: page
                .segments
                .down_segments
                .into_iter()
                .map(Into::into)
                .collect(),
            core_segments: page
                .segments
                .core_segments
                .into_iter()
                .map(Into::into)
                .collect(),
            next_page_token: page.next_page_token,
        }
    }
}

impl TryFrom<ListSegmentsResponse> for scion_proto::path::segment::SegmentsPage {
    type Error = InvalidSegmentError;
    fn try_from(response: ListSegmentsResponse) -> Result<Self, Self::Error> {
        let convert = |segs: Vec<_>| {
            segs.into_iter()
                .map(scion_proto::path::PathSegment::try_from)
                .collect::<Result<_, _>>()
        };
        Ok(scion_proto::path::segment::SegmentsPage {
            segments: Segments {
                up_segments: convert(response.up_segments)?,
                down_segments: convert(response.down_segments)?,
                core_segments: convert(response.core_segments)?,
            },
            next_page_token: response.next_page_token,
        })
    }
}
