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
//! Network underlay models.

use std::net::SocketAddr;

use sciparse::identifier::isd_asn::IsdAsn;
use serde::{Deserialize, Serialize};
use url::Url;

/// Network underlays available to the endhost.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Underlays {
    /// The UDP/IP underlay consisting of the available SCION routers.
    pub udp_underlay: Vec<ScionRouter>,
    /// The SNAP underlay.
    pub snap_underlay: Vec<Snap>,
}

impl std::fmt::Display for Underlays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Underlays[udp: [{}] snap: [{}]]",
            self.udp_underlay
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            self.snap_underlay
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// SCION router information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScionRouter {
    /// ISD-AS of the SCION router.
    pub isd_as: IsdAsn,
    /// The internal interface socket address of the SCION router.
    pub internal_interface: SocketAddr,
    /// The list of interfaces available on the SCION router.
    pub interfaces: Vec<u16>,
}

impl std::fmt::Display for ScionRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ScionRouter[isd_as: {}, internal_interface: {}, interfaces: {:?}]",
            self.isd_as, self.internal_interface, self.interfaces
        )
    }
}

/// The SNAP underlay consisting of the available SNAP control plane API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Snap {
    /// The SNAP control plane API address.
    pub address: Url,
    /// The list of ISD-ASes available via this SNAP.
    pub isd_ases: Vec<IsdAsn>,
}

impl std::fmt::Display for Snap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Snap[address: {}, isd_ases: {:?}]",
            self.address, self.isd_ases
        )
    }
}
