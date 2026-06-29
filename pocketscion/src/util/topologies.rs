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

//! Example pocket SCION topologies for testing.

pub mod minimal;

use std::collections::BTreeMap;

use sciparse::identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn};
use url::Url;

use crate::{comp::endhost_api::EndhostApiId, runtime::PocketScionRuntime, util::addr_to_http_url};

/// 1-ff00:0:132
pub const IA132: IsdAsn = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0132));

/// 2-ff00:0:212
pub const IA212: IsdAsn = IsdAsn::new(Isd(2), Asn::new(0xff00_0000_0212));

/// 2-ff00:0:222
pub const IA222: IsdAsn = IsdAsn::new(Isd(2), Asn::new(0xff00_0000_0222));

/// Underlay type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnderlayType {
    /// UDP underlay.
    Udp,
    /// SNAP underlay.
    Snap,
}

/// A running PocketSCION test topology setup.
///
/// Contains the runtime and the endhost API IDs for each AS in the topology.
pub struct PsSetup {
    /// The running PocketSCION runtime.
    pub runtime: PocketScionRuntime,
    /// Map from ISD-AS to endhost API ID.
    pub endhost_apis: BTreeMap<IsdAsn, EndhostApiId>,
}

impl PsSetup {
    /// Returns the endhost API address for the given ISD-AS as an HTTP [Url].
    pub fn endhost_api(&self, isd_as: IsdAsn) -> Option<Url> {
        let id = self.endhost_apis.get(&isd_as)?;
        let addr = self.runtime.endhost_api_addr(*id)?;
        Some(addr_to_http_url(addr))
    }
}
