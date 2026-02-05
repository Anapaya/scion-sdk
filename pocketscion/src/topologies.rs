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

use std::net::SocketAddr;

use scion_proto::address::{Asn, Isd, IsdAsn};
use url::Url;

use crate::{api::admin::client::ApiClient, runtime::PocketScionRuntime};

/// 1-ff00:0:132
pub const IA132: IsdAsn = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0132));

/// 2-ff00:0:212
pub const IA212: IsdAsn = IsdAsn::new(Isd(2), Asn::new(0xff00_0000_0212));

/// 2-ff00:0:222
pub const IA222: IsdAsn = IsdAsn::new(Isd(2), Asn::new(0xff00_0000_0222));

/// A handle for a running PocketSCION instance. The handle provides convenience methods for
/// interacting with the PocketSCION instance, such as retrieving endhost API URLs etc.
pub struct PocketScionHandle {
    /// The PocketSCION runtime for the topology.
    pub runtime: PocketScionRuntime,
    /// API client for interacting with the PocketSCION runtime.
    pub api_client: ApiClient,
}

impl PocketScionHandle {
    /// Creates a new PocketSCION handle.
    pub fn new(pocketscion: PocketScionRuntime, api_client: ApiClient) -> Self {
        Self {
            runtime: pocketscion,
            api_client,
        }
    }

    /// Retrieves an endhost API URL for the given ISD-AS.
    pub async fn endhost_api(&self, isd_as: IsdAsn) -> anyhow::Result<Url> {
        let resp = self.api_client.get_endhost_apis().await?;
        let (_id, entry) = resp
            .endhost_apis
            .iter()
            .find(|(_id, entry)| entry.local_ases.contains(&isd_as))
            .ok_or_else(|| anyhow::anyhow!("No endhost API for AS {isd_as} found in topology"))?;
        Ok(entry.url.clone())
    }

    /// Retrieves a router socket address for the given ISD-AS.
    pub async fn router_addr(&self, isd_as: IsdAsn) -> anyhow::Result<SocketAddr> {
        let resp = self.api_client.get_routers().await?;
        let (_id, entry) = resp
            .routers
            .iter()
            .find(|(_id, entry)| entry.isd_as == isd_as)
            .ok_or_else(|| {
                anyhow::anyhow!("No router address for AS {isd_as} found in topology")
            })?;
        Ok(entry.addr)
    }
}

/// Underlay type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnderlayType {
    /// UDP underlay.
    Udp,
    /// SNAP underlay.
    Snap,
}
