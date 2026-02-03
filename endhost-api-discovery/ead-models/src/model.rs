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

//! Models for Endhost API discovery.

use std::net::IpAddr;

use url::Url;

/// RPC paths for the Endhost API Discovery service.
pub struct RpcEndhostApiDiscoveryService;
impl RpcEndhostApiDiscoveryService {
    /// Service path for the Endhost API Discovery service.
    pub const SERVICE_PATH: &'static str = "/endhost.discovery.v1.EndhostApiDiscoveryService";
    /// RPC path for the GetEndhostApis method.
    pub const GET_ENDHOST_APIS_PATH: &'static str = "/GetEndhostApis";
}

/// Allows discovery of available Endhost APIs.

#[async_trait::async_trait]
pub trait EndhostApiDiscovery: Send + Sync {
    /// Discover available Endhost APIs
    ///
    /// Returns a list of EndhostApiInfos representing the discovered Endhost APIs.
    /// This list is ordered by preference, with the most preferred API first.
    ///
    /// # Parameters
    /// - `public_ip`: The public IP address of the endhost making the discovery request.
    async fn discover_endhost_api(&self, public_ip: IpAddr) -> Vec<EndhostApiInfo>;
}

/// Information about an Endhost API.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EndhostApiInfo {
    /// URL of the Endhost API.
    pub address: Url,
}
