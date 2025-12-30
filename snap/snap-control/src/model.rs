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
//! SNAP control plane models.

use std::net::SocketAddr;

#[cfg(test)]
use mockall::{automock, predicate::*};
use scion_proto::address::IsdAsn;
use thiserror::Error;

/// List the available data planes.
#[cfg_attr(test, automock)]
pub trait UnderlayDiscovery: Send + Sync {
    /// List all SNAP data planes.
    fn list_snap_underlays(&self) -> Vec<SnapUnderlay>;
    /// List all UDP data planes.
    fn list_udp_underlays(&self) -> Vec<UdpUnderlay>;
}

#[derive(Clone)]
/// SNAP data plane information.
pub struct SnapUnderlay {
    /// The listener address of the data plane.
    pub address: SocketAddr,
    /// The ISD-ASes of the data plane.
    pub isd_ases: Vec<IsdAsn>,
}

#[derive(Clone)]
/// UDP data plane information.
pub struct UdpUnderlay {
    /// The UDP socket address of the data plane.
    pub endpoint: SocketAddr,
    /// The ISD-ASes and their associated interfaces for this UDP data plane.
    pub isd_ases: Vec<IsdAsInterfaces>,
}

#[derive(Clone)]
/// The interface IDs for an ISD-AS.
pub struct IsdAsInterfaces {
    /// The ISD-AS identifier
    pub isd_as: IsdAsn,
    /// The interface IDs for this ISD-AS
    pub interfaces: Vec<u16>,
}

/// SNAP resolution error.
#[derive(Debug, Error)]
pub enum ResolveSnapError {
    /// No data plane available
    #[error("no data plane could be found")]
    NoDataPlaneAvailable,
}

/// SNAP data plane resolver.
pub trait SnapResolver: Send + Sync {
    /// Get the corresponding SNAP data plane address for a given endhost IP address.
    fn resolve(&self, endhost_ip: std::net::IpAddr) -> Result<SocketAddr, ResolveSnapError>;
}
