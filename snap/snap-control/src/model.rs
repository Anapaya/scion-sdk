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

use std::net::{IpAddr, SocketAddr};

#[cfg(test)]
use mockall::{automock, predicate::*};
use scion_proto::address::IsdAsn;
use snap_dataplane::session::{manager::SessionTokenError, state::SessionOpenError};
use snap_tokens::snap_token::SnapTokenClaims;
use thiserror::Error;

use crate::crpc_api::api_service::model::SessionGrant;

/// List the available data planes.
#[cfg_attr(test, automock)]
pub trait UnderlayDiscovery: Send + Sync {
    /// List all SNAP data planes.
    fn list_snap_underlays(&self) -> Vec<SnapUnderlay>;
    /// List all UDP data planes.
    fn list_udp_underlays(&self) -> Vec<UdpUnderlay>;
}

/// Data plane session granter.
#[cfg_attr(test, automock)]
pub trait SessionGranter: Send + Sync {
    /// Authorizes the usage of a (set of) data planes based on the requesting
    /// endhost's IP address and returns a session grant for each such data
    /// plane.
    fn create_sessions(
        &self,
        endhost_ip_addr: IpAddr,
        snap_token: SnapTokenClaims,
    ) -> Result<Vec<SessionGrant>, CreateSessionError>;
}

/// Session creation error.
#[derive(Debug, Error)]
pub enum CreateSessionError {
    /// No data plane available
    #[error("open session error: {reason}")]
    NoDataPlaneAvailable {
        /// The reason no data plane could be found.
        reason: String,
    },
    /// Failed to open session.
    #[error("open session error: {0}")]
    OpenSession(#[from] SessionOpenError),
    /// Failed to issue session token.
    #[error("failed to issue session token: {0}")]
    IssueSessionToken(#[from] SessionTokenError),
}

/// SNAP data plane information.
pub struct SnapUnderlay {
    /// The listener address of the data plane.
    pub address: SocketAddr,
    /// The ISD-ASes of the data plane.
    pub isd_ases: Vec<IsdAsn>,
}

/// UDP data plane information.
pub struct UdpUnderlay {
    /// The UDP socket address of the data plane.
    pub endpoint: SocketAddr,
    /// The ISD-ASes and their associated interfaces for this UDP data plane.
    pub isd_ases: Vec<IsdAsInterfaces>,
}

/// The interface IDs for an ISD-AS.
pub struct IsdAsInterfaces {
    /// The ISD-AS identifier
    pub isd_as: IsdAsn,
    /// The interface IDs for this ISD-AS
    pub interfaces: Vec<u32>,
}
