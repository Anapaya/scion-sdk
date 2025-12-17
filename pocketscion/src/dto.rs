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
//! This module provides the public facing DTOs (Data Transfer Object) for the pocket SCION
//! system.
//!
//! Public facing dto types are types that are exposed to end-users of the
//! system. In contrast to component internal types, the dto types must be
//! serializable and deserializable such that they can be used in APIs and
//! configuration files.
//!
//! Types that are used by the pocket SCION management API must also implement
//! the [`ToSchema`] trait to generate OpenAPI schema definitions.

use std::{collections::BTreeMap, time::Duration};

use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use snap_control::server::state::dto::IoControlPlaneConfigDto;
use snap_dataplane::{
    dto::DataPlaneStateDto,
    session::state::dto::{SessionManagerStateDto, SessionTokenIssuerStateDto},
    state::Hostname,
    tunnel_gateway::state::dto::IoDataPlaneConfigDto,
};
use utoipa::ToSchema;

use crate::{
    endhost_api::{EndhostApiId, EndhostApiState},
    network::scion::topology::dto::ScionTopologyDto,
    state::{RouterId, SnapId},
};

/// The pocket SCION system state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SystemStateDto {
    /// XXX(uniquefine): This is temporary until we properly model the rendevous hashing.
    /// If set, only one data plane per snap and only one snap per ISD-AS is allowed.
    /// If a snap is configured, then it is registered as wildcard sim_receiver
    /// thus all traffic is forwarded to the snaps.
    /// If not set, the old behavior is used.
    pub forward_all_traffic_to_snaps: bool,
    /// The public key (PEM format) to verify SNAP tokens.
    pub snap_token_public_key: String,
    /// Test authentication server.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auth_server_state: Option<AuthServerStateDto>,
    /// The list of SNAPs in the system.
    pub snaps: BTreeMap<SnapId, SnapStateDto>,
    /// The list of SCION routers.
    pub routers: BTreeMap<RouterId, RouterStateDto>,
    /// The list of Endhost APIs
    pub endhost_apis: BTreeMap<EndhostApiId, EndhostApiState>,
    /// Scion Topology used for routing
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub topology: Option<ScionTopologyDto>,
}

/// The state of the authentication server.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AuthServerStateDto {
    /// The token exchange state.
    pub token_exchanger: TokenExchangerStateDto,
}

/// The state of the token exchanger.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TokenExchangerStateDto {
    /// The configuration of the token exchanger.
    pub config: TokenExchangerConfigDto,
    /// List of identity mappings (SSID -> PSSID).
    pub id_mapping: BTreeMap<String, String>,
}

/// Token exchanger configuration.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TokenExchangerConfigDto {
    /// The private key (PEM format) used to sign SNAP tokens.
    pub private_key: String,
    /// The lifetime of the SNAP tokens.
    pub token_lifetime: Duration,
    /// The fake identity provider for testing.
    pub fake_idp: FakeIdpDto,
}

/// The fake identity provider configuration for testing.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct FakeIdpDto {
    /// The public key (PEM format) used to verify ID tokens.
    pub(crate) public_key: String,
}

/// The pocket SCION I/O configuration.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct IoConfigDto {
    /// The I/O state of the optional Auth server.
    pub auth_server: IoAuthServerConfigDto,
    /// The list of SNAP I/O configurations.
    pub snaps: BTreeMap<SnapId, IoSnapConfigDto>,
    /// The list of SCION router sockets.
    pub router_sockets: BTreeMap<RouterId, String>,
    /// Listening Sockets for Endhost APIs
    pub endhost_apis: BTreeMap<EndhostApiId, String>,
}

/// The I/O configuration of the Auth server.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct IoAuthServerConfigDto {
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) addr: Option<String>,
}

/// The state of a SNAP.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SnapStateDto {
    /// Session manager state.
    pub session_manager: SessionManagerStateDto,
    /// Session token issuer state.
    pub session_issuer: SessionTokenIssuerStateDto,
    /// The list of SNAP data planes.
    pub data_planes: BTreeMap<Hostname, DataPlaneStateDto>,
}

/// The I/O configuration of a SNAP.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct IoSnapConfigDto {
    /// The control plane address of the SNAP.
    pub control_plane: IoControlPlaneConfigDto,
    /// The list of data plane I/O configurations.
    pub data_planes: BTreeMap<Hostname, IoDataPlaneConfigDto>,
}

/// The state of a SCION router emulated by PocketScion.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RouterStateDto {
    /// The ISD-AS of the router.
    pub isd_as: IsdAsn,
    /// The list of interface IDs of the router.
    pub if_ids: Vec<u16>,
    /// The SNAP data planes that are connected to the router.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub snap_data_plane_interfaces: BTreeMap<String, String>,
    /// The list of networks towards which SCION traffic will not be routed through
    /// the available SNAPs.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub snap_data_plane_excludes: Vec<String>,
}
