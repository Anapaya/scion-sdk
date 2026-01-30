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
//! Data transfer objects (DTOs) for the tunnel gateway state.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::tunnel_gateway_deprecated::state::TunnelGatewayIoConfig;

/// The I/O configuration of a SNAP data plane.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct IoDataPlaneConfigDto {
    /// The data plane address.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub addr: Option<String>,
}

impl From<&TunnelGatewayIoConfig> for IoDataPlaneConfigDto {
    fn from(value: &TunnelGatewayIoConfig) -> Self {
        IoDataPlaneConfigDto {
            addr: value.listen_addr.map(|addr| addr.to_string()),
        }
    }
}

impl TryFrom<IoDataPlaneConfigDto> for TunnelGatewayIoConfig {
    type Error = anyhow::Error;

    fn try_from(value: IoDataPlaneConfigDto) -> Result<Self, Self::Error> {
        let listen_addr = match value.addr {
            Some(addr) => Some(addr.parse().context("invalid listen address")?),
            None => None,
        };

        Ok(Self { listen_addr })
    }
}
