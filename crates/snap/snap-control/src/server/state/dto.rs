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
//! Data transfer objects (DTOs) for the SNAP control plane server state.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::server::state::ControlPlaneIoConfig;

/// The I/O configuration of a SNAP control plane.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct IoControlPlaneConfigDto {
    /// The Control plane API address.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub api_addr: Option<String>,
}

impl TryFrom<IoControlPlaneConfigDto> for ControlPlaneIoConfig {
    type Error = anyhow::Error;

    fn try_from(value: IoControlPlaneConfigDto) -> Result<Self, Self::Error> {
        let api_addr = match value.api_addr {
            Some(addr) => Some(addr.parse().context("invalid control plane API address")?),
            None => None,
        };

        Ok(Self { api_addr })
    }
}

impl From<&ControlPlaneIoConfig> for IoControlPlaneConfigDto {
    fn from(value: &ControlPlaneIoConfig) -> Self {
        IoControlPlaneConfigDto {
            api_addr: value.api_addr.map(|addr| addr.to_string()),
        }
    }
}
