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

//! External AS DTOs

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ExternalAsInterfaceState, ExternalAsState};
use crate::util::{BtreeMapError, map_btree, map_btree_fallible};

/// Serialized state for ExternalAsState
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExternalAsStateDto {
    pub(crate) interfaces: BTreeMap<u16, ExternalAsInterfaceDto>,
}

impl From<ExternalAsState> for ExternalAsStateDto {
    fn from(value: ExternalAsState) -> Self {
        ExternalAsStateDto {
            interfaces: map_btree(value.interfaces, |iface_state| iface_state.into()),
        }
    }
}

impl TryFrom<ExternalAsStateDto> for ExternalAsState {
    type Error = BtreeMapError<u16, std::net::AddrParseError>;

    fn try_from(value: ExternalAsStateDto) -> Result<Self, Self::Error> {
        Ok(ExternalAsState {
            interfaces: map_btree_fallible(value.interfaces, |iface_state| iface_state.try_into())?,
        })
    }
}

/// Serialized state for ExternalAsInterfaceState
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExternalAsInterfaceDto {
    /// ID of the interface described
    pub(crate) interface_id: u16,
    /// Address to where this interface connects, used for sending packets to the External AS and
    /// validating received packets
    pub(crate) target_addr: String,
}

impl From<ExternalAsInterfaceState> for ExternalAsInterfaceDto {
    fn from(value: ExternalAsInterfaceState) -> Self {
        ExternalAsInterfaceDto {
            interface_id: value.interface_id,
            target_addr: value.target_addr.to_string(),
        }
    }
}

impl TryFrom<ExternalAsInterfaceDto> for ExternalAsInterfaceState {
    type Error = std::net::AddrParseError;

    fn try_from(value: ExternalAsInterfaceDto) -> Result<Self, Self::Error> {
        Ok(ExternalAsInterfaceState {
            interface_id: value.interface_id,
            target_addr: value.target_addr.parse()?,
        })
    }
}
