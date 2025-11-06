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
//! Data transfer objects (DTOs) for the address registry.

use std::time::Duration;

use anyhow::Context;
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    allocator::{AddressAllocator, dto::AddressAllocatorDto},
    dto::IpNetDto,
    manager::{AddressGrantEntry, AddressManager},
};

/// The data plane address registry.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AddressManagerDto {
    /// The id of the address registry.
    pub id: u64,
    /// The ISD-AS of the data plane.
    pub isd_as: IsdAsn,
    /// The duration for which an address is held.
    pub hold_duration: Duration,
    /// The list of address grants.
    pub address_grants: Vec<AddressGrantDto>,
    /// Bookkeeping of free IP addresses.
    pub free_ips: AddressAllocatorDto,
    /// The maximum number of attempts to allocate an address.
    pub max_attempts: usize,
    /// Prefixes this AddressManager is responsible for.
    pub prefixes: Vec<IpNetDto>,
}

impl From<&AddressManager> for AddressManagerDto {
    fn from(state: &AddressManager) -> Self {
        AddressManagerDto {
            id: state.id,
            isd_as: state.isd_as,
            hold_duration: state.hold_duration,
            address_grants: state.address_grants.values().map(|ag| ag.into()).collect(),
            free_ips: (&state.free_ips).into(),
            max_attempts: state.max_attempts,
            prefixes: state.prefixes.iter().cloned().map(From::from).collect(),
        }
    }
}

impl TryFrom<AddressManagerDto> for AddressManager {
    type Error = anyhow::Error;

    fn try_from(value: AddressManagerDto) -> Result<Self, Self::Error> {
        let address_grants = value
            .address_grants
            .into_iter()
            .map(|ag| {
                Ok((
                    ag.endhost_addr.parse().context("invalid endhost address")?,
                    AddressGrantEntry::try_from(ag).context("invalid address grant")?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        let free_ips = AddressAllocator::try_from(value.free_ips)?;

        Ok(Self {
            id: value.id,
            isd_as: value.isd_as,
            hold_duration: value.hold_duration,
            address_grants,
            free_ips,
            max_attempts: value.max_attempts,
            prefixes: value
                .prefixes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, Self::Error>>()?,
        })
    }
}
/// An address grant.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AddressGrantDto {
    /// The endhost address.
    pub endhost_addr: String,
    /// The ID of the token that was used to retrieve this address grant.
    pub id: String,
    /// The duration for which the grant is kept on hold.
    pub on_hold_until: Option<Duration>,
}

impl TryFrom<AddressGrantDto> for AddressGrantEntry {
    type Error = anyhow::Error;

    fn try_from(value: AddressGrantDto) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            on_hold_expiry: value.on_hold_until,
            endhost_address: value
                .endhost_addr
                .parse()
                .context("invalid endhost address")?,
        })
    }
}

impl From<&AddressGrantEntry> for AddressGrantDto {
    fn from(rg: &AddressGrantEntry) -> Self {
        AddressGrantDto {
            endhost_addr: rg.endhost_address.to_string(),
            id: rg.id.clone(),
            on_hold_until: rg.on_hold_expiry,
        }
    }
}
