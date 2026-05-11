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

//! Registry for external ASes in the network simulation, allowing to define custom behavior for
//! specific ASes.

use std::{collections::HashMap, fmt::Debug, sync::Arc};

use scion_proto::address::IsdAsn;

use crate::network::local::external_as_handler::ExternalAsHandler;

/// Registry for external ASes in the network simulation, allowing to define custom behavior for
/// specific ASes.
///
/// The as added to the registry must also be set as external in the topology, otherwise the
/// registered handler will not be used for that AS.
#[derive(Clone, Default)]
pub struct ExternalAsRegistry {
    external_as_mapping: HashMap<IsdAsn, Arc<dyn ExternalAsHandler>>,
}

impl Debug for ExternalAsRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalAsRegistry")
            .field("external_as_mapping", &self.external_as_mapping.keys())
            .finish()
    }
}

impl ExternalAsRegistry {
    /// Creates a new empty ExternalAsRegistry.
    pub fn new() -> Self {
        Self {
            external_as_mapping: HashMap::new(),
        }
    }

    /// Registers a handler for a given ISD-AS.
    pub fn register_external_as(&mut self, isd_asn: IsdAsn, adapter: Arc<dyn ExternalAsHandler>) {
        self.external_as_mapping.insert(isd_asn, adapter);
    }

    /// Checks if a given ISD-AS is registered as an external AS.
    pub fn contains_key(&self, isd_asn: &IsdAsn) -> bool {
        self.external_as_mapping.contains_key(isd_asn)
    }

    /// Retrieves the handler for a given external AS, if it exists.
    pub fn get(&self, isd_asn: &IsdAsn) -> Option<&Arc<dyn ExternalAsHandler>> {
        self.external_as_mapping.get(isd_asn)
    }
}
