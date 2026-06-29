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

//! Path providers to be used in the network simulator.

use std::{collections::HashMap, sync::Mutex};

use sciparse::{
    dataplane_path::{
        model::DpPath,
        view::{ScionDpPathViewExt, ScionDpPathViewRef},
    },
    identifier::isd_asn::IsdAsn,
};

use crate::comp::sim_network_stack::NetSimPathProvider;

/// A simple implementation of a path provider for the network simulator that allows manually
/// setting the path to be returned.
#[derive(Debug, Default)]
pub struct ManualPathProvider {
    /// The path to be returned by this path provider. Wrapped in a Mutex to allow mutation.
    pub path: Mutex<Option<DpPath>>,
}

impl ManualPathProvider {
    /// Sets the path to be returned by this path provider.
    pub fn set_path(&self, path: DpPath) {
        self.path.lock().unwrap().replace(path);
    }
}

impl NetSimPathProvider for ManualPathProvider {
    fn get_path(&self, _src_as: IsdAsn, _dst_as: IsdAsn) -> Option<DpPath> {
        self.path.lock().unwrap().clone()
    }
}

/// A path provider mirroring paths informed to it through `inform_path`.
#[derive(Debug, Default)]
pub struct MirroringPathProvider {
    /// Maps (src AS, dst AS) to the path to be used for packets from src AS to dst AS
    pub paths: Mutex<HashMap<(IsdAsn, IsdAsn), DpPath>>,
}

impl MirroringPathProvider {
    /// Sets the path to be returned for packets from src AS to dst AS.
    ///
    /// This path may be overridden when the path provider is informed of a path from src AS to dst
    /// AS through `inform_path`.
    #[allow(dead_code)]
    pub fn set_path(&self, src_as: IsdAsn, dst_as: IsdAsn, path: DpPath) {
        self.paths.lock().unwrap().insert((src_as, dst_as), path);
    }
}

impl NetSimPathProvider for MirroringPathProvider {
    fn inform_path(&self, src_as: IsdAsn, dst_as: IsdAsn, path: ScionDpPathViewRef<'_>) {
        let mut reversed_path = path.to_model();

        let Ok(_) = reversed_path.try_reverse() else {
            tracing::debug!(src_as = %src_as, dst_as = %dst_as, "Failed to reverse path, not setting path for MirroringPathProvider");
            return;
        };

        self.paths
            .lock()
            .unwrap()
            .insert((dst_as, src_as), reversed_path);
    }

    fn get_path(&self, src_as: IsdAsn, dst_as: IsdAsn) -> Option<DpPath> {
        self.paths.lock().unwrap().get(&(src_as, dst_as)).cloned()
    }
}
