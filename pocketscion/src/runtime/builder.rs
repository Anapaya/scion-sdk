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

//! PocketSCION Runtime builder.

use std::{io, path::Path};

use anyhow::Context;
use tokio::task::JoinSet;

use crate::{
    io_config::{IoConfig, IoConfigInner},
    runtime::PocketScionRuntime,
    state::PocketScionState,
    util::serde_ext::SerdeExt,
};

/// Builder for a PocketSCION runtime.
#[derive(Debug, Default)]
pub struct PocketScionRuntimeBuilder {
    system_state: Option<PocketScionState>,
    io_config: Option<IoConfig>,
}

/// Default management API port.
pub const DEFAULT_MGMT_PORT: u16 = 9000;

// Builder functions
impl PocketScionRuntimeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set PocketSCION's initial IO-configuration to `io_config`.
    pub fn with_io_config(mut self, io_config: IoConfig) -> Self {
        self.io_config = Some(io_config);
        self
    }

    /// Load PocketSCION's initial IO-configuration from a file at `path`.
    pub fn with_io_config_path<P: AsRef<Path>>(mut self, path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let inner = IoConfigInner::load_from_file(path)
            .with_context(|| format!("Failed to load I/O config from path {path:?}"))?;
        self.io_config = Some(IoConfig::from_inner(inner));
        Ok(self)
    }

    /// Set PocketSCION's initial system state to `system_state`.
    pub fn with_system_state(mut self, system_state: PocketScionState) -> Self {
        self.system_state = Some(system_state);
        self
    }

    /// Start the PocketSCION runtime.
    pub async fn start(self) -> anyhow::Result<PocketScionRuntime> {
        self.start_with_join_set(JoinSet::new()).await
    }
}

// Start functions
impl PocketScionRuntimeBuilder {
    /// Create an instance of a PocketSCION.
    pub async fn start_with_join_set(
        self,
        join_set: JoinSet<Result<(), io::Error>>,
    ) -> anyhow::Result<PocketScionRuntime> {
        let system_state = self
            .system_state
            .ok_or_else(|| anyhow::anyhow!("System state must be provided"))?;
        let io_config = self.io_config.unwrap_or_default();
        PocketScionRuntime::start(system_state, io_config, join_set).await
    }
}
