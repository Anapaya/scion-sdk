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

//! The object that Kotlin holds.
//!
//! Kotlin polls each exported future on its own threads. The future only waits
//! for a task on the runtime of the engine, so the polling thread needs no
//! tokio runtime, and the exports need no `async_runtime` attribute.
//!
//! UniFFI does not promise that a cancelled coroutine drops its Rust future.
//! So the Ktor engine calls [`ScionCore::release`] after each request, which
//! also ends a request that still runs.

use crate::{
    engine::Engine,
    ffi::types::{CoreConfig, CoreError, CoreRequest, CoreResponse},
};

#[derive(uniffi::Object)]
pub struct ScionCore {
    engine: Engine,
}

#[uniffi::export]
impl ScionCore {
    /// Builds the client without waiting on the network.
    #[uniffi::constructor]
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Ok(ScionCore {
            engine: Engine::new(config)?,
        })
    }

    /// Hands out the key of a request. Each key needs one [`Self::release`],
    /// also after the request ended.
    pub fn next_request_id(&self) -> u64 {
        self.engine.next_request_id()
    }

    pub async fn execute(
        &self,
        request_id: u64,
        request: CoreRequest,
    ) -> Result<CoreResponse, CoreError> {
        self.engine.execute(request_id, request).await
    }

    /// Ends the request if it still runs, and frees its key. Does nothing for
    /// a key that is free already.
    pub fn release(&self, request_id: u64) {
        self.engine.release(request_id);
    }
}
