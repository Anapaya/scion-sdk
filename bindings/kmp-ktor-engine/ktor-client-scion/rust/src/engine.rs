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

//! Runs each request as a task on the shared runtime.
//!
//! A request ends in one of three ways: the task finishes, [`Engine::release`]
//! arrives, or the future that waits for the task drops. The last two abort
//! the task.
//!
//! The submodules hold the parts that run while the client lives: the tokio
//! runtime, the transports, the certificate trust of the platform, and the
//! token refresh through the AA. [`Engine::new`] builds them from a
//! [`CoreConfig`], through the engine [`Config`](config::Config).

pub(crate) mod aa;
mod config;
pub(crate) mod platform;
mod runtime;
mod setup;
pub(crate) mod transport;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{runtime::Runtime, sync::oneshot};

use self::{
    runtime::AbortOnDrop,
    transport::{Request, Transport},
};
use crate::ffi::types::{CoreConfig, CoreError, CoreRequest, CoreResponse};

pub(crate) struct Engine {
    transport: Arc<dyn Transport>,
    runtime: &'static Runtime,
    inflight: Mutex<HashMap<u64, Inflight>>,
    next_id: AtomicU64,
}

/// The cancel channel of a request, from its key until its release.
struct Inflight {
    sender: oneshot::Sender<()>,
    /// [`Engine::execute`] takes it.
    receiver: Option<oneshot::Receiver<()>>,
}

impl Engine {
    pub(crate) fn new(config: CoreConfig) -> Result<Self, CoreError> {
        let config = config::Config::new(config)?;
        let runtime = runtime::shared()?;

        // Build the transport inside the runtime context.
        let transport = {
            let _runtime = runtime.enter();
            setup::transport(config)?
        };

        Ok(Engine {
            transport,
            runtime,
            inflight: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    /// Hands out the key of a request and opens its cancel channel. Each key
    /// needs one [`Self::release`], also after the request ended.
    pub(crate) fn next_request_id(&self) -> u64 {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.entries().insert(
            request_id,
            Inflight {
                sender,
                receiver: Some(receiver),
            },
        );
        request_id
    }

    pub(crate) async fn execute(
        &self,
        request_id: u64,
        request: CoreRequest,
    ) -> Result<CoreResponse, CoreError> {
        // Take the cancel channel. Without one, the release came first.
        let cancel_rx = self
            .entries()
            .get_mut(&request_id)
            .and_then(|entry| entry.receiver.take())
            .ok_or(CoreError::Cancelled)?;
        let request = Request::try_from(request)?;

        // Run it until it ends or a cancel arrives.
        let transport = self.transport.clone();
        let task = AbortOnDrop(
            self.runtime
                .spawn(async move { transport.send(request).await }),
        );
        let result = tokio::select! {
            biased;
            // A dropped sender also resolves the receiver. Only a sent value
            // counts as a cancel.
            Ok(()) = cancel_rx => Err(CoreError::Cancelled),
            joined = task => joined.unwrap_or_else(|error| {
                Err(CoreError::Internal { message: format!("request task failed: {error}") })
            }),
        };

        // Unregister.
        self.forget(request_id);
        result
    }

    /// Ends the request if it still runs, and frees its key. Does nothing for
    /// a key that is free already.
    pub(crate) fn release(&self, request_id: u64) {
        if let Some(entry) = self.forget(request_id) {
            let _ = entry.sender.send(());
        }
    }

    fn forget(&self, request_id: u64) -> Option<Inflight> {
        self.entries().remove(&request_id)
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<u64, Inflight>> {
        self.inflight.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Kotlin destroys the object on its own thread, and closing is async.
        let transport = self.transport.clone();
        drop(self.runtime.spawn(async move { transport.close().await }));
    }
}

/// Includes the source chain. scion-http3 puts the useful part there.
fn describe_error(error: &dyn std::error::Error) -> String {
    // Append each cause.
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }

    text
}
