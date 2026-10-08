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

//! The tokio runtime that runs the requests.

use std::{
    future::Future,
    pin::Pin,
    sync::{Mutex, OnceLock},
    task::{Context, Poll},
};

use tokio::{runtime::Runtime, task::JoinHandle};

use crate::ffi::types::CoreError;

/// Two workers, because the Apple certificate check of scion-quic can block
/// one. The checks on the other targets block too, but in `block_in_place`,
/// see `platform::verifier`.
const MIN_WORKERS: usize = 2;
const MAX_WORKERS: usize = 4;

/// One runtime serves every client and lives as long as the process.
pub(crate) fn shared() -> Result<&'static Runtime, CoreError> {
    // The runtime, and a lock to build it once.
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    static BUILDING: Mutex<()> = Mutex::new(());

    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    // Check again under the lock.
    let _building = BUILDING.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    // Build the runtime.
    let workers = std::thread::available_parallelism()
        .map_or(MIN_WORKERS, |n| n.get().clamp(MIN_WORKERS, MAX_WORKERS));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .thread_name("ktor-scion-rt")
        .build()
        .map_err(|error| {
            CoreError::Internal {
                message: format!("cannot start the runtime: {error}"),
            }
        })?;
    Ok(RUNTIME.get_or_init(|| runtime))
}

/// Aborts the task when the future that waits for it drops.
pub(crate) struct AbortOnDrop<T>(pub(crate) JoinHandle<T>);

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
