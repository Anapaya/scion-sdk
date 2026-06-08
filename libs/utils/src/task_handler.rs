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
//! Utilities for managing tasks and subprocesses.

use tokio::{process::Child, task::JoinSet};
use tokio_util::sync::CancellationToken;

/// A in-process task set that is cancelled when dropped.
pub struct InProcess {
    /// Cancellable task set.
    pub task_set: CancelTaskSet,
}

impl InProcess {
    /// Creates a new in-process task set.
    pub fn new(task_set: CancelTaskSet) -> Self {
        Self { task_set }
    }
}

impl Drop for InProcess {
    fn drop(&mut self) {
        self.task_set.cancellation_token().cancel();
    }
}

/// A subprocess that is killed when dropped.
pub struct Subprocess {
    /// The child process.
    pub child: Child,
}

impl Subprocess {
    /// Creates a new subprocess.
    pub fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for Subprocess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.try_wait();
    }
}

/// A combination of a [tokio::task::JoinSet] and
/// [tokio_util::sync::CancellationToken].
///
/// Provides methods that are commonly used in conjunction with those two data
/// structures.
pub struct CancelTaskSet {
    /// Task set join set.
    pub join_set: JoinSet<Result<(), std::io::Error>>,
    cancellation_token: CancellationToken,
}

impl CancelTaskSet {
    /// Creates a new task set.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let cancellation_token = CancellationToken::new();
        Self::from_cancel_token(false, cancellation_token)
    }

    /// Creates a task set and registers a signal handler that calls `cancel()`
    /// on the cancellation token upon receiving `SIGINT` and `SIGTERM`.
    pub fn new_with_signal_handler() -> Self {
        let cancellation_token = CancellationToken::new();
        Self::from_cancel_token(true, cancellation_token)
    }

    /// Creates a task set from an existing cancellation token.
    ///
    /// # Arguments
    /// * `register_signal_handler`: If true, a signal handler is registered that calls `cancel()`
    ///   on the cancellation token upon receiving `SIGINT` and `SIGTERM`.
    /// * `cancellation_token`: The cancellation token to use.
    pub fn from_cancel_token(
        register_signal_handler: bool,
        cancellation_token: CancellationToken,
    ) -> Self {
        let mut join_set = JoinSet::new();
        if register_signal_handler {
            Self::spawn_shutdown_handler(&mut join_set, cancellation_token.clone());
        }
        CancelTaskSet {
            join_set,
            cancellation_token,
        }
    }

    /// Creates a task set from the given parts. Without registering a signal handler.
    pub fn new_from_parts(
        join_set: JoinSet<Result<(), std::io::Error>>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            join_set,
            cancellation_token,
        }
    }

    /// Decomposes the task set into its parts.
    ///
    /// This will cause the task set to stop managing the tasks and cancellation token, and the
    /// caller will be responsible for managing them.
    pub fn into_parts(mut self) -> (JoinSet<Result<(), std::io::Error>>, CancellationToken) {
        // TODO: this is a hack, only acceptable since CancelTaskSet will be removed soon.
        let new_set = JoinSet::new();
        let join_set = std::mem::replace(&mut self.join_set, new_set);
        let new_token = CancellationToken::new();
        let cancellation_token = std::mem::replace(&mut self.cancellation_token, new_token);

        (join_set, cancellation_token)
    }

    /// Returns a clone of the cancellation token.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    fn spawn_shutdown_handler(
        join_set: &mut JoinSet<Result<(), std::io::Error>>,
        cancellation_token: CancellationToken,
    ) {
        join_set.spawn(async move {
            #[cfg(target_family = "unix")]
            {
                use tokio::signal::unix::{SignalKind, signal};

                let mut sigint =
                    signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = sigint.recv() => {
                        tracing::debug!("Received SIGINT, cancelling token");
                        cancellation_token.cancel();
                    },
                    _ = sigterm.recv() => {
                        tracing::debug!("Received SIGTERM, cancelling token");
                        cancellation_token.cancel();
                    },
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Cancellation token cancelled, exiting shutdown handler");
                    },
                }
            }

            #[cfg(target_family = "windows")]
            {
                use tokio::signal::windows;

                let mut ctrl_c = windows::ctrl_c().expect("failed to register CTRL-C handler");
                let mut ctrl_break =
                    windows::ctrl_break().expect("failed to register CTRL-BREAK handler");

                tokio::select! {
                    _ = ctrl_c.recv() => {
                        tracing::debug!("Received CTRL-C, cancelling token");
                        cancellation_token.cancel();
                    },
                    _ = ctrl_break.recv() => {
                        tracing::debug!("Received CTRL-BREAK, cancelling token");
                        cancellation_token.cancel();
                    },
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Cancellation token cancelled, exiting shutdown handler");
                    },
                }
            }

            Ok(())
        });
    }

    /// Spawns a task that will run until it is cancelled or completes.
    pub fn spawn_cancellable_task<Fut>(&mut self, task: Fut)
    where
        Fut: Future<Output = Result<(), std::io::Error>> + Send + 'static,
    {
        let token = self.cancellation_token();
        self.join_set.spawn(async move {
            match token.run_until_cancelled(task).await {
                Some(Ok(_)) => Ok(()),  // task completed successfully
                Some(Err(e)) => Err(e), // task failed
                None => Ok(()),         // task was successfully cancelled
            }
        });
    }

    /// Joins all tasks in the set. If any task fails to join or returns an error, cancel the token
    /// to signal a graceful shutdown to the remaining tasks.
    pub async fn join_all(&mut self) {
        while let Some(result) = self.join_set.join_next().await {
            match result {
                Ok(Ok(())) => {} // Task completed successfully
                Ok(Err(e)) => {
                    tracing::error!(error=%e, "Task failed");
                    self.cancellation_token.cancel();
                }
                Err(e) => {
                    tracing::error!(error=%e, "Task join failed");
                    self.cancellation_token.cancel();
                }
            }
        }
    }
}

impl Drop for CancelTaskSet {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
        self.join_set.abort_all();
    }
}
