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

//! The Tokio runtime this crate owns, and the only three ways to reach it.
//!
//! UniFFI polls exported futures from foreign threads, which have no ambient Tokio runtime, so
//! nothing here may assume one: [`spawn`], [`spawn_detached`] and [`spawn_forget`] hand the work to
//! a runtime this crate created, and the future the foreign side polls does nothing but await the
//! result. See the crate documentation for why the runtime is owned rather than inherited.
//!
//! Those three take the runtime rather than looking it up, so that whoever holds one has already
//! established it exists. [`runtime`] is the only fallible step, and a caller does it once.
//!
//! One runtime, built on first use and never shut down. What that costs is two to four parked
//! worker threads for the rest of the process, which use no processor time and a few megabytes of
//! mostly untouched stack. The blocking pool is left at its default: it is a cap rather than an
//! allocation, threads spawn on demand and are reaped once idle, and it is where every endhost-API
//! hostname lookup runs, so capping it low would serialise the resolutions that discovery issues
//! concurrently. What it buys is the absence of a
//! teardown: no reference counting, no shutdown thread, no window in which a client is gone but its
//! runtime is not, and nothing for a foreign caller to observe or to race with.

use std::{
    any::Any,
    future::Future,
    io,
    pin::Pin,
    sync::{Mutex, OnceLock, PoisonError},
    task::{Context, Poll},
    thread,
};

use tokio::{
    runtime::{Builder, Runtime},
    task::{JoinError, JoinHandle},
};

use crate::error::Error;

/// Worker threads, whatever the machine reports.
///
/// The work is I/O-bound (one connection driver per pooled origin, bounded by `max_origins`), so
/// Tokio's default of one worker per core buys nothing on an eight-core phone and reserves a stack
/// for each.
const MIN_WORKERS: usize = 2;
const MAX_WORKERS: usize = 4;

/// Thread name for the runtime's workers.
///
/// Linux caps a thread name at 15 characters and truncates silently, so this is short enough to
/// survive into `/proc/self/task/*/comm`, where it is the only evidence of these threads: they are
/// plain operating-system threads that never attach to a foreign language's runtime, so a foreign
/// caller cannot enumerate them.
const WORKER_THREAD_NAME: &str = "scion-h3-rt";

/// The runtime, once something has needed one.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Held while the runtime is being built.
///
/// `OnceLock` alone would let two threads build one each and drop the loser, and dropping a runtime
/// is the operation with all the caveats: it blocks, and it panics outright inside another runtime.
/// Building under a lock means the loser is never built.
static BUILDING: Mutex<()> = Mutex::new(());

/// Returns the runtime, building it if this is the first call to need one.
///
/// Fallible because building one is: it asks the operating system for threads and for an event
/// queue. Reported rather than panicked, so that a machine at its limits gives the caller an error
/// instead of taking the host process down.
pub(crate) fn runtime() -> Result<&'static Runtime, Error> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    // A poisoned lock here means a previous caller panicked while building. There is no state to
    // protect beyond the OnceLock, which is sound either way, so recovering beats propagating a
    // panic across the FFI boundary.
    let _building = BUILDING.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    let built = build()
        .map_err(|error| Error::internal(format!("starting the SCION runtime failed: {error}")))?;
    // Cannot run the closure for anyone else: nothing else can be past the check above while this
    // holds the lock.
    Ok(RUNTIME.get_or_init(|| built))
}

fn build() -> io::Result<Runtime> {
    Builder::new_multi_thread()
        // The time driver backs every deadline in scion-http3, and the I/O driver backs both the
        // UDP sockets and the endhost API's TCP. Without either, the first request hangs.
        .enable_all()
        .worker_threads(worker_threads())
        .thread_name(WORKER_THREAD_NAME)
        .build()
}

fn worker_threads() -> usize {
    thread::available_parallelism().map_or(MIN_WORKERS, |n| n.get().clamp(MIN_WORKERS, MAX_WORKERS))
}

/// Runs `work` on the runtime and awaits its result, aborting it if the returned future is dropped.
///
/// This is the shape every cancellable export uses, and the reason for it is the whole runtime
/// strategy: dropping the returned future is how a cancelled foreign call reaches us, and aborting
/// the task means the request future is dropped on a worker rather than on the thread that dropped
/// it, which for a caller that cancels can be a user-interface thread.
pub(crate) async fn spawn<F, T>(runtime: &'static Runtime, work: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>> + Send + 'static,
    T: Send + 'static,
{
    match AbortOnDrop(runtime.spawn(work)).await {
        Ok(result) => result,
        // Let UniFFI's catch_unwind report it, with the original payload, rather than flattening a
        // panic into an ordinary error the caller might retry.
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        // The runtime is never shut down, so a cancelled JoinError can only be this future's own
        // abort, which means nothing is left to return the result to.
        Err(_) => Err(Error::internal("the request was cancelled")),
    }
}

/// Runs `work` on the runtime and awaits its completion, letting it finish even if the returned
/// future is dropped.
///
/// The counterpart to [`spawn`], for the teardown paths: a foreign caller that cancels the call it
/// invoked `shutdown` from must not thereby cancel the shutdown.
pub(crate) async fn spawn_detached<F>(runtime: &'static Runtime, work: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    // Dropping a JoinHandle detaches its task, which is the behaviour wanted here.
    if let Err(join) = runtime.spawn(work).await
        && join.is_panic()
    {
        std::panic::resume_unwind(join.into_panic());
    }
}

/// Runs `work` on the runtime without awaiting it at all.
///
/// For a destructor, which cannot await and has nowhere to report to. The runtime is never shut
/// down, so work started this way runs to completion whatever happens to whoever started it.
///
/// Nothing awaits the handle, so a panic here has no caller to surface at, and logging it is the
/// whole of what can be done.
///
/// Note that nothing in this crate or the bindings above it installs a `tracing` subscriber, so the
/// record below reaches nowhere as things stand and the default panic hook's stderr is the only
/// signal. It is written for whoever installs one, which the library that owns the host process is
/// the right place to do; the same is true of every other `tracing` call in this crate.
pub(crate) fn spawn_forget<F>(runtime: &'static Runtime, work: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    // Awaited from a second task rather than wrapped in a catch_unwind, so that this needs no
    // unwind-safety assertion and no extra dependency: a JoinHandle already carries the payload.
    let handle = runtime.spawn(work);
    drop(runtime.spawn(async move {
        if let Err(join) = handle.await
            && join.is_panic()
        {
            tracing::error!(
                panic = panic_message(&*join.into_panic()),
                "a detached task panicked; it had no caller to report to"
            );
        }
    }));
}

/// The message from a panic payload, for the two shapes `panic!` produces.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

/// Awaits a spawned task, aborting it if this future is dropped first.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        // A no-op once the task has finished, so this needs no "did it complete" bookkeeping.
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering::SeqCst},
            mpsc,
        },
        time::Duration,
    };

    use super::*;

    /// Guards the invariant the whole module exists for: the exported future must be pollable from
    /// a thread that knows nothing about Tokio, because that is the only kind of thread UniFFI
    /// polls it from.
    #[test]
    fn work_runs_when_polled_without_an_ambient_runtime() {
        let result = thread::spawn(|| {
            let runtime = runtime().expect("building a runtime");
            futures::executor::block_on(spawn(runtime, async {
                // A timer, because it needs the runtime the polling thread does not have.
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(42)
            }))
        })
        .join()
        .expect("the polling thread panicked");

        assert_eq!(result.expect("the work failed"), 42);
    }

    /// The one branch of `spawn` that does not return: a panic in spawned work is re-raised on the
    /// awaiting side, so UniFFI's catch_unwind reports it with the original payload rather than the
    /// caller seeing an ordinary error it might retry.
    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn a_panic_in_spawned_work_reaches_the_caller() {
        let _: Result<(), Error> = spawn(runtime().expect("building a runtime"), async {
            panic!("boom")
        })
        .await;
    }

    /// Dropping the exported future must abort the work rather than detach it: this is the
    /// mechanism a cancelled foreign call reaches, wherever its bindings drop the future on
    /// cancellation, and the reason no cancellation handle is needed for those that do.
    #[tokio::test]
    async fn dropping_the_future_aborts_the_work() {
        let completed = Arc::new(AtomicBool::new(false));

        let flag = completed.clone();
        // By value, so that the timeout owns the future and drops it when it elapses. A pinned
        // borrow would outlive the timeout and defer the abort to the end of this function.
        let work = spawn(runtime().expect("building a runtime"), async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            flag.store(true, SeqCst);
            Ok(())
        });
        tokio::time::timeout(Duration::from_millis(50), work)
            .await
            .expect_err("the work finished before it could be cancelled");

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !completed.load(SeqCst),
            "the aborted work ran to completion"
        );
    }

    /// *Where* the aborted work is dropped, which is the property the whole strategy exists for and
    /// the one nothing else checks.
    ///
    /// Under `async_runtime = "tokio"` the drop chain runs inline on the thread that freed the
    /// future, which for a caller that cancels can be a user-interface thread. Spawning and
    /// aborting moves it to a worker instead. Timing cannot tell the two apart, because a real
    /// teardown takes well under a millisecond either way; the thread it runs on can.
    #[tokio::test]
    async fn cancelled_work_is_torn_down_on_a_worker() {
        let (tx, rx) = mpsc::channel();

        /// Reports the thread its owner is dropped on, standing in for the request future's own
        /// drop guards.
        struct ReportThread(mpsc::Sender<String>);

        impl Drop for ReportThread {
            fn drop(&mut self) {
                let name = thread::current().name().unwrap_or("<unnamed>").to_owned();
                let _ = self.0.send(name);
            }
        }

        let work = spawn(runtime().expect("building a runtime"), async move {
            let _report = ReportThread(tx);
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        });
        // Dropped by the timeout, which is what a foreign binding does to it on cancellation.
        tokio::time::timeout(Duration::from_millis(100), work)
            .await
            .expect_err("the work finished before it could be cancelled");

        // Blocking is fine here: the drop runs on the owned runtime, not on this test's.
        let thread = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the aborted work was never dropped");
        assert!(
            thread.starts_with(WORKER_THREAD_NAME),
            "the teardown ran on {thread}, not on a runtime worker"
        );
    }

    /// `shutdown` must survive its caller being cancelled, or a foreign caller that cancels the
    /// call it closed from would leave the pool open.
    #[tokio::test]
    async fn detached_work_survives_a_dropped_caller() {
        let completed = Arc::new(AtomicBool::new(false));

        let flag = completed.clone();
        let work = spawn_detached(runtime().expect("building a runtime"), async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            flag.store(true, SeqCst);
        });
        tokio::time::timeout(Duration::from_millis(10), work)
            .await
            .expect_err("the work finished before the caller was dropped");

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(completed.load(SeqCst), "the detached work was cancelled");
    }

    /// Every caller shares one runtime, however many ask for it and from wherever.
    #[test]
    fn the_runtime_is_built_once() {
        let first = runtime().expect("building a runtime");
        let second = thread::spawn(|| runtime().expect("the runtime from another thread"))
            .join()
            .expect("the other thread panicked");

        assert!(std::ptr::eq(first, second), "a second runtime was built");
    }
}
