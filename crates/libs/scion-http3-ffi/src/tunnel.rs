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

//! A byte stream through a `CONNECT` tunnel.
//!
//! One object holding the read and write halves of a [`scion_http3::Tunnel`] and a reference to the
//! owned runtime. The halves are independent, so a read and a write can run at the same time from
//! two foreign callers. Every asynchronous method has the shape the `client` module describes: the
//! work runs on the owned runtime and the future the foreign side polls awaits nothing but the
//! result.

use std::{fmt, future::Future, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    runtime::Runtime,
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::{
    cancel::{CancelHandle, cancellable},
    error::Error,
    runtime,
};

/// One read returns at most one DATA frame, which the transport caps well below this, so a larger
/// buffer would be allocated and never filled.
const MAX_READ_BYTES: usize = 64 * 1024;

/// What a call on a tunnel that `abort` has closed reports.
const ABORTED: &str = "the tunnel was aborted";

/// Rejects a read that cannot mean anything before a task is spawned for it.
fn check_max(max: u32) -> Result<(), Error> {
    if max == 0 {
        return Err(Error::invalid_request(
            "a read of zero bytes is not possible: an empty result means the end of the stream",
        ));
    }
    Ok(())
}

/// A byte stream through an accepted `CONNECT` tunnel.
///
/// The read and the write direction are independent: a read and a write can run at the same
/// time. [`shutdown_write`](Self::shutdown_write) ends the write direction while reads
/// continue. A read returns an empty vector at the end of the stream.
///
/// Dropping the tunnel, or calling [`abort`](Self::abort), resets the stream.
///
/// A tunnel does not keep its client alive. Shutting the client down, or dropping it, closes the
/// connection under every tunnel it opened and their calls report
/// [`Closed`](crate::ScionHttp3Error::Closed) from then on.
///
/// Dropping a pending `read` or `write` call (a cancelled foreign call) ends that call on a
/// runtime worker and leaves the tunnel open. Two things are lost with the call: a read that
/// completed in the same moment loses its bytes and a write may have sent partial data.
/// A caller that cancels a read or a write must therefore treat the tunnel as unusable and abort
/// it. [`read_cancellable`](Self::read_cancellable) and
/// [`write_cancellable`](Self::write_cancellable) do not have the read loss: their cancellation is
/// decided on the runtime, where a completed read wins against it.
#[derive(uniffi::Object)]
pub struct Tunnel {
    shared: Arc<Shared>,
    runtime: &'static Runtime,
}

/// What the spawned tasks share with the object.
struct Shared {
    /// `None` once `abort` took the half away.
    reader: Mutex<Option<ReadHalf<scion_http3::Tunnel>>>,
    writer: Mutex<WriteState>,
    /// Fired by `abort` and by `Drop`. Every call in flight ends when it fires.
    aborted: CancellationToken,
    /// Fired when the client that opened the tunnel is shut down or dropped.
    client_closed: CancellationToken,
}

/// The write direction over its life.
enum WriteState {
    Open(WriteHalf<scion_http3::Tunnel>),
    /// `shutdown_write` ended the direction.
    Shut,
    /// `abort` took the half away.
    Closed,
}

#[uniffi::export]
impl Tunnel {
    /// Reads up to `max` bytes. Returns an empty vector at the end of the stream.
    ///
    /// One call returns at most one DATA frame, so the result is often shorter than `max`. `max`
    /// must be greater than zero, because an empty result means the end of the stream.
    pub async fn read(&self, max: u32) -> Result<Vec<u8>, Error> {
        check_max(max)?;
        let shared = self.shared.clone();
        runtime::spawn(self.runtime, async move { shared.read(max).await }).await
    }

    /// Reads as [`read`](Self::read) does and stops when `cancel` fires.
    pub async fn read_cancellable(
        &self,
        max: u32,
        cancel: Arc<CancelHandle>,
    ) -> Result<Vec<u8>, Error> {
        check_max(max)?;
        let shared = self.shared.clone();
        let token = cancel.token();
        runtime::spawn(self.runtime, async move {
            cancellable(token, shared.read(max)).await
        })
        .await
    }

    /// Writes all of `data`.
    pub async fn write(&self, data: Vec<u8>) -> Result<(), Error> {
        let shared = self.shared.clone();
        runtime::spawn(self.runtime, async move { shared.write(&data).await }).await
    }

    /// Writes as [`write`](Self::write) does and stops when `cancel` fires. A cancelled write may
    /// have sent a prefix of `data`.
    pub async fn write_cancellable(
        &self,
        data: Vec<u8>,
        cancel: Arc<CancelHandle>,
    ) -> Result<(), Error> {
        let shared = self.shared.clone();
        let token = cancel.token();
        runtime::spawn(self.runtime, async move {
            cancellable(token, shared.write(&data)).await
        })
        .await
    }

    /// Ends the write direction: the peer sees the end of the stream and reads continue.
    ///
    /// Idempotent. A later `write` reports
    /// [`TunnelClosed`](crate::ScionHttp3Error::TunnelClosed).
    pub async fn shutdown_write(&self) -> Result<(), Error> {
        let shared = self.shared.clone();
        runtime::spawn(self.runtime, async move { shared.shutdown_write().await }).await
    }

    /// Resets the stream and ends every call in flight with
    /// [`TunnelClosed`](crate::ScionHttp3Error::TunnelClosed).
    ///
    /// Returns immediately and never fails. Idempotent and also what dropping the tunnel does.
    /// Every later call reports `TunnelClosed`.
    pub fn abort(&self) {
        self.abort_inner();
    }
}

impl Tunnel {
    pub(crate) fn new(
        tunnel: scion_http3::Tunnel,
        runtime: &'static Runtime,
        client_closed: CancellationToken,
    ) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(tunnel);
        Arc::new(Tunnel {
            shared: Arc::new(Shared {
                reader: Mutex::new(Some(reader)),
                writer: Mutex::new(WriteState::Open(writer)),
                aborted: CancellationToken::new(),
                client_closed,
            }),
            runtime,
        })
    }

    fn abort_inner(&self) {
        if self.shared.aborted.is_cancelled() {
            return;
        }
        self.shared.aborted.cancel();
        // The halves are dropped on a worker only once the calls in flight have released them.
        let shared = self.shared.clone();
        runtime::spawn_forget(self.runtime, async move {
            let reader = shared.reader.lock().await.take();
            let writer = std::mem::replace(&mut *shared.writer.lock().await, WriteState::Closed);
            drop((reader, writer));
        });
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.abort_inner();
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel")
            .field("aborted", &self.shared.aborted.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Shared {
    async fn read(&self, max: u32) -> Result<Vec<u8>, Error> {
        self.until_aborted(async {
            let mut guard = self.reader.lock().await;
            let Some(reader) = guard.as_mut() else {
                return Err(Error::tunnel_closed(ABORTED));
            };
            let capacity = usize::try_from(max)
                .unwrap_or(usize::MAX)
                .min(MAX_READ_BYTES);
            let mut buf = Vec::with_capacity(capacity);
            reader.read_buf(&mut buf).await.map_err(Error::from_io)?;
            Ok(buf)
        })
        .await
    }

    async fn write(&self, data: &[u8]) -> Result<(), Error> {
        self.until_aborted(async {
            let mut guard = self.writer.lock().await;
            match &mut *guard {
                WriteState::Open(writer) => {
                    writer.write_all(data).await.map_err(Error::from_io)?;
                    writer.flush().await.map_err(Error::from_io)
                }
                WriteState::Shut => Err(Error::tunnel_closed("the write direction was shut down")),
                WriteState::Closed => Err(Error::tunnel_closed(ABORTED)),
            }
        })
        .await
    }

    async fn shutdown_write(&self) -> Result<(), Error> {
        self.until_aborted(async {
            let mut guard = self.writer.lock().await;
            match &mut *guard {
                WriteState::Open(writer) => {
                    // The direction is over whether the end of the stream went out or not.
                    let result = writer.shutdown().await.map_err(Error::from_io);
                    *guard = WriteState::Shut;
                    result
                }
                WriteState::Shut => Ok(()),
                WriteState::Closed => Err(Error::tunnel_closed(ABORTED)),
            }
        })
        .await
    }

    /// Runs `work` unless, or until, the tunnel is aborted or its client is closed.
    async fn until_aborted<T>(
        &self,
        work: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        if self.aborted.is_cancelled() {
            return Err(Error::tunnel_closed(ABORTED));
        }
        if self.client_closed.is_cancelled() {
            return Err(Error::client_closed());
        }
        let result = tokio::select! {
            biased;
            result = work => result,
            () = self.aborted.cancelled() => Err(Error::tunnel_closed(ABORTED)),
            () = self.client_closed.cancelled() => Err(Error::client_closed()),
        };
        // Closing the client closes the connection under the tunnel, and that failure can win
        // the race against the token. The cause is reported, not the symptom.
        match result {
            Err(Error::TunnelDisconnected { .. }) if self.client_closed.is_cancelled() => {
                Err(Error::client_closed())
            }
            other => other,
        }
    }
}
