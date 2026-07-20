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

//! An individual HTTP/3 request stream and its two halves (request and response).
//!
//! The two directional halves live in the `request` (write) and `response` (read)
//! submodules; `duplex` fuses them into a single [`H3DuplexStream`] for
//! `CONNECT`-tunnel byte streaming.

mod duplex;
mod request;
mod response;

use std::sync::Arc;

pub use duplex::H3DuplexStream;
pub use request::RequestBodyWriter;
use request::{WriteGuard, request_headers};
use response::ReadGuard;
pub use response::{H3ResponseBody, ResponseFut};

use crate::{
    h3::client::{
        app::{Http3ClientApp, register_stream},
        error::RequestError,
    },
    quic::connection::{ConnectionHandle, QuicScionConn, WeakConnectionHandle},
};

/// Opens a new request stream and returns its two halves.
///
/// Sends the request head on a fresh stream (without a FIN), registers the
/// per-stream read/write and head-routing state, and returns a [`ResponseFut`]
/// that resolves once the response head arrives plus a [`RequestBodyWriter`] that
/// streams the request body. The write side is never finished implicitly — the
/// caller drives the body and finishes it explicitly.
pub(crate) fn initiate_request(
    handle: &ConnectionHandle<Http3ClientApp>,
    req: http::Request<()>,
) -> Result<(ResponseFut, RequestBodyWriter), RequestError> {
    let (parts, ()) = req.into_parts();
    let headers = request_headers(&parts);

    let stream_id = {
        let mut guard = handle.lock();
        let QuicScionConn { inner, app, .. } = &mut *guard;
        let Some(h3) = app.h3.as_mut() else {
            return Err(RequestError::ConnectionClosed);
        };
        match h3.send_request(inner, &headers, false) {
            Ok(stream_id) => {
                register_stream(app, stream_id);
                stream_id
            }
            Err(squiche::h3::Error::StreamBlocked) => return Err(RequestError::StreamBlocked),
            Err(err) => return Err(RequestError::H3(err)),
        }
    };
    handle.notify();

    let stream_ref = StreamRef::new(handle.downgrade(), stream_id);
    let response = ResponseFut::new(ReadGuard::new(stream_ref.clone()));
    let writer = RequestBodyWriter::new(WriteGuard::new(stream_ref));
    Ok((response, writer))
}

/// Shared lifetime token for one client stream, cloned into every handle that
/// references the stream — its read half ([`ReadGuard`], carried by the response
/// future and then [`H3ResponseBody`]) and its write half ([`WriteGuard`], carried
/// by the request-body sender). When the **last** clone drops, the per-stream
/// bookkeeping — the shared `streams` entry plus the client-only `response_heads`
/// entry — is released.
///
/// Directional teardown (read `STOP_SENDING`, write `RESET_STREAM`) is performed
/// by the guards as each half drops; this token only collects the map entries,
/// and only once both halves are gone, so neither half can strand the other's
/// wakers.
pub(crate) struct StreamRef {
    handle: WeakConnectionHandle<Http3ClientApp>,
    stream_id: u64,
}

impl StreamRef {
    pub(crate) fn new(handle: WeakConnectionHandle<Http3ClientApp>, stream_id: u64) -> Arc<Self> {
        Arc::new(Self { handle, stream_id })
    }

    /// A weak handle to the owning connection.
    pub(crate) fn handle(&self) -> WeakConnectionHandle<Http3ClientApp> {
        self.handle.clone()
    }

    /// The stream this token governs.
    pub(crate) fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Drop for StreamRef {
    fn drop(&mut self) {
        let Some(handle) = self.handle.upgrade() else {
            return;
        };
        let mut guard = handle.lock_recovering();
        guard.app.streams.remove(&self.stream_id);
        guard.app.response_heads.remove(&self.stream_id);
    }
}
