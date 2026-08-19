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

//! The exported client: construction, requests, and shutdown.
//!
//! One object holding a [`scion_http3::Client`] and a reference to the owned runtime. Each method
//! converts its arguments, hands the work to the runtime, and converts what comes back. What a
//! request *does* lives in `scion-http3`.
//!
//! Every asynchronous method here has the same body: translate, hand the work to the owned runtime
//! through [`runtime::spawn`], and await it. That shape is the crate's contract with UniFFI rather
//! than a style choice: the future the foreign side polls runs on a thread with no Tokio runtime,
//! so nothing that needs one may be awaited in it. Adding a `tokio::time::sleep` or a
//! `tokio::spawn` to one of these bodies compiles and then panics at the boundary;
//! `tests/no_runtime_context.rs` exists to catch that.

use std::sync::Arc;

use scion_http3::Client;
use tokio::runtime::Runtime;

use crate::{
    convert::collect_response,
    error::Error,
    runtime,
    token::AuthToken,
    types::{ClientConfig, HttpRequest, HttpResponse},
};

/// An HTTP/3-over-SCION client.
///
/// Construction performs no network I/O; the first request builds connectivity. Thread-safe,
/// cheap to hold, and meant to live as long as the application: it owns a connection pool, and one
/// client per request would throw away every connection it opened.
#[derive(uniffi::Object)]
pub struct ScionHttp3Client {
    inner: Arc<Client>,
    /// Held rather than looked up per call, so that every path here has the runtime's existence in
    /// hand instead of having to consider its absence. Its lifetime is the process's.
    runtime: &'static Runtime,
    /// The client-wide response-body limit, used for requests that do not carry their own.
    max_response_body_bytes: u64,
    /// The token every request authenticates with, or `None` for a client configured without one.
    auth_token: Option<Arc<AuthToken>>,
}

#[uniffi::export]
impl ScionHttp3Client {
    /// Creates a client from `config`.
    #[uniffi::constructor]
    pub fn new(config: ClientConfig) -> Result<Arc<Self>, Error> {
        // Endhost API discovery speaks TLS through rustls, which refuses to build a client
        // configuration until a provider is installed. Doing it here means the first request
        // cannot fail for a reason that has nothing to do with it.
        scion_sdk_utils::rustls::select_ring_crypto_provider();

        let max_response_body_bytes = config.max_response_body_bytes;
        // Created before the configuration so that the configuration can hold a handle to it, which
        // is what lets `set_auth_token` reach connectivity that has already been built.
        let auth_token = config.auth_token.clone().map(AuthToken::new).map(Arc::new);
        let config = config.into_client_config(auth_token.as_ref().map(AuthToken::shared))?;
        // Built here rather than on the first request, so that a machine which cannot start it says
        // so while the caller is still constructing rather than at some later request. This is the
        // only place that can fail on its account.
        let runtime = runtime::runtime()?;

        Ok(Arc::new(ScionHttp3Client {
            inner: Arc::new(Client::new(config)),
            runtime,
            max_response_body_bytes,
            auth_token,
        }))
    }

    /// Issues `request` and returns the response with its body collected.
    ///
    /// Dropping this call on the foreign side cancels the request on the wire: the stream is reset,
    /// the connection stays usable, and the teardown runs on a runtime thread rather than on the
    /// thread that dropped it. Whether cancelling a call drops it is a property of the generated
    /// bindings for that language.
    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let max_body_bytes = request
            .max_response_body_bytes
            .unwrap_or(self.max_response_body_bytes);
        // Before the work is handed over, so that a request the caller got wrong is reported
        // without starting anything.
        let request = request.into_request()?;

        let client = self.inner.clone();
        runtime::spawn(self.runtime, async move {
            let response = client.request(request).await?;
            collect_response(response, max_body_bytes).await
        })
        .await
    }

    /// Replaces the token used to authenticate with the endhost API and the SNAP control plane.
    ///
    /// Not a header on the requests this client issues: those carry whatever the [`HttpRequest`]
    /// says. This is the credential the stack presents to the infrastructure it discovers
    /// connectivity through.
    ///
    /// Synchronous, and takes effect on the next request rather than on those already in flight.
    /// Connectivity built earlier keeps working: the token lives in a channel the client owns, so
    /// it survives the rebuild that follows a network change or a [`reset`](Self::reset).
    ///
    /// Fails if the client was built without `auth_token`, since there is then nothing to replace
    /// and nothing reading a token; construct a client with one instead.
    pub fn set_auth_token(&self, token: String) -> Result<(), Error> {
        match &self.auth_token {
            Some(auth_token) => {
                auth_token.set(token);
                Ok(())
            }
            None => {
                Err(Error::invalid_request(
                    "this client was built without an auth_token, so there is no token to replace",
                ))
            }
        }
    }

    /// Establishes connectivity to `url`'s origin ahead of the first request to it.
    pub async fn warm_up(&self, url: String) -> Result<(), Error> {
        let client = self.inner.clone();
        runtime::spawn(self.runtime, async move {
            client.warm_up(url).await.map_err(Error::from)
        })
        .await
    }

    /// Marks connectivity stale, so that the next request rebuilds the stack and its connections.
    ///
    /// Returns immediately and does no work of its own. Call it when the network underneath the
    /// client changed.
    pub fn reset(&self) {
        self.inner.reset();
    }

    /// Closes the connection pool, faulting in-flight requests; later requests fail as closed.
    ///
    /// Idempotent. A caller cancelled while this runs still gets its pool closed, because the close
    /// is spawned and then awaited rather than run inline. A caller cancelled before the call is
    /// ever polled never starts one, and there the object's own disposal closes the pool instead.
    pub async fn shutdown(&self) {
        let client = self.inner.clone();
        runtime::spawn_detached(self.runtime, async move { client.close().await }).await;
    }
}

impl Drop for ScionHttp3Client {
    fn drop(&mut self) {
        // Destroying the foreign object is a synchronous call on whichever thread the caller used,
        // and closing a pool is asynchronous, so the close is handed to the runtime. Without it, a
        // client that is dropped rather than shut down leaves its peers waiting out the QUIC idle
        // timeout instead of receiving a CONNECTION_CLOSE.
        //
        // Fire and forget, and it outlives this object: the runtime is never shut down, so there is
        // nothing for the close to race against.
        let client = self.inner.clone();
        runtime::spawn_forget(self.runtime, async move { client.close().await });
    }
}
