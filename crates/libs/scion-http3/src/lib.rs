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

//! # SCION HTTP/3 client
//!
//! A high-level HTTP/3-over-SCION client: give it a URL, get a response.
//!
//! ## Features
//!
//! - SCION connectivity, discovered through an endhost API
//! - TSAR DNS resolution (SCION addresses from DNS TXT records)
//! - Per-origin connection pooling
//! - Staggered multi-candidate connection establishment ([RFC 8305], Happy Eyeballs)
//! - Connect, request, and idle-connection timeouts
//! - Recovery from network changes
//!
//! The transport engine underneath is [`scion_quic::h3::client::Http3Client`]. It stays
//! available for callers that need transport-level control.
//!
//! ## Usage
//!
//! Issue a GET request with the [`Client::get`] shorthand (see also [`Client::post`]):
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use scion_http3::{Client, Config};
//!
//! /// Cap on a collected response body.
//! const MAX_BODY_SIZE: usize = 1 << 20;
//!
//! let client = Client::new(
//!     Config::new("https://endhost-api.example.org".parse()?).with_auth_token("token"),
//! );
//! let response = client.get("https://chat.example.org/rooms").await?;
//! let (rooms, _trailers) = response.text(Some(MAX_BODY_SIZE)).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Or build a [`Request`] from scratch and issue it with [`Client::request`]:
//!
//! ```no_run
//! # async fn example(client: scion_http3::Client) -> Result<(), Box<dyn std::error::Error>> {
//! use scion_http3::Request;
//!
//! let request = Request::post("https://chat.example.org/messages")
//!     .header("content-type", "application/json")
//!     .body(r#"{"room":"general","text":"hi"}"#)
//!     .build()?;
//! let response = client.request(request).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Connection pooling and lifecycle
//!
//! A [`Client`] holds a connection pool, so create one client per application and share it.
//!
//! Construction does no I/O: connections are established lazily on first use and then reused
//! per origin. Use [`Client::warm_up`] to establish a connection before the first request.
//!
//! [`Client::close`] closes all pooled connections and frees their resources. Calling it
//! before dropping the client is optional.
//!
//! ## Network changes
//!
//! Call [`Client::reset`] when the network below the client changes, for example when the
//! platform reports a switch from Wi-Fi to mobile data. The call never blocks: it marks the
//! current connections stale, and the next request tears them down and rebuilds connectivity.
//!
//! ## Error handling
//!
//! Every request-path failure surfaces as one error type, [`Error`]. To decide whether to
//! retry a failed request, use [`Error::is_retryable`] instead of matching variants.
//! A retryable error does not imply the request never reached the server, so retry
//! non-idempotent requests with care.
//!
//! [RFC 8305]: https://datatracker.ietf.org/doc/html/rfc8305

// Linter baseline for the published API surface.
#![warn(clippy::pedantic)]
#![allow(
    // The module path deliberately echoes type names where a module has one main type.
    clippy::module_name_repetitions,
    // `#[must_use]` is applied deliberately where it matters rather than everywhere.
    clippy::must_use_candidate,
    // `# Errors` / `# Panics` sections are added where they aid the caller, not mechanically.
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

mod client;
mod config;
mod epoch;
mod error;
mod establish;
mod origin;
mod pool;
mod request;
mod response;
#[cfg(test)]
mod test_support;

// Re-exported dependencies
//
// These crates appear in `scion-http3`'s public API by deliberate choice. They are re-exported
// here so a client can name and construct the types our signatures require without adding
// its own direct dependency.
/// Body bytes ([`bytes::Bytes`]) used for request bodies and collected response bodies.
pub use bytes;
pub use client::Client;
pub use config::{
    Config, DEFAULT_CONNECT_TIMEOUT, DEFAULT_CONNECTION_ATTEMPT_DELAY,
    DEFAULT_IDLE_CONNECTION_TIMEOUT, DEFAULT_MAX_ORIGINS, DEFAULT_REQUEST_TIMEOUT,
};
pub use error::{BuildRequestError, Error, TimeoutPhase};
/// HTTP vocabulary types ([`http::Method`], [`http::HeaderMap`], [`http::StatusCode`]) used by
/// requests and responses.
pub use http;
pub use request::{IntoUrl, Request, RequestBuilder};
pub use response::Response;
/// The transport engine. Its types appear in this API as the QUIC configuration
/// ([`scion_quic::quic::config::QuicConfig`], see [`Config::with_quic_config`]).
pub use scion_quic;
/// The SCION stack. Its types appear in this API as the builder passthroughs
/// ([`Config::with_preferred_underlay`], [`Config::with_stack_customizer`]) and the resolver
/// escape hatch ([`Config::with_resolver`]).
pub use scion_stack;
/// Authentication token plumbing for [`Config::with_auth_token_source`]: implement
/// [`TokenSource`] to supply tokens that expire; [`StaticTokenSource`] wraps a fixed one.
pub use scion_stack::reqwest_connect_rpc::token_source::{
    TokenSource, TokenSourceError, TokenSourceWatch, static_token::StaticTokenSource,
};
/// SCION address types ([`sciparse::address::ip_addr::ScionIpAddr`]) used by the
/// [`RequestBuilder::target`] / [`RequestBuilder::targets`] escape hatches.
pub use sciparse;
/// URL type used for request URLs and the endhost API address.
pub use url;
