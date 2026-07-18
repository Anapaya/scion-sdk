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
//! SCION stack library.
//!
//! See `API_CONVENTIONS.md` for the naming, error, builder, and `#[non_exhaustive]` conventions
//! this crate follows.

// Linter baseline for the published API surface. See API_CONVENTIONS.md § Linting.
#![warn(clippy::pedantic)]
#![allow(
    // The module path deliberately echoes type names (e.g. `stack::ScionStack`).
    clippy::module_name_repetitions,
    // `#[must_use]` is applied deliberately where it matters rather than everywhere.
    clippy::must_use_candidate,
    // `# Errors` / `# Panics` sections are added where they aid the caller, not mechanically.
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    // Casts are used deliberately in scoring/serialization hot paths.
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    // `const`/`fn` items declared next to their use inside a function body read fine here.
    clippy::items_after_statements,
    // The following are stylistic preferences we deliberately do not enforce; the underlying code
    // is intentional (object-safe `BoxFuture` trait methods, stateless scorer `&self`, explicit
    // `match`/`if let` control flow, intentional score equality checks, fixed-size datagram
    // buffers).
    clippy::manual_async_fn,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::unused_self,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::ref_option,
    clippy::large_stack_arrays,
    clippy::float_cmp,
    clippy::unnecessary_wraps
)]

pub mod ea_source;
pub mod path;
pub mod resolver;
pub mod stack;
pub mod underlays;

pub(crate) mod internal;

// Re-exported dependencies
//
// These crates appear in `scion-stack`'s public API by deliberate choice. They are re-exported here
// so a client can name and construct the types our signatures require *without* adding its own
// direct dependency — which keeps the client pinned to exactly the versions `scion-stack` was built
// against. Reach a type through `scion_stack::<crate>::...`.
//
// Adding a crate to this list is a semver commitment: a breaking release of a re-exported crate is
// a breaking change for `scion-stack`. Do not re-export a crate here unless a type from it is
// intentionally part of the public API. Conversely, no foreign type may appear in a public
// signature without its crate being re-exported here (see the "Dependency exposure" section of
// `API_CONVENTIONS.md`). `tests/public_api_reexports.rs` pins these re-exports so they cannot be
// dropped silently.
/// Endhost API client trait consumed by [`path::fetcher::EndhostApiSegmentFetcher::new`].
pub use endhost_api_client;
/// Endhost API discovery models (`EndhostApiGroup`, `EndhostApiInfo`) returned by
/// [`ea_source::EndhostApiSource`].
pub use endhost_api_discovery_models;
/// DNS resolver backend. Exposed as the escape hatch behind
/// [`resolver::txt::ScionTxtDnsResolver::builder`] for full control over DNS resolution.
pub use hickory_resolver;
/// HTTP client used by the connect-RPC transport. Exposed by the `with_crpc_client` escape
/// hatch (e.g. [`ScionStackBuilder::with_crpc_client`]) for custom name resolution / TLS.
pub use reqwest;
/// Generic SCION UDP socket trait ([`scion_sdk_quic_scion::socket::GenericScionUdpSocket`])
/// that [`stack::UdpScionSocket`] implements so it can back QUIC / HTTP/3 connections.
pub use scion_sdk_quic_scion;
/// Authentication token-source trait (`TokenSource`) used by the `with_auth_token_source`
/// setters.
pub use scion_sdk_reqwest_connect_rpc;
/// SCION packet, address, path, and policy types (`ScionSocketIpAddr`, `IsdAsn`, `ScionPath`,
/// ...).
///
/// This is the foundational type crate of the SDK and appears throughout `scion-stack`'s API.
pub use sciparse;
/// URL type used to configure endhost API / control-plane addresses.
pub use url;
/// X25519 key type ([`x25519_dalek::StaticSecret`]) for supplying a static SNAP identity via
/// [`stack::builder::SnapUnderlayConfig::with_static_identity`].
pub use x25519_dalek;

// Common entry points are re-exported at the crate root for ergonomics.
pub use crate::stack::{
    PathUnawareUdpScionSocket, RawScionSocket, ScionStack, ScionStackBuilder, ScmpScionSocket,
    SocketConfig, UdpScionSocket,
};
