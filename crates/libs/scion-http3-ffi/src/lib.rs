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

//! # Foreign-language bindings for the SCION HTTP/3 client
//!
//! A UniFFI wrapper over [`scion_http3`], built as a shared library and consumed from Kotlin and
//! Swift through generated bindings. It translates and nothing else: types in, types out, one error
//! mapping, and ownership of the async runtime. Every decision about what a request does lives in
//! `scion-http3`, where all platforms share it, and everything platform-specific lives in the
//! hand-written library above these bindings.
//!
//! ## The runtime is owned here, deliberately
//!
//! Exported `async fn`s carry no `async_runtime = "tokio"` attribute. That attribute does not give
//! this crate a runtime: it only wraps the future in `async_compat::Compat`, which enters the
//! current runtime or, failing that, a process-global current-thread runtime belonging to
//! `async-compat`. UniFFI polls from foreign threads, which never have a current runtime, so under
//! the attribute every QUIC socket and every timer in the host application would be driven by one
//! thread this crate does not own, cannot size and cannot shut down.
//!
//! Instead, this crate owns a multi-threaded runtime, each exported function spawns its work onto
//! it, and the future the foreign side polls does nothing but await the result. The mechanics are
//! in the `runtime` module.
//!
//! The consequence worth knowing is which thread runs the teardown. When the foreign side drops an
//! exported future, the spawned task is aborted, and the request future, with the stream reset that
//! cancels the request on the wire, is dropped on a runtime worker. Under the attribute that whole
//! chain would run inline on the thread that dropped it, which for a caller that cancels can be a
//! user-interface thread. The price is that the teardown is fire-and-forget: the abort returns
//! before the work it started has finished.
//!
//! *Whether* a cancelled foreign call drops the exported future is a property of the generated
//! bindings for that language, not of this crate. What this crate provides is that the drop,
//! wherever and whenever it happens, is both correct and cheap. Each binding's own tests establish
//! when it happens.
//!
//! One runtime serves every client, built when the first one is constructed and never shut down.
//! Shutting a client down closes its connection pool and leaves the runtime alone. The cost is two
//! to four parked worker threads for the life of the process; what it avoids is a teardown, which
//! is where every subtle problem in this area lives. See the `runtime` module.
//!
//! ## Bodies
//!
//! Buffered in both directions in this version: a request body crosses as a byte array, and a
//! response body is collected before the response record is returned. Streaming needs a
//! bidirectional channel across the language boundary, and is deliberately not in the first
//! release.
//!
//! ## Platform differences
//!
//! Every binding loads this same crate, and the exported surface is the union of what they all need
//! rather than a per-platform selection. Two reasons, both practical. UniFFI checks a per-function
//! checksum when generated code loads the library, so the bindings and the library have to agree on
//! the surface exactly. And the tests that exercise this crate most cheaply are compiled for the
//! build host, so anything hidden behind a `cfg(target_os = ...)` would be covered by none of them.
//!
//! So a binding that needs something the others do not gets an *added* export, and the hand-written
//! library above it hides whatever it does not use; [`internal_panic_for_test`] is the existing
//! example. Adding one is additive and harms nobody. Forking this crate per platform, by
//! feature or by `cfg`, is not on the table.
//!
//! Cancellation is where that will be needed first, and it is worth knowing why the runtime
//! strategy above is not what differs. Kotlin's generated code frees a rust future in a `finally`
//! block, so a cancelled call reaches the drop this crate is built around. Swift's, at the pinned
//! version, awaits each poll with a non-throwing `withUnsafeContinuation`, never checks
//! `Task.checkCancellation()`, and frees the future in a `defer` that is only reached once the call
//! completes; its cancelled branch is a `fatalError("Cancellation not supported yet")`. A cancelled
//! Swift task therefore runs to completion, and the abort-on-drop guard is inactive rather than
//! wrong. Owning the runtime helps both equally; delivering cancellation on a binding whose
//! generated code does not drop the future needs an explicit cancel export, on a function of its
//! own so that the bindings which do not need it do not change.

// The FFI boundary catches panics and turns them into errors. Under panic=abort a panic in Rust
// would instead take the host application's process down, which is both a worse failure and one
// that no test would attribute to us. The `mobile` profile sets panic=unwind explicitly; this
// makes any configuration that does not a compile error rather than a runtime surprise.
#[cfg(panic = "abort")]
compile_error!(
    "scion-http3-ffi requires panic=unwind: the FFI boundary relies on catch_unwind to keep a \
     Rust panic from aborting the host process. Build with `--profile mobile`."
);

mod client;
mod convert;
mod error;
mod runtime;
mod token;
mod types;

pub use client::ScionHttp3Client;
pub use error::{ScionHttp3Error, TimeoutPhase};
pub use types::{
    ClientConfig, DiscoveryConfig, Header, HttpRequest, HttpResponse, SnapConfig, TrustAnchors,
    UdpConfig, Underlay,
};

// No namespace argument: the namespace then follows the crate name, which keeps the shared
// library's name, the generated bindings' library lookup and the exported contract-version symbol
// (`ffi_scion_http3_ffi_uniffi_contract_version`, which the Android build checks for) in step.
uniffi::setup_scaffolding!();

/// The defaults `scion-http3` applies, as a configuration record.
///
/// Exported so that the foreign builder does not restate them: a default that is written down
/// twice is a default that eventually disagrees with itself.
#[uniffi::export]
#[must_use]
pub fn default_client_config(endhost_api_url: String) -> ClientConfig {
    ClientConfig::with_defaults(endhost_api_url)
}

/// Panics, so that a foreign test can show what a panic does at the boundary.
///
/// UniFFI turns a panic into an error at the boundary, which it can only do while unwinding; under
/// `panic = "abort"` the process would go down instead, which is why the crate refuses to compile
/// that way. Nothing in the API panics deliberately, so without this there is no way to exercise
/// the property that refusal protects. Not part of the supported surface; the hand-written library
/// hides it.
#[uniffi::export]
pub fn internal_panic_for_test() {
    panic!("deliberate panic, to show that a panic crosses the boundary as an error");
}
