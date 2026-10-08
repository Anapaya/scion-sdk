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

//! scion-http3 behind a UniFFI interface.
//!
//! Gobley generates the Kotlin side of everything here. Kotlin/Native reaches
//! it through cinterop and the JVM through JNA, from one description.
//!
//! - [`ffi`] holds the Kotlin API. Nothing outside it depends on `ffi::core`.
//! - [`engine`] runs each request as a task.
//! - [`engine::transport`] is the way a request reaches the origin.
//!
//! We currently support two transports:
//! - [`engine::transport::http3::Http3Transport`] sends each request over SCION HTTP/3 to the
//!   origin.
//! - [`engine::transport::connect::ConnectTransport`] sends each request through a `CONNECT` tunnel
//!   to a PathGuard WebGateway.
//!
//! # Flow
//!
//! 1. Kotlin builds a `ScionCore` from a [`CoreConfig`](ffi::types::CoreConfig).
//!    [`Engine::new`](engine::Engine::new) picks one of the transports above from the config and
//!    builds it on the shared tokio runtime.
//! 2. For each request, Kotlin takes a key from `next_request_id` and awaits `execute`.
//! 3. [`Engine::execute`](engine::Engine::execute) spawns the request as a task on the runtime. The
//!    future that Kotlin polls only waits for that task.
//! 4. The transport sends the request through scion-http3 and collects the body up to the limit. A
//!    failure becomes a [`CoreError`](ffi::types::CoreError).
//! 5. Kotlin releases the key. A release ends the request if it still runs.
//! 6. When Kotlin drops the `ScionCore`, the engine closes the connections.

// The crate has no Rust API, only the UniFFI one. Its docs are for maintainers
// and link to private modules.
#![allow(rustdoc::private_intra_doc_links)]

mod engine;
mod ffi;

uniffi::setup_scaffolding!();
