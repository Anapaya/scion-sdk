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

//! Connect-RPC client library over HTTP/3.
//!
//! This library provides a generic Connect-RPC client that operates over HTTP/3
//! using QUIC via SCION transport.

pub mod client;
pub mod error;

// Re-export the transport trait
pub use http::Method;
pub use url;
