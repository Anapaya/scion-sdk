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

//! Bindings for [gRPC](https://grpc.io/) types and services used within SCION's control plane.
//!
//!
//! [scionproto]: https://github.com/scionproto/scion

// Needs to be renamed to avoid name collision with our export
#[allow(missing_docs)]
#[path = "proto/mod.rs"]
mod proto_root;
// Re-exports
pub use buffa;
pub use buffa_types;
pub use connectrpc;
// Drop one `proto` level from the generated code
pub use proto_root::proto;
