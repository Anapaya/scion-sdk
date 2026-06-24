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

//! The legacy QUIC stack.
//!
//! This is the original channel/driver-based QUIC server ([`server::QuicServer`])
//! and client ([`client::QuicConnection`] + `QuicConnectionDriver`). It predates the
//! sans-I/O [`super::server_endpoint`]/[`super::connection`] stack and is retained
//! only for call sites that have not yet migrated.

mod addr_validation_token;
pub mod client;
pub mod server;
