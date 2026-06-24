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

//! The legacy HTTP/3 stack.
//!
//! This is the original HTTP/3 client and server: a self-contained
//! `QuicConnection` + `QuicConnectionDriver` plus a separate `H3Driver` event
//! loop, with [`request::H3Request`]/[`request::H3Response`] types and
//! bodies that are fully buffered in memory.
//!
//! It is retained here only for call sites that have not yet migrated to the
//! rewritten stack.

pub mod client;
pub mod request;
pub mod server;
