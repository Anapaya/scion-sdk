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

//! HTTP/3 over SCION transport.
//!
//! The modern stack is sans-I/O: a per-connection
//! [`QuicScionApplication`](crate::app::QuicScionApplication) stepped in lockstep
//! by the connection driver, with streaming `http_body` bodies flow-controlled by
//! the QUIC stream window. It is split into a [`client`] and a [`server`], with
//! their shared machinery in `common`.
//!
//! The legacy stack lives under [`deprecated`] and is retained only until its
//! remaining call sites migrate.

pub mod client;
pub(crate) mod common;
pub mod deprecated;
pub mod server;
