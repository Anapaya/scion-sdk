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

//! SciParse: A library for parsing and constructing SCION packets.
//!
//! This library provides functionality to parse and construct SCION packets,
//! including support for various SCION headers and extensions. It is designed
//! to be efficient and flexible, allowing users to work with SCION packets
//! in a straightforward manner.
//!
//! SciParse offers views and loaded representations of SCION packet headers,
//!
//! Views are Zero-copy representations that allow for efficient access to packet data
//! without unnecessary copying.
//!
//! Loaded representations provide owned data structures that can be manipulated
//! more easily.

mod scion;
pub use scion::*;

pub mod helper;
pub mod traits;
