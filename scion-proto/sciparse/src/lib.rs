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

//! SciParse: Zero-Copy SCION Packets
//!
//! This library provides functionality to parse and construct SCION packets.
//!
//! Parsing is performed via zero-copy views over byte buffers, providing direct
//! field access without allocation or data transformation, and with only the
//! validation required to uphold safety.
//!
//! The library is designed to be efficient and flexible, allowing users to work
//! with SCION packets in a straightforward manner.
//!
//! SciParse exposes both view-based and model-based representations of SCION packets.
//!
//! ## Views
//!
//! Views are zero-copy projections over byte buffers.
//!
//! A view provides read access and limited write access to SCION packet fields
//! directly on the underlying buffer, with minimal overhead.
//!
//! Views do not support modification of dynamically sized fields
//! (e.g., addresses, path segments).
//!
//! ## Models
//!
//! Models represent SCION packets as structured Rust types.
//!
//! They are intended for constructing new packets or performing complex
//! modifications that are impractical or unsafe using views alone.

mod proto;
pub use proto::*;

/// Core traits and utilities for working with bit-level data
pub mod core;
