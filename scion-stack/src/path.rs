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
//! SCION stack path handling.

pub mod fetcher;
pub mod manager;
pub(crate) mod types;

mod strategy;
// Explicit re-exports (no glob) so additions to `strategy` do not silently widen the public API.
// Scoring is an internal concern of the stack; re-exported crate-internally only.
pub(crate) use strategy::scoring;
pub use strategy::{PathStrategy, policy};
