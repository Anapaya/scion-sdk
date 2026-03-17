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

//! Client for the Anapaya AA (Auth/n Auth/z) service.
//!
//! This crate provides an [`ApiKeyTokenRefresher`] that implements the
//! [`scion_sdk_reqwest_connect_rpc::token_source::refresh::TokenRefresher`]
//! trait, enabling automatic SNAP token acquisition and renewal using static
//! API key credentials.

pub mod client;
pub mod refresher;

pub use client::{AaAuthClient, CrpcAaAuthClient};
pub use refresher::{ApiKeyTokenRefresher, ApiKeyTokenRefresherError};
