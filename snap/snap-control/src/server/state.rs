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
//! SNAP control plane server state.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod dto;

/// SNAP control plane I/O configuration.
#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ControlPlaneIoConfig {
    /// The control plane API socket address.
    #[schema(value_type = Option<String>, example = "127.0.0.1:8080")]
    pub api_addr: Option<SocketAddr>,
}
