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

//! Edge-tun: WireGuard-based IP tunnel library for edge applications.
//!
//! This crate provides the building blocks for establishing secure IP tunnels between
//! an edge application server and its clients via the control/data plane components
//! (see [`control`] / [`data`]).

/// Edge-tun control plane API.
pub mod control;
/// Edge-tun data plane implementation.
pub mod data;
/// Packet fragmentation and reassembly for edge-tun tunnels.
pub mod fragmenting;
/// Prometheus metrics for edge-tun connections.
pub mod metrics;
/// Protobuf definitions
pub mod proto;
/// High-level edge-tun client tunnel orchestration.
pub mod tunnel;
