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

//! Edge-tun: QUIC-based and WireGuard-based IP tunnel library for edge applications.
//!
//! This crate provides the building blocks for establishing secure IP tunnels between
//! an edge application server and its clients. Tunnels are transported over QUIC
//! connections (see [`server`] / [`client`]) or WireGuard sessions (see [`wg`]).

/// Address allocation traits and types for edge-tun servers.
pub mod address_allocation;
/// QUIC-based edge-tun client implementation.
pub mod client;
/// Packet fragmentation and reassembly for edge-tun tunnels.
pub mod fragmenting;
/// IP packet validation utilities.
pub mod ip;
/// Prometheus metrics for edge-tun connections.
pub mod metrics;
/// Next-generation edge-tun control plane API.
pub mod ng;
/// Wire-format request and response types for the edge-tun control protocol.
pub mod requests;
/// QUIC-based edge-tun server implementation.
pub mod server;
/// Test utilities for building synthetic IP packets.
pub mod test_util;
/// WireGuard-based edge-tun tunnel implementation.
pub mod wg;
