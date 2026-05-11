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

//! Edge-tun control plane trait and associated types.

use std::net::IpAddr;

use ana_gotatun::x25519;
use ipnet::IpNet;
use scion_proto::address::SocketAddr as EndhostSocketAddr;

/// Configuration for the edge-tun data plane.
pub struct EdgeTunDataPlaneConfig {
    /// SCION socket address of the control plane (for further control requests).
    pub control_plane_scion_sockaddr: EndhostSocketAddr,
    /// SCION socket address of the data plane.
    pub data_plane_scion_sockaddr: EndhostSocketAddr,
}

/// Trait implemented by the edge-tun server to handle control plane requests.
///
/// The methods on this trait are called by [`EdgeTunControlPlaneCrpcApi`] when
/// the corresponding Connect-RPC endpoint is invoked.
///
/// [`EdgeTunControlPlaneCrpcApi`]: crate::ng::api::server::EdgeTunControlPlaneCrpcApi
pub trait EdgeTunControlPlane: Send + Sync {
    /// Returns the data plane configuration when the client calls
    /// `/anapaya.edgetun.v1/data_plane_configuration`.
    fn get_data_plane_config(&self) -> EdgeTunDataPlaneConfig;

    /// Registers a static WireGuard identity for an edge-tun connection when the
    /// client calls `/anapaya.edgetun.v1/register_identity`.
    ///
    /// Returns the server's responder static public key and an optional PSK share.
    fn register_edge_tun_identity(
        &self,
        initiator_static_x25519: x25519::PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> (x25519::PublicKey, Option<[u8; 32]>);

    /// Assigns an IP address to the client when the client calls
    /// `/anapaya.edgetun.v1/assign_addresses`.
    ///
    /// While the interface specification allows for multiple addresses to be requested,
    /// only requests that request a single IP address shall be accepted. In all other
    /// cases, an error is returned.
    ///
    /// If `requested_address` is `Some(...)` and the requested address is not available
    /// or outside the available range, the effect of this call is the same as passing
    /// `None` for the `requested_address`.
    ///
    /// Returns `None` if no address can be assigned at the moment.
    fn assign_address(
        &self,
        initiator_static_x25519: x25519::PublicKey,
        requested_address: Option<IpAddr>,
    ) -> Option<IpAddr>;

    /// Returns the advertised routes for the given client identity when the client
    /// calls `/anapaya.edgetun.v1/request_routes`.
    fn get_route_advertisement(&self, identity: x25519::PublicKey) -> Vec<IpNet>;
}
