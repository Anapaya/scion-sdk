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

//! Connect-RPC client for the edge-tun ng control plane API.
//!
//! The [`EdgeTunControlPlaneClient`] makes calls to the edge-tun control plane
//! over HTTP/3 + QUIC via SCION transport.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ana_gotatun::x25519;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use scion_proto::address::SocketAddr as EndhostSocketAddr;
use scion_sdk_scion_connect_rpc::{
    Method,
    client::{ConnectRpcClient, RequestError},
};
use thiserror::Error;
use url::Url;

use crate::ng::{
    api::server::{
        ASSIGN_ADDRESSES, DATA_PLANE_CONFIGURATION, REGISTER_IDENTITY, REQUEST_ROUTES, SERVICE_PATH,
    },
    control_plane::EdgeTunDataPlaneConfig,
    protobuf::anapaya::edgetun::v1::{
        AddressAssignRequest, AddressAssignResponse, GetDataPlaneConfigurationRequest,
        GetDataPlaneConfigurationResponse, IpAddressRange, RegisterEdgeTunIdentityRequest,
        RegisterEdgeTunIdentityResponse, RouteAdvertisementRequest, RouteAdvertisementResponse,
    },
};

/// Base URL used internally – the actual server address comes from the CrpcClient.
const BASE_URL: &str = "https://localhost";

/// Error returned by the edge-tun control plane client.
#[derive(Debug, Error)]
pub enum EdgeTunClientError {
    /// A transport-level error occurred.
    #[error("request error: {0}")]
    RequestError(#[from] RequestError),
    /// The server returned an invalid or unexpected response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Connect-RPC client for the edge-tun ng control plane API.
///
/// This client wraps any [`ConnectRpcClient`] implementation (e.g. the SCION-transport
/// backed [`scion_sdk_scion_connect_rpc::client::CrpcClient`]) and exposes typed
/// methods corresponding to the edge-tun control plane endpoints.
pub struct EdgeTunControlPlaneClient<C: ConnectRpcClient> {
    client: C,
    base_url: Url,
}

impl<C: ConnectRpcClient> EdgeTunControlPlaneClient<C> {
    /// Creates a new [`EdgeTunControlPlaneClient`].
    ///
    /// # Arguments
    /// * `client` - The Connect-RPC client to use for transport.
    pub fn new(client: C) -> Self {
        Self {
            client,
            base_url: Url::parse(BASE_URL).expect("base URL is valid"),
        }
    }

    /// Overrides the base URL. Useful for testing.
    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }

    fn make_url(&self, method: &str) -> Url {
        self.base_url
            .join(&format!("{SERVICE_PATH}/{method}"))
            .expect("URL construction should not fail")
    }

    /// Fetches the data plane configuration from the server.
    ///
    /// Calls `/anapaya.edgetun.v1/data_plane_configuration`.
    pub async fn get_data_plane_config(
        &self,
    ) -> Result<EdgeTunDataPlaneConfig, EdgeTunClientError> {
        let url = self.make_url(DATA_PLANE_CONFIGURATION);
        let resp = self
            .client
            .unary_request::<GetDataPlaneConfigurationRequest, GetDataPlaneConfigurationResponse>(
                Method::POST,
                url,
                GetDataPlaneConfigurationRequest {},
            )
            .await?;

        let control_plane_scion_sockaddr = resp
            .control_plane_scion_sockaddr
            .parse::<EndhostSocketAddr>()
            .map_err(|e| {
                EdgeTunClientError::InvalidResponse(format!(
                    "invalid control_plane_scion_sockaddr: {e}"
                ))
            })?;

        let data_plane_scion_sockaddr = resp
            .data_plane_scion_sockaddr
            .parse::<EndhostSocketAddr>()
            .map_err(|e| {
                EdgeTunClientError::InvalidResponse(format!(
                    "invalid data_plane_scion_sockaddr: {e}"
                ))
            })?;

        Ok(EdgeTunDataPlaneConfig {
            control_plane_scion_sockaddr,
            data_plane_scion_sockaddr,
        })
    }

    /// Registers a WireGuard static identity with the edge-tun server.
    ///
    /// Calls `/anapaya.edgetun.v1/register_identity`.
    ///
    /// Returns the server's responder static public key and an optional PSK share.
    pub async fn register_edge_tun_identity(
        &self,
        initiator_static_x25519: x25519::PublicKey,
        psk_share: Option<[u8; 32]>,
    ) -> Result<(x25519::PublicKey, Option<[u8; 32]>), EdgeTunClientError> {
        let url = self.make_url(REGISTER_IDENTITY);
        let resp = self
            .client
            .unary_request::<RegisterEdgeTunIdentityRequest, RegisterEdgeTunIdentityResponse>(
                Method::POST,
                url,
                RegisterEdgeTunIdentityRequest {
                    initiator_static_x25519: initiator_static_x25519.as_bytes().to_vec(),
                    psk_share: option_to_psk_bytes(psk_share),
                },
            )
            .await?;

        let responder_key_bytes: [u8; 32] = resp
            .responder_static_x25519
            .as_slice()
            .try_into()
            .map_err(|_| {
                EdgeTunClientError::InvalidResponse(
                    "responder_static_x25519 must be 32 bytes".to_string(),
                )
            })?;
        let responder_key = x25519::PublicKey::from(responder_key_bytes);

        let responder_psk = psk_bytes_to_option(&resp.psk_share)
            .map_err(|e| EdgeTunClientError::InvalidResponse(format!("invalid psk_share: {e}")))?;

        Ok((responder_key, responder_psk))
    }

    /// Requests an IP address assignment from the edge-tun server.
    ///
    /// Calls `/anapaya.edgetun.v1/assign_addresses`.
    ///
    /// Returns `None` if the server could not assign an address, or `Some(addr)` if successful.
    pub async fn assign_address(
        &self,
        client_identity: x25519::PublicKey,
        requested_address: Option<IpAddr>,
    ) -> Result<Option<IpAddr>, EdgeTunClientError> {
        let url = self.make_url(ASSIGN_ADDRESSES);
        let requested_addresses = requested_address
            .map(addr_to_ip_address_range)
            .into_iter()
            .collect();

        let resp = self
            .client
            .unary_request::<AddressAssignRequest, AddressAssignResponse>(
                Method::POST,
                url,
                AddressAssignRequest {
                    client_identity: client_identity.as_bytes().to_vec(),
                    requested_addresses,
                },
            )
            .await?;

        match resp.assigned_addresses.into_iter().next() {
            None => Ok(None),
            Some(range) => {
                let addr = ip_address_range_to_addr(range)
                    .map_err(|e| EdgeTunClientError::InvalidResponse(e.to_string()))?;
                Ok(Some(addr))
            }
        }
    }

    /// Fetches advertised routes for the given client identity.
    ///
    /// Calls `/anapaya.edgetun.v1/request_routes`.
    pub async fn get_route_advertisement(
        &self,
        client_identity: x25519::PublicKey,
    ) -> Result<Vec<IpNet>, EdgeTunClientError> {
        let url = self.make_url(REQUEST_ROUTES);
        let resp = self
            .client
            .unary_request::<RouteAdvertisementRequest, RouteAdvertisementResponse>(
                Method::POST,
                url,
                RouteAdvertisementRequest {
                    client_identity: client_identity.as_bytes().to_vec(),
                },
            )
            .await?;

        resp.route
            .into_iter()
            .map(|range| {
                ip_address_range_to_net(range)
                    .map_err(|e| EdgeTunClientError::InvalidResponse(e.to_string()))
            })
            .collect()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Converts an `Option<[u8; 32]>` to PSK bytes (all-zero if `None`).
fn option_to_psk_bytes(psk: Option<[u8; 32]>) -> Vec<u8> {
    psk.map(|p| p.to_vec()).unwrap_or_else(|| vec![0u8; 32])
}

/// Converts PSK bytes to `Option<[u8; 32]>`.
///
/// All-zero bytes (or empty) indicate no PSK.
fn psk_bytes_to_option(psk: &[u8]) -> Result<Option<[u8; 32]>, String> {
    if psk.is_empty() || psk == [0u8; 32] {
        Ok(None)
    } else {
        psk.try_into()
            .map(Some)
            .map_err(|_| format!("psk_share must be 32 bytes, got {}", psk.len()))
    }
}

/// Wraps a single IP address in an [`IpAddressRange`] with a host prefix length.
fn addr_to_ip_address_range(addr: IpAddr) -> IpAddressRange {
    match addr {
        IpAddr::V4(v4) => {
            IpAddressRange {
                version: 4,
                prefix_length: 32,
                address: v4.octets().to_vec(),
            }
        }
        IpAddr::V6(v6) => {
            IpAddressRange {
                version: 6,
                prefix_length: 128,
                address: v6.octets().to_vec(),
            }
        }
    }
}

/// Extracts the IP address from an [`IpAddressRange`], ignoring prefix length.
fn ip_address_range_to_addr(range: IpAddressRange) -> Result<IpAddr, String> {
    match range.version {
        4 => {
            let bytes: [u8; 4] = range.address.as_slice().try_into().map_err(|_| {
                format!("IPv4 address must be 4 bytes, got {}", range.address.len())
            })?;
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        6 => {
            let bytes: [u8; 16] = range.address.as_slice().try_into().map_err(|_| {
                format!("IPv6 address must be 16 bytes, got {}", range.address.len())
            })?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        v => Err(format!("invalid IP version: {v}, expected 4 or 6")),
    }
}

/// Converts an [`IpAddressRange`] to an [`IpNet`].
fn ip_address_range_to_net(range: IpAddressRange) -> Result<IpNet, String> {
    match range.version {
        4 => {
            let bytes: [u8; 4] = range.address.as_slice().try_into().map_err(|_| {
                format!("IPv4 address must be 4 bytes, got {}", range.address.len())
            })?;
            let addr = Ipv4Addr::from(bytes);
            let net = Ipv4Net::new(addr, range.prefix_length as u8)
                .map_err(|e| format!("invalid IPv4 prefix length {}: {e}", range.prefix_length))?;
            Ok(IpNet::V4(net))
        }
        6 => {
            let bytes: [u8; 16] = range.address.as_slice().try_into().map_err(|_| {
                format!("IPv6 address must be 16 bytes, got {}", range.address.len())
            })?;
            let addr = Ipv6Addr::from(bytes);
            let net = Ipv6Net::new(addr, range.prefix_length as u8)
                .map_err(|e| format!("invalid IPv6 prefix length {}: {e}", range.prefix_length))?;
            Ok(IpNet::V6(net))
        }
        v => Err(format!("invalid IP version: {v}, expected 4 or 6")),
    }
}
