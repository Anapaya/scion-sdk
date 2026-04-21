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

//! Server-side Connect-RPC API for the edge-tun ng control plane.
//!
//! The [`EdgeTunControlPlaneCrpcApi`] listens for incoming QUIC/HTTP3 connections
//! on a SCION socket and routes Connect-RPC requests to an [`EdgeTunControlPlane`]
//! implementation.

use std::{net::IpAddr, sync::Arc};

use ana_gotatun::x25519;
use ipnet::IpNet;
use prost::Message;
use scion_sdk_quic_scion::{
    h3::server::{H3ResponseSender, H3Server, H3ServerConnection},
    quic::server::QuicServer,
};
use scion_sdk_scion_connect_rpc::error::{CrpcError, CrpcErrorCode};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing;

use crate::ng::{
    control_plane::EdgeTunControlPlane,
    protobuf::anapaya::edgetun::v1::{
        AddressAssignRequest, AddressAssignResponse, GetDataPlaneConfigurationRequest,
        GetDataPlaneConfigurationResponse, IpAddressRange, RegisterEdgeTunIdentityRequest,
        RegisterEdgeTunIdentityResponse, RouteAdvertisementRequest, RouteAdvertisementResponse,
    },
};

/// Connect-RPC path for the edge-tun control plane service.
pub(crate) const SERVICE_PATH: &str = "anapaya.edgetun.v1";

/// Connect-RPC method path for data plane configuration.
pub(crate) const DATA_PLANE_CONFIGURATION: &str = "data_plane_configuration";

/// Connect-RPC method path for identity registration.
pub(crate) const REGISTER_IDENTITY: &str = "register_identity";

/// Connect-RPC method path for address assignment.
pub(crate) const ASSIGN_ADDRESSES: &str = "assign_addresses";

/// Connect-RPC method path for route advertisement.
pub(crate) const REQUEST_ROUTES: &str = "request_routes";

/// Full Connect-RPC path for data plane configuration.
const PATH_DATA_PLANE_CONFIGURATION: &str = "/anapaya.edgetun.v1/data_plane_configuration";

/// Full Connect-RPC path for identity registration.
const PATH_REGISTER_IDENTITY: &str = "/anapaya.edgetun.v1/register_identity";

/// Full Connect-RPC path for address assignment.
const PATH_ASSIGN_ADDRESSES: &str = "/anapaya.edgetun.v1/assign_addresses";

/// Full Connect-RPC path for route advertisement.
const PATH_REQUEST_ROUTES: &str = "/anapaya.edgetun.v1/request_routes";

/// The edge-tun control plane Connect-RPC API server.
///
/// This struct listens for incoming QUIC/HTTP3 connections on a SCION socket
/// and dispatches Connect-RPC requests to the provided [`EdgeTunControlPlane`]
/// implementation.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use scion_sdk_edge_tun::ng::{api::server::EdgeTunControlPlaneCrpcApi, control_plane::EdgeTunControlPlane};
/// use tokio_util::sync::CancellationToken;
///
/// # async fn example<C: EdgeTunControlPlane + 'static>(quic_server: scion_sdk_quic_scion::quic::server::QuicServer, control_plane: Arc<C>) {
/// let api = Arc::new(EdgeTunControlPlaneCrpcApi::new(quic_server, control_plane));
/// let token = CancellationToken::new();
/// api.start_listening(token).await;
/// # }
/// ```
pub struct EdgeTunControlPlaneCrpcApi<C> {
    h3_server: Mutex<H3Server>,
    control_plane: Arc<C>,
}

impl<C: EdgeTunControlPlane + 'static> EdgeTunControlPlaneCrpcApi<C> {
    /// Creates a new [`EdgeTunControlPlaneCrpcApi`].
    ///
    /// # Arguments
    /// * `quic_server` - A configured QUIC server that will accept incoming connections. The caller
    ///   is responsible for setting up TLS certificates in the QUIC config.
    /// * `control_plane` - The control plane implementation to dispatch requests to.
    pub fn new(quic_server: QuicServer, control_plane: Arc<C>) -> Self {
        Self {
            h3_server: Mutex::new(H3Server::new(quic_server)),
            control_plane,
        }
    }

    /// Starts listening for incoming Connect-RPC requests.
    ///
    /// This method runs until the provided `cancellation_token` is cancelled or
    /// the underlying QUIC server stops accepting connections.
    pub async fn start_listening(&self, cancellation_token: CancellationToken) {
        let mut h3_server = self.h3_server.lock().await;

        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    tracing::info!("EdgeTunControlPlaneCrpcApi: cancellation requested, shutting down");
                    break;
                }
                conn_opt = h3_server.accept() => {
                    match conn_opt {
                        Some(conn) => {
                            let control_plane = self.control_plane.clone();
                            tokio::spawn(async move {
                                handle_connection(conn, control_plane).await;
                            });
                        }
                        None => {
                            tracing::warn!("EdgeTunControlPlaneCrpcApi: H3 server stopped accepting connections");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handles a single H3 connection by dispatching all requests until the connection closes.
async fn handle_connection<C: EdgeTunControlPlane + 'static>(
    mut conn: H3ServerConnection,
    control_plane: Arc<C>,
) {
    while let Some((req, responder)) = conn.handle_request().await {
        let cp = control_plane.clone();
        tokio::spawn(async move {
            handle_request(req, responder, &*cp).await;
        });
    }
}

/// Handles a single Connect-RPC request by routing it to the appropriate handler.
async fn handle_request<C: EdgeTunControlPlane>(
    req: scion_sdk_quic_scion::h3::request::H3Request,
    mut responder: H3ResponseSender,
    control_plane: &C,
) {
    let path = req.headers.path.as_str();

    let result = match path {
        PATH_DATA_PLANE_CONFIGURATION => handle_data_plane_configuration(&req, control_plane),
        PATH_REGISTER_IDENTITY => handle_register_identity(&req, control_plane),
        PATH_ASSIGN_ADDRESSES => handle_assign_addresses(&req, control_plane),
        PATH_REQUEST_ROUTES => handle_request_routes(&req, control_plane),
        _ => {
            tracing::warn!(path, "EdgeTunControlPlaneCrpcApi: unknown path");
            Err(CrpcError::new(
                CrpcErrorCode::NotFound,
                format!("unknown path: {path}"),
            ))
        }
    };

    let (status, body) = match result {
        Ok(body) => (http::StatusCode::OK, body),
        Err(err) => {
            let code = http_status_from_crpc_code(err.code);
            let body = serde_json::to_vec(&err).unwrap_or_default();
            (code, body)
        }
    };

    if let Err(e) = responder.send_response(status, &body).await {
        tracing::error!(?e, "EdgeTunControlPlaneCrpcApi: failed to send response");
    }
}

/// Handles a `/anapaya.edgetun.v1/data_plane_configuration` request.
fn handle_data_plane_configuration<C: EdgeTunControlPlane>(
    req: &scion_sdk_quic_scion::h3::request::H3Request,
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    let body = req.body.as_deref().unwrap_or_default();
    let _request = GetDataPlaneConfigurationRequest::decode(body).map_err(|e| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            format!("failed to decode request: {e}"),
        )
    })?;

    let config = control_plane.get_data_plane_config();

    let response = GetDataPlaneConfigurationResponse {
        control_plane_scion_sockaddr: config.control_plane_scion_sockaddr.to_string(),
        data_plane_scion_sockaddr: config.data_plane_scion_sockaddr.to_string(),
    };

    Ok(response.encode_to_vec())
}

/// Handles a `/anapaya.edgetun.v1/register_identity` request.
fn handle_register_identity<C: EdgeTunControlPlane>(
    req: &scion_sdk_quic_scion::h3::request::H3Request,
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    let body = req.body.as_deref().unwrap_or_default();
    let request = RegisterEdgeTunIdentityRequest::decode(body).map_err(|e| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            format!("failed to decode request: {e}"),
        )
    })?;

    let initiator_key = extract_x25519_public_key(request.initiator_static_x25519.as_slice())?;

    let psk_share = psk_bytes_to_option(&request.psk_share)?;

    let (responder_key, responder_psk) =
        control_plane.register_edge_tun_identity(initiator_key, psk_share);

    let response = RegisterEdgeTunIdentityResponse {
        responder_static_x25519: responder_key.as_bytes().to_vec(),
        psk_share: option_to_psk_bytes(responder_psk),
    };

    Ok(response.encode_to_vec())
}

fn extract_x25519_public_key(bytes: &[u8]) -> Result<x25519::PublicKey, CrpcError> {
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            "initiator_static_x25519 must be 32 bytes".to_string(),
        )
    })?;
    Ok(x25519::PublicKey::from(key_bytes))
}

/// Handles a `/anapaya.edgetun.v1/assign_addresses` request.
fn handle_assign_addresses<C: EdgeTunControlPlane>(
    req: &scion_sdk_quic_scion::h3::request::H3Request,
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    let body = req.body.as_deref().unwrap_or_default();
    let request = AddressAssignRequest::decode(body).map_err(|e| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            format!("failed to decode request: {e}"),
        )
    })?;

    let initiator_key = extract_x25519_public_key(request.client_identity.as_slice())?;

    // The trait only accepts a single address request.
    if request.requested_addresses.len() > 1 {
        return Err(CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            "only a single address can be requested at a time".to_string(),
        ));
    }

    let requested_address = request
        .requested_addresses
        .into_iter()
        .next()
        .map(ip_address_range_to_addr)
        .transpose()?;

    let assigned = control_plane.assign_address(initiator_key, requested_address);

    let response = AddressAssignResponse {
        assigned_addresses: assigned.map(addr_to_ip_address_range).into_iter().collect(),
    };

    Ok(response.encode_to_vec())
}

/// Handles a `/anapaya.edgetun.v1/request_routes` request.
fn handle_request_routes<C: EdgeTunControlPlane>(
    req: &scion_sdk_quic_scion::h3::request::H3Request,
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    let body = req.body.as_deref().unwrap_or_default();
    let request = RouteAdvertisementRequest::decode(body).map_err(|e| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            format!("failed to decode request: {e}"),
        )
    })?;

    let identity_bytes: [u8; 32] = request.client_identity.as_slice().try_into().map_err(|_| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            "client_identity must be 32 bytes".to_string(),
        )
    })?;
    let identity = x25519::PublicKey::from(identity_bytes);

    let routes = control_plane.get_route_advertisement(identity);

    let response = RouteAdvertisementResponse {
        route: routes.into_iter().map(ipnet_to_ip_address_range).collect(),
    };

    Ok(response.encode_to_vec())
}

/// Converts a PSK byte vector to an `Option<[u8; 32]>`.
///
/// All-zero PSK bytes indicate no PSK (returns `None`).
fn psk_bytes_to_option(psk: &[u8]) -> Result<Option<[u8; 32]>, CrpcError> {
    if psk.is_empty() || psk == [0u8; 32] {
        Ok(None)
    } else {
        psk.try_into().map(Some).map_err(|_| {
            CrpcError::new(
                CrpcErrorCode::InvalidArgument,
                "psk_share must be 32 bytes".to_string(),
            )
        })
    }
}

/// Converts an `Option<[u8; 32]>` to PSK bytes (all-zero if `None`).
fn option_to_psk_bytes(psk: Option<[u8; 32]>) -> Vec<u8> {
    psk.map(|p| p.to_vec())
        .unwrap_or_else(|| [0u8; 32].to_vec())
}

/// Extracts the IP address from an [`IpAddressRange`], ignoring prefix length.
fn ip_address_range_to_addr(range: IpAddressRange) -> Result<IpAddr, CrpcError> {
    match range.version {
        4 => {
            let bytes: [u8; 4] = range.address.as_slice().try_into().map_err(|_| {
                CrpcError::new(
                    CrpcErrorCode::InvalidArgument,
                    "IPv4 address must be 4 bytes".to_string(),
                )
            })?;
            Ok(IpAddr::V4(bytes.into()))
        }
        6 => {
            let bytes: [u8; 16] = range.address.as_slice().try_into().map_err(|_| {
                CrpcError::new(
                    CrpcErrorCode::InvalidArgument,
                    "IPv6 address must be 16 bytes".to_string(),
                )
            })?;
            Ok(IpAddr::V6(bytes.into()))
        }
        v => {
            Err(CrpcError::new(
                CrpcErrorCode::InvalidArgument,
                format!("invalid IP version: {v}, expected 4 or 6"),
            ))
        }
    }
}

/// Wraps a single IP address in an [`IpAddressRange`] with prefix_length = 32 (v4) or 128 (v6).
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

/// Converts an [`IpNet`] to an [`IpAddressRange`].
fn ipnet_to_ip_address_range(net: IpNet) -> IpAddressRange {
    match net {
        IpNet::V4(v4) => {
            IpAddressRange {
                version: 4,
                prefix_length: v4.prefix_len() as u32,
                address: v4.addr().octets().to_vec(),
            }
        }
        IpNet::V6(v6) => {
            IpAddressRange {
                version: 6,
                prefix_length: v6.prefix_len() as u32,
                address: v6.addr().octets().to_vec(),
            }
        }
    }
}

/// Converts a [`CrpcErrorCode`] to an HTTP status code.
fn http_status_from_crpc_code(code: CrpcErrorCode) -> http::StatusCode {
    match code {
        CrpcErrorCode::InvalidArgument => http::StatusCode::BAD_REQUEST,
        CrpcErrorCode::NotFound => http::StatusCode::NOT_FOUND,
        CrpcErrorCode::Unauthenticated => http::StatusCode::UNAUTHORIZED,
        CrpcErrorCode::PermissionDenied => http::StatusCode::FORBIDDEN,
        CrpcErrorCode::ResourceExhausted => http::StatusCode::TOO_MANY_REQUESTS,
        CrpcErrorCode::Unavailable => http::StatusCode::SERVICE_UNAVAILABLE,
        _ => http::StatusCode::INTERNAL_SERVER_ERROR,
    }
}
