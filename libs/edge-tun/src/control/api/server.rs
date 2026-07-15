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

//! Server-side Connect-RPC API for the edge-tun control plane.
//!
//! [`EdgeTunControlPlaneCrpcApi`] drives a [`QuicScionServerEndpoint`] running an
//! [`Http3Server`] whose [`HttpService`] routes Connect-RPC requests to an
//! [`EdgeTunControlPlane`] implementation.

use std::{convert::Infallible, future::poll_fn, net::IpAddr, pin::Pin, sync::Arc, task::Poll};

use ana_gotatun::x25519;
use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame};
use ipnet::IpNet;
use prometheus::IntGauge;
use prost::Message;
use scion_sdk_quic_scion::{
    h3::server::{H3RequestBody, Http3Server, Http3ServerConfig, HttpService},
    quic::{
        connection::ConnectionHandle,
        server_endpoint::{Metrics, QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    reexport::squiche,
    socket::GenericScionUdpSocket,
};
use scion_sdk_scion_connect_rpc::error::{CrpcError, CrpcErrorCode};
use tokio_util::sync::CancellationToken;
use tracing;

use crate::{
    control::EdgeTunControlPlane,
    proto::anapaya::edgetun::v1::{
        AddressAssignRequest, AddressAssignResponse, GetDataPlaneConfigurationRequest,
        GetDataPlaneConfigurationResponse, GetRouteAdvertisementRequest,
        GetRouteAdvertisementResponse, IpAddressRange, RegisterEdgeTunIdentityRequest,
        RegisterEdgeTunIdentityResponse,
    },
};
/// Connect-RPC path for the edge-tun control plane service.
pub(crate) const SERVICE_PATH: &str = "anapaya.edgetun.v1.EdgeTunControlService";

/// Connect-RPC method path for data plane configuration.
pub(crate) const DATA_PLANE_CONFIGURATION: &str = "GetDataPlaneConfiguration";

/// Connect-RPC method path for identity registration.
pub(crate) const REGISTER_IDENTITY: &str = "RegisterEdgeTunIdentity";

/// Connect-RPC method path for address assignment.
pub(crate) const ASSIGN_ADDRESSES: &str = "AddressAssign";

/// Connect-RPC method path for route advertisement.
pub(crate) const REQUEST_ROUTES: &str = "GetRouteAdvertisement";

/// Full Connect-RPC path for data plane configuration.
const PATH_DATA_PLANE_CONFIGURATION: &str =
    "/anapaya.edgetun.v1.EdgeTunControlService/GetDataPlaneConfiguration";

/// Full Connect-RPC path for identity registration.
const PATH_REGISTER_IDENTITY: &str =
    "/anapaya.edgetun.v1.EdgeTunControlService/RegisterEdgeTunIdentity";

/// Full Connect-RPC path for address assignment.
const PATH_ASSIGN_ADDRESSES: &str = "/anapaya.edgetun.v1.EdgeTunControlService/AddressAssign";

/// Full Connect-RPC path for route advertisement.
const PATH_REQUEST_ROUTES: &str = "/anapaya.edgetun.v1.EdgeTunControlService/GetRouteAdvertisement";

/// Deprecated full Connect-RPC paths without the service prefix, still accepted by the server for
/// backward compatibility.
pub(crate) mod deprecated_paths {
    /// Deprecated full Connect-RPC path for data plane configuration (without service prefix).
    pub const DEPR_DATA_PLANE_CONFIGURATION: &str = "/anapaya.edgetun.v1/data_plane_configuration";

    /// Deprecated full Connect-RPC path for identity registration (without service prefix).
    pub const DEPR_REGISTER_IDENTITY: &str = "/anapaya.edgetun.v1/register_identity";
    /// Deprecated full Connect-RPC path for address assignment (without service prefix).
    pub const DEPR_ASSIGN_ADDRESSES: &str = "/anapaya.edgetun.v1/assign_addresses";

    /// Deprecated full Connect-RPC path for route advertisement (without service prefix).
    pub const DEPR_REQUEST_ROUTES: &str = "/anapaya.edgetun.v1/request_routes";
}

/// The [`HttpService`] that routes Connect-RPC requests to an
/// [`EdgeTunControlPlane`] implementation.
///
/// One instance is shared (via [`Http3ServerConfig`]) across every connection
/// served by the endpoint.
struct EdgeTunControlService<C> {
    control_plane: Arc<C>,
}

impl<C: EdgeTunControlPlane + 'static> HttpService for EdgeTunControlService<C> {
    type Body = H3RequestBody;
    type ResponseBody = FullBody;

    async fn call(&self, req: Request<H3RequestBody>) -> Response<FullBody> {
        let path = req.uri().path().to_owned();

        let result = match read_request_body(req.into_body()).await {
            Ok(body) => dispatch(&path, &body, &*self.control_plane),
            Err(err) => Err(err),
        };

        let (status, body) = match result {
            Ok(body) => (http::StatusCode::OK, body),
            Err(err) => {
                let code = http_status_from_crpc_code(err.code);
                let body = serde_json::to_vec(&err).unwrap_or_default();
                (code, body)
            }
        };

        Response::builder()
            .status(status)
            .body(FullBody::new(body))
            .expect("response is always well-formed")
    }
}

/// Routes a single Connect-RPC request (already buffered) to the appropriate
/// handler based on its `path`.
fn dispatch<C: EdgeTunControlPlane>(
    path: &str,
    body: &[u8],
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    match path {
        deprecated_paths::DEPR_DATA_PLANE_CONFIGURATION | PATH_DATA_PLANE_CONFIGURATION => {
            handle_get_data_plane_configuration(body, control_plane)
        }
        deprecated_paths::DEPR_REGISTER_IDENTITY | PATH_REGISTER_IDENTITY => {
            handle_register_edge_tun_identity(body, control_plane)
        }
        deprecated_paths::DEPR_ASSIGN_ADDRESSES | PATH_ASSIGN_ADDRESSES => {
            handle_address_assign(body, control_plane)
        }
        deprecated_paths::DEPR_REQUEST_ROUTES | PATH_REQUEST_ROUTES => {
            handle_get_route_advertisement(body, control_plane)
        }
        _ => {
            tracing::warn!(path, "EdgeTunControlPlaneCrpcApi: unknown path");
            Err(CrpcError::new(
                CrpcErrorCode::NotFound,
                format!("unknown path: {path}"),
            ))
        }
    }
}

/// Maximum size, in bytes, of a request body accepted by [`read_request_body`].
///
/// Requests whose body exceeds this limit are rejected rather than buffered, to
/// bound the server's per-request memory usage.
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1 MiB

/// Reads an HTTP/3 request body to completion, concatenating its data frames.
///
/// The body is rejected with [`CrpcErrorCode::ResourceExhausted`] once the
/// accumulated size would exceed [`MAX_REQUEST_BODY_SIZE`].
async fn read_request_body(mut body: H3RequestBody) -> Result<Vec<u8>, CrpcError> {
    let mut collected = Vec::new();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|e| {
            CrpcError::new(
                CrpcErrorCode::Internal,
                format!("failed to read request body: {e}"),
            )
        })?;
        // Trailing header sections carry no body bytes and are ignored.
        if let Ok(data) = frame.into_data() {
            if collected.len() + data.len() > MAX_REQUEST_BODY_SIZE {
                return Err(CrpcError::new(
                    CrpcErrorCode::ResourceExhausted,
                    format!("request body exceeds maximum size of {MAX_REQUEST_BODY_SIZE} bytes"),
                ));
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected)
}

/// The edge-tun control plane Connect-RPC API server.
///
/// This drives a [`QuicScionServerEndpoint`] running an [`Http3Server`] on a
/// SCION socket and dispatches Connect-RPC requests to the provided
/// [`EdgeTunControlPlane`] implementation.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
///
/// use scion_sdk_edge_tun::control::{
///     EdgeTunControlPlane, api::server::EdgeTunControlPlaneCrpcApi,
/// };
/// use scion_sdk_quic_scion::socket::GenericScionUdpSocket;
/// use tokio_util::sync::CancellationToken;
///
/// # async fn example<C: EdgeTunControlPlane + 'static>(
/// #     rnd_seed: [u8; 32],
/// #     socket: Arc<dyn GenericScionUdpSocket>,
/// #     config: scion_sdk_quic_scion::reexport::squiche::Config,
/// #     control_plane: Arc<C>,
/// # ) {
/// let api = EdgeTunControlPlaneCrpcApi::new(rnd_seed, socket, config, control_plane);
/// let token = CancellationToken::new();
/// api.start_listening(token).await;
/// # }
/// ```
pub struct EdgeTunControlPlaneCrpcApi<C: EdgeTunControlPlane + 'static> {
    endpoint: QuicScionServerEndpoint<ConnectionHandle<Http3Server<EdgeTunControlService<C>>>>,
    socket: Arc<dyn GenericScionUdpSocket>,
    service: EdgeTunControlService<C>,
}

impl<C: EdgeTunControlPlane + 'static> EdgeTunControlPlaneCrpcApi<C> {
    /// Creates a new [`EdgeTunControlPlaneCrpcApi`].
    ///
    /// # Arguments
    /// * `rnd_seed` - Seed for the endpoint's connection-ID and address-validation-token
    ///   generators. The caller is responsible for sourcing it from a cryptographically secure RNG;
    ///   it is the single point at which randomness enters the server.
    /// * `socket` - The SCION socket the control plane listens on.
    /// * `config` - The QUIC server configuration. The caller is responsible for loading the TLS
    ///   certificate chain and private key into it.
    /// * `control_plane` - The control plane implementation to dispatch requests to.
    pub fn new(
        rnd_seed: [u8; 32],
        socket: Arc<dyn GenericScionUdpSocket>,
        config: squiche::Config,
        control_plane: Arc<C>,
    ) -> Self {
        Self::with_metrics(
            rnd_seed,
            socket,
            config,
            control_plane,
            unregistered_metrics(),
        )
    }

    /// Like [`Self::new`], but lets the caller provide the endpoint [`Metrics`]
    /// (for example to register them with a prometheus registry).
    pub fn with_metrics(
        rnd_seed: [u8; 32],
        socket: Arc<dyn GenericScionUdpSocket>,
        config: squiche::Config,
        control_plane: Arc<C>,
        metrics: Metrics,
    ) -> Self {
        let local_addr = socket.local_addr();

        let endpoint = QuicScionServerEndpoint::new(rnd_seed, config, local_addr, metrics);

        Self {
            endpoint,
            socket,
            service: EdgeTunControlService { control_plane },
        }
    }

    /// Starts listening for incoming Connect-RPC requests.
    ///
    /// This runs until the provided `cancellation_token` is cancelled or a fatal
    /// socket error occurs.
    pub async fn start_listening(self, cancellation_token: CancellationToken) {
        let driver = QuicScionEndpointDriver::with_config(
            self.endpoint,
            self.socket,
            // Requests are served by the endpoint's internal HTTP/3 dispatch, so
            // the per-connection handle is not needed here.
            |_handle: ConnectionHandle<Http3Server<EdgeTunControlService<C>>>| {},
            Http3ServerConfig::new(self.service),
        );

        if let Err(e) = driver.run(cancellation_token).await {
            tracing::error!(?e, "EdgeTunControlPlaneCrpcApi: endpoint driver stopped");
        }
    }
}

/// Constructs a standalone (unregistered) set of endpoint [`Metrics`].
///
/// Used when the caller does not provide its own metrics; the gauges are not
/// registered with any prometheus registry.
fn unregistered_metrics() -> Metrics {
    Metrics {
        establishing_connections_gauge: IntGauge::new(
            "edgetun_control_establishing_connections",
            "Number of control plane connections currently being established.",
        )
        .expect("gauge name is valid"),
        routed_source_cids_gauge: IntGauge::new(
            "edgetun_control_registered_connections",
            "Number of currently registered control plane connections.",
        )
        .expect("gauge name is valid"),
    }
}

fn handle_get_data_plane_configuration<C: EdgeTunControlPlane>(
    body: &[u8],
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
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

fn handle_register_edge_tun_identity<C: EdgeTunControlPlane>(
    body: &[u8],
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
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

fn handle_address_assign<C: EdgeTunControlPlane>(
    body: &[u8],
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
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

fn handle_get_route_advertisement<C: EdgeTunControlPlane>(
    body: &[u8],
    control_plane: &C,
) -> Result<Vec<u8>, CrpcError> {
    let request = GetRouteAdvertisementRequest::decode(body).map_err(|e| {
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

    let response = GetRouteAdvertisementResponse {
        route: routes.into_iter().map(ipnet_to_ip_address_range).collect(),
    };

    Ok(response.encode_to_vec())
}

/// A minimal HTTP/3 response body that yields its bytes in a single data frame.
pub struct FullBody(Option<Bytes>);

impl FullBody {
    fn new(data: Vec<u8>) -> Self {
        if data.is_empty() {
            Self(None)
        } else {
            Self(Some(Bytes::from(data)))
        }
    }
}

impl Body for FullBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }
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
