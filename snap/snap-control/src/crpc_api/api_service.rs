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
//! Connect RPC API endpoint definitions and endpoint handlers.

use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

use axum::{
    Extension, Router,
    extract::{ConnectInfo, State},
};
use scion_sdk_axum_connect_rpc::{
    error::{CrpcError, CrpcErrorCode},
    extractor::ConnectRpc,
};
use scion_sdk_token_validator::validator::Token;
use snap_tokens::snap_token::SnapTokenClaims;
use x25519_dalek::PublicKey;

use crate::{
    crpc_api::api_service::model::{
        RegisterError, SnapDataPlaneResolver, SnapTunIdentityRegistrar,
    },
    protobuf::anapaya::snap::v1::api_service::{
        GetSnapDataPlaneRequest, GetSnapDataPlaneResponse, RegisterSnapTunIdentityRequest,
        RegisterSnapTunIdentityResponse,
    },
};

/// SNAP control plane API models.
pub mod model {
    use std::{
        borrow::Cow,
        net::{IpAddr, SocketAddr},
        time::{Duration, Instant},
    };

    use axum::http::StatusCode;
    use x25519_dalek::PublicKey;

    /// SNAP data plane discovery trait.
    pub trait SnapDataPlaneResolver: Send + Sync {
        /// Get the SNAP data plane address for a given endhost IP address.
        fn get_data_plane_address(
            &self,
            endhost_ip: IpAddr,
        ) -> Result<SnapDataPlane, (StatusCode, anyhow::Error)>;
    }

    /// SnapDataPlane resolution response.
    pub struct SnapDataPlane {
        /// The SNAP data plane address according to the rendezvous hashing that must be used by
        /// the client.
        pub address: SocketAddr,
        /// XXX(uniquefine): Make this required once all servers have been updated.
        /// The address (host:port) of the SNAPtun control plane API. This can be the same
        /// as the data plane address.
        pub snap_tun_control_address: Option<SocketAddr>,
        /// XXX(uniquefine): Make this required once all servers have been updated.
        /// The static identity of the snaptun-ng server.
        pub snap_static_x25519: Option<PublicKey>,
    }

    /// Error returned when registering a static identity for a snaptun connection.
    #[derive(thiserror::Error, Debug)]
    pub enum RegisterError {
        /// The provided identity or psk share is invalid.
        #[error("invalid argument: {0}")]
        InvalidArgument(Cow<'static, str>),
        /// The requested identity is already registered.
        #[error("the requested identity is already registered: {0}")]
        Conflict(Cow<'static, str>),
        /// The requested lifetime is too short.
        #[error("the requested lifetime is too short: {0}")]
        InsufficientLifetime(Cow<'static, str>),
    }

    /// Trait for registering a static identity for a snaptun connection.
    pub trait SnapTunIdentityRegistrar: Send + Sync {
        /// Register a static identity for a snaptun connection.
        /// Returns the servers PSK share if the registration was successful.
        fn register(
            &self,
            now: Instant,
            // The static identity of the client.
            initiator_identity: PublicKey,
            // The PSK share used to establish a shared secret with the server.
            psk_share: Option<[u8; 32]>,
            // The lifetime the registered identity is valid for.
            // Usually this is determined by the expiration of the SNAP token.
            lifetime: Duration,
        ) -> Result<Option<[u8; 32]>, RegisterError>;
    }
}

pub(crate) mod convert {
    use std::net::AddrParseError;

    use x25519_dalek::PublicKey;

    use crate::{
        crpc_api::api_service::model::SnapDataPlane,
        protobuf::anapaya::snap::v1::api_service as rpc,
    };

    /// This error is returned when converting a GetSnapDataPlaneResponse to a SnapDataPlane.
    #[derive(thiserror::Error, Debug)]
    pub enum ConvertError {
        #[error("failed to parse data plane address: {0}")]
        ParseAddr(AddrParseError),
        #[error("failed to parse server control address: {0}")]
        ParseSnapTunControlAddr(AddrParseError),
        #[error("server static identity is not 32 bytes")]
        InvalidServerStaticIdentityLength,
    }

    // Protobuf to Model
    impl TryFrom<rpc::GetSnapDataPlaneResponse> for SnapDataPlane {
        type Error = ConvertError;
        fn try_from(value: rpc::GetSnapDataPlaneResponse) -> Result<Self, Self::Error> {
            let snap_tun_control_address = value
                .snap_tun_control_address
                .map(|address| {
                    address
                        .parse()
                        .map_err(ConvertError::ParseSnapTunControlAddr)
                })
                .transpose()?;
            let snap_static_x25519 = value
                .snap_static_x25519
                .map(|key| {
                    TryInto::<[u8; 32]>::try_into(key.as_slice())
                        .map_err(|_| ConvertError::InvalidServerStaticIdentityLength)
                        .map(PublicKey::from)
                })
                .transpose()?;
            Ok(SnapDataPlane {
                address: value.address.parse().map_err(ConvertError::ParseAddr)?,
                snap_tun_control_address,
                snap_static_x25519,
            })
        }
    }
}

pub(crate) const SERVICE_PATH: &str = "/anapaya.snap.v1.SnapControl";
pub(crate) const GET_SNAP_DATA_PLANE_ADDRESS: &str = "/GetSnapDataPlaneAddress";
pub(crate) const REGISTER_SNAPTUN_IDENTITY: &str = "/RegisterSnapTunIdentity";

/// Nests the SNAP control API routes into the provided `base_router`.
pub fn nest_snap_control_api(
    router: axum::Router,
    snap_resolver: Arc<dyn SnapDataPlaneResolver>,
    identity_registrar: Arc<dyn SnapTunIdentityRegistrar>,
) -> axum::Router {
    router.nest(
        SERVICE_PATH,
        Router::new()
            .route(
                GET_SNAP_DATA_PLANE_ADDRESS,
                axum::routing::post(get_snap_data_plane_address_handler),
            )
            .with_state(snap_resolver)
            .route(
                REGISTER_SNAPTUN_IDENTITY,
                axum::routing::post(register_snaptun_identity_handler),
            )
            .with_state(identity_registrar),
    )
}

async fn get_snap_data_plane_address_handler(
    State(rendezvous_hasher): State<Arc<dyn SnapDataPlaneResolver>>,
    _snap_token: Extension<SnapTokenClaims>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    ConnectRpc(_request): ConnectRpc<GetSnapDataPlaneRequest>,
) -> Result<ConnectRpc<GetSnapDataPlaneResponse>, CrpcError> {
    let addr = rendezvous_hasher.get_data_plane_address(addr.ip())?;
    Ok(ConnectRpc(GetSnapDataPlaneResponse {
        address: addr.address.to_string(),
        snap_tun_control_address: addr
            .snap_tun_control_address
            .map(|address| address.to_string()),
        snap_static_x25519: addr.snap_static_x25519.map(|key| key.to_bytes().to_vec()),
    }))
}

async fn register_snaptun_identity_handler(
    State(identity_registrar): State<Arc<dyn SnapTunIdentityRegistrar>>,
    snap_token: Extension<SnapTokenClaims>,
    ConnectInfo(_): ConnectInfo<std::net::SocketAddr>,
    ConnectRpc(request): ConnectRpc<RegisterSnapTunIdentityRequest>,
) -> Result<ConnectRpc<RegisterSnapTunIdentityResponse>, CrpcError> {
    let now = SystemTime::now();
    let lifetime = snap_token.0.exp_time().duration_since(now).map_err(|_| {
        CrpcError::new(
            CrpcErrorCode::InvalidArgument,
            "expiration time is in the past".to_string(),
        )
    })?;

    let initiator_identity = {
        let key_bytes: [u8; 32] = request
            .initiator_static_x25519
            .as_slice()
            .try_into()
            .map_err(|_| {
                CrpcError::new(
                    CrpcErrorCode::InvalidArgument,
                    "initiator identity is not 32 bytes".to_string(),
                )
            })?;
        PublicKey::from(key_bytes)
    };

    let psk_share: Option<[u8; 32]> = if request.psk_share.as_slice() == [0u8; 32] {
        None
    } else {
        Some(request.psk_share.as_slice().try_into().map_err(|_| {
            CrpcError::new(
                CrpcErrorCode::InvalidArgument,
                "psk share is not 32 bytes".to_string(),
            )
        })?)
    };

    let psk_share = identity_registrar
        .register(Instant::now(), initiator_identity, psk_share, lifetime)
        .map_err(|e| {
            match e {
                RegisterError::InvalidArgument(e) => {
                    CrpcError::new(CrpcErrorCode::InvalidArgument, e.to_string())
                }
                RegisterError::Conflict(e) => {
                    CrpcError::new(CrpcErrorCode::AlreadyExists, e.to_string())
                }
                RegisterError::InsufficientLifetime(e) => {
                    CrpcError::new(CrpcErrorCode::InvalidArgument, e.to_string())
                }
            }
        })?;
    Ok(ConnectRpc(RegisterSnapTunIdentityResponse {
        psk_share: psk_share.unwrap_or([0u8; 32]).to_vec(),
    }))
}
