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

use std::sync::Arc;

use axum::{
    Extension, Router,
    extract::{ConnectInfo, State},
};
use scion_sdk_axum_connect_rpc::{error::CrpcError, extractor::ConnectRpc};
use snap_tokens::snap_token::SnapTokenClaims;

use crate::{
    crpc_api::api_service::model::SnapDataPlaneResolver,
    protobuf::anapaya::snap::v1::api_service::{GetSnapDataPlaneRequest, GetSnapDataPlaneResponse},
};

/// SNAP control plane API models.
pub mod model {
    use std::net::{IpAddr, SocketAddr};

    use axum::http::StatusCode;

    /// SNAP data plane discovery trait.
    pub trait SnapDataPlaneResolver: Send + Sync {
        /// Get the SNAP data plane address for a given endhost IP address.
        fn get_data_plane_address(
            &self,
            endhost_ip: IpAddr,
        ) -> Result<SocketAddr, (StatusCode, anyhow::Error)>;
    }

    /// SnapDataPlane resolution response.
    pub struct SnapDataPlane {
        /// The SNAP data plane address according to the rendezvous hashing that must be used by
        /// the client.
        pub address: SocketAddr,
    }
}

pub(crate) mod convert {
    use std::net::AddrParseError;

    use crate::{
        crpc_api::api_service::model::SnapDataPlane,
        protobuf::anapaya::snap::v1::api_service as rpc,
    };

    // Protobuf to Model
    impl TryFrom<rpc::GetSnapDataPlaneResponse> for SnapDataPlane {
        type Error = AddrParseError;
        fn try_from(value: rpc::GetSnapDataPlaneResponse) -> Result<Self, Self::Error> {
            Ok(SnapDataPlane {
                address: value.address.parse()?,
            })
        }
    }
}

pub(crate) const SERVICE_PATH: &str = "/anapaya.snap.v1.SnapControl";
pub(crate) const GET_SNAP_DATA_PLANE_ADDRESS: &str = "/GetSnapDataPlaneAddress";

/// Nests the SNAP control API routes into the provided `base_router`.
pub fn nest_snap_control_api(
    router: axum::Router,
    snap_resolver: Arc<dyn SnapDataPlaneResolver>,
) -> axum::Router {
    router.nest(
        SERVICE_PATH,
        Router::new()
            .route(
                GET_SNAP_DATA_PLANE_ADDRESS,
                axum::routing::post(get_snap_data_plane_address_handler),
            )
            .with_state(snap_resolver),
    )
}

#[axum_macros::debug_handler]
async fn get_snap_data_plane_address_handler(
    State(rendezvous_hasher): State<Arc<dyn SnapDataPlaneResolver>>,
    _snap_token: Extension<SnapTokenClaims>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    ConnectRpc(_request): ConnectRpc<GetSnapDataPlaneRequest>,
) -> Result<ConnectRpc<GetSnapDataPlaneResponse>, CrpcError> {
    let addr = rendezvous_hasher.get_data_plane_address(addr.ip())?;
    Ok(ConnectRpc(GetSnapDataPlaneResponse {
        address: addr.to_string(),
    }))
}
