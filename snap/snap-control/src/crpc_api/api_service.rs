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
    http::StatusCode,
};
use scion_sdk_axum_connect_rpc::{error::CrpcError, extractor::ConnectRpc};
use snap_tokens::snap_token::SnapTokenClaims;

use crate::{
    crpc_api::api_service::model::SessionManager,
    protobuf::anapaya::snap::v1::api_service::{
        GetSnapDataPlaneSessionGrantRequest, GetSnapDataPlaneSessionGrantResponse,
        RenewSnapDataPlaneSessionGrantRequest, RenewSnapDataPlaneSessionGrantResponse,
    },
};

/// SNAP control plane API models.
pub mod model {
    use std::net::{IpAddr, SocketAddr};

    use axum::http::StatusCode;
    use snap_tokens::snap_token::SnapTokenClaims;

    /// Session manager trait.
    pub trait SessionManager: Send + Sync {
        /// Create a SNAP data plane session for the given SNAP token.
        fn create_sessions(
            &self,
            endhost_ip_addr: IpAddr,
            snap_token: SnapTokenClaims,
        ) -> Result<Vec<SessionGrant>, (StatusCode, anyhow::Error)>;
        /// Renew a SNAP data plane session for the given address and SNAP token.
        fn renew_session(
            &self,
            dataplane_addr: SocketAddr,
            endhost_ip_addr: IpAddr,
            snap_token: SnapTokenClaims,
        ) -> Result<SessionGrant, (StatusCode, anyhow::Error)>;
    }

    /// Session grant.
    pub struct SessionGrant {
        /// The SNAP data plane address for which the session is valid.
        pub address: SocketAddr,
        /// The issued SNAP data plane session token.
        pub token: String,
    }
}

pub(crate) mod convert {
    use std::net::AddrParseError;

    use thiserror::Error;

    use crate::{
        crpc_api::api_service::model::SessionGrant, protobuf::anapaya::snap::v1::api_service as rpc,
    };

    // Model to Protobuf
    impl From<SessionGrant> for rpc::SnapDataPlaneSessionGrant {
        fn from(value: SessionGrant) -> Self {
            rpc::SnapDataPlaneSessionGrant {
                address: value.address.to_string(),
                token: value.token,
            }
        }
    }

    /// Session grant error.
    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum SessionGrantError {
        /// Missing grant field.
        // This error only exists as there are no required fields in protobuf.
        #[error("session grant field is required")]
        MissingGrant,
        /// Invalid address.
        #[error("invalid address: {0}")]
        InvalidAddress(#[from] AddrParseError),
    }

    // Protobuf to Model
    impl TryFrom<rpc::SnapDataPlaneSessionGrant> for SessionGrant {
        type Error = SessionGrantError;
        fn try_from(value: rpc::SnapDataPlaneSessionGrant) -> Result<Self, Self::Error> {
            Ok(SessionGrant {
                address: value.address.parse()?,
                token: value.token,
            })
        }
    }

    impl TryFrom<rpc::GetSnapDataPlaneSessionGrantResponse> for Vec<SessionGrant> {
        type Error = SessionGrantError;
        fn try_from(value: rpc::GetSnapDataPlaneSessionGrantResponse) -> Result<Self, Self::Error> {
            value
                .grants
                .into_iter()
                .map(SessionGrant::try_from)
                .collect()
        }
    }

    impl TryFrom<rpc::RenewSnapDataPlaneSessionGrantResponse> for SessionGrant {
        type Error = SessionGrantError;
        fn try_from(
            value: rpc::RenewSnapDataPlaneSessionGrantResponse,
        ) -> Result<Self, Self::Error> {
            match value.grant {
                Some(grant) => SessionGrant::try_from(grant),
                None => Err(SessionGrantError::MissingGrant),
            }
        }
    }
}

pub(crate) const SERVICE_PATH: &str = "/anapaya.snap.v1.SnapControl";
pub(crate) const GET_SNAP_DATA_PLANE_SESSION_GRANT: &str = "/GetSnapDataPlaneSessionGrant";
pub(crate) const RENEW_SNAP_DATA_PLANE_SESSION_GRANT: &str = "/RenewSnapDataPlaneSessionGrant";

/// Nests the SNAP control API routes into the provided `base_router`.
pub fn nest_snap_control_api(
    router: axum::Router,
    session_service: Arc<dyn SessionManager>,
) -> axum::Router {
    router.nest(
        SERVICE_PATH,
        Router::new()
            .route(
                GET_SNAP_DATA_PLANE_SESSION_GRANT,
                axum::routing::post(add_snap_data_plane_session_handler),
            )
            .route(
                RENEW_SNAP_DATA_PLANE_SESSION_GRANT,
                axum::routing::post(renew_snap_data_plane_session_handler),
            )
            .with_state(session_service),
    )
}

#[axum_macros::debug_handler]
async fn add_snap_data_plane_session_handler(
    State(session_manager): State<Arc<dyn SessionManager>>,
    snap_token: Extension<SnapTokenClaims>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    ConnectRpc(_request): ConnectRpc<GetSnapDataPlaneSessionGrantRequest>,
) -> Result<ConnectRpc<GetSnapDataPlaneSessionGrantResponse>, CrpcError> {
    let grants = session_manager.create_sessions(addr.ip(), snap_token.0.clone())?;
    Ok(ConnectRpc(GetSnapDataPlaneSessionGrantResponse {
        grants: grants.into_iter().map(Into::into).collect(),
    }))
}

async fn renew_snap_data_plane_session_handler(
    State(session_manager): State<Arc<dyn SessionManager>>,
    snap_token: Extension<SnapTokenClaims>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    ConnectRpc(request): ConnectRpc<RenewSnapDataPlaneSessionGrantRequest>,
) -> Result<ConnectRpc<RenewSnapDataPlaneSessionGrantResponse>, CrpcError> {
    let address = request.address.parse().map_err(|e| {
        CrpcError::new(
            StatusCode::BAD_REQUEST.into(),
            format!("invalid data plane address: {e}"),
        )
    })?;

    let grant = session_manager.renew_session(address, addr.ip(), snap_token.0.clone())?;
    Ok(ConnectRpc(RenewSnapDataPlaneSessionGrantResponse {
        grant: Some(grant.into()),
    }))
}
