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
//! SNAP control plane API server.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::anyhow;
use axum::{BoxError, Router, error_handling::HandleErrorLayer};
use endhost_api::routes::nest_endhost_api;
use endhost_api_models::{
    PathDiscovery,
    underlays::{ScionRouter, Underlays},
};
use http::StatusCode;
use jsonwebtoken::DecodingKey;
use scion_proto::address::IsdAsn;
use scion_sdk_observability::info_trace_layer;
use snap_dataplane::session::manager::SessionTokenError;
use snap_tokens::snap_token::SnapTokenClaims;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::{ServiceBuilder, timeout::TimeoutLayer};
use url::Url;

use crate::{
    crpc_api::api_service::{
        model::{SessionGrant, SessionManager},
        nest_snap_control_api,
    },
    model::{CreateSessionError, DataPlaneDiscovery, SessionGranter, SnapDataPlane},
    server::{
        auth::AuthMiddlewareLayer,
        metrics::{Metrics, PrometheusMiddlewareLayer},
    },
};

pub mod auth;
pub mod metrics;
pub mod mock_segment_lister;
pub mod state;

const CONTROL_PLANE_API_TIMEOUT: Duration = Duration::from_secs(30);

// The control plane API rate limit is set to 5 requests per second.
const CONTROL_PLANE_RATE_LIMIT: u64 = 20;
const CONTROL_PLANE_RATE_LIMIT_PERIOD: Duration = Duration::from_secs(1);

/// Start the SNAP control plane API server.
pub async fn start<DP, SM, SL>(
    cancellation_token: CancellationToken,
    listener: TcpListener,
    dp_discovery: DP,
    session_manager: SM,
    segment_lister: SL,
    snap_token_decoding_key: DecodingKey,
    metrics: Metrics,
) -> std::io::Result<()>
where
    DP: DataPlaneDiscovery + 'static + Send + Sync,
    SM: SessionGranter + 'static + Send + Sync,
    SL: PathDiscovery + 'static + Send + Sync,
{
    let router = Router::new();

    let dp_discovery = Arc::new(dp_discovery);
    let session_manager = Arc::new(session_manager);
    let segment_lister = Arc::new(segment_lister);

    let snap_cp_addr = listener
        .local_addr()
        .map_err(|e| std::io::Error::other(format!("Failed to get own local address: {e}")))?;

    let snap_cp_api = match snap_cp_addr {
        SocketAddr::V4(addr) => {
            Url::parse(&format!("http://{addr}"))
                .expect("It is safe to format a SocketAddr as a URL")
        }
        SocketAddr::V6(addr) => {
            Url::parse(&format!("http://[{}]:{}", addr.ip(), addr.port()))
                .expect("It is safe to format a SocketAddr as a URL")
        }
    };

    let router = nest_endhost_api(
        router,
        Arc::new(UnderlayDiscoveryAdapter::new(
            dp_discovery.clone(),
            snap_cp_api,
        )),
        segment_lister.clone(),
    );

    let router = nest_snap_control_api(
        router,
        Arc::new(SessionManagerAdapter::new(
            session_manager.clone(),
            dp_discovery.clone(),
        )),
    );

    let router = router.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|err: BoxError| {
                async move {
                    tracing::error!(error=%err, "Control plane API error");

                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled error: {err}"),
                    )
                }
            }))
            .layer(info_trace_layer())
            .layer(TimeoutLayer::new(CONTROL_PLANE_API_TIMEOUT))
            .layer(tower::buffer::BufferLayer::new(1024))
            .layer(tower::limit::RateLimitLayer::new(
                CONTROL_PLANE_RATE_LIMIT,
                CONTROL_PLANE_RATE_LIMIT_PERIOD,
            ))
            .layer(PrometheusMiddlewareLayer::new(metrics))
            .layer(AuthMiddlewareLayer::new(snap_token_decoding_key)),
    );

    tracing::info!(addr=%snap_cp_addr, "Starting control plane API");

    if let Err(e) = axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(cancellation_token.cancelled_owned())
        .await
    {
        tracing::error!(error=%e, "Control plane API server unexpectedly stopped");
    }

    tracing::info!("Shutting down control plane API server");

    Ok(())
}

/// Adapter implementing UnderlayDiscovery for any DataPlaneDiscovery.
struct UnderlayDiscoveryAdapter<T: DataPlaneDiscovery> {
    dp_discovery: Arc<T>,
    snap_cp_api: Url,
}

impl<T: DataPlaneDiscovery> UnderlayDiscoveryAdapter<T> {
    fn new(dp_discovery: Arc<T>, snap_cp_api: Url) -> Self {
        Self {
            dp_discovery,
            snap_cp_api,
        }
    }
}

impl<T: DataPlaneDiscovery> endhost_api_models::UnderlayDiscovery for UnderlayDiscoveryAdapter<T> {
    fn list_underlays(&self, isd_as: IsdAsn) -> Underlays {
        let dps = self.dp_discovery.list_udp_data_planes();
        let mut udp_underlay = Vec::new();
        for dp in dps {
            for router_as in dp.isd_ases {
                if isd_as != IsdAsn::WILDCARD && router_as.isd_as != isd_as {
                    continue;
                };

                udp_underlay.push(ScionRouter {
                    isd_as: router_as.isd_as,
                    internal_interface: dp.endpoint,
                    interfaces: router_as.interfaces.iter().map(|&i| i as u16).collect(),
                });
            }
        }

        let sus = self.dp_discovery.list_snap_data_planes();
        if sus.is_empty() {
            return Underlays {
                udp_underlay,
                snap_underlay: Vec::new(),
            };
        }

        let mut snap_underlay = Vec::new();
        let all_ases: Vec<IsdAsn> = sus.iter().flat_map(|su| su.isd_ases.clone()).collect();
        if isd_as == IsdAsn::WILDCARD || all_ases.contains(&isd_as) {
            snap_underlay.push(endhost_api_models::underlays::Snap {
                address: self.snap_cp_api.clone(),
                isd_ases: all_ases,
            });
        }

        Underlays {
            udp_underlay,
            snap_underlay,
        }
    }
}

/// Adapter implementing SessionManager for any SessionManagerDeprecated.
struct SessionManagerAdapter {
    session_manager: Arc<dyn SessionGranter>,
    dp_discovery: Arc<dyn DataPlaneDiscovery>,
}

impl SessionManagerAdapter {
    fn new(
        session_manager: Arc<dyn SessionGranter>,
        dp_discovery: Arc<dyn DataPlaneDiscovery>,
    ) -> Self {
        Self {
            session_manager,
            dp_discovery,
        }
    }
}

impl SessionManager for SessionManagerAdapter {
    fn create_session(
        &self,
        snap_token: SnapTokenClaims,
    ) -> Result<Vec<SessionGrant>, (StatusCode, anyhow::Error)> {
        let dps = self.dp_discovery.list_snap_data_planes();

        let mut grants: Vec<SessionGrant> = Vec::with_capacity(dps.len());
        for dp in dps.iter() {
            let res = self
                .session_manager
                .create_session(dp.address, snap_token.clone());

            // XXX(bunert): We currently fail the entire request if creating a session for any data
            // plane fails. Eventually we want to return partial results here.
            match res {
                Ok(grant) => grants.push(grant),
                Err(err) => return Err(handle_session_error(dp, err)),
            }
        }

        Ok(grants)
    }

    fn renew_session(
        &self,
        address: SocketAddr,
        snap_token: SnapTokenClaims,
    ) -> Result<SessionGrant, (StatusCode, anyhow::Error)> {
        let dps = self.dp_discovery.list_snap_data_planes();
        let Some(dp) = dps.iter().find(|dp| dp.address == address) else {
            return Err((
                StatusCode::NOT_FOUND,
                anyhow!("No data plane with address {address}."),
            ));
        };

        let res = self.session_manager.create_session(dp.address, snap_token);

        match res {
            Ok(grant) => Ok(grant),
            Err(err) => Err(handle_session_error(dp, err)),
        }
    }
}

fn handle_session_error(
    dp: &SnapDataPlane,
    error: CreateSessionError,
) -> (StatusCode, anyhow::Error) {
    match error {
        CreateSessionError::DataPlaneNotFound => {
            (
                StatusCode::NOT_FOUND,
                anyhow!("no data plane with address {}", dp.address),
            )
        }
        CreateSessionError::IssueSessionToken(SessionTokenError::EncodingError(err)) => {
            tracing::error!(%err, "Failed to encode session token");
            (StatusCode::INTERNAL_SERVER_ERROR, anyhow!("internal error"))
        }
        CreateSessionError::OpenSession(session_open_error) => {
            tracing::error!(err=%session_open_error, "Failed to open session");
            (StatusCode::INTERNAL_SERVER_ERROR, anyhow!("internal error"))
        }
    }
}
