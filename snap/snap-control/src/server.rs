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

use std::{sync::Arc, time::Duration};

use axum::{BoxError, Router, error_handling::HandleErrorLayer};
use endhost_api::routes::nest_endhost_api;
use endhost_api_models::{
    SegmentsDiscovery,
    underlays::{ScionRouter, Underlays},
};
use http::StatusCode;
use scion_sdk_observability::info_trace_layer;
use sciparse::identifier::isd_asn::IsdAsn;
use tower::{ServiceBuilder, timeout::TimeoutLayer};
use url::Url;

use crate::{
    api::{
        crpc::{
            model::{SnapDataPlaneResolver, SnapTunIdentityRegistry},
            nest_crpc_api,
        },
        http::{model::PgWapSessionManager, nest_http_api},
    },
    model::UnderlayDiscovery,
    server::{
        auth::AuthMiddlewareLayer,
        metrics::{Metrics, PrometheusMiddlewareLayer},
    },
};

pub mod auth;
pub mod identity_registry;
pub mod jwks_key_store;
pub mod metrics;
pub mod mock_segment_lister;
pub mod state;
pub mod token_verifier;

pub use token_verifier::SnapTokenVerifier;

const CONTROL_PLANE_API_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the SNAP control plane router.
pub fn build_router<UD, SL, SR, IR>(
    underlay_discovery: UD,
    snap_cp_api: Url,
    segment_lister: SL,
    snap_resolver: SR,
    identity_registry: Arc<IR>,
    pg_wap_session_manager: Option<Arc<dyn PgWapSessionManager>>,
    token_verifier: SnapTokenVerifier,
    metrics: Metrics,
) -> std::io::Result<Router>
where
    UD: UnderlayDiscovery + 'static + Send + Sync,
    SL: SegmentsDiscovery + 'static + Send + Sync,
    SR: SnapDataPlaneResolver + 'static + Send + Sync,
    IR: SnapTunIdentityRegistry + 'static + Send + Sync,
{
    // Create a sub-router for authenticated endpoints
    let mut auth_router = Router::new();
    auth_router = nest_endhost_api(
        auth_router,
        Arc::new(UnderlayDiscoveryAdapter::new(
            Arc::new(underlay_discovery),
            snap_cp_api,
        )),
        Arc::new(segment_lister),
    );
    auth_router = nest_crpc_api(auth_router, Arc::new(snap_resolver), identity_registry);
    auth_router =
        auth_router.layer(ServiceBuilder::new().layer(AuthMiddlewareLayer::new(token_verifier)));

    // Main unauthorized router.
    let mut router = Router::new();
    // XXX(bunert): For now the pathguard WAP HTTP API is unauthenticated. This will change in the
    // future.
    if let Some(pg_wap_session_manager) = pg_wap_session_manager {
        router = nest_http_api(router, pg_wap_session_manager);
    }

    // Merge the authenticated router into the main router
    router = router.merge(auth_router);

    // Apply common middlewares to ALL routes (error handling, tracing, timeout, metrics)
    router = router.layer(
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
            .layer(PrometheusMiddlewareLayer::new(metrics)),
    );
    Ok(router)
}

/// Adapter implementing UnderlayDiscovery for any DataPlaneDiscovery.
struct UnderlayDiscoveryAdapter<T: UnderlayDiscovery> {
    underlay_discovery: Arc<T>,
    snap_cp_api: Url,
}

impl<T: UnderlayDiscovery> UnderlayDiscoveryAdapter<T> {
    fn new(underlay_discovery: Arc<T>, snap_cp_api: Url) -> Self {
        Self {
            underlay_discovery,
            snap_cp_api,
        }
    }
}

impl<T: UnderlayDiscovery> endhost_api_models::UnderlayDiscovery for UnderlayDiscoveryAdapter<T> {
    fn list_underlays(&self, isd_as: IsdAsn) -> Underlays {
        let dps = self.underlay_discovery.list_udp_underlays();
        let mut udp_underlay = Vec::new();
        for dp in dps {
            for router_as in dp.isd_ases {
                if isd_as != IsdAsn::WILDCARD && router_as.isd_as != isd_as {
                    continue;
                };

                udp_underlay.push(ScionRouter {
                    isd_as: router_as.isd_as,
                    internal_interface: dp.endpoint,
                    interfaces: router_as.interfaces.clone(),
                });
            }
        }

        let sus = self.underlay_discovery.list_snap_underlays();
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
