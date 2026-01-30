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
//! PocketScion management API.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
};

use axum::{
    Json,
    extract::{self, State},
    response::IntoResponse,
};
use http::StatusCode;
use scion_proto::address::IsdAsn;
use scion_sdk_observability::info_trace_layer;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use url::Url;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    addr_to_http_url,
    dto::{IoConfigDto, SystemStateDto},
    endhost_api::EndhostApiId,
    io_config::SharedPocketScionIoConfig,
    state::{SharedPocketScionState, snap::SnapId},
};

const MANAGEMENT_TAG: &str = "management";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Pocket SCION Management API",
        description = "Management API for Pocket SCION",
        contact(
            name = "Anapaya Operations",
            email = "ops@anapaya.net",
        ),
    ),
    servers(
        (url = "http://{host}:{port}/api/v1"),
    ),
    tags(
        (name = MANAGEMENT_TAG, description = "Operations related to the management of Pocket SCION"),
    ),
)]
struct ManagementApi;

pub(crate) fn build_management_api(
    ready_state: Arc<AtomicBool>,
    system_state: SharedPocketScionState,
    io_config: SharedPocketScionIoConfig,
) -> OpenApiRouter {
    let logging_layer = ServiceBuilder::new().layer(info_trace_layer());

    OpenApiRouter::with_openapi(ManagementApi::openapi())
        .routes(routes!(get_status))
        .with_state(ready_state.clone())
        .merge(
            OpenApiRouter::new()
                .routes(routes!(get_snaps))
                .routes(routes!(get_io_config))
                .routes(routes!(get_system_state))
                .routes(routes!(get_auth_server))
                .routes(routes!(get_endhost_apis))
                .routes(routes!(set_link_state))
                .with_state((system_state.clone(), io_config.clone())),
        )
        .layer(logging_layer)
}

/// Status response.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct StatusResponse {
    /// The current ready state of pocketSCION.
    #[schema(example = State::Ready)]
    pub state: ReadyState,
}

/// PocketSCION ready state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq)]
pub enum ReadyState {
    /// Ready.
    Ready,
    /// Not ready.
    NotReady,
}

/// Status of the Pocket SCION service.
#[utoipa::path(
    get,
    path = "/status",
    tag = MANAGEMENT_TAG,
    responses(
        (
            status = 200,
            description = "Pocket SCION status",
            body = StatusResponse
        )
    )
)]
async fn get_status(State(ready_state): State<Arc<AtomicBool>>) -> Json<StatusResponse> {
    match ready_state.load(std::sync::atomic::Ordering::Relaxed) {
        true => {
            Json(StatusResponse {
                state: ReadyState::Ready,
            })
        }
        false => {
            Json(StatusResponse {
                state: ReadyState::NotReady,
            })
        }
    }
}

/// SNAP response.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SnapsResponse {
    /// Map of SNAPs.
    pub snaps: BTreeMap<SnapId, Snap>,
}

/// SNAP in pocketSCION.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Snap {
    /// SNAP control plane API address.
    #[schema(value_type = String)]
    pub control_plane_api: Url,
}

/// List all available SNAPs of the Pocket SCION.
#[utoipa::path(
    get,
    path = "/snaps",
    tag = MANAGEMENT_TAG,
    responses(
        (
            status = 200,
            description = "List all available SNAPs",
            body = SnapsResponse
        )
    )
)]
async fn get_snaps(
    State((system_state, io_config)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
) -> Json<SnapsResponse> {
    let mut snaps: BTreeMap<SnapId, Snap> = BTreeMap::new();
    system_state.snaps_ids().iter().for_each(|snap_id| {
        match io_config.snap_control_addr(*snap_id) {
            Some(addr) => {
                snaps.insert(
                    *snap_id,
                    Snap {
                        control_plane_api: addr_to_http_url(addr),
                    },
                );
            }
            None => {
                tracing::error!(snap=%snap_id, "No control plane API port for SNAP in I/O config");
            }
        }
    });

    Json(SnapsResponse { snaps })
}

/// Authorization server response.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AuthServerResponse {
    /// Address of the authorization server.
    #[schema(value_type = String)]
    pub addr: SocketAddr,
}

/// Fake authorization server details.
#[utoipa::path(
    get,
    path = "/auth_server",
    tag = MANAGEMENT_TAG,
    responses(
        (
            status = 200,
            description = "Authorization Server details",
            body = AuthServerResponse
        ),
        (
            status = 404,
            description = "No Authorization Server running"
        ),
    )
)]
async fn get_auth_server(
    State((_system_state, io_config)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
) -> impl IntoResponse {
    match io_config.auth_server_addr() {
        Some(addr) => Json(AuthServerResponse { addr }).into_response(),
        None => (StatusCode::NOT_FOUND).into_response(),
    }
}

/// Get the current pocket SCION I/O config.
#[utoipa::path(
    get,
    path = "/io_config",
    tag = MANAGEMENT_TAG,
    responses(
        (status = 200, description = "The pocket SCION I/O config", body = IoConfigDto)
    )
)]
async fn get_io_config(
    State((_, io_config)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
) -> Json<IoConfigDto> {
    Json(io_config.to_dto())
}

/// Get the current pocket SCION system state.
#[utoipa::path(
    get,
    path = "/system_state",
    tag = MANAGEMENT_TAG,
    responses(
        (status = 200, description = "The pocket SCION system state.", body = SystemStateDto)
    )
)]
async fn get_system_state(
    State((system_state, _)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
) -> Json<SystemStateDto> {
    Json(system_state.to_dto())
}

/// Response for the endhost APIs.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct EndhostApisResponse {
    /// Map of endhost APIs.
    pub endhost_apis: BTreeMap<EndhostApiId, EndhostApiResponseEntry>,
}

/// Endhost API information.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndhostApiResponseEntry {
    /// The ID of the Endhost API.
    pub id: EndhostApiId,
    /// The local ASes the Endhost API serves.
    pub local_ases: BTreeSet<IsdAsn>,
    /// The URL of the Endhost API.
    pub url: Url,
}

#[utoipa::path(
    get,
    path = "/endhost_apis",
    tag = MANAGEMENT_TAG,
    responses(
        (status = 200, description = "The pocket SCION endhost APIs.", body = EndhostApisResponse)
    )
)]
async fn get_endhost_apis(
    State((system_state, io)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
) -> Json<EndhostApisResponse> {
    let endhost_apis = system_state.endhost_apis();

    let mut resp_endhost_apis = BTreeMap::new();
    for (id, api) in &endhost_apis {
        match io.endhost_api_addr(*id) {
            Some(addr) => {
                resp_endhost_apis.insert(
                    *id,
                    EndhostApiResponseEntry {
                        id: *id,
                        local_ases: api.local_ases.clone(),
                        url: addr_to_http_url(addr),
                    },
                );
            }
            None => {
                tracing::error!(%id, "No Endhost API address in I/O config, cant list");
            }
        }
    }

    Json(EndhostApisResponse {
        endhost_apis: resp_endhost_apis,
    })
}

/// Response for the endhost APIs.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SetLinkStateRequest {
    /// The link state to set.
    pub up: bool,
    /// The interface ID of the link.
    pub interface_id: u16,
    /// The ISD-AS of the AS
    pub isd_as: IsdAsn,
}

/// Set the link state of a link in the topology.
///
/// Returns 200 OK on success or 404 Not Found if the link does not exist.
#[utoipa::path(
    post,
    path = "/link_state",
    tag = MANAGEMENT_TAG,
    responses(
        (status = 200, description = "Link state set successfully"),
        (status = 404, description = "Link not found"),
    )
)]
async fn set_link_state(
    State((system_state, _io)): State<(SharedPocketScionState, SharedPocketScionIoConfig)>,
    Json(req): extract::Json<SetLinkStateRequest>,
) -> impl IntoResponse {
    // Example function to demonstrate usage of system state and I/O config.
    match system_state.set_link_state(req.isd_as, req.interface_id, req.up) {
        Some(_) => {
            tracing::info!(%req.isd_as, interface_id=req.interface_id, up=req.up, "Link state set successfully");
            StatusCode::OK
        }
        None => {
            tracing::error!(%req.isd_as, interface_id=req.interface_id, "Failed to set link state, either no topology or link not found");
            StatusCode::NOT_FOUND
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::SystemTime};

    use super::*;

    /// Test that the generated OpenAPI specification matches the expected spec file.
    ///
    /// If this test fails, it means the OpenAPI spec has changed. To update the expected
    /// spec file, run:
    /// ```bash
    /// UPDATE=true cargo test --lib -p pocketscion api::admin::api::tests::should_generate_valid_openapi_spec
    /// ```
    #[test]
    fn should_generate_valid_openapi_spec() {
        let update = std::env::var("UPDATE").is_ok();

        let current = include_str!("spec.gen.yml");

        let (_, openapi) = build_management_api(
            Arc::new(AtomicBool::new(false)),
            SharedPocketScionState::new(SystemTime::now()),
            SharedPocketScionIoConfig::new(),
        )
        .split_for_parts();

        const GENERATED_SPEC_HEADER: &str = "# GENERATED FILE DO NOT EDIT\n# This file was generated by the `generate_openapi` test in `src/api/admin/api.rs`\n";
        let newest = format!("{}{}", GENERATED_SPEC_HEADER, openapi.to_yaml().unwrap());

        if update {
            let path: PathBuf = [
                env!("CARGO_MANIFEST_DIR"),
                "src",
                "api",
                "admin",
                "spec.gen.yml",
            ]
            .iter()
            .collect();
            std::fs::write(path, newest).unwrap();
        } else {
            assert_eq!(
                newest, current,
                "The OpenAPI specification has changed. Run the test with UPDATE=true to update the file."
            );
        }
    }
}
