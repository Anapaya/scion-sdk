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

//! HTTP API of the PocketSCION AA.

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use scion_sdk_observability::info_trace_layer;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_redoc::{Redoc, Servable};

use crate::comp::aa::AaConfig;

/// The path of the SNAP token route, relative to the base URL of the PocketSCION AA.
pub const SNAP_TOKEN_PATH: &str = "api/v1/snap-token";

/// Starts the PocketSCION AA API on the provided listener.
pub(crate) async fn start(
    cancellation_token: CancellationToken,
    config: AaConfig,
    listener: TcpListener,
) -> std::io::Result<()> {
    let logging_layer = ServiceBuilder::new().layer(info_trace_layer());
    let (router, openapi) = OpenApiRouter::with_openapi(AaApi::openapi())
        .routes(routes!(post_snap_token))
        .with_state(config)
        .layer(logging_layer)
        .split_for_parts();

    let final_router = Router::new()
        .nest("/api/v1", router)
        .merge(Redoc::with_url("/docs", openapi));

    tracing::info!(addr=?listener.local_addr(), "Starting PocketSCION AA API");
    if let Err(e) = axum::serve(listener, final_router.into_make_service())
        .with_graceful_shutdown(async move {
            cancellation_token.cancelled().await;
        })
        .await
    {
        tracing::error!(error=%e, "PocketSCION AA unexpectedly stopped");
    }

    tracing::info!("Shutting down PocketSCION AA");
    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "PocketSCION AA API",
        description = "The PocketSCION AA takes the place of a production AA. It gives SNAP tokens for a local PocketSCION network without an API key",
    ),
    servers(
        (url = "http://{host}:{port}/api/v1"),
    ),
)]
struct AaApi;

/// A SNAP token from the PocketSCION AA.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapTokenResponse {
    /// The SNAP token.
    pub snap_token: String,
    /// The number of seconds that the SNAP token stays valid.
    pub expires_in: u64,
}

/// Gives a SNAP token that the SNAPs of the PocketSCION network accept.
///
/// The route does not ask for an API key, and the request has no body.
#[utoipa::path(
    post,
    path = "/snap-token",
    summary = "Get a SNAP token",
    responses(
        (status = 200, description = "A SNAP token", body = SnapTokenResponse),
        (status = 500, description = "The AA cannot sign the token"),
    )
)]
async fn post_snap_token(State(config): State<AaConfig>) -> Response {
    match config.issue_token() {
        Ok(response) => Json(response).into_response(),
        Err(error) => {
            tracing::error!(%error, "Cannot issue a SNAP token");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use jsonwebtoken::DecodingKey;
    use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
    use snap_control::server::SnapTokenVerifier;
    use test_log::test;
    use url::Url;

    use super::*;
    use crate::{
        comp::aa::DEFAULT_TOKEN_VALIDITY,
        runtime::{PocketScionRuntime, builder::PocketScionRuntimeBuilder},
        state::PocketScionState,
        util::addr_to_http_url,
    };

    async fn start_aa() -> (PocketScionRuntime, Url) {
        let mut pstate = PocketScionState::new(Utc::now());
        pstate.set_aa(AaConfig::default()).unwrap();
        let runtime = PocketScionRuntimeBuilder::new()
            .with_system_state(pstate)
            .start()
            .await
            .unwrap();
        let url = addr_to_http_url(runtime.aa_addr().expect("the runtime starts the AA"));
        (runtime, url)
    }

    async fn request_token(aa_url: &Url) -> SnapTokenResponse {
        reqwest::Client::new()
            .post(aa_url.join(SNAP_TOKEN_PATH).unwrap())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn verify(token: &str) {
        let public_key = insecure_const_ed25519_key_pair_pem().1;
        let key = DecodingKey::from_ed_pem(pem::encode(&public_key).as_bytes()).unwrap();
        SnapTokenVerifier::new(key)
            .verify(token)
            .await
            .expect("the SNAPs accept the token");
    }

    #[test(tokio::test)]
    async fn token_passes_the_snap_verifier() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let (_runtime, aa_url) = start_aa().await;

        let response = request_token(&aa_url).await;

        verify(&response.snap_token).await;
        assert_eq!(response.expires_in, DEFAULT_TOKEN_VALIDITY.as_secs());
    }
}
