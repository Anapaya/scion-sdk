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
//! PocketSCION Authorization Server API.

use std::net::{Ipv4Addr, SocketAddr};

use axum::{Form, Json, Router, extract::State, response::IntoResponse};
use http::StatusCode;
use scion_sdk_observability::info_trace_layer;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_redoc::{Redoc, Servable};

use super::token_exchanger::{ID_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchange};
use crate::{
    authorization_server::token_exchanger::TokenExchangeError, dto::IoAuthServerConfigDto,
    io_config::SharedPocketScionIoConfig, state::AuthorizationServerHandle,
};

/// I/O configuration for the authorization server.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct IoAuthServerConfig {
    pub(crate) addr: Option<SocketAddr>,
}

impl From<&IoAuthServerConfig> for IoAuthServerConfigDto {
    fn from(config: &IoAuthServerConfig) -> Self {
        Self {
            addr: config.addr.map(|addr| addr.to_string()),
        }
    }
}

impl TryFrom<IoAuthServerConfigDto> for IoAuthServerConfig {
    type Error = std::io::Error;

    fn try_from(value: IoAuthServerConfigDto) -> Result<Self, Self::Error> {
        let addr = match value.addr {
            Some(addr) => {
                match addr.parse() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Invalid auth server address: {e}"),
                        ));
                    }
                }
            }
            None => None,
        };

        Ok(Self { addr })
    }
}

/// Starts the authorization server.
pub(crate) async fn start(
    cancellation_token: CancellationToken,
    token_exchanger: AuthorizationServerHandle,
    io_config: SharedPocketScionIoConfig,
) -> std::io::Result<()> {
    let listener = match io_config.auth_server_addr() {
        Some(addr) => {
            TcpListener::bind(&addr).await.map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to bind to authorization server address {addr}: {e}"),
                )
            })?
        }
        None => {
            tracing::debug!("No authorization server API address specified");
            let listener = TcpListener::bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            io_config.set_auth_server_addr(listener.local_addr()?);
            listener
        }
    };

    let logging_layer = ServiceBuilder::new().layer(info_trace_layer());
    let (router, openapi) = OpenApiRouter::with_openapi(AuhtorizationServerApi::openapi())
        .routes(routes!(post_token))
        .with_state(token_exchanger)
        .layer(logging_layer)
        .split_for_parts();

    let final_router = Router::new()
        .nest("/api/v1", router)
        .merge(Redoc::with_url("/docs", openapi));

    tracing::info!(addr=?listener.local_addr(), "Starting authorization server API");
    if let Err(e) = axum::serve(listener, final_router.into_make_service())
        .with_graceful_shutdown(async move {
            cancellation_token.cancelled().await;
        })
        .await
    {
        tracing::error!(error=%e, "Authorization server unexpectedly stopped");
    }

    tracing::info!("Shutting down auhtorization server");
    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Authorization Server API",
        description = "Authorization Server API for token exchange",
        contact(
            name = "Anapaya Operations",
            email = "ops@anapaya.net",
        ),
    ),
    servers(
        (url = "http://{host}:{port}/api/v1"),
    ),
)]
struct AuhtorizationServerApi;

/// Token exchange request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenRequest {
    // The grant type indicates that a token exchange is being performed.
    pub(crate) grant_type: String,
    // A security token that represents the identity of the party on behalf of
    // whom the request is being made. Typically, the subject of this token
    // will be the subject of the security token issued in response to the
    // request.
    pub(crate) subject_token: String,
    // Identifier that indicates the type of the security token in the
    // subject_token parameter.
    pub(crate) subject_token_type: String,
    // IGNORED: Optional URI that indicates the target service or resource where the
    // client intends to use the requested security token.
    pub(crate) resource: Option<String>,
    // IGNORED: Optional logical name of the target service where the client
    // intends to use the requested security token.
    pub(crate) audience: Option<String>,
    // IGNORED: Optional list of space-delimited, case-sensitive strings that
    // allow the client to specify the desired scope of the requested security
    // token in the context of the service or resource where the token will be
    // used.
    pub(crate) scope: Option<String>,
    // IGNORED: Optional identifier for the type of the requested security token.
    pub(crate) requested_token_type: Option<String>,
}

impl TokenRequest {
    /// Creates a new token exchange request with the given subject token.
    #[allow(unused)]
    pub fn new(subject_token: String) -> Self {
        Self {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_string(),
            subject_token,
            subject_token_type: ID_TOKEN_TYPE.to_string(),
            resource: None,
            audience: None,
            scope: None,
            requested_token_type: None,
        }
    }
}

/// Token exchange response.
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct TokenResponse {
    /// The security token issued by the authorization server in response to the
    /// token exchange request.
    pub access_token: String,
    /// Identifier for the representation of the issued security token.
    pub issued_token_type: String,
    /// A case-insensitive value specifying the method of using the access token issued.
    pub token_type: String,
    /// Token-type-agnostic indication of how long the token can be expected to be valid (in
    /// seconds).
    pub expires_in: u64,
    /// Optional if the scope of the issued security token is identical to the
    /// scope requested by the client; otherwise, it is required.
    pub scope: Option<String>,
}

/// Error response for a token exchange request if the request itself is not
/// valid or if the subject token is invalid for any reason
/// (<https://www.rfc-editor.org/rfc/rfc6749#section-5.2>).
#[derive(Serialize, Deserialize, ToSchema)]
struct ErrorResponse {
    error: ErrorResponseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

/// Error response types as defined in
/// <https://www.rfc-editor.org/rfc/rfc6749#section-5.2>.
#[derive(Debug, PartialEq, Serialize, Deserialize, ToSchema)]
enum ErrorResponseType {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Token exchange endpoint as specified in RFC 8693
/// (https://datatracker.ietf.org/doc/html/rfc8693).
///
/// For now, the only supported subject token type is ID Token as defined in
/// https://openid.net/specs/openid-connect-core-1_0.html.
///
/// Note: There is no client authentication, meaning a compromised token can be
/// leverage by anyone to exchange it for a SNAP token.
#[utoipa::path(
    post,
    path = "/token",
    summary = "Exchange an OIDC ID token for a SNAP token",
    request_body(
        content = TokenRequest,
        content_type = "application/x-www-form-urlencoded",
    ),
    responses(
        (status = 200, description = "Successful token exchange", body = TokenResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
    )
)]
async fn post_token(
    State(mut token_exchanger): State<AuthorizationServerHandle>,
    Form(token_exchange_request): Form<TokenRequest>,
) -> impl IntoResponse {
    match token_exchanger.exchange(token_exchange_request) {
        Ok(token) => Json(token).into_response(),
        Err(error) => handle_token_exchange_error(error).into_response(),
    }
}

fn handle_token_exchange_error(error: TokenExchangeError) -> impl IntoResponse {
    tracing::debug!(err = %error, "Token exchange failed");

    let (error_type, error_description) = match error {
        TokenExchangeError::InvalidGrantType(grant_type) => {
            (
                ErrorResponseType::UnsupportedGrantType,
                Some(format!("Unsupported grant type: {grant_type}")),
            )
        }
        TokenExchangeError::JwtError(jwt_error) => {
            (
                ErrorResponseType::InvalidRequest,
                Some(format!("Invalid subject token: {jwt_error}")),
            )
        }
        TokenExchangeError::VerifyIdTokenError(verify_error) => {
            (
                ErrorResponseType::InvalidRequest,
                Some(format!("Failed verification: {verify_error}")),
            )
        }
        TokenExchangeError::InvalidSubjectTokenType(subject_type) => {
            (
                ErrorResponseType::InvalidRequest,
                Some(format!("Invalid subject token type: {subject_type}")),
            )
        }
        TokenExchangeError::UnknownIdentityProvider(issuer) => {
            (
                ErrorResponseType::InvalidRequest,
                Some(format!("Unknown issuer: {issuer}")),
            )
        }
    };

    ErrorResponse {
        error: error_type,
        error_description,
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use axum::Router;
    use jsonwebtoken::DecodingKey;
    use scion_sdk_token_validator::validator::{
        TokenValidator, Validator, insecure_const_ed25519_key_pair_pem,
    };
    use snap_tokens::snap_token::SnapTokenClaims;
    use test_log::test;

    use super::*;
    use crate::{
        authorization_server::{
            client::ApiClient,
            fake_idp::oidc_id_token,
            token_exchanger::{JWT_TOKEN_TYPE, NO_ACCESS_TOKEN_TYPE},
        },
        state::SharedPocketScionState,
    };

    #[test(tokio::test)]
    async fn should_exchange_oidc_token_for_snap_token() {
        let (snap_token_private_pem, snap_token_public_pem) = insecure_const_ed25519_key_pair_pem();

        let token = oidc_id_token("test-user".to_string());

        let mut pstate = SharedPocketScionState::new(SystemTime::now());
        pstate.set_auth_server(snap_token_private_pem);

        let app = Router::new()
            .route("/api/v1/token", axum::routing::post(post_token))
            .with_state(pstate.auth_server());

        let listener = TcpListener::bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let client = ApiClient::new(&format!("http://{addr}/").parse().unwrap()).unwrap();
        let snap_token_dec_key =
            DecodingKey::from_ed_pem(pem::encode(&snap_token_public_pem).as_bytes())
                .expect("no fail");

        // Valid request using the API client.
        {
            let req = TokenRequest::new(token.clone());
            let res = client.post_token(req).await.expect("no fail");

            assert_eq!(res.token_type, NO_ACCESS_TOKEN_TYPE);
            assert_eq!(res.issued_token_type, JWT_TOKEN_TYPE);

            let _claims = Validator::<SnapTokenClaims>::new(snap_token_dec_key, None)
                .validate(SystemTime::now(), &res.access_token)
                .expect("failed to verify SNAP token");
        }

        // Malformed request: missing grant_type
        {
            let req = [
                ("subject_token", token.clone()),
                ("subject_token_type", ID_TOKEN_TYPE.to_string()),
            ];
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/api/v1/token"))
                .form(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

        // Malformed request: Missing subject_token
        {
            let req = [
                ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE.to_string()),
                ("subject_token_type", ID_TOKEN_TYPE.to_string()),
            ];
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/api/v1/token"))
                .form(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

        // Malformed request: invalid subject token type
        {
            let req = [
                ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE.to_string()),
                ("subject_token", token.clone()),
                ("subject_token_type", "invalid_token_type".to_string()),
            ];
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/api/v1/token"))
                .form(&req)
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let error_response: ErrorResponse = response.json().await.unwrap();
            assert_eq!(error_response.error, ErrorResponseType::InvalidRequest);
        }

        // Malformed request: invalid subject token
        {
            let req = TokenRequest::new("invalid_token".to_string());
            let res = client.post_token(req).await;

            assert!(res.is_err());
            // TODO(bunert): rework api client error handling
        }
    }
}
