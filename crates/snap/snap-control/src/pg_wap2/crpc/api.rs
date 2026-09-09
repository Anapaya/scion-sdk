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

//! Endpoint definitions and endpoint handlers of the WAP control service.
//!
//! Authorization is granted for the address a request arrives on, so the router has to be served
//! with
//! [`into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info);
//! without it the [`ConnectInfo`] extractor has nothing to read and every request fails.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use axum::{
    Router,
    extract::{ConnectInfo, State},
};
use axum_connect_rpc::{
    error::{CrpcError, CrpcErrorCode},
    extractor::ConnectRpcAny,
};

use crate::{
    pg_wap2::crpc::model::{AuthorizeTargetsError, ControlServiceAPIHandler},
    proto::anapaya::wap::v1 as rpc,
};

/// The Connect RPC path of the `anapaya.wap.v1.WapControl` service.
pub const SERVICE_PATH: &str = "/anapaya.wap.v1.WapControl";
/// The path of the `AuthorizeTargets` method, relative to [`SERVICE_PATH`].
pub const AUTHORIZE_TARGETS: &str = "/AuthorizeTargets";

/// Nests the WAP control plane API routes into the provided `router`.
pub fn nest_crpc_api(router: Router, handler: Arc<dyn ControlServiceAPIHandler>) -> Router {
    router.nest(
        SERVICE_PATH,
        Router::new()
            .route(
                AUTHORIZE_TARGETS,
                axum::routing::post(authorize_targets_handler),
            )
            .with_state(handler),
    )
}

async fn authorize_targets_handler(
    State(handler): State<Arc<dyn ControlServiceAPIHandler>>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    request: ConnectRpcAny<rpc::AuthorizeTargetsRequest>,
) -> Result<ConnectRpcAny<rpc::AuthorizeTargetsResponse>, CrpcError> {
    // One timestamp for the whole request, so everything it grants expires together.
    let now = SystemTime::now();

    let codec = request.codec();

    let request = request.into_inner().try_into_model().map_err(|err| {
        tracing::debug!(%client, "Rejecting an authorization request: {err}");
        CrpcError::new(CrpcErrorCode::InvalidArgument, err.to_string())
    })?;

    // The grant goes to the address the request came from, not to one the request could name.
    match handler.authorize_targets(client.ip(), request, now) {
        Ok(res) => Ok(ConnectRpcAny::from_parts(res.into(), codec)),
        Err(e) => {
            tracing::info!(%client, ?e, "Authorization request failed");

            let (code, msg) = match e {
                AuthorizeTargetsError::InvalidRequest(msg) => (CrpcErrorCode::InvalidArgument, msg),
                AuthorizeTargetsError::LimitReached(msg) => (CrpcErrorCode::PermissionDenied, msg),
                AuthorizeTargetsError::Internal(_) => {
                    (CrpcErrorCode::Internal, "internal error".to_owned())
                }
            };

            Err(CrpcError::new(code, msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::Mutex,
        time::{Duration, UNIX_EPOCH},
    };

    use axum::{
        body::Body,
        http::{Request, Response, StatusCode, header},
    };
    use buffa::Message as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::pg_wap2::{
        crpc::model::{AuthorizeTargetsRequest, AuthorizeTargetsResponse},
        sni::CustomerDomain,
        test_util::{client_ip, sni},
    };

    const WAP_ID: &str = "wap-1";
    const DATA_PLANE_PORT: u16 = 8443;
    /// The expiry the [`MockHandler`] hands out, as seconds since the UNIX epoch.
    const EXPIRY_SECS: u64 = 1_800;

    /// Records the address and request it was called with and hands out a fixed grant, or fails.
    struct MockHandler {
        request: Mutex<Option<(IpAddr, AuthorizeTargetsRequest)>>,
        failing: bool,
    }

    impl MockHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                request: Mutex::new(None),
                failing: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                request: Mutex::new(None),
                failing: true,
            })
        }

        /// The address and request the handler was called with.
        fn request(&self) -> (IpAddr, AuthorizeTargetsRequest) {
            self.request
                .lock()
                .unwrap()
                .take()
                .expect("the handler was called")
        }
    }

    impl ControlServiceAPIHandler for MockHandler {
        fn authorize_targets(
            &self,
            client_ip: IpAddr,
            request: AuthorizeTargetsRequest,
            _now: SystemTime,
        ) -> Result<AuthorizeTargetsResponse, AuthorizeTargetsError> {
            *self.request.lock().unwrap() = Some((client_ip, request));

            if self.failing {
                return Err(AuthorizeTargetsError::Internal(anyhow::anyhow!(
                    "set to fail"
                )));
            }

            Ok(AuthorizeTargetsResponse {
                client_ip,
                wap_id: WAP_ID.to_owned(),
                data_plane_port: DATA_PLANE_PORT,
                expiry_time: UNIX_EPOCH + Duration::from_secs(EXPIRY_SECS),
            })
        }
    }

    /// The address the requests in these tests come from.
    fn client_addr() -> SocketAddr {
        SocketAddr::new(client_ip(), 54321)
    }

    /// Posts `request` to the `AuthorizeTargets` endpoint of a router serving `handler`.
    async fn call(
        handler: Arc<MockHandler>,
        request: rpc::AuthorizeTargetsRequest,
    ) -> Response<Body> {
        let mut http_request = Request::builder()
            .method("POST")
            .uri(format!("{SERVICE_PATH}{AUTHORIZE_TARGETS}"))
            .header(header::CONTENT_TYPE, "application/proto")
            .body(Body::from(request.encode_to_vec()))
            .expect("a valid request");

        // The router is served with `into_make_service_with_connect_info` in production, which is
        // what puts this extension in place.
        http_request
            .extensions_mut()
            .insert(ConnectInfo(client_addr()));

        nest_crpc_api(Router::new(), handler)
            .oneshot(http_request)
            .await
            .expect("the router is infallible")
    }

    async fn body_bytes(response: Response<Body>) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body can be collected")
            .to_vec()
    }

    /// Calls the endpoint and expects it to fail, returning the connect RPC error.
    async fn call_expecting_error(
        handler: Arc<MockHandler>,
        request: rpc::AuthorizeTargetsRequest,
        want_status: StatusCode,
    ) -> CrpcError {
        let response = call(handler, request).await;
        assert_eq!(response.status(), want_status);

        serde_json::from_slice(&body_bytes(response).await).expect("a connect RPC error body")
    }

    /// A request granting nothing for the customer domain of [`sni`].
    fn request_for_sni() -> rpc::AuthorizeTargetsRequest {
        rpc::AuthorizeTargetsRequest {
            targets: [(
                sni().customer_domain().as_str().to_owned(),
                rpc::AuthSegments::default(),
            )]
            .into_iter()
            .collect(),
        }
    }

    #[tokio::test]
    async fn a_grant_is_handed_out_for_the_address_the_request_came_from() {
        let handler = MockHandler::new();

        let response = call(handler.clone(), request_for_sni()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/proto"
        );

        let response =
            rpc::AuthorizeTargetsResponse::decode_from_slice(&body_bytes(response).await)
                .expect("a response message");
        assert_eq!(
            response,
            rpc::AuthorizeTargetsResponse {
                client_ip: client_ip().to_string(),
                wap_id: WAP_ID.to_owned(),
                data_plane_port: u32::from(DATA_PLANE_PORT),
                expiry_time: EXPIRY_SECS,
            }
        );

        let (authorized_ip, request) = handler.request();
        assert_eq!(
            authorized_ip,
            client_ip(),
            "the authorized address is the one the connection came from, not one the request \
             could name"
        );
        assert_eq!(
            request.targets.keys().collect::<Vec<_>>(),
            vec![&CustomerDomain::from(sni().customer_domain())],
            "the target is authorized under its customer domain"
        );
    }

    #[tokio::test]
    async fn a_request_that_cannot_be_converted_is_an_invalid_argument() {
        let error = call_expecting_error(
            MockHandler::new(),
            // A request without targets, see the `convert` tests for the other rejections.
            rpc::AuthorizeTargetsRequest::default(),
            StatusCode::BAD_REQUEST,
        )
        .await;

        assert_eq!(error.code, CrpcErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_passes_error_from_failing_handler() {
        let error = call_expecting_error(
            MockHandler::failing(),
            request_for_sni(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;

        assert_eq!(error.code, CrpcErrorCode::Internal);
        println!("error message: {}", error.message);
        assert_eq!(
            error.message, "internal error",
            "the endpoint returns the message of the handler"
        );
    }
}
