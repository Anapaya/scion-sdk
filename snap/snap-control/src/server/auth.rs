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
//! SNAP control plane API authentication middleware.

use std::{
    fmt::Display,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::SystemTime,
};

use axum::body::Body;
use http::{Request, Response};
use jsonwebtoken::DecodingKey;
use scion_sdk_token_validator::validator::{TokenValidator, Validator};
use snap_tokens::AnyClaims;
use thiserror::Error;
use tower::{BoxError, Layer, Service};

#[derive(Clone)]
pub(crate) struct AuthMiddlewareLayer {
    validator: Validator<AnyClaims>,
}

impl AuthMiddlewareLayer {
    pub(crate) fn new(dec: DecodingKey) -> Self {
        Self {
            validator: Validator::new(dec, Some(&["snap"])),
        }
    }
}

impl<S> Layer<S> for AuthMiddlewareLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware::new(inner, self.validator.clone())
    }
}

#[derive(Clone)]
pub(crate) struct AuthMiddleware<S> {
    inner: S,
    validator: Validator<AnyClaims>,
}

impl<S> AuthMiddleware<S> {
    pub(crate) fn new(inner: S, validator: Validator<AnyClaims>) -> Self {
        Self { inner, validator }
    }
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let token = match extract_bearer_token(&request) {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!(%err, "Extract bearer token");
                return Box::pin(async { Ok(build_unauthorized_response(err)) });
            }
        };

        match self.validator.validate(SystemTime::now(), token.as_str()) {
            Ok(token_claims) => {
                match token_claims {
                    AnyClaims::V0(claims) => {
                        request.extensions_mut().insert(claims);
                    }
                    AnyClaims::V1(claims) => {
                        request.extensions_mut().insert(claims);
                    }
                }
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(request).await.map_err(Into::into) })
            }
            Err(err) => {
                tracing::debug!(%err, "Invalid Token");
                Box::pin(async { Ok(build_unauthorized_response(err)) })
            }
        }
    }
}

fn build_unauthorized_response<E: Display>(err: E) -> Response<Body> {
    Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .body(Body::from(format!("SNAP Token validation failed: {err}")))
        .expect("no fail")
}

/// Extracts the bearer token from the `Authorization` header of the request.
pub fn extract_bearer_token(req: &Request<Body>) -> Result<String, ExtractBearerTokenError> {
    let auth_header = match req.headers().get("authorization") {
        Some(header) => header,
        None => return Err(ExtractBearerTokenError::AuthHeaderMissing),
    };

    let auth_str = match auth_header.to_str() {
        Ok(str) => str,
        Err(_) => return Err(ExtractBearerTokenError::AuthHeaderInvalidUtf8),
    };

    match auth_str.strip_prefix("Bearer ") {
        Some(token) => Ok(token.to_string()),
        None => Err(ExtractBearerTokenError::AuthHeaderNotBearer),
    }
}

/// Bearer token extraction error.
#[derive(Debug, Error)]
pub enum ExtractBearerTokenError {
    /// Authorization header is missing.
    #[error("authorization header is missing")]
    AuthHeaderMissing,
    /// Authorization header is not valid UTF-8.
    #[error("authorization header is not valid UTF-8")]
    AuthHeaderInvalidUtf8,
    /// Authorization header is not a Bearer token.
    #[error("authorization header is not a bearer token")]
    AuthHeaderNotBearer,
}
