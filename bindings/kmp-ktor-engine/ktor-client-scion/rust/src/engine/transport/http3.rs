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

//! Requests over HTTP/3 to the origin.

use std::sync::Arc;

use async_trait::async_trait;
use scion_http3::Client;

use super::{Request, Transport, classify, convert_headers};
use crate::{
    engine::describe_error,
    ffi::types::{CoreError, CoreHttpVersion, CoreResponse},
};

/// Sends requests over HTTP/3 to the origin.
pub(crate) struct Http3Transport {
    client: Arc<Client>,
    max_body_bytes: usize,
}

impl Http3Transport {
    pub(crate) fn new(client: Arc<Client>, max_body_bytes: usize) -> Self {
        Http3Transport {
            client,
            max_body_bytes,
        }
    }
}

#[async_trait]
impl Transport for Http3Transport {
    async fn send(&self, request: Request) -> Result<CoreResponse, CoreError> {
        // Send the request.
        let response = self
            .client
            .request(into_http3(request)?)
            .await
            .map_err(classify)?;

        // Collect the response.
        let status = response.status().as_u16();
        let headers = convert_headers(response.headers());
        let (body, _trailers) = response
            .bytes(Some(self.max_body_bytes))
            .await
            .map_err(classify)?;

        return Ok(CoreResponse {
            status,
            version: CoreHttpVersion::Http3,
            headers,
            body: body.to_vec(),
        });

        /// Re-checks the request against the rules of scion-http3, for example
        /// the `https` scheme.
        fn into_http3(request: Request) -> Result<scion_http3::Request, CoreError> {
            // Copy the request.
            let (parts, body) = request.http.into_parts();
            let mut builder = scion_http3::Request::builder()
                .method(parts.method)
                .url(parts.uri.to_string())
                .body(body);
            for (name, value) in &parts.headers {
                builder = builder.header(name.clone(), value.clone());
            }

            if let Some(timeout) = request.timeout {
                builder = builder.request_timeout(timeout);
            }

            // Let scion-http3 check it.
            builder
                .build()
                .map_err(|error| CoreError::invalid(describe_error(&error)))
        }
    }

    async fn close(&self) {
        self.client.close().await;
    }
}
