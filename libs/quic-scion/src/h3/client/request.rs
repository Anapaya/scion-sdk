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

//! HTTP/3 request/response helpers.

use url::Url;

/// An HTTP/3 request.
#[derive(Debug, Clone)]
pub struct H3Request {
    /// HTTP method.
    pub method: http::Method,
    /// Request path.
    pub path: String,
    /// Authority (host:port).
    pub authority: String,
    /// Request scheme (http or https).
    pub scheme: String,
    /// Additional headers.
    pub headers: Vec<(String, String)>,
    /// Request body (if any).
    pub body: Option<Vec<u8>>,
}

impl H3Request {
    /// Creates a new GET request for the given URL.
    pub fn get(url: Url) -> H3RequestBuilder {
        H3RequestBuilder::new(http::Method::GET, url)
    }

    /// Creates a new POST request for the given URL.
    pub fn post(url: Url) -> H3RequestBuilder {
        H3RequestBuilder::new(http::Method::POST, url)
    }

    /// Creates a new PUT request for the given URL.
    pub fn put(url: Url) -> H3RequestBuilder {
        H3RequestBuilder::new(http::Method::PUT, url)
    }

    /// Creates a new DELETE request for the given URL.
    pub fn delete(url: Url) -> H3RequestBuilder {
        H3RequestBuilder::new(http::Method::DELETE, url)
    }

    /// Creates a new request builder with the specified method.
    pub fn builder(method: http::Method, url: Url) -> H3RequestBuilder {
        H3RequestBuilder::new(method, url)
    }

    /// Converts headers to quiche format.
    pub(crate) fn to_quiche_headers(&self) -> Vec<squiche::h3::Header> {
        let mut headers: Vec<squiche::h3::Header> = vec![
            // All pseudo-header fields must appear in the header section before regular header
            // fields. See https://datatracker.ietf.org/doc/html/rfc9114#name-http-control-data
            squiche::h3::Header::new(b":method", self.method.as_str().as_bytes()),
            squiche::h3::Header::new(b":scheme", self.scheme.as_bytes()),
            squiche::h3::Header::new(b":authority", self.authority.as_bytes()),
            squiche::h3::Header::new(b":path", self.path.as_bytes()),
            // Regular headers
            squiche::h3::Header::new(b"Content-Type", b"application/proto"),
            squiche::h3::Header::new(b"connect-protocol-version", b"1"),
        ];

        for (name, value) in &self.headers {
            headers.push(squiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }

        headers
    }
}

/// Builder for [`H3Request`].
pub struct H3RequestBuilder {
    method: http::Method,
    url: Url,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl H3RequestBuilder {
    /// Creates a new request builder.
    pub fn new(method: http::Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: vec![],
            body: None,
        }
    }

    /// Adds a header to the request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the request body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Builds the request.
    pub fn build(self) -> H3Request {
        H3Request {
            method: self.method,
            path: self.url.path().to_string(),
            authority: self.url.authority().to_string(),
            scheme: self.url.scheme().to_string(),
            headers: self.headers,
            body: self.body,
        }
    }
}

/// An HTTP/3 response.
#[derive(Debug)]
pub struct H3Response {
    /// HTTP status code.
    pub status: http::StatusCode,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl H3Response {
    /// Returns the status code.
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    /// Checks if the response is successful (2xx).
    pub fn is_success(&self) -> bool {
        self.status().is_success()
    }

    /// Gets a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the raw body bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }
}
