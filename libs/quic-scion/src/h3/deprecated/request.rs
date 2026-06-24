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

use std::ops::Deref;

use squiche::h3::NameValue;
use thiserror::Error;
use url::Url;

const METHOD_HEADER: &[u8] = b":method";
const SCHEME_HEADER: &[u8] = b":scheme";
const AUTHORITY_HEADER: &[u8] = b":authority";
const PATH_HEADER: &[u8] = b":path";

/// HTTP/3 headers.
#[derive(Debug, Clone)]
pub struct H3Headers {
    /// HTTP method.
    pub method: http::Method,
    /// Request scheme (http or https).
    pub scheme: http::uri::Scheme,
    /// Authority (host:port).
    pub authority: http::uri::Authority,
    /// Request path.
    pub path: http::uri::PathAndQuery,
    /// Additional headers.
    pub headers: Vec<squiche::h3::Header>,
}

/// header error
#[derive(Debug, Error)]
pub enum HeaderError {
    /// HTTP/3 header missing
    #[error("missing {0:?} header")]
    MissingHeader(&'static [u8]),
    /// Invalid HTTP/3 header
    #[error("invalid {0:?} header, got: {1:?}")]
    InvalidHeader(&'static [u8], Vec<u8>),
}

impl TryFrom<Vec<squiche::h3::Header>> for H3Headers {
    type Error = HeaderError;

    fn try_from(headers: Vec<squiche::h3::Header>) -> Result<Self, Self::Error> {
        let mut method = None;
        let mut scheme = None;
        let mut authority = None;
        let mut path = None;
        let mut other_headers = Vec::new();

        for header in headers {
            match header.name() {
                METHOD_HEADER => {
                    if let Ok(m) = http::Method::from_bytes(header.value()) {
                        method = Some(m);
                    } else {
                        return Err(HeaderError::InvalidHeader(
                            METHOD_HEADER,
                            header.value().to_vec(),
                        ));
                    }
                }
                SCHEME_HEADER => {
                    if let Ok(s) = http::uri::Scheme::try_from(header.value()) {
                        scheme = Some(s);
                    } else {
                        return Err(HeaderError::InvalidHeader(
                            SCHEME_HEADER,
                            header.value().to_vec(),
                        ));
                    }
                }
                AUTHORITY_HEADER => {
                    if let Ok(a) = http::uri::Authority::try_from(header.value()) {
                        authority = Some(a);
                    } else {
                        return Err(HeaderError::InvalidHeader(
                            AUTHORITY_HEADER,
                            header.value().to_vec(),
                        ));
                    }
                }
                PATH_HEADER => {
                    if let Ok(a) = http::uri::PathAndQuery::try_from(header.value()) {
                        path = Some(a);
                    } else {
                        return Err(HeaderError::InvalidHeader(
                            PATH_HEADER,
                            header.value().to_vec(),
                        ));
                    }
                }
                _ => {
                    other_headers.push(header);
                }
            }
        }

        Ok(Self {
            method: method.ok_or(HeaderError::MissingHeader(METHOD_HEADER))?,
            scheme: scheme.ok_or(HeaderError::MissingHeader(SCHEME_HEADER))?,
            authority: authority.ok_or(HeaderError::MissingHeader(AUTHORITY_HEADER))?,
            path: path.ok_or(HeaderError::MissingHeader(PATH_HEADER))?,
            headers: other_headers,
        })
    }
}

/// An HTTP/3 request.
#[derive(Debug, Clone)]
pub struct H3Request {
    /// HTTP3 headers.
    pub headers: H3Headers,
    /// Request body (if any).
    pub body: Option<Vec<u8>>,
}

impl Deref for H3Request {
    type Target = H3Headers;

    fn deref(&self) -> &Self::Target {
        &self.headers
    }
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
            squiche::h3::Header::new(METHOD_HEADER, self.method.as_str().as_bytes()),
            squiche::h3::Header::new(SCHEME_HEADER, self.scheme.as_str().as_bytes()),
            squiche::h3::Header::new(AUTHORITY_HEADER, self.authority.as_str().as_bytes()),
            squiche::h3::Header::new(PATH_HEADER, self.path.as_str().as_bytes()),
            // Regular headers
            // TODO: this should be configurable by the caller.
            squiche::h3::Header::new(b"Content-Type", b"application/proto"),
            squiche::h3::Header::new(b"connect-protocol-version", b"1"),
        ];

        headers.extend_from_slice(&self.headers.headers);
        headers
    }
}

/// Builder for [`H3Request`].
pub struct H3RequestBuilder {
    method: http::Method,
    url: Url,
    headers: Vec<squiche::h3::Header>,
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
        self.headers.push(squiche::h3::Header::new(
            name.into().as_bytes(),
            value.into().as_bytes(),
        ));
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
            headers: H3Headers {
                method: self.method,
                scheme: self.url.scheme().parse().unwrap(),
                authority: self.url.authority().parse().unwrap(),
                path: self.url.path().parse().unwrap(),
                headers: self.headers,
            },
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
