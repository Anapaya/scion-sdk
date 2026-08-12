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

//! Requests and how they are built.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body::Frame;
use sciparse::address::ip_addr::ScionIpAddr;
use url::Url;

use crate::error::BuildRequestError;

/// A type that can be converted into a [`Url`].
///
/// Implemented for [`Url`] itself and for strings, so URLs can be passed as
/// `"https://example.org/path"` without an explicit parse step. This trait is
/// sealed, i.e., it cannot be implemented outside this crate.
pub trait IntoUrl: sealed::Sealed {
    /// Converts the value into a parsed [`Url`].
    fn into_url(self) -> Result<Url, BuildRequestError>;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url, BuildRequestError> {
        Ok(self)
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, BuildRequestError> {
        Url::parse(self).map_err(|e| {
            BuildRequestError::InvalidUrl {
                source: Box::new(e),
            }
        })
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url, BuildRequestError> {
        self.as_str().into_url()
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> Result<Url, BuildRequestError> {
        self.as_str().into_url()
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for url::Url {}
    impl Sealed for &str {}
    impl Sealed for String {}
    impl Sealed for &String {}
}

/// An HTTP request: method, URL, headers, and a buffered body.
///
/// Built with [`Request::builder`] (or the [`get`](Request::get) /
/// [`post`](Request::post) shorthands) and issued with
/// [`Client::request`](crate::Client::request). A validated request always
/// has an `https` URL with a host.
#[derive(Debug, Clone)]
pub struct Request {
    method: http::Method,
    url: Url,
    headers: http::HeaderMap,
    body: Bytes,
    targets: Option<Vec<ScionIpAddr>>,
    timeout: Option<Duration>,
}

impl Request {
    /// Returns a builder with no fields set. The URL is the only required
    /// field.
    #[must_use]
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    /// Returns a builder for a GET request to `url`.
    #[must_use]
    pub fn get(url: impl IntoUrl) -> RequestBuilder {
        RequestBuilder::new().method(http::Method::GET).url(url)
    }

    /// Returns a builder for a POST request to `url`.
    #[must_use]
    pub fn post(url: impl IntoUrl) -> RequestBuilder {
        RequestBuilder::new().method(http::Method::POST).url(url)
    }

    /// The request method.
    #[must_use]
    pub fn method(&self) -> &http::Method {
        &self.method
    }

    /// The request URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The request headers.
    #[must_use]
    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// The request body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The caller-supplied candidate addresses, if any (see
    /// [`RequestBuilder::targets`]). Sorted and de-duplicated.
    #[must_use]
    pub fn targets(&self) -> Option<&[ScionIpAddr]> {
        self.targets.as_deref()
    }

    /// The per-request timeout override, if any.
    #[must_use]
    pub fn request_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Builds the transport-level `http::Request`. The URI is the full URL,
    /// so `:authority` reflects where the request is addressed.
    pub(crate) fn to_http(&self) -> Result<http::Request<BufferedBody>, crate::Error> {
        let mut builder = http::Request::builder()
            .method(self.method.clone())
            .uri(self.url.as_str());
        if let Some(headers) = builder.headers_mut() {
            headers.extend(self.headers.clone());
        }
        builder
            .body(BufferedBody::new(self.body.clone()))
            .map_err(|e| {
                crate::Error::InvalidRequest {
                    reason: e.to_string().into(),
                }
            })
    }
}

/// Builder for a [`Request`].
///
/// Setters are infallible; errors (an unparsable URL, an invalid header) are
/// deferred and reported by [`build`](Self::build), mirroring
/// `http::request::Builder`. The first error wins.
#[derive(Debug)]
pub struct RequestBuilder {
    method: http::Method,
    url: Option<Url>,
    headers: http::HeaderMap,
    body: Bytes,
    targets: Option<Vec<ScionIpAddr>>,
    timeout: Option<Duration>,
    error: Option<BuildRequestError>,
}

impl RequestBuilder {
    fn new() -> Self {
        RequestBuilder {
            method: http::Method::GET,
            url: None,
            headers: http::HeaderMap::new(),
            body: Bytes::new(),
            targets: None,
            timeout: None,
            error: None,
        }
    }

    /// Sets the request method (default: GET).
    #[must_use]
    pub fn method(mut self, method: http::Method) -> Self {
        self.method = method;
        self
    }

    /// Sets the request URL. Required; the scheme must be `https`.
    #[must_use]
    pub fn url(mut self, url: impl IntoUrl) -> Self {
        match url.into_url() {
            Ok(url) => self.url = Some(url),
            Err(e) => {
                self.error.get_or_insert(e);
            }
        }
        self
    }

    /// Appends a header.
    #[must_use]
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<http::header::HeaderName>,
        K::Error: Into<http::Error>,
        V: TryInto<http::header::HeaderValue>,
        V::Error: Into<http::Error>,
    {
        match (key.try_into(), value.try_into()) {
            (Ok(key), Ok(value)) => {
                self.headers.append(key, value);
            }
            (Err(e), _) => {
                self.error.get_or_insert(BuildRequestError::InvalidHeader {
                    source: Box::new(e.into()),
                });
            }
            (_, Err(e)) => {
                self.error.get_or_insert(BuildRequestError::InvalidHeader {
                    source: Box::new(e.into()),
                });
            }
        }
        self
    }

    /// Sets the request body. Bodies are buffered; they are sent in full and
    /// can be replayed if connection establishment has to be repeated.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Bypasses DNS resolution: connect to `addr`, as if resolution had
    /// returned exactly this address. The address carries no port — the port
    /// always comes from the URL. The URL's host remains the server name for SNI
    /// and certificate validation.
    ///
    /// This is the one-element case of [`targets`](Self::targets).
    #[must_use]
    pub fn target(self, addr: ScionIpAddr) -> Self {
        self.targets(vec![addr])
    }

    /// Supplies the result of a resolution the caller performed itself:
    /// connect to any of `addrs`, as if DNS had returned exactly this list.
    /// The caller asserts the addresses are equivalent servers for the URL's
    /// origin; certificate validation against the URL's host enforces it.
    ///
    /// Like [`target`](Self::target), the addresses carry no port. The list
    /// is sorted and de-duplicated, so element order does not affect
    /// connection reuse. It must not be empty.
    #[must_use]
    pub fn targets(mut self, mut addrs: Vec<ScionIpAddr>) -> Self {
        if addrs.is_empty() {
            self.error.get_or_insert(BuildRequestError::EmptyTargets);
            return self;
        }
        addrs.sort_unstable();
        addrs.dedup();
        self.targets = Some(addrs);
        self
    }

    /// Overrides the client's request timeout for this request.
    ///
    /// One deadline covering establishment, the response head, and body
    /// collection; raise it for a response the caller will not collect right
    /// away (see [`Response`](crate::Response)).
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Validates the accumulated state and builds the [`Request`].
    pub fn build(self) -> Result<Request, BuildRequestError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let url = self.url.ok_or(BuildRequestError::MissingUrl)?;
        if url.scheme() != "https" {
            return Err(BuildRequestError::UnsupportedScheme {
                scheme: url.scheme().to_string(),
            });
        }
        if url.host_str().is_none() {
            return Err(BuildRequestError::MissingHost);
        }
        // The URL becomes the request URI verbatim, and `:authority` must not
        // carry userinfo (RFC 9114 §4.3.1) — sending it would leak the
        // credentials on the wire.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(BuildRequestError::UserinfoNotAllowed);
        }
        Ok(Request {
            method: self.method,
            url,
            headers: self.headers,
            body: self.body,
            targets: self.targets,
            timeout: self.timeout,
        })
    }
}

/// A fully buffered request body: yields one data frame and ends.
pub(crate) struct BufferedBody {
    data: Option<Bytes>,
}

impl BufferedBody {
    fn new(data: Bytes) -> Self {
        let data = if data.is_empty() { None } else { Some(data) };
        BufferedBody { data }
    }
}

impl http_body::Body for BufferedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.get_mut().data.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let len = self.data.as_ref().map_or(0, Bytes::len) as u64;
        http_body::SizeHint::with_exact(len)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn addr(last_octet: u8) -> ScionIpAddr {
        ScionIpAddr::new(
            "1-ff00:0:110".parse().unwrap(),
            Ipv4Addr::new(10, 0, 0, last_octet).into(),
        )
    }

    #[test]
    fn get_builds_with_defaults() {
        let req = Request::get("https://chat.example.org/rooms")
            .build()
            .unwrap();
        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(req.url().as_str(), "https://chat.example.org/rooms");
        assert!(req.targets().is_none());
        assert!(req.request_timeout().is_none());
        assert!(req.body().is_empty());
    }

    #[test]
    fn non_https_scheme_is_rejected() {
        let err = Request::get("http://chat.example.org/")
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            BuildRequestError::UnsupportedScheme { scheme } if scheme == "http"
        ));
    }

    #[test]
    fn userinfo_is_rejected() {
        for url in [
            "https://user:secret@api.example.org/x",
            "https://user@api.example.org/x",
        ] {
            let err = Request::get(url).build().unwrap_err();
            assert!(
                matches!(err, BuildRequestError::UserinfoNotAllowed),
                "{url}"
            );
        }
    }

    #[test]
    fn unparsable_url_is_reported_at_build() {
        let err = Request::get("not a url").build().unwrap_err();
        assert!(matches!(err, BuildRequestError::InvalidUrl { .. }));
    }

    #[test]
    fn missing_url_is_reported_at_build() {
        let err = Request::builder().build().unwrap_err();
        assert!(matches!(err, BuildRequestError::MissingUrl));
    }

    #[test]
    fn invalid_header_is_deferred_to_build() {
        let err = Request::get("https://example.org/")
            .header("bad header name", "value")
            .build()
            .unwrap_err();
        assert!(matches!(err, BuildRequestError::InvalidHeader { .. }));
    }

    #[test]
    fn targets_are_sorted_and_deduplicated() {
        let req = Request::get("https://example.org/")
            .targets(vec![addr(2), addr(1), addr(2)])
            .build()
            .unwrap();
        assert_eq!(req.targets(), Some(&[addr(1), addr(2)][..]));
    }

    #[test]
    fn empty_targets_are_rejected() {
        let err = Request::get("https://example.org/")
            .targets(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(err, BuildRequestError::EmptyTargets));
    }

    #[test]
    fn to_http_uses_the_full_url_as_uri() {
        let req = Request::post("https://example.org:8443/echo")
            .header("content-type", "text/plain")
            .body("hello")
            .build()
            .unwrap();
        let http_req = req.to_http().unwrap();
        assert_eq!(http_req.uri(), "https://example.org:8443/echo");
        assert_eq!(
            http_req.uri().authority().map(http::uri::Authority::as_str),
            Some("example.org:8443")
        );
        assert_eq!(http_req.headers()["content-type"], "text/plain");
    }
}
