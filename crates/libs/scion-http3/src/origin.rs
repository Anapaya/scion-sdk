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

//! Origins: what connection reuse is keyed by.
//!
//! An origin is a server's identity from HTTP's point of view: the (host,
//! port) pair of the URL, e.g., `api.example.org:443`, independent of the
//! request path, and independent of which of the server's addresses a
//! connection happens to reach. HTTP defines connection reuse per origin,
//! and this crate follows that: one pooled connection per distinct [`Origin`].

use std::fmt;

use crate::{authority::Authority, error::Error, request::Request};

/// The pool key: host and port.
///
/// Connection reuse is defined per origin, not per resolved address: keying
/// by address would fragment the pool every time resolution returns a
/// different address, and would leave "try several candidates, keep the
/// winner" with no component to live in. The host doubles as the SNI and
/// certificate-validation identity, which is what makes attempts across
/// candidate addresses sound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Origin {
    /// The host, as it appears in the URL (also SNI and `:authority`).
    pub(crate) host: String,
    /// The port. Single-sourced from the URL; resolved addresses deliberately
    /// carry no port so the two cannot disagree.
    pub(crate) port: u16,
}

impl Origin {
    /// Derives the origin from a validated request: host and port from the
    /// URL (default port 443).
    pub(crate) fn from_request(request: &Request) -> Result<Origin, Error> {
        let url = request.url();
        let host = url
            .host_str()
            .ok_or_else(|| {
                Error::InvalidRequest {
                    reason: "URL has no host".into(),
                }
            })?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        Ok(Origin { host, port })
    }

    /// Derives a DNS-resolved origin from a `CONNECT` authority.
    pub(crate) fn from_authority(authority: &Authority) -> Origin {
        Origin {
            host: authority.host().to_string(),
            port: authority.port(),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_defaults_to_443() {
        let req = Request::get("https://example.org/x").build().unwrap();
        let origin = Origin::from_request(&req).unwrap();
        assert_eq!(origin.host, "example.org");
        assert_eq!(origin.port, 443);
    }

    #[test]
    fn explicit_port_is_used() {
        let req = Request::get("https://example.org:8443/").build().unwrap();
        let origin = Origin::from_request(&req).unwrap();
        assert_eq!(origin.port, 8443);
    }

    #[test]
    fn same_url_same_origin_regardless_of_path() {
        let a = Origin::from_request(&Request::get("https://example.org/a").build().unwrap());
        let b = Origin::from_request(&Request::get("https://example.org/b?x=1").build().unwrap());
        assert_eq!(a.unwrap(), b.unwrap());
    }

    #[test]
    fn authority_is_a_dns_origin() {
        let authority = Authority::new("example.org", 8443).unwrap();
        let origin = Origin::from_authority(&authority);
        assert_eq!(origin.host, "example.org");
        assert_eq!(origin.port, 8443);
    }
}
