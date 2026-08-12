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
//!
//! The key here carries one extra component beyond host and port: the
//! [`Candidates`] source, i.e. whether the origin's addresses come from DNS
//! (the default) or were supplied by the caller
//! ([`RequestBuilder::targets`](crate::RequestBuilder::targets)). Requests to
//! the same host and port with different candidate sources are deliberately
//! distinct origins, since they may legitimately reach different servers.

use std::fmt;

use sciparse::address::ip_addr::ScionIpAddr;

use crate::{error::Error, request::Request};

/// The pool key: host, port, and where the candidate addresses come from.
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
    /// The port. Single-sourced from the URL; candidates deliberately carry
    /// no port so the two cannot disagree.
    pub(crate) port: u16,
    /// Where the origin's candidate addresses come from.
    pub(crate) candidates: Candidates,
}

/// Where an origin's candidate addresses come from. In both variants the
/// element type is what resolution produces (addresses without ports), so
/// nothing downstream distinguishes the two paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Candidates {
    /// Resolve the origin's host via TSAR TXT records (the default).
    Dns,
    /// A caller-supplied resolution result: "proceed as if DNS had returned
    /// exactly this". Sorted, de-duplicated, and non-empty (enforced by
    /// [`RequestBuilder::targets`](crate::RequestBuilder::targets)).
    Static(Vec<ScionIpAddr>),
}

impl Origin {
    /// Derives the origin from a validated request: host and port from the
    /// URL (default port 443), candidate source from the request's targets.
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
        let candidates = match request.targets() {
            Some(targets) => Candidates::Static(targets.to_vec()),
            None => Candidates::Dns,
        };
        Ok(Origin {
            host,
            port,
            candidates,
        })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)?;
        if let Candidates::Static(targets) = &self.candidates {
            write!(f, " ({} static candidate(s))", targets.len())?;
        }
        Ok(())
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
    fn port_defaults_to_443() {
        let req = Request::get("https://example.org/x").build().unwrap();
        let origin = Origin::from_request(&req).unwrap();
        assert_eq!(origin.host, "example.org");
        assert_eq!(origin.port, 443);
        assert_eq!(origin.candidates, Candidates::Dns);
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
    fn target_order_does_not_fragment_the_key() {
        let a = Request::get("https://example.org/")
            .targets(vec![addr(1), addr(2)])
            .build()
            .unwrap();
        let b = Request::get("https://example.org/")
            .targets(vec![addr(2), addr(1)])
            .build()
            .unwrap();
        assert_eq!(
            Origin::from_request(&a).unwrap(),
            Origin::from_request(&b).unwrap()
        );
    }

    #[test]
    fn dns_and_static_are_distinct_origins() {
        let dns = Request::get("https://example.org/").build().unwrap();
        let stat = Request::get("https://example.org/")
            .target(addr(1))
            .build()
            .unwrap();
        assert_ne!(
            Origin::from_request(&dns).unwrap(),
            Origin::from_request(&stat).unwrap()
        );
    }
}
