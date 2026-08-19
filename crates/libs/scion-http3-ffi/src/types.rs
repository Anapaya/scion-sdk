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

//! The records and enumerations that cross the boundary.
//!
//! Plain data, with no behaviour beyond the defaults in [`ClientConfig::with_defaults`]; the
//! conversions to and from `scion-http3` live in [`crate::convert`].
//!
//! Two conventions run through all of it.
//!
//! Durations cross as milliseconds in a `u64` rather than as `std::time::Duration`. UniFFI maps a
//! `Duration` to each language's own standard type, and the tightest constraint among the targets
//! decides for all of them: the type Kotlin maps to, `java.time.Duration`, needs a higher Android
//! API level than the library supports. An integer needs no such lowest common denominator, and
//! each hand-written library converts it to whatever its callers expect.
//!
//! And a setting that `scion-stack` has a default for is optional here, applied only when present,
//! so that the default stays in one place instead of being copied into the bindings where it would
//! quietly drift.

use scion_http3::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_CONNECTION_ATTEMPT_DELAY, DEFAULT_IDLE_CONNECTION_TIMEOUT,
    DEFAULT_MAX_ORIGINS, DEFAULT_REQUEST_TIMEOUT,
};

/// Default bound on a buffered response body.
///
/// `scion-http3` has no default of its own: [`scion_http3::Response::bytes`] takes the limit per
/// call and accepts `None`. Unbounded is not an option here, because the body is buffered into a
/// foreign array before anyone can look at it, so an unbounded response from a server the
/// application does not control is an out-of-memory condition rather than a slow request.
const DEFAULT_MAX_RESPONSE_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// One header field. A list of these rather than a map, because HTTP/3 allows a field name to
/// repeat and the repetitions are meaningful (`set-cookie` above all).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Header {
    /// The field name, lowercased on the wire.
    pub name: String,
    /// The field value.
    pub value: String,
}

/// A request to issue.
///
/// Everything but the URL has a default, so that the common case is a URL and nothing else.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HttpRequest {
    /// The absolute request URL. Must be `https`.
    pub url: String,
    /// The HTTP method.
    #[uniffi(default = "GET")]
    pub method: String,
    /// Header fields, in the order they should be sent.
    #[uniffi(default)]
    pub headers: Vec<Header>,
    /// The request body, buffered.
    ///
    /// `None` and an empty vector are equivalent.
    #[uniffi(default)]
    pub body: Option<Vec<u8>>,
    /// SCION addresses to use instead of resolving the URL's host, without ports: the port always
    /// comes from the URL. An empty list resolves normally.
    #[uniffi(default)]
    pub targets: Vec<String>,
    /// Overrides the client's request timeout for this request.
    #[uniffi(default)]
    pub request_timeout_ms: Option<u64>,
    /// Overrides the client's response-body limit for this request.
    #[uniffi(default)]
    pub max_response_body_bytes: Option<u64>,
}

/// A response, with its body already collected.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The response header fields, in the order received.
    pub headers: Vec<Header>,
    /// The response body.
    pub body: Vec<u8>,
    /// The trailing header section, empty if the server sent none.
    pub trailers: Vec<Header>,
}

/// Which underlay to prefer among the ones discovery returns.
///
/// A preference, not a selection: both underlays always exist, and this decides which is used when
/// the endhost API offers both.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum Underlay {
    /// Prefer SNAP.
    Snap,
    /// Prefer UDP.
    Udp,
}

/// Trust anchors for validating server certificates.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TrustAnchors {
    /// Whatever the TLS stack trusts on its own, which is nothing this crate configures.
    ///
    /// How useful that is varies by platform, and on some it is not useful at all: Android keeps
    /// its system anchors in a keystore rather than in a file or directory the TLS stack can
    /// find, so the library above these bindings reads them and passes them as
    /// [`TrustAnchors::Pem`].
    SystemDefault,
    /// Anchors supplied in memory, as a PEM bundle.
    Pem {
        /// The PEM bundle.
        pem: Vec<u8>,
    },
    /// Anchors read from a PEM file.
    CaCertsFile {
        /// Path to the file.
        path: String,
    },
    /// Anchors read from a directory laid out the way OpenSSL expects one.
    ///
    /// Not simply a directory of PEM files: this is OpenSSL's `CApath`, so each certificate has to
    /// be named by its subject hash. A directory of ordinary `.pem` files loads without complaint
    /// and then fails every handshake, with nothing in the error to say why. Prefer
    /// [`TrustAnchors::Pem`] or [`TrustAnchors::CaCertsFile`] unless something else already
    /// maintains such a directory.
    CaCertsDir {
        /// Path to the directory.
        path: String,
    },
    /// No verification at all.
    ///
    /// Every certificate is accepted, which also removes what makes trying several candidate
    /// addresses for one origin safe. For local development against a throwaway topology, never
    /// for anything reachable by anyone else.
    InsecureNoVerify,
}

/// Endhost API discovery tuning. Every field is optional; an absent one keeps the stack's default.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct DiscoveryConfig {
    /// How many priority groups of endhost APIs to try.
    #[uniffi(default)]
    pub max_groups: Option<u32>,
    /// How many APIs to sample from each group.
    #[uniffi(default)]
    pub apis_per_group: Option<u32>,
    /// Delay before each successive group starts connecting.
    #[uniffi(default)]
    pub per_group_delay_ms: Option<u64>,
}

/// SNAP underlay settings. Every field is optional; an absent one keeps the stack's default.
#[derive(Clone, Default, uniffi::Record)]
pub struct SnapConfig {
    /// Which discovered SNAP data plane to use.
    #[uniffi(default)]
    pub dp_index: Option<u32>,
    /// The X25519 private key for snap-tun connections, 32 bytes.
    ///
    /// Worth supplying rather than leaving to the default: connectivity is rebuilt on every
    /// network change, and each rebuild that has no identity generates a fresh random one, so the
    /// endpoint's identity would change under the peer every time the network does.
    #[uniffi(default)]
    pub static_identity: Option<Vec<u8>>,
}

/// UDP underlay settings. Every field is optional; an absent one keeps the stack's default.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct UdpConfig {
    /// Source addresses for outgoing packets. Empty means "whichever address reaches the endhost
    /// API".
    #[uniffi(default)]
    pub outbound_ips: Vec<String>,
    /// How often to refresh the next-hop resolution.
    #[uniffi(default)]
    pub next_hop_resolver_fetch_interval_ms: Option<u64>,
}

/// Everything a client is built from.
///
/// Only `endhost_api_url` has no sensible default: it is how the stack discovers the data planes
/// available to it, and pointing it somewhere else is the whole difference between a local
/// topology and a production network. Build one with
/// [`default_client_config`](crate::default_client_config) and change what you need.
#[derive(Clone, uniffi::Record)]
pub struct ClientConfig {
    /// The endhost API to discover connectivity through.
    pub endhost_api_url: String,
    /// The bearer token for the endhost API and the SNAP control plane.
    ///
    /// Replaceable while the client runs, through
    /// [`set_auth_token`](crate::ScionHttp3Client::set_auth_token), which is how a token that
    /// expires is renewed. Leave it unset only where neither endpoint requires one: a client built
    /// without a token cannot be given one later, because `None` installs no token source at all
    /// and there is no second state meaning "a token is coming". A caller who needs a token but
    /// does not hold one yet must therefore wait for it and build the client afterwards.
    ///
    /// No type on the Rust side derives `Debug` while it holds this, so no Rust log line can print
    /// it by accident. That protection stops at the boundary: uniffi generates `ClientConfig` as a
    /// Kotlin `data class`, and its `toString()` prints every property, this one included. Kotlin
    /// callers must keep the whole config out of their logs.
    pub auth_token: Option<String>,
    /// The preferred underlay, applied to whatever discovery returns.
    pub preferred_underlay: Option<Underlay>,
    /// Endhost API discovery tuning.
    pub discovery: DiscoveryConfig,
    /// SNAP underlay settings.
    pub snap: SnapConfig,
    /// UDP underlay settings.
    pub udp: UdpConfig,
    /// Trust anchors for server certificates.
    pub trust: TrustAnchors,
    /// Timeout for establishing a connection to an origin.
    pub connect_timeout_ms: u64,
    /// Default timeout for a whole request, including body collection.
    pub request_timeout_ms: u64,
    /// How long a pooled connection may sit unused before it is swept.
    pub idle_connection_timeout_ms: u64,
    /// Bound on the number of distinct origins with pooled connections.
    pub max_origins: u32,
    /// Stagger between connection attempts to an origin's candidate addresses.
    pub connection_attempt_delay_ms: u64,
    /// Default bound on a buffered response body.
    ///
    /// A limit beyond what a foreign byte array can hold is not clamped, because a caller that
    /// raises it has said something deliberate: such a response fails when it is handed over
    /// rather than being silently truncated.
    pub max_response_body_bytes: u64,
}

impl ClientConfig {
    /// The configuration `scion-http3` would apply on its own, for the given endhost API.
    pub(crate) fn with_defaults(endhost_api_url: String) -> Self {
        ClientConfig {
            endhost_api_url,
            auth_token: None,
            preferred_underlay: None,
            discovery: DiscoveryConfig::default(),
            snap: SnapConfig::default(),
            udp: UdpConfig::default(),
            trust: TrustAnchors::SystemDefault,
            connect_timeout_ms: millis(DEFAULT_CONNECT_TIMEOUT),
            request_timeout_ms: millis(DEFAULT_REQUEST_TIMEOUT),
            idle_connection_timeout_ms: millis(DEFAULT_IDLE_CONNECTION_TIMEOUT),
            max_origins: u32::try_from(DEFAULT_MAX_ORIGINS).unwrap_or(u32::MAX),
            connection_attempt_delay_ms: millis(DEFAULT_CONNECTION_ATTEMPT_DELAY),
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
        }
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults must come from `scion-http3`, not from a copy of its numbers that drifts the
    /// first time one of them is tuned.
    #[test]
    fn defaults_follow_the_client_crate() {
        let config = ClientConfig::with_defaults("https://endhost-api.example.org".to_string());
        assert_eq!(
            config.request_timeout_ms,
            DEFAULT_REQUEST_TIMEOUT.as_millis() as u64
        );
        assert_eq!(
            config.connect_timeout_ms,
            DEFAULT_CONNECT_TIMEOUT.as_millis() as u64
        );
        assert_eq!(
            config.idle_connection_timeout_ms,
            DEFAULT_IDLE_CONNECTION_TIMEOUT.as_millis() as u64
        );
        assert_eq!(config.max_origins as usize, DEFAULT_MAX_ORIGINS);
        assert_eq!(
            config.connection_attempt_delay_ms,
            DEFAULT_CONNECTION_ATTEMPT_DELAY.as_millis() as u64
        );
    }

    /// Anything the stack has a default for stays absent, so that the stack keeps deciding.
    #[test]
    fn stack_settings_start_unset() {
        let config = ClientConfig::with_defaults("https://endhost-api.example.org".to_string());
        assert!(config.preferred_underlay.is_none());
        assert!(config.discovery.max_groups.is_none());
        assert!(config.snap.dp_index.is_none());
        assert!(config.udp.outbound_ips.is_empty());
        assert!(config.udp.next_hop_resolver_fetch_interval_ms.is_none());
    }
}
