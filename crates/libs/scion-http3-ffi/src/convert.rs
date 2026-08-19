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

//! Conversions between the records that cross the boundary and the `scion-http3` API.
//!
//! Everything here is mechanical. Where a caller can get something wrong (an address, a method, a
//! header name) it is rejected as [`Error::invalid_request`] before any I/O happens, so that a
//! typo does not arrive as a connection failure.

use std::time::Duration;

use scion_http3::{
    Config, Request, Response,
    http::{HeaderMap, HeaderName, HeaderValue, Method},
    scion_quic::quic::config::QuicConfig,
    scion_stack::{
        ScionStackBuilder,
        stack::builder::{PreferredUnderlay, SnapUnderlayConfig, UdpUnderlayConfig},
        x25519_dalek::StaticSecret,
    },
    sciparse::address::ip_addr::ScionIpAddr,
};

use crate::{
    error::Error,
    token::SharedToken,
    types::{
        ClientConfig, DiscoveryConfig, Header, HttpRequest, HttpResponse, SnapConfig, TrustAnchors,
        UdpConfig, Underlay,
    },
};

/// Length of an X25519 private key.
const STATIC_IDENTITY_LEN: usize = 32;

impl ClientConfig {
    /// Builds the `scion-http3` configuration this record describes.
    ///
    /// `auth_token` is the client's own handle rather than this record's string, so that a token
    /// set later reaches the configuration that is already running.
    pub(crate) fn into_client_config(
        self,
        auth_token: Option<SharedToken>,
    ) -> Result<Config, Error> {
        let endhost_api = self
            .endhost_api_url
            .parse()
            .map_err(|e| Error::invalid_request(format!("invalid endhost API URL: {e}")))?;

        let mut config = Config::new(endhost_api)
            .with_connect_timeout(Duration::from_millis(self.connect_timeout_ms))
            .with_request_timeout(Duration::from_millis(self.request_timeout_ms))
            .with_idle_connection_timeout(Duration::from_millis(self.idle_connection_timeout_ms))
            .with_max_origins(self.max_origins as usize)
            .with_connection_attempt_delay(Duration::from_millis(self.connection_attempt_delay_ms))
            .with_quic_config(quic_config(&self.trust)?);

        // Installed only when there is a token. The stack's get_token awaits the first value, so a
        // source with nothing in it would make the first endhost-API request hang rather than go
        // out unauthenticated, which is what a client configured without a token wants.
        if let Some(token) = auth_token {
            config = config.with_auth_token_source(token);
        }

        if let Some(underlay) = self.preferred_underlay {
            config = config.with_preferred_underlay(match underlay {
                Underlay::Snap => PreferredUnderlay::Snap,
                Underlay::Udp => PreferredUnderlay::Udp,
            });
        }

        // Everything the stack builder owns has to go through the customizer, which runs on every
        // rebuild of connectivity rather than once. Validate here, where a bad value can still be
        // reported to the caller, and let the closure only assemble.
        let discovery = self.discovery;
        let snap = validated_snap(self.snap)?;
        let udp = validated_udp(self.udp)?;
        if customization_needed(&discovery, &snap, &udp) {
            config = config
                .with_stack_customizer(move |builder| customize(builder, &discovery, &snap, &udp));
        }

        Ok(config)
    }
}

/// Whether anything in the record needs the stack builder touched at all. Without this every
/// client would carry a customizer that does nothing.
fn customization_needed(
    discovery: &DiscoveryConfig,
    snap: &ValidatedSnap,
    udp: &ValidatedUdp,
) -> bool {
    discovery.max_groups.is_some()
        || discovery.apis_per_group.is_some()
        || discovery.per_group_delay_ms.is_some()
        || snap.is_set()
        || udp.is_set()
}

fn customize(
    mut builder: ScionStackBuilder,
    discovery: &DiscoveryConfig,
    snap: &ValidatedSnap,
    udp: &ValidatedUdp,
) -> ScionStackBuilder {
    if let Some(max_groups) = discovery.max_groups {
        builder = builder.with_endhost_api_discovery_max_groups(max_groups as usize);
    }
    if let Some(apis_per_group) = discovery.apis_per_group {
        builder = builder.with_anapaya_ead_apis_per_group(apis_per_group as usize);
    }
    if let Some(delay_ms) = discovery.per_group_delay_ms {
        builder =
            builder.with_endhost_api_discovery_per_group_delay(Duration::from_millis(delay_ms));
    }

    // Both underlay configurations are single-use, so each rebuild gets a fresh one assembled from
    // the same settings rather than a clone of one built earlier.
    if snap.is_set() {
        builder = builder.with_snap_underlay_config(snap.build());
    }
    if udp.is_set() {
        builder = builder.with_udp_underlay_config(udp.build());
    }

    builder
}

/// A [`SnapConfig`] whose values are known to be usable, so that the customizer cannot fail.
struct ValidatedSnap {
    dp_index: Option<u32>,
    static_identity: Option<[u8; STATIC_IDENTITY_LEN]>,
}

impl ValidatedSnap {
    fn is_set(&self) -> bool {
        self.dp_index.is_some() || self.static_identity.is_some()
    }

    fn build(&self) -> SnapUnderlayConfig {
        let mut config = SnapUnderlayConfig::default();
        if let Some(dp_index) = self.dp_index {
            config = config.with_snap_dp_index(dp_index as usize);
        }
        if let Some(identity) = self.static_identity {
            config = config.with_static_identity(StaticSecret::from(identity));
        }
        config
    }
}

fn validated_snap(snap: SnapConfig) -> Result<ValidatedSnap, Error> {
    let static_identity = match snap.static_identity {
        None => None,
        Some(bytes) => {
            Some(
                <[u8; STATIC_IDENTITY_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
                    Error::invalid_request(format!(
                        "a SNAP static identity is {STATIC_IDENTITY_LEN} bytes, got {}",
                        bytes.len()
                    ))
                })?,
            )
        }
    };
    Ok(ValidatedSnap {
        dp_index: snap.dp_index,
        static_identity,
    })
}

/// A [`UdpConfig`] whose values are known to be usable, so that the customizer cannot fail.
struct ValidatedUdp {
    outbound_ips: Vec<std::net::IpAddr>,
    next_hop_resolver_fetch_interval: Option<Duration>,
}

impl ValidatedUdp {
    fn is_set(&self) -> bool {
        !self.outbound_ips.is_empty() || self.next_hop_resolver_fetch_interval.is_some()
    }

    fn build(&self) -> UdpUnderlayConfig {
        let mut config = UdpUnderlayConfig::default();
        if !self.outbound_ips.is_empty() {
            config = config.with_outbound_ips(self.outbound_ips.clone());
        }
        if let Some(interval) = self.next_hop_resolver_fetch_interval {
            config = config.with_udp_next_hop_resolver_fetch_interval(interval);
        }
        config
    }
}

fn validated_udp(udp: UdpConfig) -> Result<ValidatedUdp, Error> {
    let outbound_ips = udp
        .outbound_ips
        .iter()
        .map(|ip| {
            ip.parse::<std::net::IpAddr>()
                .map_err(|e| Error::invalid_request(format!("invalid outbound IP `{ip}`: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ValidatedUdp {
        outbound_ips,
        next_hop_resolver_fetch_interval: udp
            .next_hop_resolver_fetch_interval_ms
            .map(Duration::from_millis),
    })
}

/// Builds the QUIC configuration for the requested trust anchors.
fn quic_config(trust: &TrustAnchors) -> Result<QuicConfig, Error> {
    let builder = QuicConfig::builder();
    let builder = match trust {
        TrustAnchors::SystemDefault => builder,
        TrustAnchors::Pem { pem } => builder.ca_certs_pem(pem.clone()),
        TrustAnchors::CaCertsFile { path } => builder.ca_certs_file(path.clone()),
        TrustAnchors::CaCertsDir { path } => builder.ca_certs_dir(path.clone()),
        TrustAnchors::InsecureNoVerify => builder.verify_peer(false),
    };
    Ok(builder.build())
}

impl HttpRequest {
    /// Builds the `scion-http3` request this record describes.
    pub(crate) fn into_request(self) -> Result<Request, Error> {
        let method = Method::from_bytes(self.method.as_bytes()).map_err(|e| {
            Error::invalid_request(format!("invalid method `{}`: {e}", self.method))
        })?;

        let mut builder = Request::builder().method(method).url(self.url);
        for Header { name, value } in self.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = self.body {
            builder = builder.body(body);
        }
        if !self.targets.is_empty() {
            let targets = self
                .targets
                .iter()
                .map(|target| {
                    target.parse::<ScionIpAddr>().map_err(|e| {
                        Error::invalid_request(format!("invalid target address `{target}`: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.targets(targets);
        }
        if let Some(timeout_ms) = self.request_timeout_ms {
            builder = builder.request_timeout(Duration::from_millis(timeout_ms));
        }

        Ok(builder.build()?)
    }
}

/// Collects a response into the record that crosses the boundary.
///
/// The body is collected here rather than behind a handle the caller holds: the response owns the
/// connection its body streams over and counts down the request's deadline while it is alive, so
/// leaving it in foreign hands would make a garbage collector decide when a stream is cancelled
/// and when a request times out.
pub(crate) async fn collect_response(
    response: Response,
    max_body_bytes: u64,
) -> Result<HttpResponse, Error> {
    let status = response.status().as_u16();
    let headers = flatten_headers(response.headers());
    // Saturating rather than failing: a limit larger than this process can address is a limit that
    // was never going to be reached.
    let limit = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
    let (body, trailers) = response.bytes(Some(limit)).await?;

    Ok(HttpResponse {
        status,
        headers,
        // `into`, not `to_vec`: the collected buffer is uniquely owned here, so this reclaims it
        // instead of copying up to the body limit a second time.
        body: body.into(),
        trailers: trailers.as_ref().map(flatten_headers).unwrap_or_default(),
    })
}

/// Flattens a header map, keeping repeated fields.
///
/// Values of one field name keep their relative order, which is the order that is defined to
/// matter. The order between names follows the map's own iteration order and is not the order
/// they arrived in; nothing in HTTP gives that meaning.
fn flatten_headers(map: &HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(name, value)| {
            Header {
                name: name.as_str().to_owned(),
                // A header value is opaque bytes, while the boundary carries strings. Values that
                // are not UTF-8 are vanishingly rare and never load-bearing for a REST client, so
                // they are replaced rather than turned into a failed request.
                value: lossy_value(name, value),
            }
        })
        .collect()
}

fn lossy_value(name: &HeaderName, value: &HeaderValue) -> String {
    match value.to_str() {
        Ok(value) => value.to_owned(),
        Err(_) => {
            tracing::debug!(header = name.as_str(), "Replacing a non-UTF-8 header value");
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use scion_http3::http::HeaderMap;

    use super::*;
    use crate::types::ClientConfig;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: vec![],
            body: None,
            targets: vec![],
            request_timeout_ms: None,
            max_response_body_bytes: None,
        }
    }

    #[test]
    fn a_request_round_trips_its_parts() {
        let built = HttpRequest {
            method: "POST".to_string(),
            headers: vec![
                Header {
                    name: "accept".to_string(),
                    value: "application/json".to_string(),
                },
                Header {
                    name: "x-trace".to_string(),
                    value: "abc".to_string(),
                },
            ],
            body: Some(b"payload".to_vec()),
            targets: vec!["2-ff00:0:212,127.0.0.1".to_string()],
            request_timeout_ms: Some(1_500),
            ..request("https://example.org:8443/rooms")
        }
        .into_request()
        .expect("building the request");

        assert_eq!(built.method(), Method::POST);
        assert_eq!(built.url().as_str(), "https://example.org:8443/rooms");
        assert_eq!(built.headers().get("accept").unwrap(), "application/json");
        assert_eq!(built.headers().get("x-trace").unwrap(), "abc");
        assert_eq!(built.body().as_ref(), b"payload");
        assert_eq!(built.targets().expect("targets").len(), 1);
        assert_eq!(
            built.request_timeout(),
            Some(Duration::from_millis(1_500)),
            "the per-request timeout was lost"
        );
    }

    #[test]
    fn an_absent_body_is_the_same_as_an_empty_one() {
        let with_body = |body| {
            HttpRequest {
                method: "POST".to_string(),
                body,
                ..request("https://example.org/")
            }
            .into_request()
            .expect("building the request")
        };

        assert_eq!(
            with_body(Some(vec![])).body(),
            with_body(None).body(),
            "an empty body and an absent one built different requests"
        );
        assert!(with_body(None).body().is_empty());
    }

    /// Mistakes the caller can make must be named, not turned into a connection failure later.
    #[test]
    fn malformed_input_is_rejected_before_any_io() {
        let bad_method = HttpRequest {
            method: "not a method".to_string(),
            ..request("https://example.org/")
        }
        .into_request()
        .expect_err("an invalid method is not a request");
        assert!(matches!(bad_method, Error::InvalidRequest { .. }));

        let bad_target = HttpRequest {
            targets: vec!["not-an-address".to_string()],
            ..request("https://example.org/")
        }
        .into_request()
        .expect_err("an invalid target is not a request");
        assert!(matches!(bad_target, Error::InvalidRequest { .. }));

        // From `scion-http3`'s own builder rather than from this crate, which is the point: the
        // two must not develop separate opinions about what a valid request is.
        let plaintext = request("http://example.org/")
            .into_request()
            .expect_err("http is not supported");
        assert!(matches!(plaintext, Error::InvalidRequest { .. }));
    }

    #[test]
    fn repeated_header_fields_keep_their_order() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", HeaderValue::from_static("a=1"));
        map.append("set-cookie", HeaderValue::from_static("b=2"));

        let flattened = flatten_headers(&map);
        assert_eq!(
            flattened,
            vec![
                Header {
                    name: "set-cookie".to_string(),
                    value: "a=1".to_string(),
                },
                Header {
                    name: "set-cookie".to_string(),
                    value: "b=2".to_string(),
                },
            ]
        );
    }

    #[test]
    fn a_non_utf8_header_value_does_not_fail_the_response() {
        let mut map = HeaderMap::new();
        map.append(
            "x-binary",
            HeaderValue::from_bytes(&[0xff, 0x61]).expect("a valid header value"),
        );

        let flattened = flatten_headers(&map);
        assert_eq!(flattened.len(), 1);
        assert!(flattened[0].value.ends_with('a'));
    }

    #[test]
    fn a_config_carries_its_settings_and_rejects_a_bad_url() {
        let config = ClientConfig::with_defaults("https://endhost-api.example.org".to_string());
        config
            .clone()
            .into_client_config(None)
            .expect("building the configuration");

        let bad = ClientConfig {
            endhost_api_url: "not a url".to_string(),
            ..config
        }
        .into_client_config(None)
        .expect_err("an invalid endhost API URL is not a configuration");
        assert!(matches!(bad, Error::InvalidRequest { .. }));
    }

    /// A key of the wrong length must be refused at construction, where it can still be explained,
    /// rather than inside a rebuild that happens on a network change.
    #[test]
    fn a_static_identity_of_the_wrong_length_is_rejected() {
        let Err(error) = validated_snap(SnapConfig {
            static_identity: Some(vec![0; 8]),
            ..SnapConfig::default()
        }) else {
            panic!("8 bytes is not an X25519 key");
        };
        assert!(matches!(error, Error::InvalidRequest { .. }));

        validated_snap(SnapConfig {
            static_identity: Some(vec![0; STATIC_IDENTITY_LEN]),
            ..SnapConfig::default()
        })
        .expect("32 bytes is an X25519 key");
    }

    #[test]
    fn an_invalid_outbound_ip_is_rejected() {
        let Err(error) = validated_udp(UdpConfig {
            outbound_ips: vec!["10.0.0.1".to_string(), "not-an-ip".to_string()],
            ..UdpConfig::default()
        }) else {
            panic!("a malformed address is not an outbound IP");
        };
        assert!(matches!(error, Error::InvalidRequest { .. }));
    }

    /// A configuration that touches nothing the stack builder owns must not install a customizer
    /// that does nothing on every rebuild.
    #[test]
    fn the_stack_customizer_is_only_installed_when_needed() {
        let untouched = ClientConfig::with_defaults("https://endhost-api.example.org".to_string());
        assert!(!customization_needed(
            &untouched.discovery,
            &validated_snap(untouched.snap).expect("no identity"),
            &validated_udp(untouched.udp).expect("no addresses"),
        ));

        let tuned = ClientConfig {
            discovery: DiscoveryConfig {
                max_groups: Some(2),
                ..DiscoveryConfig::default()
            },
            ..ClientConfig::with_defaults("https://endhost-api.example.org".to_string())
        };
        assert!(customization_needed(
            &tuned.discovery,
            &validated_snap(tuned.snap).expect("no identity"),
            &validated_udp(tuned.udp).expect("no addresses"),
        ));
    }
}
