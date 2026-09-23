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
        ScionStackBuilder, reqwest,
        stack::builder::{PreferredUnderlay, SnapUnderlayConfig, UdpUnderlayConfig},
        x25519_dalek::StaticSecret,
    },
    sciparse::address::ip_addr::ScionIpAddr,
};

use crate::{
    error::Error,
    token::SharedToken,
    types::{
        ClientConfig, DiscoveryConfig, DnsOverride, Header, HttpRequest, HttpResponse, SnapConfig,
        TrustAnchors, UdpConfig, Underlay,
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

        for DnsOverride { host, addresses } in self.dns_overrides {
            if addresses.is_empty() {
                return Err(Error::invalid_request(format!(
                    "the DNS override for `{host}` has no addresses"
                )));
            }
            config = config.with_dns_override(host, parse_addresses(&addresses)?);
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
        let control_plane = validated_control_plane(self.control_plane_anchors_pem.as_deref())?;
        if customization_needed(&discovery, &snap, &udp, control_plane.as_ref()) {
            config = config.with_stack_customizer(move |builder| {
                customize(builder, &discovery, &snap, &udp, control_plane.as_ref())
            });
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
    control_plane: Option<&ValidatedControlPlane>,
) -> bool {
    discovery.max_groups.is_some()
        || discovery.apis_per_group.is_some()
        || discovery.per_group_delay_ms.is_some()
        || snap.is_set()
        || udp.is_set()
        || control_plane.is_some()
}

fn customize(
    mut builder: ScionStackBuilder,
    discovery: &DiscoveryConfig,
    snap: &ValidatedSnap,
    udp: &ValidatedUdp,
    control_plane: Option<&ValidatedControlPlane>,
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
    // The stack passes this client to the SNAP control plane as well, since the SNAP configuration
    // sets none of its own.
    if let Some(control_plane) = control_plane {
        match control_plane.build() {
            Ok(client) => builder = builder.with_crpc_client(client),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Could not build the control-plane HTTP client, using the default one"
                );
            }
        }
    }

    builder
}

/// Timeout for one control-plane request. The same value that `CrpcClient::new` applies.
const CONTROL_PLANE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Control-plane trust anchors that are known to build an HTTP client.
struct ValidatedControlPlane {
    anchors: Vec<reqwest::Certificate>,
}

impl ValidatedControlPlane {
    /// Builds a new HTTP client that trusts the anchors and nothing else.
    ///
    /// Each rebuild gets a new client, so that no pooled connection outlives the network it was
    /// opened on.
    fn build(&self) -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .timeout(CONTROL_PLANE_REQUEST_TIMEOUT)
            .tls_certs_only(self.anchors.iter().cloned())
            .build()
    }
}

fn validated_control_plane(pem: Option<&[u8]>) -> Result<Option<ValidatedControlPlane>, Error> {
    let Some(pem) = pem else {
        // The platform verifier on Android reads the trust store through JNI, and this library
        // registers no JavaVM for it. Without this check, the first HTTPS request to the endhost
        // API fails with an error that names only the verifier crate.
        if cfg!(target_os = "android") {
            return Err(Error::invalid_request(
                "on Android, `control_plane_anchors_pem` must be set: the platform verifier is \
                 not available, so the endhost API and SNAP certificates cannot be verified \
                 without it",
            ));
        }
        return Ok(None);
    };

    let anchors = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| {
        Error::invalid_request(format!(
            "the control-plane trust anchors are not a readable PEM bundle: {e}"
        ))
    })?;
    if anchors.is_empty() {
        return Err(Error::invalid_request(
            "the control-plane trust anchors hold no certificate",
        ));
    }

    let control_plane = ValidatedControlPlane { anchors };
    control_plane.build().map_err(|e| {
        Error::invalid_request(format!(
            "the control-plane trust anchors do not build an HTTP client: {e}"
        ))
    })?;
    Ok(Some(control_plane))
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
        TrustAnchors::SystemDefault => builder.with_platform_verifier(),
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
        if let Some(timeout_ms) = self.request_timeout_ms {
            builder = builder.request_timeout(Duration::from_millis(timeout_ms));
        }

        Ok(builder.build()?)
    }
}

/// Parses a list of SCION addresses.
fn parse_addresses(addresses: &[String]) -> Result<Vec<ScionIpAddr>, Error> {
    addresses
        .iter()
        .map(|address| {
            address.parse::<ScionIpAddr>().map_err(|e| {
                Error::invalid_request(format!("invalid SCION address `{address}`: {e}"))
            })
        })
        .collect()
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
            None,
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
            None,
        ));
    }

    /// A certificate authority and a `localhost` certificate that it signed, both as PEM.
    struct TestPki {
        ca_pem: String,
        leaf_pem: String,
        leaf_key_pem: String,
    }

    fn test_pki() -> TestPki {
        let mut ca_params = rcgen::CertificateParams::new(vec![]).expect("CA parameters");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::CertifiedIssuer::self_signed(
            ca_params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("CA certificate");

        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("leaf parameters")
            .signed_by(&leaf_key, &ca)
            .expect("leaf certificate");

        TestPki {
            ca_pem: ca.pem(),
            leaf_pem: leaf.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    #[test]
    fn unusable_control_plane_anchors_are_rejected() {
        let not_pem = validated_control_plane(Some(b"not a certificate"));
        assert!(matches!(not_pem, Err(Error::InvalidRequest { .. })));

        let empty = validated_control_plane(Some(b""));
        assert!(matches!(empty, Err(Error::InvalidRequest { .. })));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn control_plane_anchors_install_a_customizer() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let untouched = ClientConfig::with_defaults("https://endhost-api.example.org".to_string());
        assert!(
            validated_control_plane(None)
                .expect("absent anchors are valid off Android")
                .is_none()
        );

        let control_plane =
            validated_control_plane(Some(test_pki().ca_pem.as_bytes())).expect("a valid bundle");
        assert!(customization_needed(
            &untouched.discovery,
            &validated_snap(untouched.snap).expect("no identity"),
            &validated_udp(untouched.udp).expect("no addresses"),
            control_plane.as_ref(),
        ));
    }

    /// The control-plane client must trust the given anchors and nothing else. This is what keeps
    /// the platform verifier, which cannot run on Android, out of the endhost API connection.
    #[tokio::test]
    async fn the_control_plane_client_trusts_only_its_anchors() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let pki = test_pki();

        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pki.leaf_pem.clone().into_bytes(),
            pki.leaf_key_pem.clone().into_bytes(),
        )
        .await
        .expect("server TLS configuration");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binding a port");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let port = listener.local_addr().expect("the bound address").port();
        let server = axum_server::from_tcp_rustls(listener, tls)
            .expect("the TLS server")
            .serve(
                axum::Router::new()
                    .route("/", axum::routing::get(|| async { "ok" }))
                    .into_make_service(),
            );
        let server = tokio::spawn(server);
        let url = format!("https://localhost:{port}/");

        let trusted = validated_control_plane(Some(pki.ca_pem.as_bytes()))
            .expect("a valid bundle")
            .expect("anchors were given")
            .build()
            .expect("the client");
        let response = trusted.get(&url).send().await.expect("the request");
        assert!(response.status().is_success());

        let other = validated_control_plane(Some(test_pki().ca_pem.as_bytes()))
            .expect("a valid bundle")
            .expect("anchors were given")
            .build()
            .expect("the client");
        let error = other
            .get(&url)
            .send()
            .await
            .expect_err("a certificate from another authority must be refused");
        assert!(error.is_connect(), "unexpected error: {error}");

        server.abort();
    }

    /// A DNS override is checked when the client is built, so a mistake in it is reported there
    /// and not as a resolution failure on the first request.
    #[test]
    fn a_malformed_dns_override_is_rejected() {
        let config = |addresses: Vec<&str>| {
            ClientConfig {
                dns_overrides: vec![DnsOverride {
                    host: "pinned.example".to_string(),
                    addresses: addresses.into_iter().map(str::to_string).collect(),
                }],
                ..ClientConfig::with_defaults("https://endhost-api.invalid".to_string())
            }
            .into_client_config(None)
        };

        assert!(matches!(
            config(vec!["not-an-address"]).expect_err("an invalid address"),
            Error::InvalidRequest { .. }
        ));
        assert!(matches!(
            config(vec![]).expect_err("an empty override"),
            Error::InvalidRequest { .. }
        ));
        config(vec!["2-ff00:0:212,127.0.0.1"]).expect("a valid override");
    }
}
