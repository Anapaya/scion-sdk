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

//! The engine config: a [`CoreConfig`] with every default applied and every
//! value checked.
//!
//! An absent value in [`CoreConfig`] takes its default here. The defaults of
//! the HTTP client come from the `DEFAULT_*` constants of scion-http3.

use std::time::Duration;

use scion_http3::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_CONNECTION_ATTEMPT_DELAY, DEFAULT_IDLE_CONNECTION_TIMEOUT,
    DEFAULT_MAX_ORIGINS, DEFAULT_REQUEST_TIMEOUT,
    scion_stack::{reqwest, stack::builder::PreferredUnderlay},
    sciparse::address::ip_addr::ScionIpAddr,
    url::Url,
};

use super::{describe_error, transport::connect::GatewayConfig};
use crate::ffi::types::{CoreConfig, CoreDnsOverride, CoreError, CoreTokenSource, CoreUnderlay};

/// The body limit if [`CoreConfig::max_response_body_bytes`] is absent.
///
/// The Rust library buffers the body before Kotlin sees it. Without a limit,
/// a large response from a server the app does not control runs it out of
/// memory.
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

const DEFAULT_AA_URL: &str = "https://auth.scion.anapaya.net";

// TODO: Handle the device ID correctly. With the default, all installs that
// share an API key look like one device to the AA.
const DEFAULT_DEVICE_ID: &str = "no-device-id";

/// The timeout of each request to the AA, the discovery service, and the
/// control plane.
const CONTROL_PLANE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct Config {
    /// If `None`, the engine discovers the endhost APIs: through the URL that
    /// the AA sends, else through the global discovery service.
    pub(crate) endhost_api: Option<Url>,
    /// If `None`, the engine sends no token.
    pub(crate) token_source: Option<TokenSource>,
    pub(crate) preferred_underlay: Option<PreferredUnderlay>,
    pub(crate) origin_trust: Trust,
    /// The client for the AA, the discovery service, and the control plane.
    /// If `None`, they use the reqwest default.
    pub(crate) control_plane_client: Option<reqwest::Client>,
    pub(crate) dns_overrides: Vec<(String, Vec<ScionIpAddr>)>,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_origins: usize,
    pub(crate) connection_attempt_delay: Duration,
    pub(crate) max_response_body_bytes: usize,
    /// If `None`, requests go over HTTP/3 to the origin.
    pub(crate) web_gateway: Option<GatewayConfig>,
}

/// Where the token for the endhost API and the SNAP control plane comes from.
pub(crate) enum TokenSource {
    /// A token from the Anapaya AA, renewed before it expires.
    AnapayaAa {
        url: Url,
        api_key: String,
        device_id: String,
    },
    /// A fixed token.
    Static(String),
}

/// What the origin certificates must chain up to.
#[derive(Clone)]
pub(crate) enum Trust {
    /// The CAs of the device.
    Platform,
    /// These anchors alone, as a PEM bundle.
    Anchors(Vec<u8>),
    /// No check. For tests only.
    None,
}

impl Config {
    pub(crate) fn new(config: CoreConfig) -> Result<Self, CoreError> {
        let endhost_api = config
            .endhost_api_url
            .map(|url| Config::url("endhost API", &url))
            .transpose()?;
        let token_source = config.token_source.map(TokenSource::new).transpose()?;
        let preferred_underlay = config.preferred_underlay.map(|underlay| {
            match underlay {
                CoreUnderlay::Snap => PreferredUnderlay::Snap,
                CoreUnderlay::Udp => PreferredUnderlay::Udp,
            }
        });

        // Pick the origin trust.
        let origin_trust = match (config.accept_invalid_certs, config.ca_certificates_pem) {
            (true, _) => Trust::None,
            (false, Some(pem)) => Trust::Anchors(pem),
            (false, None) => Trust::Platform,
        };

        // Built here to report a bad bundle now, not at the first request.
        let control_plane_client = config
            .control_plane_ca_certificates_pem
            .map(|pem| Config::control_plane_client(&pem))
            .transpose()?;

        let dns_overrides = config
            .dns_overrides
            .into_iter()
            .map(Config::dns_override)
            .collect::<Result<_, _>>()?;

        // 0 is a valid delay: all attempts start at once.
        let connection_attempt_delay = match config.connection_attempt_delay_ms {
            None => DEFAULT_CONNECTION_ATTEMPT_DELAY,
            Some(delay) => {
                let delay = u64::try_from(delay).map_err(|_| {
                    CoreError::invalid(format!(
                        "connection_attempt_delay_ms must not be negative, got {delay}"
                    ))
                })?;
                Duration::from_millis(delay)
            }
        };

        let resolved = Config {
            endhost_api,
            token_source,
            preferred_underlay,
            origin_trust,
            control_plane_client,
            dns_overrides,
            connect_timeout: Config::fallback_duration(
                "connect_timeout_ms",
                config.connect_timeout_ms,
                DEFAULT_CONNECT_TIMEOUT,
            )?,
            request_timeout: Config::fallback_duration(
                "request_timeout_ms",
                config.request_timeout_ms,
                DEFAULT_REQUEST_TIMEOUT,
            )?,
            idle_timeout: Config::fallback_duration(
                "idle_timeout_ms",
                config.idle_timeout_ms,
                DEFAULT_IDLE_CONNECTION_TIMEOUT,
            )?,
            max_origins: Config::fallback_count(
                "max_origins",
                config.max_origins.map(i64::from),
                DEFAULT_MAX_ORIGINS,
            )?,
            connection_attempt_delay,
            max_response_body_bytes: Config::fallback_count(
                "max_response_body_bytes",
                config.max_response_body_bytes,
                DEFAULT_MAX_RESPONSE_BODY_BYTES,
            )?,
            web_gateway: config
                .web_gateway
                .map(|gateway| GatewayConfig { port: gateway.port }),
        };
        Ok(resolved)
    }

    fn url(name: &str, url: &str) -> Result<Url, CoreError> {
        url.parse()
            .map_err(|error| CoreError::invalid(format!("bad {name} URL: {error}")))
    }

    fn control_plane_client(pem: &[u8]) -> Result<reqwest::Client, CoreError> {
        let client = reqwest::Certificate::from_pem_bundle(pem).and_then(|anchors| {
            reqwest::Client::builder()
                .timeout(CONTROL_PLANE_TIMEOUT)
                .tls_certs_only(anchors)
                .build()
        });
        client.map_err(|error| {
            CoreError::invalid(format!(
                "bad control-plane anchors: {}",
                describe_error(&error)
            ))
        })
    }

    fn dns_override(
        CoreDnsOverride { host, addresses }: CoreDnsOverride,
    ) -> Result<(String, Vec<ScionIpAddr>), CoreError> {
        if addresses.is_empty() {
            return Err(CoreError::invalid(format!(
                "the DNS override for {host} has no addresses"
            )));
        }

        // Parse the addresses.
        let addresses = addresses
            .iter()
            .map(|address| {
                address.parse::<ScionIpAddr>().map_err(|error| {
                    CoreError::invalid(format!("bad SCION address {address}: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((host, addresses))
    }

    /// `default` if `millis` is absent.
    fn fallback_duration(
        name: &str,
        millis: Option<i64>,
        default: Duration,
    ) -> Result<Duration, CoreError> {
        let duration = match millis {
            None => default,
            Some(millis) => Duration::from_millis(Config::check_positive(name, millis)?),
        };
        Ok(duration)
    }

    /// `default` if `value` is absent.
    fn fallback_count(name: &str, value: Option<i64>, default: usize) -> Result<usize, CoreError> {
        let count = match value {
            None => default,
            Some(value) => {
                usize::try_from(Config::check_positive(name, value)?).unwrap_or(usize::MAX)
            }
        };
        Ok(count)
    }

    fn check_positive(name: &str, value: i64) -> Result<u64, CoreError> {
        u64::try_from(value)
            .ok()
            .filter(|&value| value > 0)
            .ok_or_else(|| CoreError::invalid(format!("{name} must be above 0, got {value}")))
    }
}

impl TokenSource {
    fn new(source: CoreTokenSource) -> Result<Self, CoreError> {
        let source = match source {
            CoreTokenSource::AnapayaAa {
                api_key,
                url,
                device_id,
            } => {
                TokenSource::AnapayaAa {
                    url: Config::url("AA", url.as_deref().unwrap_or(DEFAULT_AA_URL))?,
                    api_key,
                    device_id: device_id.unwrap_or_else(|| DEFAULT_DEVICE_ID.into()),
                }
            }
            CoreTokenSource::Static { token } => TokenSource::Static(token),
        };
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use scion_http3::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_ORIGINS};

    use super::{Config, DEFAULT_AA_URL, DEFAULT_MAX_RESPONSE_BODY_BYTES, TokenSource};
    use crate::ffi::types::{CoreConfig, CoreError, CoreTokenSource};

    fn empty() -> CoreConfig {
        CoreConfig {
            endhost_api_url: None,
            token_source: None,
            preferred_underlay: None,
            ca_certificates_pem: None,
            control_plane_ca_certificates_pem: None,
            accept_invalid_certs: false,
            dns_overrides: Vec::new(),
            connect_timeout_ms: None,
            request_timeout_ms: None,
            idle_timeout_ms: None,
            max_origins: None,
            connection_attempt_delay_ms: None,
            max_response_body_bytes: None,
            web_gateway: None,
        }
    }

    #[test]
    fn absent_values_take_the_defaults() {
        let config = Config::new(CoreConfig {
            token_source: Some(CoreTokenSource::AnapayaAa {
                api_key: "key".into(),
                url: None,
                device_id: None,
            }),
            ..empty()
        })
        .unwrap();

        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.max_origins, DEFAULT_MAX_ORIGINS);
        assert_eq!(
            config.max_response_body_bytes,
            DEFAULT_MAX_RESPONSE_BODY_BYTES
        );
        let Some(TokenSource::AnapayaAa { url, .. }) = config.token_source else {
            panic!("expected AA auth");
        };
        assert_eq!(url.as_str().trim_end_matches('/'), DEFAULT_AA_URL);
    }

    #[test]
    fn set_values_win() {
        let config = Config::new(CoreConfig {
            connect_timeout_ms: Some(1500),
            max_origins: Some(2),
            connection_attempt_delay_ms: Some(0),
            ..empty()
        })
        .unwrap();

        assert_eq!(config.connect_timeout, Duration::from_millis(1500));
        assert_eq!(config.max_origins, 2);
        assert_eq!(config.connection_attempt_delay, Duration::ZERO);
    }

    #[test]
    fn zero_and_negative_values_are_rejected() {
        for config in [
            CoreConfig {
                request_timeout_ms: Some(0),
                ..empty()
            },
            CoreConfig {
                max_origins: Some(-1),
                ..empty()
            },
            CoreConfig {
                connection_attempt_delay_ms: Some(-1),
                ..empty()
            },
        ] {
            assert!(matches!(
                Config::new(config),
                Err(CoreError::InvalidArgument { .. })
            ));
        }
    }
}
