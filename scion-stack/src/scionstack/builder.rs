// Copyright 2025 Anapaya Systems
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
//! SCION stack builder.

use std::{borrow::Cow, net, sync::Arc, time::Duration};

use endhost_api_client::client::CrpcEndhostApiClient;
pub use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use scion_sdk_reqwest_connect_rpc::token_source::{TokenSource, static_token::StaticTokenSource};
use scion_sdk_utils::backoff::ExponentialBackoff;
use url::Url;
use x25519_dalek::StaticSecret;

use crate::{
    ea_source::{
        EndhostApiSource, EndhostApiSourceError, StaticEndhostApiDiscovery, StaticEndhostApis,
    },
    scionstack::ScionStack,
    underlays::{
        SnapSocketConfig, UnderlayStack,
        discovery::PeriodicUnderlayDiscovery,
        udp::{LocalIpResolver, TargetAddrLocalIpResolver},
    },
};

const DEFAULT_UDP_NEXT_HOP_RESOLVER_FETCH_INTERVAL: Duration = Duration::from_secs(600);

/// Builder for creating a [ScionStack].
///
/// # Example
///
/// ```no_run
/// use scion_stack::scionstack::builder::ScionStackBuilder;
/// use url::Url;
///
/// async fn setup_scion_stack() {
///     let control_plane_url: Url = "http://127.0.0.1:1234".parse().unwrap();
///
///     let scion_stack = ScionStackBuilder::new()
///         .with_endhost_api(control_plane_url)
///         .with_auth_token("snap_token".to_string())
///         .build()
///         .await
///         .unwrap();
/// }
/// ```
pub struct ScionStackBuilder {
    endhost_api_token_source: Option<Arc<dyn TokenSource>>,
    auth_token_source: Option<Arc<dyn TokenSource>>,
    endhost_api_source: Arc<dyn EndhostApiSource>,
    preferred_underlay: PreferredUnderlay,
    snap: SnapUnderlayConfig,
    udp: UdpUnderlayConfig,
}

impl ScionStackBuilder {
    /// Create a new [ScionStackBuilder].
    ///
    /// The stack uses the the endhost API to discover the available data planes.
    /// By default, udp dataplanes are preferred over snap dataplanes.
    pub fn new() -> Self {
        Self {
            endhost_api_token_source: None,
            auth_token_source: None,
            endhost_api_source: Arc::new(StaticEndhostApiDiscovery::global()),
            preferred_underlay: PreferredUnderlay::Udp,
            snap: SnapUnderlayConfig::default(),
            udp: UdpUnderlayConfig::default(),
        }
    }

    /// When discovering data planes, prefer SNAP data planes if available.
    pub fn with_prefer_snap(mut self) -> Self {
        self.preferred_underlay = PreferredUnderlay::Snap;
        self
    }

    /// When discovering data planes, prefer UDP data planes if available.
    pub fn with_prefer_udp(mut self) -> Self {
        self.preferred_underlay = PreferredUnderlay::Udp;
        self
    }

    /// Set a static endhost API
    ///
    /// Replaces existing endhost API source.
    ///
    /// See [Self::with_endhost_api_discovery_source] for more flexible configuration
    pub fn with_endhost_api(mut self, endhost_api_url: Url) -> Self {
        let source = StaticEndhostApis::new().add_group(vec![endhost_api_url]);
        self.endhost_api_source = Arc::new(source);

        self
    }

    /// Sets how the client will find its endhost APIs.
    ///
    /// If none is set, the stack will fall back to using the global discovery API.
    pub fn with_endhost_api_discovery_source(mut self, source: impl EndhostApiSource) -> Self {
        self.endhost_api_source = Arc::new(source);
        self
    }

    /// Set a token source to use for authentication with the endhost API.
    pub fn with_endhost_api_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.endhost_api_token_source = Some(Arc::new(source));
        self
    }

    /// Set a static token to use for authentication with the endhost API.
    pub fn with_endhost_api_auth_token(mut self, token: String) -> Self {
        self.endhost_api_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Set a token source to use for authentication both with the endhost API and the SNAP control
    /// plane.
    /// If a more specific token source is set, it takes precedence over this token source.
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.auth_token_source = Some(Arc::new(source));
        self
    }

    /// Set a static token to use for authentication both with the endhost API and the SNAP control
    /// plane.
    /// If a more specific token is set, it takes precedence over this token.
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Set SNAP underlay specific configuration for the SCION stack.
    pub fn with_snap_underlay_config(mut self, config: SnapUnderlayConfig) -> Self {
        self.snap = config;
        self
    }

    /// Set UDP underlay specific configuration for the SCION stack.
    pub fn with_udp_underlay_config(mut self, config: UdpUnderlayConfig) -> Self {
        self.udp = config;
        self
    }

    /// Build the SCION stack.
    ///
    /// # Returns
    ///
    /// A new SCION stack.
    pub async fn build(self) -> Result<ScionStack, BuildScionStackError> {
        let ScionStackBuilder {
            endhost_api_token_source,
            auth_token_source,
            endhost_api_source,
            preferred_underlay,
            snap,
            udp,
        } = self;

        let mut endhost_apis = endhost_api_source
            .endhost_apis()
            .await?
            .into_iter()
            .filter(|group| !group.apis.is_empty());

        let api_group = endhost_apis.next().ok_or(EndhostApiSourceError {
            error: anyhow::anyhow!("Endhost API discovery returned empty list"),
            // Likely not transient, since it indicates a misconfiguration on client or server side.
            transient: false,
        })?;

        // TODO: Failover between apis, should be implemented in the CRPC client.
        let endhost_api_url = api_group
            .apis
            .first()
            .expect("API group with no APIs should have been filtered out")
            .address
            .clone();

        let endhost_api_client = {
            let mut client = CrpcEndhostApiClient::new(&endhost_api_url)
                .map_err(BuildScionStackError::EndhostApiClientSetupError)?;

            if let Some(token_source) = endhost_api_token_source.or(auth_token_source.clone()) {
                client.use_token_source(token_source);
            }

            Arc::new(client)
        };

        // XXX(bunert): Add support for statically configured underlays.

        let underlay_discovery = PeriodicUnderlayDiscovery::new(
            endhost_api_client.clone(),
            udp.udp_next_hop_resolver_fetch_interval,
            // TODO(uniquefine): make this configurable.
            ExponentialBackoff::new(0.5, 10.0, 2.0, 0.5),
        )
        .await
        .map_err(BuildScionStackError::UnderlayDiscoveryError)?;

        // Use the endhost API URL to resolve the local IP addresses for the UDP underlay
        // sockets.
        // Here we assume that the interface used to reach the endhost API is
        // the same as the interface used to reach the data planes.
        let local_ip_resolver: Arc<dyn LocalIpResolver> = match udp.local_ips {
            Some(ips) => Arc::new(ips),
            None => {
                Arc::new(
                    TargetAddrLocalIpResolver::new(endhost_api_url.clone())
                        .map_err(BuildUdpScionStackError::LocalIpResolutionError)?,
                )
            }
        };

        let underlay_stack = UnderlayStack::new(
            preferred_underlay,
            Arc::new(underlay_discovery),
            local_ip_resolver,
            snap.static_identity.unwrap_or_else(StaticSecret::random),
            SnapSocketConfig {
                snap_token_source: snap.snap_token_source.or(auth_token_source),
            },
        );

        Ok(ScionStack::new(
            endhost_api_client,
            Arc::new(underlay_stack),
        ))
    }
}

impl Default for ScionStackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build SCION stack errors.
#[derive(thiserror::Error, Debug)]
pub enum BuildScionStackError {
    /// Discovery returned no underlay or no underlay was provided.
    #[error("no underlay available: {0}")]
    UnderlayUnavailable(Cow<'static, str>),
    /// Error making the underlay discovery request to the endhost API.
    /// E.g. because the endhost API is not reachable.
    /// This error is only returned if the underlay is not statically configured.
    #[error("underlay discovery request error: {0:#}")]
    UnderlayDiscoveryError(CrpcClientError),
    /// Failed to find a usable endhost API.
    #[error("endhost api source error: {0:#}")]
    EndhostApiSourceError(#[from] EndhostApiSourceError),
    /// Error setting up the endhost API client.
    #[error("endhost API client setup error: {0:#}")]
    EndhostApiClientSetupError(anyhow::Error),
    /// Error building the SNAP SCION stack.
    /// This error is only returned if a SNAP underlay is used.
    #[error(transparent)]
    Snap(#[from] BuildSnapScionStackError),
    /// Error building the UDP SCION stack.
    /// This error is only returned if a UDP underlay is used.
    #[error(transparent)]
    Udp(#[from] BuildUdpScionStackError),
    /// Internal error, this should never happen.
    #[error("internal error: {0:#}")]
    Internal(anyhow::Error),
}

/// Build SNAP SCION stack errors.
#[derive(thiserror::Error, Debug)]
pub enum BuildSnapScionStackError {
    /// Discovery returned no SNAP data plane.
    #[error("no SNAP data plane available: {0}")]
    DataPlaneUnavailable(Cow<'static, str>),
    /// Error setting up the SNAP control plane client.
    #[error("control plane client setup error: {0:#}")]
    ControlPlaneClientSetupError(anyhow::Error),
    /// Error making the data plane discovery request to the SNAP control plane.
    #[error("data plane discovery request error: {0:#}")]
    DataPlaneDiscoveryError(CrpcClientError),
}

/// Build UDP SCION stack errors.
#[derive(thiserror::Error, Debug)]
pub enum BuildUdpScionStackError {
    /// Error resolving the local IP addresses.
    #[error("local IP resolution error: {0:#}")]
    LocalIpResolutionError(anyhow::Error),
}

/// Preferred underlay type (if available).
pub enum PreferredUnderlay {
    /// SNAP underlay.
    Snap,
    /// UDP underlay.
    Udp,
}

/// SNAP underlay configuration.
#[derive(Default)]
pub struct SnapUnderlayConfig {
    snap_token_source: Option<Arc<dyn TokenSource>>,
    snap_dp_index: usize,
    /// Private key used for snap-tun connections. If unset, a random static identity is generated.
    static_identity: Option<StaticSecret>,
}

impl SnapUnderlayConfig {
    /// Create a new [SnapUnderlayConfigBuilder] to configure the SNAP underlay.
    pub fn builder() -> SnapUnderlayConfigBuilder {
        SnapUnderlayConfigBuilder(Self::default())
    }
}

/// SNAP underlay configuration builder.
pub struct SnapUnderlayConfigBuilder(SnapUnderlayConfig);

impl SnapUnderlayConfigBuilder {
    /// Set a static token to use for authentication with the SNAP control plane.
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.0.snap_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Set a token source to use for authentication with the SNAP control plane.
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.0.snap_token_source = Some(Arc::new(source));
        self
    }

    /// Set the index of the SNAP data plane to use.
    ///
    /// # Arguments
    ///
    /// * `dp_index` - The index of the SNAP data plane to use.
    pub fn with_snap_dp_index(mut self, dp_index: usize) -> Self {
        self.0.snap_dp_index = dp_index;
        self
    }

    /// Set the static identity to use for snap-tun connections.
    /// If unset, a random static identity is generated.
    pub fn with_static_identity(mut self, identity: StaticSecret) -> Self {
        self.0.static_identity = Some(identity);
        self
    }

    /// Build the SNAP stack configuration.
    ///
    /// # Returns
    ///
    /// A new SNAP stack configuration.
    pub fn build(self) -> SnapUnderlayConfig {
        self.0
    }
}

/// UDP underlay configuration.
pub struct UdpUnderlayConfig {
    udp_next_hop_resolver_fetch_interval: Duration,
    local_ips: Option<Vec<net::IpAddr>>,
}

impl Default for UdpUnderlayConfig {
    fn default() -> Self {
        Self {
            udp_next_hop_resolver_fetch_interval: DEFAULT_UDP_NEXT_HOP_RESOLVER_FETCH_INTERVAL,
            local_ips: None,
        }
    }
}

impl UdpUnderlayConfig {
    /// Create a new [UdpUnderlayConfigBuilder] to configure the UDP underlay.
    pub fn builder() -> UdpUnderlayConfigBuilder {
        UdpUnderlayConfigBuilder(Self::default())
    }
}

/// UDP underlay configuration builder.
pub struct UdpUnderlayConfigBuilder(UdpUnderlayConfig);

impl UdpUnderlayConfigBuilder {
    /// Set the local IP addresses to use for the UDP underlay.
    /// If not set, the UDP underlay will use the local IP that can reach the endhost API.
    pub fn with_local_ips(mut self, local_ips: Vec<net::IpAddr>) -> Self {
        self.0.local_ips = Some(local_ips);
        self
    }

    /// Set the interval at which the UDP next hop resolver fetches the next hops
    /// from the endhost API.
    pub fn with_udp_next_hop_resolver_fetch_interval(mut self, fetch_interval: Duration) -> Self {
        self.0.udp_next_hop_resolver_fetch_interval = fetch_interval;
        self
    }

    /// Build the UDP underlay configuration.
    pub fn build(self) -> UdpUnderlayConfig {
        self.0
    }
}
