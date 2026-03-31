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

mod priority_connect;

use std::{borrow::Cow, fmt, net, sync::Arc, time::Duration};

use endhost_api_client::client::CrpcEndhostApiClient;
use rand::seq::IndexedRandom;
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
const DEFAULT_ENDHOST_API_DISCOVERY_MAX_GROUPS: usize = 5;
const DEFAULT_ENDHOST_API_DISCOVERY_APIS_PER_GROUP: usize = 2;
const DEFAULT_ENDHOST_API_DISCOVERY_PER_GROUP_DELAY: Duration = Duration::from_millis(500);

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
    endhost_api_discovery: EndhostApiDiscoveryConfig,
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
            endhost_api_discovery: EndhostApiDiscoveryConfig::default(),
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

    /// Set the maximum number of API groups to probe during endhost API
    /// discovery.
    ///
    /// Groups are ordered by priority; only the first `max_groups` non-empty
    /// groups returned by the discovery source are considered. Defaults to 5.
    pub fn with_endhost_api_discovery_max_groups(mut self, max_groups: usize) -> Self {
        self.endhost_api_discovery.max_groups = max_groups;
        self
    }

    /// Set the maximum number of APIs to probe per group during endhost API
    /// discovery.
    ///
    /// APIs are selected at random within each group. Setting this to a higher
    /// value increases redundancy at the cost of additional concurrent
    /// connections. Defaults to 2.
    pub fn with_endhost_api_discovery_apis_per_group(mut self, apis_per_group: usize) -> Self {
        self.endhost_api_discovery.apis_per_group = apis_per_group;
        self
    }

    /// Set the delay before APIs in group `k` begin connecting, measured from
    /// the start of discovery.
    ///
    /// Group `k` starts after `k × per_group_delay` **or** as soon as group
    /// `k-1` is fully exhausted, whichever comes first. A shorter delay reduces
    /// time-to-connect when a high-priority group is slow, at the cost of
    /// additional concurrent connections to lower-priority groups. Defaults to
    /// 500 ms.
    pub fn with_endhost_api_discovery_per_group_delay(mut self, per_group_delay: Duration) -> Self {
        self.endhost_api_discovery.per_group_delay = per_group_delay;
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
            endhost_api_discovery,
            snap,
            udp,
        } = self;

        // Race a random sample of APIs from each of the first N groups,
        // staggered by group priority. Group k starts after k *
        // per_group_delay or when group k-1 is fully exhausted, whichever
        // comes first.
        let api_groups = endhost_api_source.endhost_apis().await?;
        let api_groups: Vec<Vec<Url>> = {
            let mut rng = rand::rng();
            api_groups
                .into_iter()
                .map(|g| g.apis.into_iter().map(|a| a.address).collect::<Vec<_>>())
                .filter(|group| !group.is_empty())
                .take(endhost_api_discovery.max_groups)
                .map(|group: Vec<Url>| {
                    group
                        .sample(&mut rng, endhost_api_discovery.apis_per_group)
                        .cloned()
                        .collect()
                })
                .collect()
        };

        if api_groups.is_empty() {
            return Err(BuildScionStackError::EndhostApiSourceError(
                EndhostApiSourceError {
                    error: anyhow::anyhow!("Endhost API discovery returned no APIs"),
                    // Likely not transient, since it indicates a misconfiguration on client or
                    // server side.
                    transient: false,
                },
            ));
        }

        let token_source: Option<Arc<dyn TokenSource>> =
            endhost_api_token_source.or(auth_token_source.clone());
        let discover_underlays = move |url: Url| {
            let token_source = token_source.clone();
            let url = url.clone();
            async move {
                let mut client =
                    CrpcEndhostApiClient::new(&url).map_err(ApiAttemptError::ClientSetup)?;
                if let Some(token_source) = &token_source {
                    client.use_token_source(token_source.clone());
                }
                let client = Arc::new(client);
                let discovery = PeriodicUnderlayDiscovery::new(
                    client.clone(),
                    udp.udp_next_hop_resolver_fetch_interval,
                    ExponentialBackoff::new(0.5, 10.0, 2.0, 0.5),
                )
                .await
                .map_err(ApiAttemptError::UnderlayDiscovery)?;
                Ok((client, discovery))
            }
        };

        let (api_url, (endhost_api_client, underlay_discovery)) =
            priority_connect::try_priority_groups(
                api_groups,
                discover_underlays,
                endhost_api_discovery.per_group_delay,
            )
            .await
            .map_err(|errors| {
                BuildScionStackError::AllEndhostApisFailed(AllEndhostApisFailed(errors))
            })?;
        tracing::info!(%api_url, "Successfully selected endhost API");

        // Use the endhost API URL to resolve the local IP addresses for the UDP underlay
        // sockets.
        // Here we assume that the interface used to reach the endhost API is
        // the same as the interface used to reach the data planes.
        let local_ip_resolver: Arc<dyn LocalIpResolver> = match udp.local_ips {
            Some(ips) => Arc::new(ips),
            None => {
                Arc::new(
                    TargetAddrLocalIpResolver::new(api_url.clone())
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
    /// All endhost APIs failed during client setup or underlay discovery.
    #[error(transparent)]
    AllEndhostApisFailed(#[from] AllEndhostApisFailed),
    /// Failed to retrieve any endhost APIs from the discovery source.
    #[error("endhost api source error: {0:#}")]
    EndhostApiSourceError(#[from] EndhostApiSourceError),
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

/// Error returned when every attempted endhost API fails.
///
/// Formats as a single-line summary suitable for use in structured logs.
#[derive(Debug)]
pub struct AllEndhostApisFailed(pub Vec<(Url, ApiAttemptError)>);

impl fmt::Display for AllEndhostApisFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "all {} endhost API(s) failed", self.0.len())?;
        let mut sep = ": ";
        for (url, err) in &self.0 {
            write!(f, "{sep}{url} ({err})")?;
            sep = "; ";
        }
        Ok(())
    }
}

impl std::error::Error for AllEndhostApisFailed {}

/// Error for a single endhost API connection attempt.
#[derive(thiserror::Error, Debug)]
pub enum ApiAttemptError {
    /// The API client could not be instantiated (e.g. invalid URL scheme).
    #[error("client setup: {0:#}")]
    ClientSetup(anyhow::Error),
    /// Underlay discovery against the API failed (e.g. server unreachable).
    #[error("underlay discovery: {0:#}")]
    UnderlayDiscovery(CrpcClientError),
}

/// Configuration for endhost API discovery during stack building.
///
/// Controls how many API groups and endpoints are probed in parallel, and
/// how long to wait before falling through to the next priority group.
pub struct EndhostApiDiscoveryConfig {
    /// Maximum number of API groups to consider, in priority order.
    max_groups: usize,
    /// Maximum number of APIs to probe per group, selected at random.
    apis_per_group: usize,
    /// Delay before group `k` begins connecting (`k × per_group_delay`),
    /// unless the previous group is exhausted sooner.
    per_group_delay: Duration,
}

impl Default for EndhostApiDiscoveryConfig {
    fn default() -> Self {
        Self {
            max_groups: DEFAULT_ENDHOST_API_DISCOVERY_MAX_GROUPS,
            apis_per_group: DEFAULT_ENDHOST_API_DISCOVERY_APIS_PER_GROUP,
            per_group_delay: DEFAULT_ENDHOST_API_DISCOVERY_PER_GROUP_DELAY,
        }
    }
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
