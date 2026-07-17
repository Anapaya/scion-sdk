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
use scion_sdk_reqwest_connect_rpc::{
    client::CrpcClientError,
    token_source::{TokenSource, static_token::StaticTokenSource},
};
use scion_sdk_utils::backoff::ExponentialBackoff;
use url::Url;
use x25519_dalek::StaticSecret;

pub use crate::underlays::udp::{OutboundIpResolver, TargetAddrOutboundIpResolver};
use crate::{
    ea_source::{
        EndhostApiSource, EndhostApiSourceError, StaticEndhostApiDiscovery, StaticEndhostApis,
    },
    path::fetcher::{EndhostApiSegmentFetcher, traits::SegmentFetcher},
    stack::ScionStack,
    underlays::{
        SnapSocketConfig, UnderlayStack,
        discovery::{PeriodicUnderlayDiscovery, UnderlayDiscovery},
    },
};

const DEFAULT_UDP_NEXT_HOP_RESOLVER_FETCH_INTERVAL: Duration = Duration::from_secs(600);
const DEFAULT_ENDHOST_API_DISCOVERY_MAX_GROUPS: usize = 5;
const DEFAULT_ENDHOST_API_DISCOVERY_APIS_PER_GROUP: usize = 2;
const DEFAULT_ENDHOST_API_DISCOVERY_PER_GROUP_DELAY: Duration = Duration::from_millis(500);

/// Factory that builds the UDP underlay's outbound IP resolver from the selected endhost API URL.
type OutboundIpResolverFactory = Box<dyn FnOnce(Url) -> Arc<dyn OutboundIpResolver> + Send>;

/// Builder for creating a [`ScionStack`].
///
/// # Example
///
/// ```no_run
/// use scion_stack::stack::builder::ScionStackBuilder;
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
    crpc_client: Option<reqwest::Client>,
    endhost_api_token_source: Option<Arc<dyn TokenSource>>,
    auth_token_source: Option<Arc<dyn TokenSource>>,
    endhost_api_source: Arc<dyn EndhostApiSource>,
    preferred_underlay: PreferredUnderlay,
    endhost_api_discovery: EndhostApiDiscoveryConfig,
    snap: SnapUnderlayConfig,
    udp: UdpUnderlayConfig,
}

impl ScionStackBuilder {
    /// Create a new [`ScionStackBuilder`].
    ///
    /// The stack uses the the endhost API to discover the available data planes.
    /// By default, udp dataplanes are preferred over snap dataplanes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            crpc_client: None,
            endhost_api_token_source: None,
            auth_token_source: None,
            endhost_api_source: Arc::new(StaticEndhostApiDiscovery::global()),
            preferred_underlay: PreferredUnderlay::Udp,
            endhost_api_discovery: EndhostApiDiscoveryConfig::default(),
            snap: SnapUnderlayConfig::default(),
            udp: UdpUnderlayConfig::default(),
        }
    }

    /// Sets which underlay to prefer when discovering data planes, if both are available.
    ///
    /// Defaults to [`PreferredUnderlay::Udp`].
    #[must_use]
    pub fn with_preferred_underlay(mut self, preferred: PreferredUnderlay) -> Self {
        self.preferred_underlay = preferred;
        self
    }

    /// Set a custom CRPC client for discovering and connecting to data planes.
    ///
    /// Can be useful if no DNS resolution is possible, so the client can be configured with custom
    /// name resolution or with IP addresses directly.
    #[must_use]
    pub fn with_crpc_client(mut self, crpc_client: reqwest::Client) -> Self {
        self.crpc_client = Some(crpc_client);
        self
    }

    /// Set a static endhost API
    ///
    /// Replaces existing endhost API source.
    ///
    /// See [`Self::with_endhost_api_discovery_source`] for more flexible configuration
    #[must_use]
    pub fn with_endhost_api(mut self, endhost_api_url: Url) -> Self {
        let source = StaticEndhostApis::new().add_group(vec![endhost_api_url]);
        self.endhost_api_source = Arc::new(source);

        self
    }

    /// Sets how the client will find its endhost APIs.
    ///
    /// If none is set, the stack will fall back to using the global discovery API.
    #[must_use]
    pub fn with_endhost_api_discovery_source(mut self, source: impl EndhostApiSource) -> Self {
        self.endhost_api_source = Arc::new(source);
        self
    }

    /// Set a token source to use for authentication with the endhost API.
    #[must_use]
    pub fn with_endhost_api_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.endhost_api_token_source = Some(Arc::new(source));
        self
    }

    /// Set a static token to use for authentication with the endhost API.
    #[must_use]
    pub fn with_endhost_api_auth_token(mut self, token: String) -> Self {
        self.endhost_api_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Set a token source to use for authentication both with the endhost API and the SNAP control
    /// plane.
    /// If a more specific token source is set, it takes precedence over this token source.
    #[must_use]
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.auth_token_source = Some(Arc::new(source));
        self
    }

    /// Set a static token to use for authentication both with the endhost API and the SNAP control
    /// plane.
    /// If a more specific token is set, it takes precedence over this token.
    #[must_use]
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.auth_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Set the maximum number of API groups to probe during endhost API
    /// discovery.
    ///
    /// Groups are ordered by priority; only the first `max_groups` non-empty
    /// groups returned by the discovery source are considered. Defaults to 5.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn with_endhost_api_discovery_per_group_delay(mut self, per_group_delay: Duration) -> Self {
        self.endhost_api_discovery.per_group_delay = per_group_delay;
        self
    }

    /// Set SNAP underlay specific configuration for the SCION stack.
    #[must_use]
    pub fn with_snap_underlay_config(mut self, config: SnapUnderlayConfig) -> Self {
        self.snap = config;
        self
    }

    /// Set UDP underlay specific configuration for the SCION stack.
    #[must_use]
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
            crpc_client,
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
            // Likely not transient, since it indicates a misconfiguration on client or server side.
            return Err(BuildScionStackError::EndhostApiSourceError(
                EndhostApiSourceError::new("endhost API discovery returned no APIs", false),
            ));
        }

        let token_source: Option<Arc<dyn TokenSource>> =
            endhost_api_token_source.or(auth_token_source.clone());
        let crpc_c = crpc_client.clone();
        let discover_underlays = move |url: Url| {
            let token_source = token_source.clone();
            let crpc_c = crpc_c.clone();
            let url = url.clone();
            async move {
                let mut client = match crpc_c {
                    Some(client) => {
                        CrpcEndhostApiClient::new_with_client(&url, client)
                            .map_err(ApiAttemptError::client_setup)?
                    }
                    None => {
                        CrpcEndhostApiClient::new(&url).map_err(ApiAttemptError::client_setup)?
                    }
                };
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
                .map_err(ApiAttemptError::underlay_discovery)?;
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
                BuildScionStackError::AllEndhostApisFailed(AllEndhostApisFailed::new(errors))
            })?;
        tracing::info!(url=%api_url, "Selected endhost API");

        // Resolve the outbound IP addresses for the UDP underlay sockets.
        // By default we assume that the interface used to reach the endhost API is the same as
        // the interface used to reach the data planes.
        let outbound_ip_resolver: Arc<dyn OutboundIpResolver> =
            (udp.outbound_ip_resolver_factory)(api_url.clone());

        let underlay_stack = UnderlayStack::new(
            preferred_underlay,
            Arc::new(underlay_discovery),
            outbound_ip_resolver,
            snap.static_identity.unwrap_or_else(StaticSecret::random),
            SnapSocketConfig {
                crpc_client: snap.crpc_client.or(crpc_client),
                snap_token_source: snap.snap_token_source.or(auth_token_source),
            },
        );

        Ok(ScionStack::new(
            Some(api_url),
            Arc::new(EndhostApiSegmentFetcher::new(endhost_api_client)),
            Arc::new(underlay_stack),
        ))
    }

    /// Build a UDP-underlay SCION stack without endhost API.
    ///
    /// Unlike [`Self::build`], this performs no endhost-API discovery and contacts no endhost API
    /// at runtime. The caller supplies everything the stack would otherwise obtain from an
    /// endhost API:
    ///
    /// * `underlay_discovery` — the underlay topology, only UDP underlay is supported.
    /// * `outbound_ip_resolver` — the outbound IP resolver.
    /// * `default_segment_fetcher` — the path-segment source registered as the stack's default
    ///   [`SegmentFetcher`]. It is consulted by every socket unless that socket opts out via
    ///   [`crate::stack::SocketConfig::disable_default_segment_fetcher`].
    ///
    /// The resulting stack uses the UDP underlay only (no SNAP) and a freshly generated static
    /// identity.
    fn build_static_udp_underlay(
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
        outbound_ip_resolver: Arc<dyn OutboundIpResolver>,
        default_segment_fetcher: Arc<dyn SegmentFetcher>,
    ) -> ScionStack {
        let underlay_stack = UnderlayStack::new(
            PreferredUnderlay::Udp,
            underlay_discovery,
            outbound_ip_resolver,
            StaticSecret::random(),
            SnapSocketConfig {
                crpc_client: None,
                snap_token_source: None,
            },
        );

        ScionStack::new(None, default_segment_fetcher, Arc::new(underlay_stack))
    }
}

impl Default for ScionStackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ScionStack {
    /// Builds a UDP-underlay SCION stack without an endhost API.
    ///
    /// Unlike [`ScionStackBuilder::build`], this performs no endhost-API discovery and contacts no
    /// endhost API at runtime. The caller supplies everything the stack would otherwise obtain from
    /// an endhost API:
    ///
    /// * `underlay_discovery` — the underlay topology, only UDP underlay is supported.
    /// * `outbound_ip_resolver` — the outbound IP resolver.
    /// * `default_segment_fetcher` — the path-segment source registered as the stack's default
    ///   [`SegmentFetcher`]. It is consulted by every socket unless that socket opts out via
    ///   [`crate::stack::SocketConfig::disable_default_segment_fetcher`].
    ///
    /// The resulting stack uses the UDP underlay only (no SNAP) and a freshly generated static
    /// identity.
    #[must_use]
    pub fn static_udp_underlay(
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
        outbound_ip_resolver: Arc<dyn OutboundIpResolver>,
        default_segment_fetcher: Arc<dyn SegmentFetcher>,
    ) -> ScionStack {
        ScionStackBuilder::build_static_udp_underlay(
            underlay_discovery,
            outbound_ip_resolver,
            default_segment_fetcher,
        )
    }
}

/// Build SCION stack errors.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BuildScionStackError {
    /// Discovery returned no underlay or no underlay was provided.
    #[error("no underlay available: {0}")]
    UnderlayUnavailable(Cow<'static, str>),
    /// All endhost APIs failed during client setup or underlay discovery.
    #[error(transparent)]
    AllEndhostApisFailed(#[from] AllEndhostApisFailed),
    /// Failed to retrieve any endhost APIs from the discovery source.
    #[error(transparent)]
    EndhostApiSourceError(#[from] EndhostApiSourceError),
    /// Error building the SNAP SCION stack.
    /// This error is only returned if a SNAP underlay is used.
    #[error(transparent)]
    Snap(#[from] BuildSnapScionStackError),
    /// Internal error, this should never happen.
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Build SNAP SCION stack errors.
///
/// The underlying cause of the client/discovery variants is available through
/// [`std::error::Error::source`]; the concrete source types are intentionally not exposed.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BuildSnapScionStackError {
    /// Discovery returned no SNAP data plane.
    #[error("no SNAP data plane available: {0}")]
    DataPlaneUnavailable(Cow<'static, str>),
    /// Error setting up the SNAP control plane client.
    #[error("control plane client setup error")]
    ControlPlaneClientSetup(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Error making the data plane discovery request to the SNAP control plane.
    #[error("data plane discovery request error")]
    DataPlaneDiscovery(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Error returned when every attempted endhost API fails.
///
/// Formats as a single-line summary suitable for use in structured logs.
#[derive(Debug)]
pub struct AllEndhostApisFailed {
    failures: Vec<(Url, ApiAttemptError)>,
}

impl AllEndhostApisFailed {
    pub(crate) fn new(failures: Vec<(Url, ApiAttemptError)>) -> Self {
        Self { failures }
    }

    /// The per-API failures, in the order the APIs were attempted.
    #[must_use]
    pub fn failures(&self) -> &[(Url, ApiAttemptError)] {
        &self.failures
    }

    /// Returns whether every attempt failed for a transient reason (e.g. a connection error), so
    /// building the stack may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        !self.failures.is_empty() && self.failures.iter().all(|(_, err)| err.is_transient())
    }
}

impl fmt::Display for AllEndhostApisFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "all {} endhost API(s) failed", self.failures.len())?;
        let mut sep = ": ";
        for (url, err) in &self.failures {
            write!(f, "{sep}{url} ({err})")?;
            sep = "; ";
        }
        Ok(())
    }
}

impl std::error::Error for AllEndhostApisFailed {}

/// Error for a single endhost API connection attempt.
///
/// The underlying cause is available through [`std::error::Error::source`]; the concrete source
/// type is intentionally not exposed. Use [`is_transient`](ApiAttemptError::is_transient) to decide
/// whether a retry may help.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ApiAttemptError {
    /// The API client could not be instantiated (e.g. invalid URL scheme).
    #[error("client setup")]
    ClientSetup {
        /// Whether the failure is transient and a retry may help.
        transient: bool,
        /// The underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Underlay discovery against the API failed (e.g. server unreachable).
    #[error("underlay discovery")]
    UnderlayDiscovery {
        /// Whether the failure is transient and a retry may help.
        transient: bool,
        /// The underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl ApiAttemptError {
    pub(crate) fn client_setup(error: anyhow::Error) -> Self {
        // Client setup failures (e.g. an invalid URL scheme) are configuration errors, not
        // transient.
        Self::ClientSetup {
            transient: false,
            source: error.into_boxed_dyn_error(),
        }
    }

    pub(crate) fn underlay_discovery(error: CrpcClientError) -> Self {
        Self::UnderlayDiscovery {
            transient: is_transient_crpc_error(&error),
            source: Box::new(error),
        }
    }

    /// Returns whether the failure is transient and a retry may help.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::ClientSetup { transient, .. } | Self::UnderlayDiscovery { transient, .. } => {
                *transient
            }
        }
    }
}

/// A CRPC error is considered transient if it stems from a connection-level failure that may
/// succeed on retry.
fn is_transient_crpc_error(error: &CrpcClientError) -> bool {
    matches!(error, CrpcClientError::ConnectionError { .. })
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreferredUnderlay {
    /// SNAP underlay.
    Snap,
    /// UDP underlay.
    Udp,
}

/// SNAP underlay configuration.
///
/// Construct with [`SnapUnderlayConfig::default`] and customize with the consuming `with_*`
/// methods, then pass to [`ScionStackBuilder::with_snap_underlay_config`].
#[derive(Default)]
pub struct SnapUnderlayConfig {
    crpc_client: Option<reqwest::Client>,
    snap_token_source: Option<Arc<dyn TokenSource>>,
    snap_dp_index: usize,
    /// Private key used for snap-tun connections. If unset, a random static identity is generated.
    static_identity: Option<StaticSecret>,
}

impl SnapUnderlayConfig {
    /// Sets a static token to use for authentication with the SNAP control plane.
    #[must_use]
    pub fn with_auth_token(mut self, token: String) -> Self {
        self.snap_token_source = Some(Arc::new(StaticTokenSource::from(token)));
        self
    }

    /// Sets a token source to use for authentication with the SNAP control plane.
    #[must_use]
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.snap_token_source = Some(Arc::new(source));
        self
    }

    /// Sets a custom CRPC client for discovering and connecting to data planes.
    #[must_use]
    pub fn with_crpc_client(mut self, client: reqwest::Client) -> Self {
        self.crpc_client = Some(client);
        self
    }

    /// Sets the index of the SNAP data plane to use.
    #[must_use]
    pub fn with_snap_dp_index(mut self, dp_index: usize) -> Self {
        self.snap_dp_index = dp_index;
        self
    }

    /// Sets the static identity to use for snap-tun connections.
    ///
    /// If unset, a random static identity is generated.
    #[must_use]
    pub fn with_static_identity(mut self, identity: StaticSecret) -> Self {
        self.static_identity = Some(identity);
        self
    }
}

/// UDP underlay configuration.
///
/// Construct with [`UdpUnderlayConfig::default`] and customize with the consuming `with_*` methods,
/// then pass to [`ScionStackBuilder::with_udp_underlay_config`].
pub struct UdpUnderlayConfig {
    udp_next_hop_resolver_fetch_interval: Duration,
    outbound_ip_resolver_factory: OutboundIpResolverFactory,
}

impl Default for UdpUnderlayConfig {
    fn default() -> Self {
        Self {
            udp_next_hop_resolver_fetch_interval: DEFAULT_UDP_NEXT_HOP_RESOLVER_FETCH_INTERVAL,
            outbound_ip_resolver_factory: Box::new(move |url| {
                Arc::new(TargetAddrOutboundIpResolver::new(url, vec![]))
            }),
        }
    }
}

impl UdpUnderlayConfig {
    /// Sets the outbound IP addresses to use for the UDP underlay.
    ///
    /// If not set, the UDP underlay will use the local IP that can reach the endhost API.
    /// This is a convenience wrapper around [`Self::with_outbound_ip_resolver`] for a fixed set of
    /// addresses.
    #[must_use]
    pub fn with_outbound_ips(mut self, outbound_ips: Vec<net::IpAddr>) -> Self {
        self.outbound_ip_resolver_factory =
            Box::new(move |_url| Arc::new(outbound_ips) as Arc<dyn OutboundIpResolver>);
        self
    }

    /// Sets a custom outbound IP resolver for the UDP underlay.
    ///
    /// Use this method when outbound IP resolution does not depend on the selected endhost API URL.
    /// If the resolver needs the endhost API URL, use [`Self::with_outbound_ip_resolver_factory`]
    /// instead.
    ///
    /// By default, [`TargetAddrOutboundIpResolver`] is used, which resolves the endhost API
    /// hostname via OS DNS.
    #[must_use]
    pub fn with_outbound_ip_resolver(
        mut self,
        resolver: impl OutboundIpResolver + 'static,
    ) -> Self {
        let resolver = Arc::new(resolver) as Arc<dyn OutboundIpResolver>;
        self.outbound_ip_resolver_factory = Box::new(move |_url| resolver.clone());
        self
    }

    /// Sets a factory that builds the UDP underlay's outbound IP resolver from the selected endhost
    /// API URL.
    ///
    /// The winning endhost API URL is only known once the stack connects during
    /// [`ScionStackBuilder::build`], so resolvers that depend on it must be constructed via this
    /// factory. The factory is invoked once with the selected URL.
    ///
    /// Use this when the hostname is only resolvable through a custom DNS override that is
    /// invisible to the OS resolver, or to provide a fully custom URL-aware resolution
    /// strategy. If the resolver does not need the URL, use [`Self::with_outbound_ip_resolver`]
    /// instead.
    #[must_use]
    pub fn with_outbound_ip_resolver_factory<F, R>(mut self, factory: F) -> Self
    where
        F: FnOnce(Url) -> R + Send + 'static,
        R: OutboundIpResolver + 'static,
    {
        self.outbound_ip_resolver_factory =
            Box::new(move |url| Arc::new(factory(url)) as Arc<dyn OutboundIpResolver>);
        self
    }

    /// Sets the interval at which the UDP next hop resolver fetches the next hops from the endhost
    /// API.
    #[must_use]
    pub fn with_udp_next_hop_resolver_fetch_interval(mut self, fetch_interval: Duration) -> Self {
        self.udp_next_hop_resolver_fetch_interval = fetch_interval;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
    use url::Url;

    use super::*;

    fn connection_error() -> CrpcClientError {
        CrpcClientError::ConnectionError {
            context: Cow::Borrowed("test"),
            source: Box::new(std::io::Error::other("boom")),
        }
    }

    fn non_connection_error() -> CrpcClientError {
        CrpcClientError::DecodeError {
            context: Cow::Borrowed("test"),
            source: Some(Box::new(std::io::Error::other("boom"))),
            body: None,
        }
    }

    #[test]
    fn api_attempt_error_transient_classification() {
        // A connection-level discovery failure is transient.
        assert!(ApiAttemptError::underlay_discovery(connection_error()).is_transient());
        // Any other discovery failure is not.
        assert!(!ApiAttemptError::underlay_discovery(non_connection_error()).is_transient());
        // Client setup failures are configuration errors, never transient.
        assert!(!ApiAttemptError::client_setup(anyhow::anyhow!("invalid url")).is_transient());
    }

    #[test]
    fn all_endhost_apis_failed_transient_classification() {
        let url: Url = "http://example.com".parse().expect("valid url");

        // An empty failure set is not transient (there was nothing to retry).
        assert!(!AllEndhostApisFailed::new(vec![]).is_transient());

        // All-transient failures are transient.
        assert!(
            AllEndhostApisFailed::new(vec![(
                url.clone(),
                ApiAttemptError::underlay_discovery(connection_error()),
            )])
            .is_transient()
        );

        // A single non-transient failure makes the whole set non-transient.
        assert!(
            !AllEndhostApisFailed::new(vec![
                (
                    url.clone(),
                    ApiAttemptError::underlay_discovery(connection_error()),
                ),
                (
                    url,
                    ApiAttemptError::underlay_discovery(non_connection_error())
                ),
            ])
            .is_transient()
        );
    }
}
