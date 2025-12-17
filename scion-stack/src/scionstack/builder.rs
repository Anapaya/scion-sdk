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

use std::{borrow::Cow, collections::HashMap, net, sync::Arc, time::Duration};

use endhost_api_client::client::{CrpcEndhostApiClient, EndhostApiClient};
use endhost_api_models::underlays::{ScionRouter, Snap};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::{EndhostAddr, IsdAsn};
// Re-export for consumer
pub use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use scion_sdk_utils::backoff::{BackoffConfig, ExponentialBackoff};
use snap_control::client::{ControlPlaneApi, CrpcSnapControlClient};
use url::Url;

use super::DynUnderlayStack;
use crate::{
    scionstack::{DefaultScmpHandler, ScionStack, ScmpHandler},
    snap_tunnel::{SessionRenewal, SnapTunnelError, SnapTunnelSender},
    underlays::{
        snap::{NewSnapUnderlayStackError, SnapUnderlayStack},
        udp::{
            LocalIpResolver, TargetAddrLocalIpResolver, UdpUnderlayStack,
            underlay_resolver::UdpUnderlayResolver,
        },
        v2::{SnapSocketConfig, V2UnderlayStack, discovery::PeriodicUnderlayDiscovery},
    },
};

const DEFAULT_RESERVED_TIME: Duration = Duration::from_secs(3);
const DEFAULT_UDP_NEXT_HOP_RESOLVER_FETCH_INTERVAL: Duration = Duration::from_secs(600);
const DEFAULT_SNAP_TUNNEL_RECONNECT_BACKOFF: BackoffConfig = BackoffConfig {
    minimum_delay_secs: 0.5,
    maximum_delay_secs: 10.0,
    factor: 1.2,
    jitter_secs: 0.1,
};

/// Default size for the socket's receive channel (in packets).
/// 64KiB max payload size * 1000 ~= 64MiB if full.
pub const DEFAULT_RECEIVE_CHANNEL_SIZE: usize = 1000;

/// Type alias for the complex SCMP handler factory type to reduce type complexity
type ScmpHandlerFactory =
    Box<dyn FnOnce(SnapTunnelSender) -> Arc<dyn ScmpHandler> + Sync + Send + 'static>;

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
///     let scion_stack = ScionStackBuilder::new(control_plane_url)
///         .with_auth_token("snap_token".to_string())
///         .build()
///         .await
///         .unwrap();
/// }
/// ```
pub struct ScionStackBuilder {
    endhost_api_url: Url,
    endhost_api_token_source: Option<Arc<dyn TokenSource>>,
    auth_token_source: Option<Arc<dyn TokenSource>>,
    underlay: Underlay,
    /// XXX(uniquefine): this is currently only used for the v2 underlay stack.
    /// But it will replace the field above as soon as the v2 underlay stack is stable.
    preferred_underlay: PreferredUnderlay,
    snap: SnapUnderlayConfig,
    udp: UdpUnderlayConfig,
    use_v2: bool,
    receive_channel_size: usize,
}

impl ScionStackBuilder {
    /// Create a new [ScionStackBuilder].
    ///
    /// The stack uses the the endhost API to discover the available data planes.
    /// By default, udp dataplanes are preferred over snap dataplanes.
    pub fn new(endhost_api_url: Url) -> Self {
        Self {
            endhost_api_url,
            endhost_api_token_source: None,
            auth_token_source: None,
            underlay: Underlay::Discover {
                preferred_underlay: PreferredUnderlay::Udp,
                isd_as: IsdAsn::WILDCARD,
            },
            preferred_underlay: PreferredUnderlay::Udp,
            snap: SnapUnderlayConfig::default(),
            udp: UdpUnderlayConfig::default(),
            use_v2: false,
            receive_channel_size: DEFAULT_RECEIVE_CHANNEL_SIZE,
        }
    }

    /// When discovering data planes, prefer SNAP data planes if available.
    pub fn with_prefer_snap(mut self) -> Self {
        self.underlay = Underlay::Discover {
            preferred_underlay: PreferredUnderlay::Snap,
            isd_as: IsdAsn::WILDCARD,
        };
        self.preferred_underlay = PreferredUnderlay::Snap;
        self
    }

    /// When discovering data planes, prefer UDP data planes if available.
    pub fn with_prefer_udp(mut self) -> Self {
        self.underlay = Underlay::Discover {
            preferred_underlay: PreferredUnderlay::Udp,
            isd_as: IsdAsn::WILDCARD,
        };
        self.preferred_underlay = PreferredUnderlay::Udp;
        self
    }

    /// When discovering underlays, query only for the given ISD-AS.
    pub fn with_discover_underlay_isd_as(mut self, isd_as: IsdAsn) -> Self {
        if let Underlay::Discover {
            preferred_underlay, ..
        } = self.underlay
        {
            self.underlay = Underlay::Discover {
                preferred_underlay,
                isd_as,
            };
        }
        self
    }

    /// Use the v2 underlay stack.
    pub fn with_use_v2(mut self) -> Self {
        self.use_v2 = true;
        self
    }

    /// Use a SNAP underlay with the provided list of SNAP control planes.
    pub fn with_static_snap_underlay(mut self, control_planes: Vec<Snap>) -> Self {
        self.underlay = Underlay::Snap(control_planes);
        self
    }

    /// Use a UDP underlay with the provided list of SCION routers (UDP data planes).
    pub fn with_static_udp_underlay(self, data_planes: Vec<ScionRouter>) -> Self {
        Self {
            underlay: Underlay::Udp(data_planes),
            ..self
        }
    }

    /// Set a token source to use for authentication with the endhost API.
    pub fn with_endhost_api_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.endhost_api_token_source = Some(Arc::new(source));
        self
    }

    /// Set a static token to use for authentication with the endhost API.
    pub fn with_endhost_api_auth_token(mut self, token: String) -> Self {
        self.endhost_api_token_source = Some(Arc::new(token));
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
        self.auth_token_source = Some(Arc::new(token));
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
            endhost_api_url,
            endhost_api_token_source,
            auth_token_source,
            underlay,
            preferred_underlay,
            snap,
            udp,
            use_v2,
            receive_channel_size,
        } = self;

        let endhost_api_client = {
            let mut client = CrpcEndhostApiClient::new(&endhost_api_url)
                .map_err(BuildScionStackError::EndhostApiClientSetupError)?;
            if let Some(token_source) = endhost_api_token_source.or(auth_token_source.clone()) {
                client.use_token_source(token_source);
            }
            Arc::new(client)
        };

        if use_v2 {
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

            let v2_underlay_stack = V2UnderlayStack::new(
                preferred_underlay,
                Arc::new(underlay_discovery),
                local_ip_resolver,
                SnapSocketConfig {
                    snap_token_source: snap.snap_token_source.or(auth_token_source),
                    renewal_wait_threshold: snap.session_auto_renewal.renewal_wait_threshold,
                    reconnect_backoff: ExponentialBackoff::new_from_config(
                        snap.tunnel_reconnect_backoff,
                    ),
                },
            );
            return Ok(ScionStack::new(
                endhost_api_client,
                Arc::new(v2_underlay_stack),
            ));
        }

        // Discover available underlays
        let underlays = match underlay {
            Underlay::Discover {
                preferred_underlay,
                isd_as,
            } => {
                discover_underlays(endhost_api_client.as_ref(), preferred_underlay, isd_as).await?
            }
            Underlay::Snap(control_planes) => {
                if control_planes.is_empty() {
                    return Err(BuildScionStackError::UnderlayUnavailable(
                        "no snap control plane provided".into(),
                    ));
                }
                DiscoveredUnderlays::Snap(control_planes)
            }
            Underlay::Udp(routers) => {
                if routers.is_empty() {
                    return Err(BuildScionStackError::UnderlayUnavailable(
                        "no udp router provided".into(),
                    ));
                }
                DiscoveredUnderlays::Udp(routers)
            }
        };

        // Construct the appropriate underlay stack based on available data planes
        let underlay: Arc<dyn DynUnderlayStack> = match underlays {
            DiscoveredUnderlays::Snap(control_planes) => {
                // XXX(uniquefine): For now we just pick the first SNAP control plane.
                let cp = control_planes
                    .first()
                    // This will never happen because we checked that there is at least one.
                    .ok_or(BuildScionStackError::UnderlayUnavailable(
                        "no snap control plane provided".into(),
                    ))?;
                tracing::info!(%cp, "Using SNAP underlay");
                // We have SNAP data planes available, construct a SNAP underlay
                let default_scmp_handler = snap.default_scmp_handler.unwrap_or_else(|| {
                    Box::new(|tunnel| Arc::new(DefaultScmpHandler::new(tunnel)))
                });
                let mut snap_cp_client = CrpcSnapControlClient::new(&cp.address)
                    .map_err(BuildSnapScionStackError::ControlPlaneClientSetupError)?;
                if let Some(token_source) = snap.snap_token_source.or(auth_token_source) {
                    snap_cp_client.use_token_source(token_source);
                }
                let snap_cp_client = Arc::new(snap_cp_client);

                // Get data planes from the snap CP API
                let session_grants = snap_cp_client
                    .create_data_plane_sessions()
                    .await
                    .map_err(BuildSnapScionStackError::DataPlaneDiscoveryError)?;
                Arc::new(
                    SnapUnderlayStack::new(
                        snap_cp_client.clone(),
                        session_grants,
                        snap.requested_addresses,
                        snap.ports_rng.unwrap_or_else(ChaCha8Rng::from_os_rng),
                        snap.ports_reserved_time,
                        default_scmp_handler,
                        receive_channel_size,
                        snap.session_auto_renewal,
                    )
                    .await
                    .map_err(|e| {
                        match e {
                            NewSnapUnderlayStackError::SnapTunnelError(e) => {
                                BuildSnapScionStackError::DataPlaneConnectionError(e)
                            }
                            NewSnapUnderlayStackError::NoSessionGrants => {
                                BuildSnapScionStackError::DataPlaneUnavailable(
                                    "create data plane sessions returned no session grants".into(),
                                )
                            }
                        }
                    })?,
                )
            }
            DiscoveredUnderlays::Udp(data_planes) => {
                tracing::info!(?data_planes, "Using UDP underlay");
                let local_ip_resolver: Arc<dyn LocalIpResolver> = match udp.local_ips {
                    Some(ips) => Arc::new(ips),
                    None => {
                        Arc::new(
                            TargetAddrLocalIpResolver::new(endhost_api_url.clone())
                                .map_err(BuildUdpScionStackError::LocalIpResolutionError)?,
                        )
                    }
                };

                Arc::new(UdpUnderlayStack::new(
                    Arc::new(UdpUnderlayResolver::new(
                        endhost_api_client.clone(),
                        udp.udp_next_hop_resolver_fetch_interval,
                        data_planes
                            .into_iter()
                            .flat_map(|dp| {
                                dp.interfaces
                                    .into_iter()
                                    .map(move |i| ((dp.isd_as, i), dp.internal_interface))
                            })
                            .collect::<HashMap<(IsdAsn, u16), net::SocketAddr>>(),
                    )),
                    local_ip_resolver,
                    receive_channel_size,
                ))
            }
        };

        Ok(ScionStack::new(endhost_api_client, underlay))
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
    /// Error connecting to the SNAP data plane.
    #[error("error connecting to data plane: {0:#}")]
    DataPlaneConnectionError(#[from] SnapTunnelError),
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

enum Underlay {
    Discover {
        preferred_underlay: PreferredUnderlay,
        /// The ISD-AS to discover the underlay for.
        isd_as: IsdAsn,
    },
    Snap(Vec<Snap>),
    Udp(Vec<ScionRouter>),
}

/// SNAP underlay configuration.
pub struct SnapUnderlayConfig {
    snap_token_source: Option<Arc<dyn TokenSource>>,
    requested_addresses: Vec<EndhostAddr>,
    default_scmp_handler: Option<ScmpHandlerFactory>,
    snap_dp_index: usize,
    session_auto_renewal: SessionRenewal,
    tunnel_reconnect_backoff: BackoffConfig,
    ports_rng: Option<ChaCha8Rng>,
    ports_reserved_time: Duration,
}

impl Default for SnapUnderlayConfig {
    fn default() -> Self {
        Self {
            snap_token_source: None,
            requested_addresses: vec![],
            ports_reserved_time: DEFAULT_RESERVED_TIME,
            snap_dp_index: 0,
            default_scmp_handler: None,
            session_auto_renewal: SessionRenewal::default(),
            tunnel_reconnect_backoff: DEFAULT_SNAP_TUNNEL_RECONNECT_BACKOFF,
            ports_rng: None,
        }
    }
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
        self.0.snap_token_source = Some(Arc::new(token));
        self
    }

    /// Set a token source to use for authentication with the SNAP control plane.
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.0.snap_token_source = Some(Arc::new(source));
        self
    }

    /// Set the addresses to request from the SNAP server.
    /// Note, that the server may choose not to assign all requested addresses
    /// and may assign additional addresses.
    /// Use assigned_addresses() to get the final list of addresses.
    ///
    /// # Arguments
    ///
    /// * `requested_addresses` - The addresses to request from the SNAP server.
    pub fn with_requested_addresses(mut self, requested_addresses: Vec<EndhostAddr>) -> Self {
        self.0.requested_addresses = requested_addresses;
        self
    }

    /// Set the random number generator used for port allocation.
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator.
    pub fn with_ports_rng(mut self, rng: ChaCha8Rng) -> Self {
        self.0.ports_rng = Some(rng);
        self
    }

    /// Set how long ports are reserved after they are released.
    ///
    /// # Arguments
    ///
    /// * `reserved_time` - The reserved time for ports.
    pub fn with_ports_reserved_time(mut self, reserved_time: Duration) -> Self {
        self.0.ports_reserved_time = reserved_time;
        self
    }

    /// Set the default SCMP handler.
    ///
    /// # Arguments
    ///
    /// * `default_scmp_handler` - The default SCMP handler.
    pub fn with_default_scmp_handler(mut self, default_scmp_handler: ScmpHandlerFactory) -> Self {
        self.0.default_scmp_handler = Some(Box::new(default_scmp_handler));
        self
    }

    /// Set the automatic session renewal.
    ///
    /// # Arguments
    ///
    /// * `interval` - The interval before session expiry to wait before attempting renewal.
    pub fn with_session_auto_renewal(mut self, interval: Duration) -> Self {
        self.0.session_auto_renewal = SessionRenewal::new(interval);
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

    /// Set the parameters for the exponential backoff configuration for reconnecting a SNAP tunnel.
    ///
    /// # Arguments
    ///
    /// * `minimum_delay_secs` - The minimum delay in seconds.
    /// * `maximum_delay_secs` - The maximum delay in seconds.
    /// * `factor` - The factor to multiply the delay by.
    /// * `jitter_secs` - The jitter in seconds.
    pub fn with_tunnel_reconnect_backoff(
        mut self,
        minimum_delay_secs: Duration,
        maximum_delay_secs: Duration,
        factor: f32,
        jitter_secs: Duration,
    ) -> Self {
        self.0.tunnel_reconnect_backoff = BackoffConfig {
            minimum_delay_secs: minimum_delay_secs.as_secs_f32(),
            maximum_delay_secs: maximum_delay_secs.as_secs_f32(),
            factor,
            jitter_secs: jitter_secs.as_secs_f32(),
        };
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

#[derive(Debug)]
enum DiscoveredUnderlays {
    Snap(Vec<Snap>),
    Udp(Vec<ScionRouter>),
}

/// Helper function to discover data plane addresses from the control plane.
async fn discover_underlays(
    client: &dyn EndhostApiClient,
    preferred_underlay: PreferredUnderlay,
    isd_as: IsdAsn,
) -> Result<DiscoveredUnderlays, BuildScionStackError> {
    // Retrieve the data plane addresses using the control plane API
    let res = client
        .list_underlays(isd_as)
        .await
        .map_err(BuildScionStackError::UnderlayDiscoveryError)?;
    let (has_udp, has_snap) = (!res.udp_underlay.is_empty(), !res.snap_underlay.is_empty());

    match (has_udp, has_snap) {
        (true, true) => {
            match preferred_underlay {
                PreferredUnderlay::Snap => Ok(DiscoveredUnderlays::Snap(res.snap_underlay)),
                PreferredUnderlay::Udp => Ok(DiscoveredUnderlays::Udp(res.udp_underlay)),
            }
        }
        (true, false) => Ok(DiscoveredUnderlays::Udp(res.udp_underlay)),
        (false, true) => Ok(DiscoveredUnderlays::Snap(res.snap_underlay)),
        (false, false) => {
            Err(BuildScionStackError::UnderlayUnavailable(
                "discovery returned no underlay".into(),
            ))
        }
    }
}
