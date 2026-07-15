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

//! # The SCION endhost stack.
//!
//! [ScionStack] is a stateful object that is the conceptual equivalent of the
//! TCP/IP-stack found in today's common operating systems. It is meant to be
//! instantiated once per process.
//!
//! ## Basic Usage
//!
//! ### Creating a path-aware socket (recommended)
//!
//! ```
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
//! use url::Url;
//!
//! # async fn socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder = ScionStackBuilder::new().with_auth_token("SNAP token".to_string());
//!
//! let scion_stack = builder.build().await?;
//! let socket = scion_stack.bind(None).await?;
//!
//! // Parse destination address
//! let destination: ScionSocketIpAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;
//!
//! socket.send_to(b"hello", destination).await?;
//! let mut buffer = [0u8; 1024];
//! let (len, src) = socket.recv_from(&mut buffer).await?;
//! println!("Received: {:?} from {:?}", &buffer[..len], src);
//!
//! # Ok(())
//! # }
//! ```
//!
//! ### Creating a connected socket.
//!
//! ```
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
//! use url::Url;
//!
//! # async fn connected_socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder = ScionStackBuilder::new().with_auth_token("SNAP token".to_string());
//!
//! // Parse destination address
//! let destination: ScionSocketIpAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;
//!
//! let scion_stack = builder.build().await?;
//! let connected_socket = scion_stack.connect(destination, None).await?;
//! connected_socket.send(b"hello").await?;
//! let mut buffer = [0u8; 1024];
//! let len = connected_socket.recv(&mut buffer).await?;
//! println!("Received: {:?}", &buffer[..len]);
//!
//! # Ok(())
//! # }
//! ```
//!
//! ### Creating a path-unaware socket
//!
//! ```
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use sciparse::{address::ip_socket_addr::ScionSocketIpAddr, path::ScionPath};
//! use url::Url;
//!
//! # async fn basic_socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder = ScionStackBuilder::new().with_auth_token("SNAP token".to_string());
//!
//! // Parse addresses
//! let bind_addr: ScionSocketIpAddr = "1-ff00:0:110,[127.0.0.1]:8080".parse()?;
//! let destination: ScionSocketIpAddr = "1-ff00:0:111,[127.0.0.1]:9090".parse()?;
//!
//! // Create a local path for demonstration
//! let path = ScionPath::local(bind_addr.isd_asn()).expect("not a wildcard AS");
//!
//! let scion_stack = builder.build().await?;
//! let socket = scion_stack.bind_path_unaware(Some(bind_addr)).await?;
//! socket.send_to_via(b"hello", destination, &path).await?;
//! let mut buffer = [0u8; 1024];
//! let (len, sender) = socket.recv_from(&mut buffer).await?;
//! println!("Received: {:?} from {:?}", &buffer[..len], sender);
//!
//! # Ok(())
//! # }
//! ```
//!
//! ### Resolving SCION TXT records
//!
//! ```
//! use scion_stack::resolver::{ScionDnsResolver, txt::ScionTxtDnsResolver};
//!
//! # async fn resolve_example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = ScionTxtDnsResolver::new()?;
//! let addresses = resolver.resolve("example.com").await?;
//!
//! for address in addresses {
//!     println!("Resolved: {}", address);
//! }
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Advanced Usage
//!
//! ### Custom path selection
//!
//! ```
//! // Implement your own path selection logic
//! use std::{sync::Arc, time::Duration};
//!
//! use bytes::Bytes;
//! use chrono::{DateTime, Utc};
//! use scion_stack::{
//!     path::manager::traits::PathManager,
//!     scionstack::{ScionStack, ScionStackBuilder, UdpScionSocket},
//!     types::ResFut,
//! };
//! use sciparse::{
//!     address::ip_socket_addr::ScionSocketIpAddr, identifier::isd_asn::IsdAsn, path::ScionPath,
//! };
//!
//! struct MyCustomPathManager;
//!
//! impl scion_stack::path::manager::traits::SyncPathManager for MyCustomPathManager {
//!     fn register_path(&self, _src: IsdAsn, _dst: IsdAsn, _now: DateTime<Utc>, _path: ScionPath) {
//!         // Optionally implement registration logic
//!     }
//!
//!     fn try_cached_path(
//!         &self,
//!         _src: IsdAsn,
//!         _dst: IsdAsn,
//!         _now: DateTime<Utc>,
//!     ) -> std::io::Result<Option<ScionPath>> {
//!         todo!()
//!     }
//! }
//!
//! impl scion_stack::path::manager::traits::PathManager for MyCustomPathManager {
//!     fn path_wait(
//!         &self,
//!         src: IsdAsn,
//!         _dst: IsdAsn,
//!         _now: DateTime<Utc>,
//!     ) -> impl ResFut<'_, ScionPath, scion_stack::path::manager::traits::PathWaitError> {
//!         async move { Ok(ScionPath::local(src).expect("not a wildcard AS")) }
//!     }
//! }
//!
//! # async fn custom_pather_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder = ScionStackBuilder::new()
//!     .with_endhost_api(control_plane_addr)
//!     .with_auth_token("SNAP token".to_string());
//!
//! // Parse addresses
//! let bind_addr: ScionSocketIpAddr = "1-ff00:0:110,[127.0.0.1]:8080".parse()?;
//! let destination: ScionSocketIpAddr = "1-ff00:0:111,[127.0.0.1]:9090".parse()?;
//!
//! let scion_stack = builder.build().await?;
//! let path_unaware_socket = scion_stack.bind_path_unaware(Some(bind_addr)).await?;
//! let socket = UdpScionSocket::new(
//!     path_unaware_socket,
//!     Arc::new(MyCustomPathManager),
//!     Duration::from_secs(30),
//!     scion_stack::types::Subscribers::new(),
//! );
//! socket.send_to(b"hello", destination).await?;
//!
//! # Ok(())
//! # }
//! ```

pub mod builder;
pub mod scmp_handler;
pub mod socket;

use std::{borrow::Cow, fmt, net, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::future::BoxFuture;
use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use sciparse::{
    address::ip_socket_addr::ScionSocketIpAddr,
    identifier::{isd::Isd, isd_asn::IsdAsn},
    packet::view::ScionRawPacketView,
};
use snap_tun::client::ConnectSnapTunSocketError;
pub use socket::{PathUnawareUdpScionSocket, RawScionSocket, ScmpScionSocket, UdpScionSocket};
use url::Url;

// Re-export the main types from the modules
pub use self::builder::ScionStackBuilder;
use crate::{
    path::{
        PathStrategy,
        fetcher::{PathFetcherImpl, traits::SegmentFetcher},
        manager::{
            MultiPathManager, MultiPathManagerConfig,
            traits::{PathWaitError, PathWaitTimeoutError},
        },
        policy::PathPolicy,
        scoring::PathScoring,
    },
    scionstack::{
        scmp_handler::{ScmpErrorHandler, ScmpErrorReceiver},
        socket::SendErrorReceiver,
    },
    types::Subscribers,
};

/// The SCION stack can be used to create path-aware SCION sockets or even Quic over SCION
/// connections.
///
/// The SCION stack abstracts over the underlay stack that is used for the underlying
/// transport.
pub struct ScionStack {
    endhost_api: Option<Url>,
    default_segment_fetcher: Arc<dyn SegmentFetcher>,
    underlay: Arc<dyn DynUnderlayStack>,
    scmp_error_receivers: Subscribers<dyn ScmpErrorReceiver>,
    send_error_receivers: Subscribers<dyn SendErrorReceiver>,
}

impl fmt::Debug for ScionStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScionStack")
            .field("endhost_api", &self.endhost_api)
            .finish()
    }
}

impl ScionStack {
    pub(crate) fn new(
        endhost_api: Option<Url>,
        default_segment_fetcher: Arc<dyn SegmentFetcher>,
        underlay: Arc<dyn DynUnderlayStack>,
    ) -> Self {
        Self {
            endhost_api,
            default_segment_fetcher,
            underlay,
            scmp_error_receivers: Subscribers::new(),
            send_error_receivers: Subscribers::new(),
        }
    }

    /// Create a path-aware SCION socket with automatic path management.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    ///
    /// # Returns
    /// A path-aware SCION socket.
    pub async fn bind(
        &self,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<UdpScionSocket, ScionSocketBindError> {
        self.bind_with_config(bind_addr, SocketConfig::default())
            .await
    }

    /// Create a path-aware SCION socket with custom configuration.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    /// * `socket_config` - Configuration for the socket.
    ///
    /// # Returns
    /// A path-aware SCION socket.
    pub async fn bind_with_config(
        &self,
        bind_addr: Option<ScionSocketIpAddr>,
        mut socket_config: SocketConfig,
    ) -> Result<UdpScionSocket, ScionSocketBindError> {
        let socket = PathUnawareUdpScionSocket::new(
            self.underlay
                .bind_socket(SocketKind::Udp, bind_addr)
                .await?,
            vec![Box::new(ScmpErrorHandler::new(
                self.scmp_error_receivers.clone(),
            ))],
        );

        if !socket_config.disable_default_segment_fetcher {
            socket_config
                .segment_fetchers
                .push(("Endhost API".into(), self.default_segment_fetcher.clone()));
        }
        let fetcher = PathFetcherImpl::new(
            socket_config.segment_fetchers,
            socket_config.segment_fetcher_timeout,
        );

        // Use default scorers if none are configured.
        if socket_config.path_strategy.scoring.is_empty() {
            socket_config.path_strategy.scoring.use_default_scorers();
        }

        let pather = Arc::new(
            MultiPathManager::new(
                MultiPathManagerConfig::default(),
                fetcher,
                socket_config.path_strategy,
            )
            .expect("should not fail with default configuration"),
        );

        // Register the path manager as a SCMP error receiver and send error receiver.
        self.scmp_error_receivers.register(pather.clone());
        self.send_error_receivers.register(pather.clone());

        Ok(UdpScionSocket::new(
            socket,
            pather,
            socket_config.connect_timeout,
            self.send_error_receivers.clone(),
        ))
    }

    /// Create a connected path-aware SCION socket with automatic path management.
    ///
    /// # Arguments
    /// * `remote_addr` - The remote address to connect to.
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    ///
    /// # Returns
    /// A connected path-aware SCION socket.
    pub async fn connect(
        &self,
        remote_addr: ScionSocketIpAddr,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<UdpScionSocket, ScionSocketConnectError> {
        let socket = self.bind(bind_addr).await?;
        socket.connect(remote_addr).await
    }

    /// Create a connected path-aware SCION socket with custom configuration.
    ///
    /// # Arguments
    /// * `remote_addr` - The remote address to connect to.
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    /// * `socket_config` - Configuration for the socket
    ///
    /// # Returns
    /// A connected path-aware SCION socket.
    pub async fn connect_with_config(
        &self,
        remote_addr: ScionSocketIpAddr,
        bind_addr: Option<ScionSocketIpAddr>,
        socket_config: SocketConfig,
    ) -> Result<UdpScionSocket, ScionSocketConnectError> {
        let socket = self.bind_with_config(bind_addr, socket_config).await?;
        socket.connect(remote_addr).await
    }

    /// Create a socket that can send and receive SCMP messages.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    ///
    /// # Returns
    /// A SCMP socket.
    pub async fn bind_scmp(
        &self,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<ScmpScionSocket, ScionSocketBindError> {
        let socket = self
            .underlay
            .bind_socket(SocketKind::Scmp, bind_addr)
            .await?;
        Ok(ScmpScionSocket::new(socket))
    }

    /// Create a raw SCION socket.
    /// A raw SCION socket can be used to send and receive raw SCION packets.
    /// It is still bound to a specific UDP port because this is needed for packets
    /// to be routed in a dispatcherless autonomous system. See <https://docs.scion.org/en/latest/dev/design/router-port-dispatch.html> for a more detailed explanation.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    ///
    /// # Returns
    /// A raw SCION socket.
    pub async fn bind_raw(
        &self,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<RawScionSocket, ScionSocketBindError> {
        let socket = self
            .underlay
            .bind_socket(SocketKind::Raw, bind_addr)
            .await?;
        Ok(RawScionSocket::new(socket))
    }

    /// Create a path-unaware SCION socket for advanced use cases.
    ///
    /// This socket can send and receive datagrams, but requires explicit paths for sending.
    /// Use this when you need full control over path selection.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    ///
    /// # Returns
    /// A path-unaware SCION socket.
    pub async fn bind_path_unaware(
        &self,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> Result<PathUnawareUdpScionSocket, ScionSocketBindError> {
        let socket = self
            .underlay
            .bind_socket(SocketKind::Udp, bind_addr)
            .await?;

        Ok(PathUnawareUdpScionSocket::new(socket, vec![]))
    }

    /// Get the list of local ISD-ASes available on the endhost.
    ///
    /// # Returns
    ///
    /// A list of local ISD-AS identifiers.
    pub fn local_ases(&self) -> Vec<IsdAsn> {
        self.underlay.local_ases()
    }

    /// Get the currently selected endhost API URL, if any.
    pub fn endhost_api(&self) -> Option<Url> {
        self.endhost_api.clone()
    }

    /// Creates a path manager with default configuration.
    pub fn create_path_manager(&self) -> MultiPathManager<PathFetcherImpl> {
        let fetcher = PathFetcherImpl::new(
            vec![("Endhost API".into(), self.default_segment_fetcher.clone())],
            DEFAULT_SEGMENT_FETCHER_TIMEOUT,
        );
        let mut strategy = PathStrategy::default();

        strategy.scoring.use_default_scorers();

        MultiPathManager::new(MultiPathManagerConfig::default(), fetcher, strategy)
            .expect("should not fail with default configuration")
    }

    /// Creates a path fetcher with default configuration.
    ///
    /// A [`PathFetcher`](crate::path::fetcher::traits::PathFetcher) exposes the *set* of paths to a
    /// destination, whereas the socket (via the path manager returned by
    /// [`create_path_manager`](Self::create_path_manager)) automatically selects one. Use this when
    /// the application wants to inspect the available paths and choose one deliberately, then send
    /// over it with [`send_to_via`](crate::scionstack::UdpScionSocket::send_to_via).
    ///
    /// ```no_run
    /// use scion_stack::{path::fetcher::traits::PathFetcher, scionstack::ScionStackBuilder};
    /// use sciparse::identifier::isd_asn::IsdAsn;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let stack = ScionStackBuilder::new().build().await?;
    /// let src: IsdAsn = "1-ff00:0:110".parse()?;
    /// let dst: IsdAsn = "2-ff00:0:222".parse()?;
    ///
    /// let paths = stack.create_path_fetcher().fetch_paths(src, dst).await?;
    /// for path in &paths {
    ///     println!("{path}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_path_fetcher(&self) -> PathFetcherImpl {
        PathFetcherImpl::new(
            vec![("Endhost API".into(), self.default_segment_fetcher.clone())],
            DEFAULT_SEGMENT_FETCHER_TIMEOUT,
        )
    }
}

/// Default timeout for creating a connected socket
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for segment fetchers to avoid waiting indefinitely for slow or unresponsive
/// fetchers.
pub const DEFAULT_SEGMENT_FETCHER_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for a path aware socket.
pub struct SocketConfig {
    pub(crate) segment_fetchers: Vec<(String, Arc<dyn SegmentFetcher>)>,
    pub(crate) segment_fetcher_timeout: Duration,
    pub(crate) disable_default_segment_fetcher: bool,
    pub(crate) path_strategy: PathStrategy,
    pub(crate) connect_timeout: Duration,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketConfig {
    /// Creates a new default socket configuration.
    pub fn new() -> Self {
        Self {
            segment_fetchers: Vec::new(),
            segment_fetcher_timeout: DEFAULT_SEGMENT_FETCHER_TIMEOUT,
            disable_default_segment_fetcher: false,
            path_strategy: Default::default(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Adds a path policy.
    ///
    /// Path policies can restrict the set of usable paths based on their characteristics.
    /// E.g. filtering out paths that go through certain ASes.
    ///
    /// See [`HopPatternPolicy`](sciparse::path::policy::hop_pattern::HopPatternPolicy) and
    /// [`AclPolicy`](sciparse::path::policy::acl::AclPolicy)
    pub fn with_path_policy(mut self, policy: impl PathPolicy) -> Self {
        self.path_strategy.add_policy(policy);
        self
    }

    /// Add a path scoring strategy.
    ///
    /// Path scores signal which paths to prioritize based on their characteristics.
    ///
    /// `scoring` - The path scoring strategy to add.
    /// `impact` - The impact weight of the scoring strategy. Higher values increase the influence
    ///
    /// If no scoring strategies are added, scoring defaults to preferring shorter and more reliable
    /// paths.
    pub fn with_path_scoring(mut self, scoring: impl PathScoring, impact: f32) -> Self {
        self.path_strategy.scoring = self.path_strategy.scoring.with_scorer(scoring, impact);
        self
    }

    /// Sets connection timeout for `connect` functions
    ///
    /// Defaults to [DEFAULT_CONNECT_TIMEOUT]
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Add an additional segment fetcher.
    ///
    /// By default, only path segments retrieved via the default segment fetcher are used. Adding
    /// additional segment fetchers enables to build paths from different segment sources.
    pub fn with_segment_fetcher(mut self, name: String, fetcher: Arc<dyn SegmentFetcher>) -> Self {
        self.segment_fetchers.push((name, fetcher));
        self
    }

    /// Disable fetching path segments from the default segment fetcher.
    pub fn disable_default_segment_fetcher(mut self) -> Self {
        self.disable_default_segment_fetcher = true;
        self
    }

    /// Sets the segment fetcher timeout. The timeout prevents waiting indefinitely for slow or
    /// unresponsive segment fetchers. If a fetcher does not respond within the timeout, it will be
    /// skipped for the current path lookup.
    ///
    /// Defaults to [DEFAULT_SEGMENT_FETCHER_TIMEOUT].
    pub fn with_segment_fetcher_timeout(mut self, timeout: Duration) -> Self {
        self.segment_fetcher_timeout = timeout;
        self
    }
}

/// Error return when binding a socket.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketBindError {
    /// The provided bind address cannot be bound to.
    /// E.g. because it is not assigned to the endhost or because the address
    /// type is not supported.
    #[error(transparent)]
    InvalidBindAddress(InvalidBindAddressError),
    /// The provided port is already in use.
    #[error("port {0} is already in use")]
    PortAlreadyInUse(u16),
    /// Failed to connect to SNAP data plane.
    #[error(transparent)]
    SnapConnectionError(SnapConnectionError),
    /// No underlay available to bind the requested address.
    #[error("underlay unavailable for the requested ISD: {0}")]
    NoUnderlayAvailable(Isd),
    /// An error that is not covered by the variants above.
    #[error("other error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Error related to the bind address of the socket.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvalidBindAddressError {
    /// The requested bind address cannot be bound to.
    #[error("cannot bind to requested address: {0}")]
    CannotBindToRequestedAddress(ScionSocketIpAddr, Cow<'static, str>),
    /// The assigned address does not match the requested address.
    /// This is likely due to NAT.
    #[error(
        "assigned address ({assigned_addr}) does not match requested address ({bind_addr}), likely due to NAT"
    )]
    AddressMismatch {
        /// The assigned address.
        assigned_addr: ScionSocketIpAddr,
        /// The requested bind address.
        bind_addr: ScionSocketIpAddr,
    },
    /// Could not find any local IP address to bind to.
    #[error("could not find any local IP address to bind to")]
    NoLocalIpAddressFound,
}

/// Error related to the connection to the SNAP data plane.
#[derive(Debug, thiserror::Error)]
pub enum SnapConnectionError {
    /// Snap sockets cannot be bound without a SNAP token source.
    #[error("SNAP token source is missing")]
    SnapTokenSourceMissing,
    /// Error establishing the SNAP tunnel.
    #[error("error establishing SNAP tunnel: {0}")]
    TunnelEstablishmentError(#[from] ConnectSnapTunSocketError),
    /// Failed to create the SNAP control plane client.
    #[error("failed to create SNAP control plane client: {0}")]
    ControlPlaneClientCreationError(anyhow::Error),
    /// Failed to discover the SNAP data plane.
    #[error("failed to discover SNAP data plane: {0}")]
    DataPlaneDiscoveryError(CrpcClientError),
}

/// Available kinds of SCION sockets.
#[derive(Hash, Eq, PartialEq, Clone, Debug, Ord, PartialOrd)]
pub enum SocketKind {
    /// UDP socket.
    Udp,
    /// SCMP socket.
    Scmp,
    /// Raw socket.
    Raw,
}
/// A trait that defines the underlay stack.
///
/// The underlay stack is the underlying transport layer that is used to send and receive SCION
/// packets. Sockets returned by the underlay stack have no path management but allow
/// sending and receiving SCION packets.
pub(crate) trait DynUnderlayStack: Send + Sync {
    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<ScionSocketIpAddr>,
    ) -> BoxFuture<'_, Result<BoundUnderlaySocket, ScionSocketBindError>>;

    fn local_ases(&self) -> Vec<IsdAsn>;
}

/// An underlay socket together with the metadata resolved when it was bound.
///
/// The [`local_addr`](Self::local_addr) and [`snap_data_plane`](Self::snap_data_plane) are fixed at
/// bind time and are therefore carried here rather than being queried on every call through the
/// [`UnderlaySocket`] trait.
pub(crate) struct BoundUnderlaySocket {
    /// The underlay socket.
    pub socket: Box<dyn UnderlaySocket>,
    /// The local SCION address the socket is bound to.
    pub local_addr: ScionSocketIpAddr,
    /// The SNAP data plane the socket is connected to, if a SNAP underlay is used.
    pub snap_data_plane: Option<net::SocketAddr>,
}

/// SCION socket connect errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketConnectError {
    /// Could not get a path to the destination
    #[error("failed to get path to destination: {0}")]
    PathLookupError(#[from] PathWaitTimeoutError),
    /// Could not bind the socket
    #[error(transparent)]
    BindError(#[from] ScionSocketBindError),
}

/// SCION socket send errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketSendError {
    /// There was an error looking up the path in the path registry.
    #[error("path lookup error: {0}")]
    PathLookupError(#[from] PathWaitError),
    /// UDP underlay next hop unreachable. This is only
    /// returned if the selected underlay is UDP.
    #[error("udp next hop {address:?} unreachable: {isd_as}#{interface_id}: {msg}")]
    UnderlayNextHopUnreachable {
        /// ISD-AS of the next hop.
        isd_as: IsdAsn,
        /// Interface ID of the next hop.
        interface_id: u16,
        /// Address of the next hop, if known.
        address: Option<net::SocketAddr>,
        /// Additional message.
        msg: String,
    },
    /// The provided packet is invalid. The underlying socket is
    /// not able to process the packet.
    #[error("invalid packet: {0}")]
    InvalidPacket(Cow<'static, str>),
    /// The underlying socket is closed.
    #[error("underlying socket is closed")]
    Closed,
    /// IO Error from the underlying connection.
    #[error("underlying connection returned an I/O error: {0:?}")]
    IoError(#[from] std::io::Error),
    /// Error return when send is called on a socket that is not connected.
    #[error("socket is not connected")]
    NotConnected,
}

/// Minimum size of the path buffer required by [`ScionSocketReceiveError::PathBufTooSmall`].
///
/// This constant can be used to allocate a correctly-sized path buffer when calling
/// [`UdpScionSocket::recv_from_with_path`](crate::scionstack::UdpScionSocket::recv_from_with_path)
/// or the corresponding method on [`PathUnawareUdpScionSocket`].
pub const MIN_PATH_BUFFER_SIZE: usize = 1024;

/// SCION socket receive errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketReceiveError {
    /// Path buffer too small.
    #[error("provided path buffer is too small (at least {MIN_PATH_BUFFER_SIZE} bytes required)")]
    PathBufTooSmall,
    /// I/O error.
    #[error("i/o error: {0:?}")]
    IoError(#[from] std::io::Error),
    /// Error return when recv is called on a socket that is not connected.
    #[error("socket is not connected")]
    NotConnected,
}

/// The maximum size in bytes of a raw SCION packet handled by the underlay.
///
/// This is large enough to hold any UDP datagram and can be used to size a receive buffer passed to
/// [`UnderlaySocket::try_recv`].
pub(crate) const MAX_UNDERLAY_PACKET_SIZE: usize = 65535;

/// A trait that defines an abstraction over an underlay socket.
///
/// The socket sends and receives raw SCION packets. Decoding of the next layer protocol or SCMP
/// handling is left to the caller.
///
/// The core operations [`try_send`](Self::try_send) and [`try_recv`](Self::try_recv) are
/// synchronous and non-blocking, so the socket can be driven from non-`async` code. The
/// [`writeable`](Self::writeable) and [`readable`](Self::readable) readiness notifications are
/// `async`. Blocking-style `send`/`recv` helpers are layered on top by the [`UnderlaySocketExt`]
/// extension trait, so implementors only provide the core primitives. Receiving is zero-copy into a
/// caller-owned buffer: `try_recv` writes the packet into `buf` and returns its length, so the
/// underlay never hides an allocation.
#[async_trait]
pub(crate) trait UnderlaySocket: 'static + Send + Sync {
    /// Attempts to send the raw packet in its entirety.
    ///
    /// Returns an error if the underlying socket is not ready to send, or if another error occurs.
    /// A socket that is not ready reports [`ScionSocketSendError::IoError`] with
    /// [`std::io::ErrorKind::WouldBlock`].
    ///
    /// Takes a [`ScionRawPacketView`] because it needs to read the path to resolve the underlay
    /// next hop.
    fn try_send(&self, packet: &ScionRawPacketView) -> Result<(), ScionSocketSendError>;

    /// Resolves once the underlying socket is ready to send.
    ///
    /// A wakeup does not guarantee that the next call to [`try_send`](Self::try_send) will succeed,
    /// as the socket may have become not ready again in the meantime. The caller should call
    /// `try_send` again after this future resolves.
    async fn writeable(&self);

    /// Attempts to receive a raw SCION packet into `buf`, returning the number of bytes written.
    ///
    /// On success the packet occupies `buf[..n]` and is guaranteed to decode with
    /// [`ScionRawPacketView::try_from_slice`]. Returns an error if the underlying socket is not
    /// ready to receive, or if another error occurs. A socket that is not ready reports
    /// [`ScionSocketReceiveError::IoError`] with [`std::io::ErrorKind::WouldBlock`].
    fn try_recv(&self, buf: &mut [u8]) -> Result<usize, ScionSocketReceiveError>;

    /// Resolves once the underlying socket is ready to receive.
    ///
    /// A wakeup does not guarantee that the next call to [`try_recv`](Self::try_recv) will succeed,
    /// as the socket may have become not ready again in the meantime. The caller should call
    /// `try_recv` again after this future resolves.
    async fn readable(&self);
}

/// Blocking-style convenience methods layered on top of [`UnderlaySocket`].
///
/// This is blanket-implemented for every [`UnderlaySocket`], so implementors only ever provide the
/// core primitives while callers get [`send`](Self::send)/[`recv`](Self::recv) built on top of
/// them.
#[async_trait]
pub(crate) trait UnderlaySocketExt: UnderlaySocket {
    /// Sends the raw packet, waiting for the socket to become writeable if necessary.
    ///
    /// Takes a [`ScionRawPacketView`] because it needs to read the path to resolve the underlay
    /// next hop.
    async fn send(&self, packet: &ScionRawPacketView) -> Result<(), ScionSocketSendError>;

    /// Receives a raw SCION packet into `buf`, waiting for the socket to become readable if
    /// necessary. Returns the number of bytes written; the packet occupies `buf[..n]`.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, ScionSocketReceiveError>;
}

#[async_trait]
impl<T: UnderlaySocket + ?Sized> UnderlaySocketExt for T {
    async fn send(&self, packet: &ScionRawPacketView) -> Result<(), ScionSocketSendError> {
        loop {
            match self.try_send(packet) {
                Err(ScionSocketSendError::IoError(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    self.writeable().await;
                }
                result => return result,
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, ScionSocketReceiveError> {
        loop {
            match self.try_recv(buf) {
                Err(ScionSocketReceiveError::IoError(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    self.readable().await;
                }
                result => return result,
            }
        }
    }
}

impl Drop for ScionStack {
    fn drop(&mut self) {
        tracing::warn!("ScionStack was dropped");
    }
}
