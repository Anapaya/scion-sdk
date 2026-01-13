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
//! use scion_proto::address::SocketAddr;
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use url::Url;
//!
//! # async fn socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder =
//!     ScionStackBuilder::new(control_plane_addr).with_auth_token("SNAP token".to_string());
//!
//! let scion_stack = builder.build().await?;
//! let socket = scion_stack.bind(None).await?;
//!
//! // Parse destination address
//! let destination: SocketAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;
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
//! use scion_proto::address::SocketAddr;
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use url::Url;
//!
//! # async fn connected_socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder =
//!     ScionStackBuilder::new(control_plane_addr).with_auth_token("SNAP token".to_string());
//!
//! // Parse destination address
//! let destination: SocketAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;
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
//! use scion_proto::{address::SocketAddr, path::Path};
//! use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
//! use url::Url;
//!
//! # async fn basic_socket_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder =
//!     ScionStackBuilder::new(control_plane_addr).with_auth_token("SNAP token".to_string());
//!
//! // Parse addresses
//! let bind_addr: SocketAddr = "1-ff00:0:110,[127.0.0.1]:8080".parse()?;
//! let destination: SocketAddr = "1-ff00:0:111,[127.0.0.1]:9090".parse()?;
//!
//! // Create a local path for demonstration
//! let path: scion_proto::path::Path<bytes::Bytes> = Path::local(bind_addr.isd_asn());
//!
//! let scion_stack = builder.build().await?;
//! let socket = scion_stack.bind_path_unaware(Some(bind_addr)).await?;
//! socket
//!     .send_to_via(b"hello", destination, &path.to_slice_path())
//!     .await?;
//! let mut buffer = [0u8; 1024];
//! let (len, sender) = socket.recv_from(&mut buffer).await?;
//! println!("Received: {:?} from {:?}", &buffer[..len], sender);
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
//! use scion_proto::{
//!     address::{IsdAsn, SocketAddr},
//!     path::Path,
//! };
//! use scion_stack::{
//!     path::manager::traits::PathManager,
//!     scionstack::{ScionStack, ScionStackBuilder, UdpScionSocket},
//!     types::ResFut,
//! };
//!
//! struct MyCustomPathManager;
//!
//! impl scion_stack::path::manager::traits::SyncPathManager for MyCustomPathManager {
//!     fn register_path(
//!         &self,
//!         _src: IsdAsn,
//!         _dst: IsdAsn,
//!         _now: DateTime<Utc>,
//!         _path: Path<Bytes>,
//!     ) {
//!         // Optionally implement registration logic
//!     }
//!
//!     fn try_cached_path(
//!         &self,
//!         _src: IsdAsn,
//!         _dst: IsdAsn,
//!         _now: DateTime<Utc>,
//!     ) -> std::io::Result<Option<Path<Bytes>>> {
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
//!     ) -> impl ResFut<'_, Path<Bytes>, scion_stack::path::manager::traits::PathWaitError>
//!     {
//!         async move { Ok(Path::local(src)) }
//!     }
//! }
//!
//! # async fn custom_pather_example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a SCION stack builder
//! let control_plane_addr: url::Url = "http://127.0.0.1:1234".parse()?;
//! let builder =
//!     ScionStackBuilder::new(control_plane_addr).with_auth_token("SNAP token".to_string());
//!
//! // Parse addresses
//! let bind_addr: SocketAddr = "1-ff00:0:110,[127.0.0.1]:8080".parse()?;
//! let destination: SocketAddr = "1-ff00:0:111,[127.0.0.1]:9090".parse()?;
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
pub mod quic;
pub mod scmp_handler;
pub mod socket;
pub(crate) mod udp_polling;

use std::{
    borrow::Cow,
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Context as _;
use bytes::Bytes;
use endhost_api_client::client::EndhostApiClient;
use futures::future::BoxFuture;
use quic::{AddressTranslator, Endpoint, ScionAsyncUdpSocket};
use scion_proto::{
    address::{IsdAsn, SocketAddr},
    packet::ScionPacketRaw,
    path::Path,
};
pub use socket::{PathUnawareUdpScionSocket, RawScionSocket, ScmpScionSocket, UdpScionSocket};

// Re-export the main types from the modules
pub use self::builder::ScionStackBuilder;
use crate::{
    path::{
        PathStrategy,
        fetcher::{ConnectRpcSegmentFetcher, PathFetcherImpl},
        manager::{MultiPathManager, MultiPathManagerConfig},
        policy::PathPolicy,
        scoring::PathScoring,
    },
    scionstack::{
        scmp_handler::{ScmpErrorHandler, ScmpErrorReceiver, ScmpHandler},
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
    client: Arc<dyn EndhostApiClient>,
    underlay: Arc<dyn DynUnderlayStack>,
    scmp_error_receivers: Subscribers<dyn ScmpErrorReceiver>,
    send_error_receivers: Subscribers<dyn SendErrorReceiver>,
}

impl fmt::Debug for ScionStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScionStack")
            .field("client", &"Arc<ConnectRpcClient>")
            .field("underlay", &"Arc<dyn DynUnderlayStack>")
            .finish()
    }
}

impl ScionStack {
    pub(crate) fn new(
        client: Arc<dyn EndhostApiClient>,
        underlay: Arc<dyn DynUnderlayStack>,
    ) -> Self {
        Self {
            client,
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
        bind_addr: Option<SocketAddr>,
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
        bind_addr: Option<SocketAddr>,
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
        let fetcher = PathFetcherImpl::new(ConnectRpcSegmentFetcher::new(self.client.clone()));

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
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
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
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
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
        bind_addr: Option<SocketAddr>,
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
        bind_addr: Option<SocketAddr>,
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
        bind_addr: Option<SocketAddr>,
    ) -> Result<PathUnawareUdpScionSocket, ScionSocketBindError> {
        let socket = self
            .underlay
            .bind_socket(SocketKind::Udp, bind_addr)
            .await?;

        Ok(PathUnawareUdpScionSocket::new(socket, vec![]))
    }

    /// Create a QUIC over SCION endpoint.
    ///
    /// This is a convenience method that creates a QUIC (quinn) endpoint over a SCION socket.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    /// * `config` - The quinn endpoint configuration.
    /// * `server_config` - The quinn server configuration.
    /// * `runtime` - The runtime to spawn tasks on.
    ///
    /// # Returns
    /// A QUIC endpoint that can be used to accept or create QUIC connections.
    pub async fn quic_endpoint(
        &self,
        bind_addr: Option<SocketAddr>,
        config: quinn::EndpointConfig,
        server_config: Option<quinn::ServerConfig>,
        runtime: Option<Arc<dyn quinn::Runtime>>,
    ) -> anyhow::Result<Endpoint> {
        self.quic_endpoint_with_config(
            bind_addr,
            config,
            server_config,
            runtime,
            SocketConfig::default(),
        )
        .await
    }

    /// Create a QUIC over SCION endpoint using custom socket configuration.
    ///
    /// This is a convenience method that creates a QUIC (quinn) endpoint over a SCION socket.
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind the socket to. If None, an available address will be
    ///   used.
    /// * `config` - The quinn endpoint configuration.
    /// * `server_config` - The quinn server configuration.
    /// * `runtime` - The runtime to spawn tasks on.
    /// * `socket_config` - Scion Socket configuration
    ///
    /// # Returns
    /// A QUIC endpoint that can be used to accept or create QUIC connections.
    pub async fn quic_endpoint_with_config(
        &self,
        bind_addr: Option<SocketAddr>,
        config: quinn::EndpointConfig,
        server_config: Option<quinn::ServerConfig>,
        runtime: Option<Arc<dyn quinn::Runtime>>,
        socket_config: SocketConfig,
    ) -> anyhow::Result<Endpoint> {
        let scmp_handlers: Vec<Box<dyn ScmpHandler>> = vec![Box::new(ScmpErrorHandler::new(
            self.scmp_error_receivers.clone(),
        ))];
        let socket = self
            .underlay
            .bind_async_udp_socket(bind_addr, scmp_handlers)
            .await?;
        let address_translator = Arc::new(AddressTranslator::default());

        let pather = {
            let fetcher = PathFetcherImpl::new(ConnectRpcSegmentFetcher::new(self.client.clone()));

            // Use default scorers if none are configured.
            let mut strategy = socket_config.path_strategy;
            if strategy.scoring.is_empty() {
                strategy.scoring.use_default_scorers();
            }

            Arc::new(
                MultiPathManager::new(MultiPathManagerConfig::default(), fetcher, strategy)
                    .map_err(|e| anyhow::anyhow!("failed to create path manager: {}", e))?,
            )
        };

        // Register the path manager as a SCMP error receiver.
        self.scmp_error_receivers.register(pather.clone());

        let local_scion_addr = socket.local_addr();

        let socket = Arc::new(ScionAsyncUdpSocket::new(
            socket,
            pather.clone(),
            address_translator.clone(),
        ));

        let runtime = match runtime {
            Some(runtime) => runtime,
            None => quinn::default_runtime().context("No runtime found")?,
        };

        Ok(Endpoint::new_with_abstract_socket(
            config,
            server_config,
            socket,
            local_scion_addr,
            runtime,
            pather,
            address_translator,
        )?)
    }

    /// Get the list of local ISD-ASes available on the endhost.
    ///
    /// # Returns
    ///
    /// A list of local ISD-AS identifiers.
    pub fn local_ases(&self) -> Vec<IsdAsn> {
        self.underlay.local_ases()
    }

    /// Creates a path manager with default configuration.
    pub fn create_path_manager(&self) -> MultiPathManager {
        let fetcher = PathFetcherImpl::new(ConnectRpcSegmentFetcher::new(self.client.clone()));
        let mut strategy = PathStrategy::default();

        strategy.scoring.use_default_scorers();

        MultiPathManager::new(MultiPathManagerConfig::default(), fetcher, strategy)
            .expect("should not fail with default configuration")
    }
}

/// Default timeout for creating a connected socket
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for a path aware socket.
#[derive(Default)]
pub struct SocketConfig {
    pub(crate) path_strategy: PathStrategy,
    pub(crate) connect_timeout: Duration,
}

impl SocketConfig {
    /// Creates a new default socket configuration.
    pub fn new() -> Self {
        Self {
            path_strategy: Default::default(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Adds a path policy.
    ///
    /// Path policies can restrict the set of usable paths based on their characteristics.
    /// E.g. filtering out paths that go through certain ASes.
    ///
    /// See [`HopPatternPolicy`](scion_proto::path::policy::hop_pattern::HopPatternPolicy) and
    /// [`AclPolicy`](scion_proto::path::policy::acl::AclPolicy)
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
}

/// Error return when binding a socket.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketBindError {
    /// The provided bind address cannot be bount to.
    /// E.g. because it is not assigned to the endhost or because the address
    /// type is not supported.
    #[error("invalid bind address {0}: {1}")]
    InvalidBindAddress(SocketAddr, String),
    /// The provided port is already in use.
    #[error("port {0} is already in use")]
    PortAlreadyInUse(u16),
    /// Failed to connect to SNAP data plane.
    #[error("SNAP data plane connection failed: {0}")]
    DataplaneError(Cow<'static, str>),
    /// No underlay available to bind the requested address.
    #[error("underlay unavailable: {0}")]
    UnderlayUnavailable(Cow<'static, str>),
    /// An error that is not covered by the variants above.
    #[error("other error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
    /// Internal error.
    #[error(
        "internal error in the SCION stack, this should never happen, please report this to the developers: {0}"
    )]
    Internal(String),
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
pub(crate) trait UnderlayStack: Send + Sync {
    type Socket: UnderlaySocket + 'static;
    type AsyncUdpSocket: AsyncUdpUnderlaySocket + 'static;

    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Self::Socket, ScionSocketBindError>>;

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<SocketAddr>,
        scmp_handlers: Vec<Box<dyn ScmpHandler>>,
    ) -> BoxFuture<'_, Result<Self::AsyncUdpSocket, ScionSocketBindError>>;

    /// Get the list of local ISD-ASes available on the endhost.
    fn local_ases(&self) -> Vec<IsdAsn>;
}

/// Dyn safe trait for an underlay stack.
pub(crate) trait DynUnderlayStack: Send + Sync {
    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Box<dyn UnderlaySocket>, ScionSocketBindError>>;

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<SocketAddr>,
        scmp_handlers: Vec<Box<dyn ScmpHandler>>,
    ) -> BoxFuture<'_, Result<Arc<dyn AsyncUdpUnderlaySocket>, ScionSocketBindError>>;

    fn local_ases(&self) -> Vec<IsdAsn>;
}

impl<U: UnderlayStack> DynUnderlayStack for U {
    fn bind_socket(
        &self,
        kind: SocketKind,
        bind_addr: Option<SocketAddr>,
    ) -> BoxFuture<'_, Result<Box<dyn UnderlaySocket>, ScionSocketBindError>> {
        Box::pin(async move {
            let socket = self.bind_socket(kind, bind_addr).await?;
            Ok(Box::new(socket) as Box<dyn UnderlaySocket>)
        })
    }

    fn bind_async_udp_socket(
        &self,
        bind_addr: Option<SocketAddr>,
        scmp_handlers: Vec<Box<dyn ScmpHandler>>,
    ) -> BoxFuture<'_, Result<Arc<dyn AsyncUdpUnderlaySocket>, ScionSocketBindError>> {
        Box::pin(async move {
            let socket = self.bind_async_udp_socket(bind_addr, scmp_handlers).await?;
            Ok(Arc::new(socket) as Arc<dyn AsyncUdpUnderlaySocket>)
        })
    }

    fn local_ases(&self) -> Vec<IsdAsn> {
        <Self as UnderlayStack>::local_ases(self)
    }
}

/// SCION socket connect errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketConnectError {
    /// Could not get a path to the destination
    #[error("failed to get path to destination: {0}")]
    PathLookupError(Cow<'static, str>),
    /// Could not bind the socket
    #[error(transparent)]
    BindError(#[from] ScionSocketBindError),
}

/// SCION socket send errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketSendError {
    /// There was an error looking up the path in the path registry.
    #[error("path lookup error: {0}")]
    PathLookupError(Cow<'static, str>),
    /// The destination is not reachable. E.g. because no path is available
    /// or because the connection to the snap is unavailable.
    #[error("network unreachable: {0}")]
    NetworkUnreachable(NetworkError),
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

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// The destination is unreachable.
    #[error("destination unreachable: {0}")]
    DestinationUnreachable(Cow<'static, str>),
    /// UDP underlay next hop unreachable. This is only
    /// returned if the selected underlay is UDP.
    #[error("udp next hop unreachable: {isd_as}#{interface_id}: {msg}")]
    UnderlayNextHopUnreachable {
        /// ISD-AS of the next hop.
        isd_as: IsdAsn,
        /// Interface ID of the next hop.
        interface_id: u16,
        /// Additional message.
        msg: String,
    },
}

/// SCION socket receive errors.
#[derive(Debug, thiserror::Error)]
pub enum ScionSocketReceiveError {
    /// Path buffer too small.
    #[error("provided path buffer is too small (at least 1024 bytes required)")]
    PathBufTooSmall,
    /// I/O error.
    #[error("i/o error: {0:?}")]
    IoError(#[from] std::io::Error),
    /// Error return when recv is called on a socket that is not connected.
    #[error("socket is not connected")]
    NotConnected,
}

/// A trait that defines an abstraction over an asynchronous underlay socket.
/// The socket sends and receives raw SCION packets. Decoding of the next layer
/// protocol or SCMP handling is left to the caller.
pub(crate) trait UnderlaySocket: 'static + Send + Sync {
    /// Send a raw packet. Takes a ScionPacketRaw because it needs to read the path
    /// to resolve the underlay next hop.
    fn send<'a>(
        &'a self,
        packet: ScionPacketRaw,
    ) -> BoxFuture<'a, Result<(), ScionSocketSendError>>;

    /// Try to send a raw packet immediately. Takes a ScionPacketRaw because it needs to read the
    /// path to resolve the underlay next hop.
    fn try_send(&self, packet: ScionPacketRaw) -> Result<(), ScionSocketSendError>;

    fn recv<'a>(&'a self) -> BoxFuture<'a, Result<ScionPacketRaw, ScionSocketReceiveError>>;

    fn local_addr(&self) -> SocketAddr;
}

/// A trait that defines an asynchronous path unaware UDP socket.
/// This can be used to implement the [quinn::AsyncUdpSocket] trait.
pub(crate) trait AsyncUdpUnderlaySocket: Send + Sync {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn udp_polling::UdpPoller>>;
    /// Try to send a raw SCION UDP packet. Path resolution and packet encoding is
    /// left to the caller.
    /// This function should return std::io::ErrorKind::WouldBlock if the packet cannot be sent
    /// immediately.
    fn try_send(&self, raw_packet: ScionPacketRaw) -> Result<(), std::io::Error>;
    /// Poll for receiving a SCION packet with sender and path.
    /// This function will only return valid UDP packets.
    /// SCMP packets will be handled internally.
    fn poll_recv_from_with_path(
        &self,
        cx: &mut Context,
    ) -> Poll<std::io::Result<(SocketAddr, Bytes, Path)>>;
    fn local_addr(&self) -> SocketAddr;
}
