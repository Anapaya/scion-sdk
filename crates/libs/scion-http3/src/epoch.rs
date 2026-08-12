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

//! Epochs: the unit of connectivity replacement.
//!
//! An [`Epoch`] bundles everything that is derived from the network the
//! process is currently on: the [`ScionStack`] (endhost API discovery and the
//! underlay, used here to bind sockets), the DNS resolver (system DNS
//! configuration is a property of the network), and the origin map with all
//! pooled connections (each pinned to a socket of that stack). When the
//! network changes, all of it goes stale at once, which is why it is replaced
//! as one unit rather than repaired piecemeal.
//!
//! The [`Client`](crate::Client) holds the current epoch and only ever swaps
//! it, never mutates it. [`Client::reset`](crate::Client::reset) marks the
//! current epoch stale; the next request builds a fresh one
//! ([`Epoch::build`]: endhost API discovery, underlay setup, a fresh
//! resolver, an empty origin map), swaps it in, and shuts the old one down in
//! the background. [`Epoch::shutdown`] closes every pooled connection so
//! requests still running on the dead network fail promptly instead of
//! timing out. A request that already holds pieces of the old epoch keeps
//! them alive through their `Arc`s, and every socket is bound from the epoch
//! the request started with. Thus, a stack and the connections built on it
//! always retire together.

use std::{
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use async_trait::async_trait;
use scion_quic::socket::GenericScionUdpSocket;
use scion_stack::{
    ScionStack,
    resolver::{ScionDnsResolver, txt::ScionTxtDnsResolver},
    stack::{ScionSocketBindError, builder::BuildScionStackError},
};
use sciparse::address::ip_addr::ScionIpAddr;

use crate::{
    config::{Config, SharedTokenSource},
    error::Error,
    origin::Origin,
    pool::{OriginClient, OriginMap},
};

/// Binds fresh SCION sockets. Implemented by [`ScionStack`]. The trait exists
/// so pool behavior is testable without a real stack.
#[async_trait]
pub(crate) trait SocketBinder: Send + Sync {
    /// Binds a new socket on an ephemeral port.
    async fn bind(&self) -> Result<Arc<dyn GenericScionUdpSocket>, ScionSocketBindError>;
}

#[async_trait]
impl SocketBinder for ScionStack {
    async fn bind(&self) -> Result<Arc<dyn GenericScionUdpSocket>, ScionSocketBindError> {
        let socket = ScionStack::bind(self, None).await?;
        Ok(Arc::new(socket))
    }
}

/// The per-network capabilities an established connection needs: somewhere to
/// bind sockets, and something to resolve names with.
///
/// Split out of [`Epoch`] so an [`OriginClient`] can hold what it needs to
/// establish without holding — or being handed back — the epoch that owns the
/// map it lives in.
pub(crate) struct Network {
    binder: Arc<dyn SocketBinder>,
    resolver: Arc<dyn ScionDnsResolver>,
}

impl Network {
    pub(crate) fn new(
        binder: Arc<dyn SocketBinder>,
        resolver: Arc<dyn ScionDnsResolver>,
    ) -> Network {
        Network { binder, resolver }
    }

    /// Binds a fresh socket from this network's stack.
    pub(crate) async fn bind(
        &self,
    ) -> Result<Arc<dyn GenericScionUdpSocket>, ScionSocketBindError> {
        self.binder.bind().await
    }

    /// Resolves `host` to its SCION addresses via this network's resolver.
    pub(crate) async fn resolve(&self, host: &str) -> Result<Vec<ScionIpAddr>, Error> {
        self.resolver
            .resolve(host)
            .await
            .map_err(|e| Error::from_resolve_error(host, e))
    }
}

/// Everything derived from the current network: the [`Network`] itself (stack
/// and resolver) and the origin map with all pooled connections. Replaced
/// wholesale when connectivity goes stale; an epoch is never mutated into a
/// new one.
pub(crate) struct Epoch {
    network: Arc<Network>,
    origins: StdMutex<OriginMap>,
    /// Set by [`shutdown`](Self::shutdown), so a caller racing it gets
    /// [`Error::Closed`] instead of repopulating a drained map.
    closed: AtomicBool,
}

impl Epoch {
    /// Builds a fresh epoch: a new stack (endhost API discovery and underlay
    /// setup) and a new resolver.
    pub(crate) async fn build(config: &Config) -> Result<Epoch, Error> {
        let resolver: Arc<dyn ScionDnsResolver> = match &config.resolver {
            Some(resolver) => resolver.clone(),
            None => {
                Arc::new(ScionTxtDnsResolver::new().map_err(|e| {
                    Error::StackBuild {
                        retryable: false,
                        source: Box::new(e),
                    }
                })?)
            }
        };

        let mut builder =
            scion_stack::ScionStackBuilder::new().with_endhost_api(config.endhost_api.clone());
        if let Some(source) = &config.auth_token_source {
            builder = builder.with_auth_token_source(SharedTokenSource(source.clone()));
        }
        if let Some(underlay) = config.preferred_underlay {
            builder = builder.with_preferred_underlay(underlay);
        }
        if let Some(customizer) = &config.stack_customizer {
            builder = customizer(builder);
        }
        let stack = builder.build().await.map_err(|e| {
            let retryable = match &e {
                BuildScionStackError::AllEndhostApisFailed(failed) => failed.is_transient(),
                _ => false,
            };
            Error::StackBuild {
                retryable,
                source: Box::new(e),
            }
        })?;

        Ok(Epoch::new(Arc::new(stack), resolver, config))
    }

    /// Assembles an epoch from parts. Production goes through
    /// [`build`](Self::build); tests inject mock binders and resolvers here.
    pub(crate) fn new(
        binder: Arc<dyn SocketBinder>,
        resolver: Arc<dyn ScionDnsResolver>,
        config: &Config,
    ) -> Epoch {
        Epoch {
            network: Arc::new(Network::new(binder, resolver)),
            origins: StdMutex::new(OriginMap::new(
                config.max_origins,
                config.idle_connection_timeout,
            )),
            closed: AtomicBool::new(false),
        }
    }

    /// Returns the pooled [`OriginClient`] for `origin`, creating (and, if the
    /// map is full, evicting) as needed. No I/O happens under the map lock.
    ///
    /// The returned client carries this epoch's [`Network`], so establishing
    /// through it needs nothing further from the epoch.
    pub(crate) fn origin_client(
        &self,
        origin: Origin,
        now: Instant,
        config: &Config,
    ) -> Result<Arc<OriginClient>, Error> {
        let mut origins = self.origins.lock().expect("origin map lock poisoned");
        // Checked under the guard: `shutdown` sets the flag before taking the
        // lock, so an insert into an already-drained map is unrepresentable.
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        Ok(origins.get_or_insert(origin, now, config, &self.network))
    }

    /// Shuts the epoch down: closes every pooled connection, faulting their
    /// in-flight requests promptly rather than leaving them to time out on a
    /// dead network. Idempotent; requests that still hold `Arc`s to evicted
    /// clients are unaffected.
    pub(crate) async fn shutdown(self: Arc<Self>) {
        // Set the flag before draining, so a caller racing the drain fails
        // rather than inserting into a map nobody will close again.
        self.closed.store(true, Ordering::Release);
        let clients = {
            let mut origins = self.origins.lock().expect("origin map lock poisoned");
            origins.drain()
        };
        // Concurrently: each close queues a CONNECTION_CLOSE on a different
        // connection, and on a dead network a serial sweep would make every
        // origin wait out the ones ahead of it.
        futures::future::join_all(clients.iter().map(|client| client.close())).await;
    }
}
