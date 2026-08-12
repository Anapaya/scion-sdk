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

//! Client configuration.

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use scion_quic::quic::config::QuicConfig;
use scion_stack::{
    ScionStackBuilder,
    reqwest_connect_rpc::token_source::{
        TokenSource, TokenSourceError, TokenSourceWatch, static_token::StaticTokenSource,
    },
    resolver::ScionDnsResolver,
    stack::builder::PreferredUnderlay,
};
use url::Url;

/// Default timeout for establishing a connection to an origin.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default timeout for a request (response head plus body collection).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default idle time after which an origin's connection is swept.
///
/// Deliberately below the default QUIC idle timeout (30 seconds,
/// [`scion_quic::quic::config::QuicConfig`]): QUIC kills an idle connection
/// after that and keep-alives are off, so sweeping later would pool
/// connections that are already dead.
pub const DEFAULT_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(25);
/// Default bound on the number of distinct origins with pooled connections.
pub const DEFAULT_MAX_ORIGINS: usize = 8;
/// Default stagger between connection attempts to an origin's candidate
/// addresses (RFC 8305, Happy Eyeballs).
pub const DEFAULT_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// The type of the [`ScionStackBuilder`] customization hook, see
/// [`Config::with_stack_customizer`].
pub(crate) type StackCustomizer =
    dyn Fn(ScionStackBuilder) -> ScionStackBuilder + Send + Sync + 'static;

/// Adapts a shared [`TokenSource`] to the by-value `impl TokenSource` the stack
/// builder takes.
///
/// A [`Config`] is cloneable and outlives every stack built from it, so it holds
/// the source behind an `Arc` and hands the builder one of these on each
/// rebuild. Both methods delegate, so a refreshing source keeps refreshing.
pub(crate) struct SharedTokenSource(pub(crate) Arc<dyn TokenSource>);

#[async_trait]
impl TokenSource for SharedTokenSource {
    fn watch(&self) -> TokenSourceWatch {
        self.0.watch()
    }

    async fn get_token(&self) -> Result<String, TokenSourceError> {
        self.0.get_token().await
    }
}

/// Configuration for a [`Client`](crate::Client).
///
/// Construct with [`Config::new`] and customize with the consuming `with_*`
/// methods. The endhost API URL is the only required setting: it is how the
/// client discovers the data planes available to it, and the same single
/// setting reaches a real SCION network or a local `PocketSCION` topology.
#[derive(Clone)]
pub struct Config {
    pub(crate) endhost_api: Url,
    pub(crate) auth_token_source: Option<Arc<dyn TokenSource>>,
    pub(crate) preferred_underlay: Option<PreferredUnderlay>,
    pub(crate) stack_customizer: Option<Arc<StackCustomizer>>,
    pub(crate) connect_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) idle_connection_timeout: Duration,
    pub(crate) max_origins: usize,
    pub(crate) connection_attempt_delay: Duration,
    pub(crate) quic: QuicConfig,
    pub(crate) resolver: Option<Arc<dyn ScionDnsResolver>>,
}

impl Config {
    /// Creates a configuration that discovers connectivity through the given
    /// endhost API.
    #[must_use]
    pub fn new(endhost_api: Url) -> Self {
        Config {
            endhost_api,
            auth_token_source: None,
            preferred_underlay: None,
            stack_customizer: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            idle_connection_timeout: DEFAULT_IDLE_CONNECTION_TIMEOUT,
            max_origins: DEFAULT_MAX_ORIGINS,
            connection_attempt_delay: DEFAULT_CONNECTION_ATTEMPT_DELAY,
            quic: QuicConfig::default(),
            resolver: None,
        }
    }

    /// Sets a fixed token to authenticate with the endhost API and the SNAP
    /// control plane.
    ///
    /// Use [`with_auth_token_source`](Self::with_auth_token_source) instead when
    /// the token expires: connectivity is rebuilt on every
    /// [`reset`](crate::Client::reset), and a token captured here is reused
    /// verbatim each time.
    #[must_use]
    pub fn with_auth_token(self, token: impl Into<String>) -> Self {
        self.with_auth_token_source(StaticTokenSource::from(token.into()))
    }

    /// Sets the token *source* used to authenticate with the endhost API and
    /// the SNAP control plane.
    ///
    /// The source is shared, not rebuilt: the same one is handed to every stack
    /// this configuration builds, so a refreshing source keeps its schedule and
    /// its cached token across a [`reset`](crate::Client::reset). Implement
    /// [`TokenSource`](scion_stack::reqwest_connect_rpc::token_source::TokenSource)
    /// to supply tokens that expire.
    ///
    /// For a source scoped to the endhost API alone, reach the builder's
    /// `with_endhost_api_auth_token_source` through
    /// [`with_stack_customizer`](Self::with_stack_customizer).
    #[must_use]
    pub fn with_auth_token_source(mut self, source: impl TokenSource) -> Self {
        self.auth_token_source = Some(Arc::new(source));
        self
    }

    /// Sets the preferred underlay, applied to whatever endhost API discovery
    /// returns (default: UDP).
    #[must_use]
    pub fn with_preferred_underlay(mut self, underlay: PreferredUnderlay) -> Self {
        self.preferred_underlay = Some(underlay);
        self
    }

    /// Customizes the [`ScionStackBuilder`] used to build connectivity, for
    /// settings this configuration does not expose directly (underlay-specific
    /// configuration, discovery tuning, token sources).
    ///
    /// The hook runs every time connectivity is (re)built: on first use and
    /// after every [`reset`](crate::Client::reset). It runs after the settings
    /// above are applied, so it can override them.
    // XXX(shitz): This hook exists because `SnapUnderlayConfig`/`UdpUnderlayConfig`
    // are single-use (not `Clone`) while every rebuild needs a fresh
    // `ScionStackBuilder` from the same settings. Once they are made `Clone`
    // in scion-stack, replace this with direct `with_snap_underlay_config` and
    // `with_udp_underlay_config` setters.
    #[must_use]
    pub fn with_stack_customizer(
        mut self,
        customizer: impl Fn(ScionStackBuilder) -> ScionStackBuilder + Send + Sync + 'static,
    ) -> Self {
        self.stack_customizer = Some(Arc::new(customizer));
        self
    }

    /// Sets the timeout for establishing a connection to an origin, covering
    /// name resolution and all staggered connection attempts.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the default timeout for a whole request: connectivity build,
    /// establishment, response head, and body collection. Overridable per
    /// request with
    /// [`RequestBuilder::request_timeout`](crate::RequestBuilder::request_timeout).
    ///
    /// It is one deadline across all of those phases, and it keeps running while
    /// the caller holds the [`Response`](crate::Response) — see there for what
    /// that means for body collection.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets how long an origin's pooled connection may sit unused before an
    /// opportunistic sweep reclaims it (and its socket).
    #[must_use]
    pub fn with_idle_connection_timeout(mut self, timeout: Duration) -> Self {
        self.idle_connection_timeout = timeout;
        self
    }

    /// Bounds the number of distinct origins with pooled connections. Each
    /// pooled connection holds a socket, and therefore a file descriptor;
    /// when the bound is hit, the least recently used origin is evicted (and
    /// the eviction logged).
    #[must_use]
    pub fn with_max_origins(mut self, max_origins: usize) -> Self {
        self.max_origins = max_origins;
        self
    }

    /// Sets the stagger between connection attempts to an origin's candidate
    /// addresses: the next candidate is only tried this long after the
    /// previous one, unless it already failed (RFC 8305, Happy Eyeballs).
    #[must_use]
    pub fn with_connection_attempt_delay(mut self, delay: Duration) -> Self {
        self.connection_attempt_delay = delay;
        self
    }

    /// Sets the QUIC configuration used for every connection: trust anchors
    /// (`ca_certs_file` / `ca_certs_dir`), peer verification, handshake and
    /// idle timeouts, and transport tuning. The application protocol list must
    /// contain `h3` (the default).
    #[must_use]
    pub fn with_quic_config(mut self, quic: QuicConfig) -> Self {
        self.quic = quic;
        self
    }

    /// Replaces the default DNS resolver
    /// ([`ScionTxtDnsResolver`](scion_stack::resolver::txt::ScionTxtDnsResolver))
    /// with a caller-supplied one.
    ///
    /// The default resolver is constructed fresh on every connectivity
    /// rebuild, because system DNS configuration is a property of the current
    /// network. An injected resolver is reused across rebuilds as-is;
    /// reacting to network changes is then its responsibility.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn ScionDnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("endhost_api", &self.endhost_api)
            .field(
                "auth_token_source",
                &self.auth_token_source.as_ref().map(|_| "<redacted>"),
            )
            .field("preferred_underlay", &self.preferred_underlay)
            .field(
                "stack_customizer",
                &self.stack_customizer.as_ref().map(|_| "<fn>"),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("idle_connection_timeout", &self.idle_connection_timeout)
            .field("max_origins", &self.max_origins)
            .field("connection_attempt_delay", &self.connection_attempt_delay)
            .field("quic", &self.quic)
            .field("resolver", &self.resolver.as_ref().map(|_| "<custom>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::new("https://endhost-api.example.org".parse().unwrap())
    }

    #[test]
    fn new_applies_defaults() {
        let config = config();
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(
            config.idle_connection_timeout,
            DEFAULT_IDLE_CONNECTION_TIMEOUT
        );
        assert_eq!(config.max_origins, DEFAULT_MAX_ORIGINS);
        assert_eq!(
            config.connection_attempt_delay,
            DEFAULT_CONNECTION_ATTEMPT_DELAY
        );
    }

    #[test]
    fn default_idle_sweep_precedes_quic_idle_timeout() {
        let config = config();
        assert!(config.idle_connection_timeout < config.quic.idle_timeout);
    }

    #[test]
    fn debug_redacts_the_auth_token() {
        let config = config().with_auth_token("super-secret-token");
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret-token"));
        assert!(debug.contains("<redacted>"));
    }
}
