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

//! In-crate test utilities: an in-memory HTTP/3 server harness (axum over
//! [`MockScionSocket`] pairs) that doubles as a [`SocketBinder`], plus mock
//! resolvers and a baseline test [`Config`].

use std::{
    io::Write,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    routing::{get, post},
};
use scion_quic::{
    quic::config::QuicConfig,
    socket::GenericScionUdpSocket,
    test_util::{BreakableScionSocket, MockScionSocket},
};
use scion_stack::{
    resolver::{ResolveError, ScionDnsResolver},
    stack::ScionSocketBindError,
};
use sciparse::address::{ip_addr::ScionIpAddr, ip_socket_addr::ScionSocketIpAddr};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    epoch::{Epoch, Network, SocketBinder},
};

/// The port every in-memory test server listens on (and test URLs use).
pub(crate) const SERVER_PORT: u16 = 4443;

/// The one live server address of a [`TestServerHarness`].
pub(crate) fn server_scion_ip() -> ScionIpAddr {
    "1-ff00:0:110,10.0.0.2".parse().unwrap()
}

/// An address nothing listens on: connection attempts to it time out at the
/// handshake. Sorts before [`server_scion_ip`], so in a sorted candidate list
/// the dead address is attempted first.
pub(crate) fn dead_scion_ip() -> ScionIpAddr {
    "1-ff00:0:110,10.0.0.1".parse().unwrap()
}

fn server_addr() -> ScionSocketIpAddr {
    let ip = server_scion_ip();
    ScionSocketIpAddr::new(ip.isd_asn(), ip.ip(), SERVER_PORT)
}

fn client_addr() -> ScionSocketIpAddr {
    let ip: ScionIpAddr = "1-ff00:0:111,10.0.1.1".parse().unwrap();
    ScionSocketIpAddr::new(ip.isd_asn(), ip.ip(), 0)
}

/// A baseline test config: peer verification off (self-signed test certs),
/// a short handshake timeout so dead candidates fail fast, and a short
/// attempt stagger.
pub(crate) fn test_config() -> Config {
    Config::new("https://endhost-api.invalid".parse().unwrap())
        .with_quic_config(
            QuicConfig::builder()
                .verify_peer(false)
                .handshake_timeout(Duration::from_millis(400))
                .build(),
        )
        .with_connection_attempt_delay(Duration::from_millis(50))
}

/// A router with the standard test routes; `hits` counts requests to
/// `/hello`.
pub(crate) fn test_router() -> (Router, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route(
            "/hello",
            get({
                let hits = hits.clone();
                move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "world"
                    }
                }
            }),
        )
        .route("/echo", post(|body: String| async move { body }))
        .route(
            "/slow",
            get(|| {
                async {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    "slow"
                }
            }),
        );
    (router, hits)
}

/// An in-memory HTTP/3 server that hands out client sockets: every
/// [`bind`](SocketBinder::bind) creates a fresh [`MockScionSocket`] pair and
/// spawns an axum-over-HTTP/3 server on the far end, listening on
/// [`server_scion_ip`]`:`[`SERVER_PORT`]. Dialing any other address over the
/// returned socket goes nowhere (the server side drops it), which is how
/// tests model dead candidates.
pub(crate) struct TestServerHarness {
    router: Router,
    server_quic: QuicConfig,
    cert_file: NamedTempFile,
    key_file: NamedTempFile,
    cancel: CancellationToken,
    /// The client sockets handed out so far, so a test can break them.
    sockets: StdMutex<Vec<Arc<BreakableScionSocket>>>,
    /// Number of sockets handed out (= connection attempts made).
    pub(crate) binds: AtomicUsize,
    /// When set, the first bind stalls until [`release_stalled`] is called.
    stall_first_bind: AtomicBool,
    stall_gate: tokio::sync::Notify,
}

impl TestServerHarness {
    pub(crate) fn new(router: Router) -> Arc<Self> {
        Self::with_server_quic(router, QuicConfig::builder().verify_peer(false).build())
    }

    /// Like [`new`](Self::new), with a custom server-side QUIC configuration
    /// (e.g. a stream limit of zero for `StreamBlocked` tests).
    pub(crate) fn with_server_quic(router: Router, server_quic: QuicConfig) -> Arc<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut cert_file = NamedTempFile::new().unwrap();
        let mut key_file = NamedTempFile::new().unwrap();
        cert_file
            .as_file_mut()
            .write_all(cert.cert.pem().as_bytes())
            .unwrap();
        key_file
            .as_file_mut()
            .write_all(cert.signing_key.serialize_pem().as_bytes())
            .unwrap();
        Arc::new(TestServerHarness {
            router,
            server_quic,
            cert_file,
            key_file,
            cancel: CancellationToken::new(),
            sockets: StdMutex::new(Vec::new()),
            binds: AtomicUsize::new(0),
            stall_first_bind: AtomicBool::new(false),
            stall_gate: tokio::sync::Notify::new(),
        })
    }

    /// Makes the next (first) bind stall until
    /// [`release_stalled`](Self::release_stalled) is called.
    pub(crate) fn stall_first_bind(&self) {
        self.stall_first_bind.store(true, Ordering::SeqCst);
    }

    /// Releases every bind currently stalled.
    pub(crate) fn release_stalled(&self) {
        self.stall_gate.notify_waiters();
    }

    /// Breaks every socket handed out so far, taking the underlay away from the
    /// connections on them at once instead of waiting on a QUIC timeout. The
    /// servers stay up but become unreachable; sockets from later binds are
    /// intact, and reach a fresh server as usual.
    pub(crate) fn break_sockets(&self) {
        for socket in self.sockets.lock().unwrap().drain(..) {
            socket.break_socket();
        }
    }

    fn server_config(&self) -> scion_quic::reexport::squiche::Config {
        let mut config = self.server_quic.to_quiche_config().unwrap();
        config
            .load_cert_chain_from_pem_file(self.cert_file.path().to_str().unwrap())
            .unwrap();
        config
            .load_priv_key_from_pem_file(self.key_file.path().to_str().unwrap())
            .unwrap();
        config
    }
}

impl Drop for TestServerHarness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl SocketBinder for TestServerHarness {
    async fn bind(&self) -> Result<Arc<dyn GenericScionUdpSocket>, ScionSocketBindError> {
        if self.stall_first_bind.swap(false, Ordering::SeqCst) {
            self.stall_gate.notified().await;
        }
        self.binds.fetch_add(1, Ordering::SeqCst);
        let (client_socket, server_socket) =
            MockScionSocket::pair(1024, client_addr(), server_addr());
        let cancel = self.cancel.clone();
        let router = self.router.clone();
        let config = self.server_config();
        tokio::spawn(async move {
            let _ = scion_h3_axum::ScionH3AxumServer::serve_with_graceful_shutdown(
                Arc::new(server_socket),
                router,
                config,
                cancel,
            )
            .await;
        });
        let client_socket = Arc::new(BreakableScionSocket::new(Arc::new(client_socket)));
        self.sockets.lock().unwrap().push(client_socket.clone());
        Ok(client_socket)
    }
}

/// A resolver that returns a fixed address list and counts calls.
pub(crate) struct StaticResolver {
    addrs: Vec<ScionIpAddr>,
    pub(crate) calls: AtomicUsize,
}

impl StaticResolver {
    pub(crate) fn new(addrs: Vec<ScionIpAddr>) -> Arc<Self> {
        Arc::new(StaticResolver {
            addrs,
            calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl ScionDnsResolver for StaticResolver {
    async fn resolve(&self, _domain: &str) -> Result<Vec<ScionIpAddr>, ResolveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addrs.clone())
    }
}

/// A resolver that always fails with a (retryable) lookup error.
pub(crate) struct FailingResolver;

#[async_trait]
impl ScionDnsResolver for FailingResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<ScionIpAddr>, ResolveError> {
        Err(ResolveError::DnsLookup(format!(
            "no DNS in tests: {domain}"
        )))
    }
}

/// Assembles a test [`Network`] from a harness and a resolver.
pub(crate) fn test_network(
    binder: Arc<dyn SocketBinder>,
    resolver: Arc<dyn ScionDnsResolver>,
) -> Arc<Network> {
    Arc::new(Network::new(binder, resolver))
}

/// Assembles a test epoch from a harness and a resolver.
pub(crate) fn test_epoch(
    binder: Arc<dyn SocketBinder>,
    resolver: Arc<dyn ScionDnsResolver>,
    config: &Config,
) -> Arc<Epoch> {
    Arc::new(Epoch::new(binder, resolver, config))
}
