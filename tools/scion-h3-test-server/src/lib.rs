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

//! A PocketSCION topology with an HTTP/3 server in it.
//!
//! For testing any HTTP/3-over-SCION client against a real request path. [`app`] documents what
//! each route serves and which client behaviour it exists to make observable, and [`app::Counters`]
//! is how a caller sees what reached the server. The `scion-h3-test-server` binary is this library
//! behind a line of JSON and a control API, for a harness in another language.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let server = scion_h3_test_server::TestServer::start(Default::default()).await?;
//! let url = server.url("/hello");
//! # Ok(())
//! # }
//! ```
//!
//! Dropping a [`TestServer`] stops the topology and everything in it.

pub mod app;
pub mod server;

use std::{net::IpAddr, sync::Arc};

use pocketscion::{
    io_config::IoConfig,
    util::{
        dev_auth_token,
        topologies::{IA132, PsSetup, UnderlayType, minimal::minimal_topology_with_io_config},
    },
};
use tokio_util::sync::CancellationToken;

use crate::{app::Counters, server::Http3Server};

type BoxError = Box<dyn std::error::Error>;

/// Everything the topology and the server in it can be told at start-up.
///
/// [`Options::default`] is what a test wants: a UDP underlay on loopback, HTTP/3 negotiated, and
/// stream credit to spare. Every field away from its default creates a condition a client cannot
/// provoke from its own side.
#[derive(Clone, Debug)]
pub struct Options {
    /// Concurrent request streams the server allows.
    ///
    /// Zero makes every request fail against the peer's concurrent-stream limit, which is
    /// otherwise impossible to provoke deliberately.
    pub max_streams: u64,
    /// The ALPN protocol the server negotiates.
    ///
    /// Anything but `h3` makes every candidate fail on ALPN, which a client reports as a TLS
    /// failure rather than as an unreachable peer.
    pub alpn: String,
    /// What carries traffic between the two autonomous systems.
    ///
    /// `Udp` puts a router in each AS and addresses endhosts by their own underlay address; `Snap`
    /// puts a SNAP in each AS and tunnels to it. The difference matters to a client behind a NAT:
    /// over `Snap` the endpoint is addressed at the address the tunnel observed, and over `Udp` at
    /// the one it believes it has, which nothing outside the NAT can reach.
    pub underlay: UnderlayType,
    /// The IP every component of the topology binds, ports staying ephemeral.
    ///
    /// `None` means loopback, which is what a client in this process or on this host wants. Move
    /// it for a client that reaches this host at an address of its own rather than through a
    /// translation of loopback.
    pub bind_ip: Option<IpAddr>,
    /// The IP a client is told to reach AS 1-ff00:0:132 at, ports unchanged.
    ///
    /// Separates where the topology listens from where it says it is, which is what a client on
    /// another host needs. That AS alone, the one a client attaches to, and not the AS the HTTP/3
    /// server sits in. The split is what lets the address be one only the client can reach, such
    /// as an emulator's `10.0.2.2`: the server is a client of this topology too, since it
    /// discovers its connectivity the same way anything else does, and it goes on using the
    /// bound addresses of its own AS.
    pub advertise_ip: Option<IpAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_streams: 100,
            alpn: "h3".to_string(),
            underlay: UnderlayType::Udp,
            bind_ip: None,
            advertise_ip: None,
        }
    }
}

/// A running topology with an HTTP/3 server in AS 2-ff00:0:212.
///
/// Everything a client needs to reach it is an accessor below. Dropping this stops the simulation,
/// so a test has to hold it for as long as it makes requests.
pub struct TestServer {
    // Held because dropping it stops the topology, and every address below belongs to it.
    _ps: PsSetup,
    io_config: IoConfig,
    server: Arc<Http3Server>,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
    endhost_api_url: String,
}

impl TestServer {
    /// Starts a topology and serves the routes in it.
    pub async fn start(options: Options) -> Result<Self, BoxError> {
        // Here rather than in each caller: discovery speaks TLS through rustls, which refuses to
        // build a configuration until a provider is installed.
        scion_sdk_utils::rustls::select_ring_crypto_provider();

        let io_config = IoConfig::new();
        if let Some(ip) = options.bind_ip {
            io_config.set_bind_ip(ip);
        }
        if let Some(ip) = options.advertise_ip {
            // The client's AS only. The server's own AS keeps its bound addresses, which is what
            // lets this process reach the topology it is hosting while the client reaches it by
            // another route entirely.
            io_config.set_advertised_ip(IA132, ip);
        }

        let ps = minimal_topology_with_io_config(options.underlay, io_config.clone()).await;
        let endhost_api_url = ps
            .endhost_api(IA132)
            .expect("endhost API for IA132")
            .to_string();
        let counters = Arc::new(Counters::default());
        let shutdown = CancellationToken::new();
        let server = Http3Server::start(&ps, &options, counters.clone(), shutdown.clone()).await?;

        Ok(TestServer {
            _ps: ps,
            io_config,
            server,
            counters,
            shutdown,
            endhost_api_url,
        })
    }

    /// Where a client discovers its connectivity.
    pub fn endhost_api_url(&self) -> &str {
        &self.endhost_api_url
    }

    /// The bearer token the endhost API and the SNAP control plane accept.
    pub fn auth_token(&self) -> String {
        dev_auth_token()
    }

    /// Where the server is, as a URL.
    pub fn base_url(&self) -> String {
        format!("https://{}:{}", server::SERVER_NAME, self.port())
    }

    /// A URL for `path` on the server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url())
    }

    /// The port clients address the server on.
    pub fn port(&self) -> u16 {
        self.server.port()
    }

    /// The server's SCION address, without a port.
    ///
    /// The topology serves no TSAR records, so a client either resolves the URL's host itself or
    /// carries this as an address override.
    pub fn target(&self) -> String {
        self.server.target()
    }

    /// The authority that signed the certificate the server presents.
    pub fn ca_pem(&self) -> &str {
        self.server.ca_pem()
    }

    /// An authority that signed nothing here, for a client that must fail to verify.
    pub fn wrong_ca_pem(&self) -> &str {
        self.server.wrong_ca_pem()
    }

    /// What the server has seen, which is how a test observes the far end of a request.
    pub fn counters(&self) -> &Arc<Counters> {
        &self.counters
    }

    /// Where the topology's components bind, for anything that has to bind beside them.
    pub fn io_config(&self) -> &IoConfig {
        &self.io_config
    }

    /// The HTTP/3 server itself, for [`Http3Server::restart`].
    ///
    /// A restart is the one thing a caller does to the server rather than through it: it throws
    /// away every connection and serves again at the same address, which is what a client sees
    /// as a reconnect. Whoever restarts it should also call [`Counters::record_restart`], as
    /// the control API does.
    pub fn http3_server(&self) -> &Arc<Http3Server> {
        &self.server
    }

    /// A token cancelled when this is dropped, for a task that has to stop with the topology.
    ///
    /// A child of the one the topology watches, so cancelling it stops whatever took it and nothing
    /// else. Stopping the topology is what dropping the [`TestServer`] is for, and the only way to
    /// do it.
    pub fn child_shutdown_token(&self) -> CancellationToken {
        self.shutdown.child_token()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
