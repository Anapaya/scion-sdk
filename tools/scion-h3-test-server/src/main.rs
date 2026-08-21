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

//! A PocketSCION topology with an HTTP/3 server in it, run as a process.
//!
//! For testing any HTTP/3-over-SCION client, from any language, against a real request path. On
//! start-up it prints one line of JSON describing everything a client needs to reach it, and then
//! runs until its standard input closes or it is killed. Closing standard input is the intended way
//! to stop it, so a harness that dies without killing it leaves no topology behind.
//!
//! ```bash
//! cargo run --release -p scion-h3-test-server
//! ```
//!
//! ```text
//! {"endhost_api_url":"http://127.0.0.1:34517","auth_token":"...","base_url":"https://localhost:45123", ...}
//! ```
//!
//! # What the JSON says
//!
//! The same object is served by `GET /info` on the control API, for a harness that did not start
//! the process and therefore has no standard output to read.
//!
//! | Field | Purpose |
//! | --- | --- |
//! | `endhost_api_url` | The endhost API of AS 1-ff00:0:132, where a client discovers its connectivity. |
//! | `auth_token` | The topology's development token, for the endhost API and the SNAP control plane. |
//! | `base_url` | Where the server is, as a URL: `https://localhost:<port>`. |
//! | `target` | The server's SCION address, without a port. The topology has no TSAR records, so a client either resolves `localhost` itself or passes this as an address override. |
//! | `ca_pem` | The self-signed certificate the server presents, to be trusted as an anchor. |
//! | `wrong_ca_pem` | A second self-signed certificate that signs nothing here, for a client that must fail to verify. |
//! | `control_url` | The control API below. |
//! | `underlay` | Which underlay the topology carries traffic over, `udp` or `snap`. |
//!
//! # Request paths
//!
//! Served over HTTP/3 in AS 2-ff00:0:212. Each one exists to make a single client behaviour
//! observable.
//!
//! | Path | Serves | Useful for |
//! | --- | --- | --- |
//! | `GET /hello` | `world` | Liveness, and showing that a connection still works after something else went wrong on it. |
//! | `POST /echo` | The request body, unchanged | Bodies that survive both directions byte for byte, at any size. |
//! | `GET /echo-headers` | The request headers as JSON | What headers actually reached the server, including repeated ones and their order. |
//! | `* /method` | The request method | Methods arriving unchanged, including ones with no special handling anywhere. |
//! | `GET /repeated-headers` | Two `set-cookie` fields | Response headers that a map keyed by name cannot represent. |
//! | `GET /status/{code}` | That status | Status codes arriving unchanged. |
//! | `GET /trailers` | A body and an `x-checksum` trailer | The trailing header section, which no ordinary handler produces. |
//! | `GET /slow?ms=` | A response after a delay | Request deadlines. Defaults to a second. |
//! | `GET /big?bytes=` | That many bytes | Response size limits, and reassembly of a body spanning many frames. Defaults to a kilobyte, and refuses more than 64 MiB rather than allocating it. |
//! | `GET /invalid-utf8` | Two bytes that are not UTF-8 | Bodies that must not be decoded on the way through. |
//! | `GET /endless-body?tag=` | A chunk every 50 ms, forever | Cancellation. The count for `tag` stops going up once the client's `STOP_SENDING` arrives, which is the only way to see from outside that a cancelled request reached the server. |
//! | `GET /reset-stream` | A status, one chunk, then a stream reset | The failure in between a clean response and an unreachable peer, which cannot be provoked from the client side. |
//!
//! # Control API
//!
//! Plain HTTP over TCP, so a client that is being tested never sees it.
//!
//! | Path | Serves |
//! | --- | --- |
//! | `GET /stats` | `{"endless_chunks": {tag: count}, "requests": {path: count}, "started": {path: count}, "restarts": count}`. Chunks sent per endless-body tag, requests per path that finished and that merely arrived, and restarts so far. |
//! | `GET /info` | The description above, for a harness with no standard output to read. |
//! | `POST /restart-server` | Stops the HTTP/3 server and starts it again at the same address, with the same certificate. Returns once the new one is serving. |
//!
//! # Options
//!
//! Two settings exist because the conditions they create cannot be provoked from the client side:
//! `--max-streams 0` makes every request fail against the peer's concurrent-stream limit, and
//! `--alpn` set to anything but `h3` makes every connection attempt fail to agree on a protocol.
//!
//! `--underlay` picks what carries the traffic. `udp` puts a router in each AS and addresses
//! endhosts by their own underlay address; `snap` puts a SNAP in each AS and tunnels to it. The
//! difference matters to a client behind a NAT: over `snap` the endpoint is addressed at the
//! address the tunnel observed, and over `udp` it is addressed at the one it believes it has, which
//! nothing outside the NAT can reach.
//!
//! `--advertise-ip` separates where the topology listens from where it tells clients it is, which
//! is what a client on another host needs. It applies to AS 1-ff00:0:132 alone, the one a client
//! attaches to, and not to the AS the HTTP/3 server sits in. That split is what lets the address be
//! one only the client can reach, such as an emulator's `10.0.2.2`: this process is a client of its
//! own topology too, since the server discovers its connectivity the same way anything else does,
//! and it goes on using the bound addresses of its own AS.
//!
//! `--bind-ip` moves where components listen, for a client that reaches this host at an address of
//! its own rather than through a translation of loopback.
//!
//! `--control-port` fixes the control API's port, so that a harness which cannot read the line of
//! JSON above still knows where to ask for it.

mod app;
mod control;
mod server;

use std::{
    io::{BufRead, Write},
    net::IpAddr,
    sync::Arc,
};

use clap::{Parser, ValueEnum};
use pocketscion::{
    io_config::IoConfig,
    util::{
        dev_auth_token,
        topologies::{IA132, UnderlayType, minimal::minimal_topology_with_io_config},
    },
};
use tokio_util::sync::CancellationToken;

use crate::{app::Counters, server::Http3Server};

/// Everything the topology and the server in it can be told at start-up.
#[derive(Parser)]
#[command(about = "A PocketSCION topology serving HTTP/3")]
pub struct Args {
    /// Concurrent request streams the server allows.
    ///
    /// Zero makes every request fail against the peer's stream limit, which is otherwise
    /// impossible to provoke deliberately.
    #[arg(long, default_value_t = 100)]
    max_streams: u64,

    /// The ALPN protocol the server negotiates.
    ///
    /// Anything but `h3` makes every candidate fail on ALPN, which is what a client reports as a
    /// TLS failure rather than as an unreachable peer.
    #[arg(long, default_value = "h3")]
    alpn: String,

    /// What carries the traffic between the two autonomous systems.
    #[arg(long, value_enum, default_value_t = Underlay::Udp)]
    underlay: Underlay,

    /// The IP every component of the topology binds, ports staying ephemeral.
    ///
    /// Defaults to loopback, which is what a client in this process or on this host wants.
    #[arg(long)]
    bind_ip: Option<IpAddr>,

    /// The IP a client is told to reach AS 1-ff00:0:132 at, ports unchanged.
    ///
    /// Only that AS, so it may be an address this host cannot reach itself; see the crate
    /// documentation.
    #[arg(long)]
    advertise_ip: Option<IpAddr>,

    /// The control API's port. Zero, the default, takes an ephemeral one.
    #[arg(long, default_value_t = 0)]
    control_port: u16,
}

/// What carries traffic between the ASes of the topology.
#[derive(Clone, Copy, ValueEnum)]
enum Underlay {
    Udp,
    Snap,
}

impl Underlay {
    fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Snap => "snap",
        }
    }
}

impl From<Underlay> for UnderlayType {
    fn from(underlay: Underlay) -> Self {
        match underlay {
            Underlay::Udp => Self::Udp,
            Underlay::Snap => Self::Snap,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let args = Args::parse();
    let counters = Arc::new(Counters::default());
    let shutdown = CancellationToken::new();

    let io_config = IoConfig::new();
    if let Some(ip) = args.bind_ip {
        io_config.set_bind_ip(ip);
    }
    if let Some(ip) = args.advertise_ip {
        // The client's AS only. The server's own AS keeps its bound addresses, which is what lets
        // this process reach the topology it is hosting while the client reaches it by another
        // route entirely.
        io_config.set_advertised_ip(IA132, ip);
    }

    let ps = minimal_topology_with_io_config(args.underlay.into(), io_config.clone()).await;
    // Bound before the description is built, served after it: the control API's own address is part
    // of the description, and the description is what it serves.
    let control = control::bind(&io_config, args.control_port).await?;
    let server = Http3Server::start(&ps, &args, counters.clone(), shutdown.clone()).await?;

    let description = serde_json::json!({
        "endhost_api_url": ps.endhost_api(IA132).expect("endhost API for IA132").to_string(),
        "auth_token": dev_auth_token(),
        "base_url": format!("https://{}:{}", server::SERVER_NAME, server.port()),
        "target": server.target(),
        "ca_pem": server.ca_pem(),
        "wrong_ca_pem": server.wrong_ca_pem(),
        "control_url": control.url(),
        "underlay": args.underlay.name(),
    });
    control.serve(counters, server, description.clone(), shutdown.clone());

    println!("{description}");
    std::io::stdout().flush()?;

    wait_for_stdin_close().await;
    tracing::info!("Standard input closed, shutting down");
    shutdown.cancel();
    Ok(())
}

/// Resolves when standard input reaches end of file.
async fn wait_for_stdin_close() {
    let _ = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        while std::io::stdin().lock().read_line(&mut line).unwrap_or(0) > 0 {
            line.clear();
        }
    })
    .await;
}
