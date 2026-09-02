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
//! Served over HTTP/3 in AS 2-ff00:0:212. `scion_h3_test_server::app` documents each one and the
//! client behaviour it exists to make observable.
//!
//! # Control API
//!
//! Plain HTTP over TCP, so a client that is being tested never sees it.
//!
//! | Path | Serves |
//! | --- | --- |
//! | `GET /stats` | Every counter in `scion_h3_test_server::app::Counters`, as JSON, keyed the way that type documents. |
//! | `GET /info` | The description above, for a harness with no standard output to read. |
//! | `POST /restart-server` | Stops the HTTP/3 server and starts it again at the same address, with the same certificate. Returns once the new one is serving. |
//!
//! # Options
//!
//! Every option but one is a field of `scion_h3_test_server::Options`, which documents what each
//! condition is for; [`Args`] is their spelling on a command line. The exception is
//! `--control-port`, which fixes the port of the control API above, so that a harness which cannot
//! read the line of JSON still knows where to ask for it.

mod control;

use std::{
    io::{BufRead, Write},
    net::IpAddr,
};

use clap::{Parser, ValueEnum};
use pocketscion::util::topologies::UnderlayType;
use scion_h3_test_server::{Options, TestServer};

/// Everything the topology and the server in it can be told at start-up, on the command line.
///
/// The same settings as [`Options`], which is what they become; this is only their spelling for a
/// caller that starts the tool as a process.
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

impl Args {
    fn into_options(self) -> Options {
        Options {
            max_streams: self.max_streams,
            alpn: self.alpn,
            underlay: self.underlay.into(),
            bind_ip: self.bind_ip,
            advertise_ip: self.advertise_ip,
        }
    }
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

    let args = Args::parse();
    let control_port = args.control_port;
    let underlay = args.underlay.name();
    let options = args.into_options();

    let server = TestServer::start(options).await?;
    // Bound before the description is built, served after it: the control API's own address is part
    // of the description, and the description is what it serves.
    let control = control::bind(server.io_config(), control_port).await?;

    let description = serde_json::json!({
        "endhost_api_url": server.endhost_api_url(),
        "auth_token": server.auth_token(),
        "base_url": server.base_url(),
        "target": server.target(),
        "ca_pem": server.ca_pem(),
        "wrong_ca_pem": server.wrong_ca_pem(),
        "control_url": control.url(),
        "underlay": underlay,
    });
    control.serve(
        server.counters().clone(),
        server.http3_server().clone(),
        description.clone(),
        server.child_shutdown_token(),
    );

    println!("{description}");
    std::io::stdout().flush()?;

    wait_for_stdin_close().await;
    tracing::info!("Standard input closed, shutting down");
    // Dropping it cancels the shutdown token, which is what every task the topology spawned
    // watches.
    drop(server);
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
