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

//! Choosing SCION paths explicitly.
//!
//! The `udp_echo` example lets the socket pick a path automatically. This one is
//! about the other half of SCION: an application that wants to *see* the available
//! paths and decide which one to use.
//!
//! It starts a [PocketSCION] network shaped like a triangle, so the client has two
//! distinct paths to the server — the direct link, or the detour via 2-ff00:0:222:
//!
//! ```text
//!                     2-ff00:0:222
//!                 #1 /            \ #2
//!                   /              \
//!             #2   /                \  #4
//!   1-ff00:0:132  #1 ───────────── #3  2-ff00:0:212
//!     (client)                           (server)
//! ```
//!
//! The example lists both paths and sends over each one explicitly with
//! [`send_to_via`].
//!
//! A real application would instead keep whichever path best fits its needs. That
//! preference can also be expressed declaratively per socket, via
//! [`SocketConfig::with_path_policy`] passed to [`bind_with_config`], in which case
//! [`send_to`] applies it automatically.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p scion-stack --example udp_paths
//! ```
//!
//! [PocketSCION]: pocketscion
//! [`send_to_via`]: scion_stack::stack::UdpScionSocket::send_to_via
//! [`send_to`]: scion_stack::stack::UdpScionSocket::send_to
//! [`bind_with_config`]: scion_stack::stack::ScionStack::bind_with_config
//! [`SocketConfig::with_path_policy`]: scion_stack::stack::SocketConfig::with_path_policy

mod common;

use std::time::Duration;

use pocketscion::util::topologies::{IA132, IA212, UnderlayType, minimal::two_path_topology};
use scion_stack::{path::fetcher::traits::PathFetcher, stack::UdpScionSocket};
use sciparse::{address::ip_socket_addr::ScionSocketIpAddr, path::ScionPath};
use tokio::time::timeout;

/// Largest datagram we bother to buffer in this example.
const MAX_DATAGRAM: usize = 2048;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts a triangular SCION network, lists the paths to the server, and sends
/// over each one explicitly.
async fn run() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // Three ASes wired in a triangle: the client (1-ff00:0:132) can reach the
    // server (2-ff00:0:212) either over the direct link or via 2-ff00:0:222.
    let ps = two_path_topology(UnderlayType::Snap).await;

    let server_stack = common::build_stack(&ps, IA212).await?;
    let server_socket = server_stack.bind(None).await?;
    let server_addr = server_socket.local_addr();
    let server = tokio::spawn(echo_server(server_socket));

    let client_stack = common::build_stack(&ps, IA132).await?;
    let client_socket = client_stack.bind(None).await?;

    // ANCHOR: fetch-paths
    // Ask the SDK for *every* path to the server's AS and inspect them ourselves,
    // rather than letting `send_to` silently pick one for us.
    let mut paths = client_stack
        .create_path_fetcher()
        .fetch_paths(IA132, IA212)
        .await?;
    anyhow::ensure!(
        !paths.is_empty(),
        "expected at least one path to the server"
    );

    // Order shortest-first so the deliberate choice below is reproducible.
    paths.sort_by_key(hop_count);
    // ANCHOR_END: fetch-paths

    println!(
        "found {} path(s) to {}:",
        paths.len(),
        server_addr.isd_asn()
    );
    for (i, path) in paths.iter().enumerate() {
        println!("  [{i}] {path}");
    }

    // ANCHOR: send-each
    // Send over each path in turn, selecting it explicitly with `send_to_via`. The
    // payload carries the path index so we can confirm the echo we accept is the
    // reply to *this* send, not a delayed echo from an earlier path.
    for (i, path) in paths.iter().enumerate() {
        let payload = format!("hello via path {i}");
        ping_via(&client_socket, server_addr, path, payload.as_bytes()).await?;
        println!("  [{i}] echo confirmed over this path");
    }
    // ANCHOR_END: send-each

    // A real application would keep whichever path best fits its needs (shortest,
    // lowest-latency, avoiding some AS, ...). Here we deliberately keep the longest
    // route to make the point that the choice belongs to the application. (See this
    // example's module docs for the declarative path-policy alternative.)
    let chosen = paths.last().expect("paths is non-empty");
    println!("deliberately selected: {chosen}");

    server.abort();
    Ok(())
}

/// Number of interfaces on a path; used only to order the candidates.
fn hop_count(path: &ScionPath) -> usize {
    path.metadata()
        .and_then(|m| m.interfaces.as_ref())
        .map_or(0, Vec::len)
}

/// Sends `payload` to `destination` over the given `path`, then waits until the
/// server echoes that same payload back, resending a few times if needed.
///
/// Matching on the payload matters: a datagram sent over one path can be delayed
/// and surface during a later call, so we ignore any echo that isn't the reply to
/// this exact send.
async fn ping_via(
    socket: &UdpScionSocket,
    destination: ScionSocketIpAddr,
    path: &ScionPath,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut buffer = [0u8; MAX_DATAGRAM];
    for _attempt in 1..=5 {
        socket.send_to_via(payload, destination, path).await?;

        // Drain replies until we see our own payload; a timeout (the `while let`
        // ending) means it is time to resend.
        while let Ok(result) =
            timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await
        {
            let (len, _from) = result?;
            if &buffer[..len] == payload {
                return Ok(());
            }
            tracing::debug!("ignoring echo that does not match our payload");
        }
    }
    anyhow::bail!("no matching echo received from {destination} after 5 attempts")
}

/// Echoes every datagram back to its sender, forever. (See the `udp_echo` example
/// for a walk-through of the server side.)
async fn echo_server(socket: UdpScionSocket) -> anyhow::Result<()> {
    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = socket.recv_from(&mut buffer).await?;
        socket.send_to(&buffer[..len], from).await?;
    }
}

#[cfg(test)]
mod tests {
    use test_log::test;

    /// Smoke test: listing paths and sending over each one must succeed.
    #[test(tokio::test)]
    #[ntest::timeout(30_000)]
    async fn udp_paths_send_over_each_path() {
        super::run()
            .await
            .expect("udp_paths example should succeed");
    }
}
