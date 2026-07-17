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

//! "Hello, SCION" over UDP.
//!
//! A client in one AS sends a datagram to an echo server in another AS and prints
//! the reply. Everything runs against a [PocketSCION] network that this example
//! starts itself.
//!
//! The network is two ASes joined by a single link:
//!
//! ```text
//!   1-ff00:0:132  #1 ───────── #3  2-ff00:0:212
//!     (client)                       (server)
//! ```
//!
//! Run it with:
//!
//! ```text
//! cargo run -p scion-stack --example udp_echo
//! ```
//!
//! [PocketSCION]: pocketscion

mod common;

use std::time::Duration;

use pocketscion::util::topologies::{IA132, IA212, UnderlayType, minimal::minimal_topology};
use scion_stack::stack::UdpScionSocket;
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tokio::time::timeout;

/// Largest datagram we bother to buffer in this example.
const MAX_DATAGRAM: usize = 2048;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts a two-AS SCION network, runs an echo server, and pings it once.
async fn run() -> anyhow::Result<()> {
    // PocketSCION uses rustls for its control plane; pick a crypto backend.
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // ANCHOR: start-pocketscion
    // Start a minimal SCION network: two ASes joined by a single link. The returned
    // handle owns the whole simulation.
    let ps = minimal_topology(UnderlayType::Snap).await;
    // ANCHOR_END: start-pocketscion

    // ANCHOR: server
    // Bring up the echo server in AS 2-ff00:0:212 and let it run in the background.
    let server_stack = common::build_stack(&ps, IA212).await?;
    let server_socket = server_stack.bind(None).await?;
    let server_addr = server_socket.local_addr();
    println!("echo server listening on {server_addr}");
    let server = tokio::spawn(echo_server(server_socket));
    // ANCHOR_END: server

    // ANCHOR: client
    // Bring up the client in AS 1-ff00:0:132 and send one datagram.
    let client_stack = common::build_stack(&ps, IA132).await?;
    let client_socket = client_stack.bind(None).await?;

    let reply = ping(&client_socket, server_addr, b"Hello, SCION!").await?;
    println!("client received echo: {}", String::from_utf8_lossy(&reply));
    // ANCHOR_END: client

    server.abort();
    Ok(())
}

/// Echoes every datagram straight back to whoever sent it, forever.
///
/// [`recv_from`](UdpScionSocket::recv_from) yields the sender's SCION address, and
/// the socket automatically remembers a return path to it, so [`send_to`] can
/// reply without the application ever touching path selection.
///
/// [`send_to`]: UdpScionSocket::send_to
// ANCHOR: echo-server
async fn echo_server(socket: UdpScionSocket) -> anyhow::Result<()> {
    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        let (len, from) = socket.recv_from(&mut buffer).await?;
        socket.send_to(&buffer[..len], from).await?;
    }
}
// ANCHOR_END: echo-server

/// Sends `payload` to `destination` and waits for the echoed reply.
///
/// UDP datagrams can be dropped, so we resend a handful of times before giving up.
// ANCHOR: ping
async fn ping(
    socket: &UdpScionSocket,
    destination: ScionSocketIpAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = [0u8; MAX_DATAGRAM];
    for attempt in 1..=5 {
        socket.send_to(payload, destination).await?;
        match timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await {
            Ok(result) => {
                let (len, _from) = result?;
                return Ok(buffer[..len].to_vec());
            }
            Err(_elapsed) => tracing::debug!(attempt, "no echo yet, resending"),
        }
    }
    anyhow::bail!("no echo received from {destination} after 5 attempts")
}
// ANCHOR_END: ping

#[cfg(test)]
mod tests {
    use test_log::test;

    /// End-to-end smoke test: the example must complete a full echo round-trip.
    #[test(tokio::test)]
    #[ntest::timeout(30_000)]
    async fn udp_echo_roundtrip() {
        super::run().await.expect("udp_echo example should succeed");
    }
}
