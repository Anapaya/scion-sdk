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

//! Filtering SCION paths with a path policy.
//!
//! The `udp_paths` example picks a path by hand. Most applications instead have a
//! *standing rule* ("never leave this ISD", "avoid AS X") that the stack should
//! apply to every send. This example expresses such a rule as a [`PathPolicy`] and
//! attaches it to the socket with [`SocketConfig::with_path_policy`], after which
//! [`send_to`] only ever routes over paths that satisfy it.
//!
//! For common cases, prefer a built-in policy: `sciparse` ships hop-pattern and
//! ACL matchers that implement [`PathPolicy`]. This example writes a small custom
//! policy to show how the trait works.
//!
//! It uses the same triangular topology as `udp_paths`: the client reaches the
//! server either directly or via the detour AS 2-ff00:0:222. The policy below
//! forbids the detour, so the stack is left with the direct path.
//!
//! ```text
//!                     2-ff00:0:222   (forbidden by the policy)
//!                 #1 /            \ #2
//!                   /              \
//!             #2   /                \  #4
//!   1-ff00:0:132  #1 ───────────── #3  2-ff00:0:212
//!     (client)                           (server)
//! ```
//!
//! Run it with:
//!
//! ```text
//! cargo run -p scion-stack --example udp_path_policy
//! ```
//!
//! [`PathPolicy`]: scion_stack::path::policy::PathPolicy
//! [`SocketConfig::with_path_policy`]: scion_stack::stack::SocketConfig::with_path_policy
//! [`send_to`]: scion_stack::stack::UdpScionSocket::send_to

mod common;

use std::time::Duration;

use pocketscion::util::topologies::{
    IA132, IA212, IA222, UnderlayType, minimal::two_path_topology,
};
use scion_stack::{
    path::policy::PathPolicy,
    stack::{SocketConfig, UdpScionSocket},
};
use sciparse::{
    address::ip_socket_addr::ScionSocketIpAddr, identifier::isd_asn::IsdAsn, path::ScionPath,
};
use tokio::time::timeout;

/// Largest datagram we bother to buffer in this example.
const MAX_DATAGRAM: usize = 2048;

// ANCHOR: path-policy
/// A path policy that rejects any path traversing the AS `avoid`.
///
/// A [`PathPolicy`](scion_stack::path::policy::PathPolicy) is just a predicate over
/// a [`ScionPath`]: return `true` to keep the path, `false` to discard it.
struct AvoidAs {
    avoid: IsdAsn,
}

impl PathPolicy for AvoidAs {
    fn predicate(&self, path: &ScionPath) -> bool {
        let Some(interfaces) = path.metadata().and_then(|m| m.interfaces.as_ref()) else {
            // Without interface metadata we cannot tell which ASes the path
            // crosses, so we keep it rather than filtering blindly.
            return true;
        };
        !interfaces
            .iter()
            .any(|hop| hop.interface.isd_asn == self.avoid)
    }
}
// ANCHOR_END: path-policy

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

/// Starts the triangular network and sends one datagram under a path policy that
/// forbids the detour AS, leaving the stack to use the direct path.
async fn run() -> anyhow::Result<()> {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let ps = two_path_topology(UnderlayType::Snap).await;

    let server_stack = common::build_stack(&ps, IA212).await?;
    let server_socket = server_stack.bind(None).await?;
    let server_addr = server_socket.local_addr();
    let server = tokio::spawn(echo_server(server_socket));

    let client_stack = common::build_stack(&ps, IA132).await?;

    // ANCHOR: bind-with-policy
    // Attach the policy to the socket when binding. From now on `send_to` only
    // ever routes over paths the policy accepts, here anything except the detour
    // through 2-ff00:0:222. No explicit path selection is needed.
    let config = SocketConfig::new().with_path_policy(AvoidAs { avoid: IA222 });
    let client_socket = client_stack.bind_with_config(None, config).await?;

    let reply = ping(
        &client_socket,
        server_addr,
        b"hello via a policy-approved path",
    )
    .await?;
    // ANCHOR_END: bind-with-policy
    println!("client received echo: {}", String::from_utf8_lossy(&reply));

    server.abort();
    Ok(())
}

/// Sends `payload` to `destination` and waits for the echoed reply, resending a
/// handful of times before giving up.
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

/// Echoes every datagram straight back to its sender. (See `udp_echo` for a
/// walk-through of the server side.)
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

    /// Smoke test: sending under the path policy must still reach the server (over
    /// the one path the policy allows).
    #[test(tokio::test)]
    #[ntest::timeout(30_000)]
    async fn udp_path_policy_reaches_server() {
        super::run()
            .await
            .expect("udp_path_policy example should succeed");
    }
}
