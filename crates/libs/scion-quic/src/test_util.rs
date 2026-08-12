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

//! Testing utilities, available behind the `test-util` cargo feature.
//!
//! These types exist so that crates building on `scion-quic` can exercise QUIC
//! endpoints in-memory, without real sockets or a SCION network. They are not
//! part of the stable API: enable them for `[dev-dependencies]` only, never
//! from library code.

use std::io;

use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use tokio::sync::{Mutex, mpsc};

use crate::socket::{BoxedSocketError, GenericScionUdpSocket};

struct MockDatagram {
    data: Vec<u8>,
    src: ScionSocketIpAddr,
    dst: ScionSocketIpAddr,
}

/// Simple in-memory mock implementation of a [`GenericScionUdpSocket`].
///
/// A [`pair`](Self::pair) of these behaves like two sockets wired directly to
/// each other through bounded queues: whatever one side sends, the other
/// receives, with no network, loss, or reordering in between.
pub struct MockScionSocket {
    recv_channel: Mutex<mpsc::Receiver<MockDatagram>>,
    send_channel: mpsc::Sender<MockDatagram>,
    local_addr: ScionSocketIpAddr,
}

impl MockScionSocket {
    /// Creates a pair of connected `MockScionSocket`s.
    pub fn pair(
        queue_size: usize,
        sockaddr_a: ScionSocketIpAddr,
        sockaddr_b: ScionSocketIpAddr,
    ) -> (MockScionSocket, MockScionSocket) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(queue_size);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(queue_size);

        let socket_a = MockScionSocket {
            recv_channel: Mutex::new(a_to_b_rx),
            send_channel: b_to_a_tx,
            local_addr: sockaddr_a,
        };

        let socket_b = MockScionSocket {
            recv_channel: Mutex::new(b_to_a_rx),
            send_channel: a_to_b_tx,
            local_addr: sockaddr_b,
        };

        (socket_a, socket_b)
    }
}

#[async_trait::async_trait]
impl GenericScionUdpSocket for MockScionSocket {
    async fn send_to(
        &self,
        payload: &[u8],
        destination: ScionSocketIpAddr,
    ) -> Result<(), BoxedSocketError> {
        let datagram = MockDatagram {
            data: payload.to_vec(),
            src: self.local_addr,
            dst: destination,
        };

        self.send_channel
            .send(datagram)
            .await
            .map_err(|e| Box::new(e) as BoxedSocketError)
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketIpAddr), BoxedSocketError> {
        loop {
            let datagram = self.recv_channel.lock().await.recv().await.ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Channel closed",
                )) as BoxedSocketError
            })?;

            // Route by the standard socket address only, ignoring the ISD-AS:
            // the endpoint-based QUIC stack tags outgoing packets with the
            // *local* ISD-AS rather than the peer's, so an ISD-AS-sensitive
            // comparison would drop legitimate server->client replies. Test
            // peers always have distinct socket addresses, so this still routes
            // unambiguously.
            if datagram.dst.socket_addr() != self.local_addr.socket_addr() {
                continue; // Ignore datagrams not addressed to this socket
            }
            let data = datagram.data;
            let src = datagram.src;

            // Fail loudly instead of truncating: a silently truncated packet
            // would surface downstream as an opaque QUIC decode failure.
            if data.len() > buf.len() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "receive buffer ({} bytes) too small for datagram ({} bytes)",
                        buf.len(),
                        data.len()
                    ),
                )) as BoxedSocketError);
            }
            buf[..data.len()].copy_from_slice(&data);
            return Ok((data.len(), src));
        }
    }

    fn local_addr(&self) -> ScionSocketIpAddr {
        self.local_addr
    }
}
