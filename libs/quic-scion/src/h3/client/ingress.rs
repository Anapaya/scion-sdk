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

//! The client connection ingress: the inbound packet loop.
//!
//! This is the client's single-connection analog of the server endpoint's recv
//! loop. The server's [`QuicScionConnDriver`](crate::quic::connection::QuicScionConnDriver)
//! only writes packets and drives timers — its inbound packets are read and
//! demultiplexed by the endpoint, which feeds them in with `conn.inner.recv(..)`
//! then [`ConnectionHandle::notify`]. A client owns its whole socket and has
//! exactly one connection, so there is no demultiplexing to do: this loop reads
//! datagrams and feeds them through that same seam, while the unmodified
//! `QuicScionConnDriver` handles the write side.
//!
//! It runs alongside the driver on the bootstrap task (see
//! [`connect`](super::connect)); when the connection closes, the driver returns
//! and the ingress loop is cancelled.

use std::sync::Arc;

use crate::{
    h3::client::app::Http3ClientApp, quic::connection::ConnectionHandle,
    socket::GenericScionUdpSocket,
};

/// Reads inbound datagrams from `socket` and feeds them into the connection,
/// waking the driver after each one.
///
/// Returns when the socket errors or the connection has closed.
pub(crate) async fn run(
    handle: ConnectionHandle<Http3ClientApp>,
    socket: Arc<dyn GenericScionUdpSocket>,
) {
    let mut recv_buf = Box::new([0u8; 65535]);
    let local_addr = socket.local_addr().socket_addr();

    loop {
        let (len, from) = match socket.recv_from(recv_buf.as_mut()).await {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(?err, "client ingress: error receiving packet; stopping");
                return;
            }
        };

        let (Some(from), Some(to)) = (from.socket_addr(), local_addr) else {
            // A packet with an address we can't represent; ignore it.
            continue;
        };
        let recv_info = squiche::RecvInfo { from, to };

        let mut conn = handle.lock();
        if conn.inner.is_closed() {
            return;
        }
        if let Err(err) = conn.inner.recv(&mut recv_buf[..len], recv_info) {
            tracing::warn!(?err, "client ingress: error feeding inbound packet");
        }
        drop(conn);
        // Wake the driver so it can step the app and flush any resulting packets.
        handle.notify();
    }
}
