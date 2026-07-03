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

//! The client connection bootstrap.
//!
//! The `connect()` function performs `squiche::connect`, drives the QUIC
//! handshake until the connection is established (the client analog of the
//! server endpoint's "establishing set", but far simpler — one connection, no
//! CID/retry/demux), enforces the `h3` ALPN, constructs the [`Http3ClientApp`]
//! via [`on_established`](crate::app::QuicScionApplication::on_established), and
//! builds the [`ConnectionHandle`].
//!
//! Once established, the connection is driven by two cooperating loops on the
//! bootstrap task: the shared [`QuicScionConnDriver`] (writes, timers, and
//! stepping the app) and the client [`ingress`] loop (reads inbound packets —
//! the single-connection analog of the server endpoint's recv
//! loop). The same task drives the handshake and then both loops, so the socket
//! is read continuously and there is no window where nobody is reading it. When
//! the connection closes the driver returns, which cancels the ingress loop.

mod ingress;

use std::{sync::Arc, time::Duration};

use ring::rand::{SecureRandom, SystemRandom};
use sciparse::address::socket_addr::ScionSocketAddr;
use tokio::sync::{Notify, oneshot};

use crate::{
    app::QuicScionApplication,
    h3::{
        client::{app::Http3ClientApp, error::EstablishError},
        common::H3_INTERNAL_ERROR,
    },
    quic::connection::{ConnectionHandle, IsdAsnPair, QuicScionConn, QuicScionConnDriver},
    socket::GenericScionUdpSocket,
};

/// Establishes an HTTP/3 connection to `remote` and returns a handle to it.
///
/// Spawns a task that drives the handshake, builds the application and handle,
/// reports the handle back, and then becomes the connection driver for the life
/// of the connection.
pub(crate) async fn connect(
    remote: ScionSocketAddr,
    socket: Arc<dyn GenericScionUdpSocket>,
    server_name: Option<String>,
    mut quiche_config: squiche::Config,
) -> Result<ConnectionHandle<Http3ClientApp>, EstablishError> {
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let handshake_result =
            handshake(remote, &socket, server_name.as_deref(), &mut quiche_config).await;
        let conn = match handshake_result {
            Ok(conn) => conn,
            Err(err) => {
                let _ = tx.send(Err(err));
                return;
            }
        };

        let mut inner = conn;
        // Enforce the `h3` ALPN: a mismatch means no usable connection.
        if inner.application_proto() != b"h3" {
            let _ = inner.close(true, H3_INTERNAL_ERROR, b"expected h3 alpn");
            let _ = tx.send(Err(EstablishError::AlpnMismatch));
            return;
        }

        let app = Http3ClientApp::on_established(&mut inner, &());
        if app.h3.is_none() {
            let _ = tx.send(Err(EstablishError::H3Init));
            return;
        }

        let asn_pair = IsdAsnPair {
            from: socket.local_addr().isd_asn(),
            to: remote.isd_asn(),
        };
        let handle = ConnectionHandle::new(
            Notify::new(),
            QuicScionConn {
                asn_pair,
                inner,
                app,
            },
        );

        if tx.send(Ok(handle.clone())).is_err() {
            // The caller gave up waiting for the connection; nothing to drive.
            return;
        }

        // Drive the established connection with two cooperating loops: the shared
        // driver (writes + timers + stepping the app) and the client ingress loop
        // (feeds inbound packets, the single-connection analog of the server
        // endpoint's recv loop). When the connection closes the driver returns,
        // and `select!` drops — and thereby cancels — the ingress loop.
        let driver = QuicScionConnDriver::new(handle.clone(), socket.clone());
        tokio::select! {
            res = driver.run() => {
                if let Err(err) = res {
                    tracing::warn!(?err, "client connection driver exited with a socket error");
                }
            }
            _ = ingress::run(handle, socket) => {}
        }
    });

    rx.await.map_err(|_| EstablishError::Handshake)?
}

/// Drives the QUIC handshake until the connection is established, returning the
/// established `squiche::Connection`.
async fn handshake(
    remote: ScionSocketAddr,
    socket: &Arc<dyn GenericScionUdpSocket>,
    server_name: Option<&str>,
    config: &mut squiche::Config,
) -> Result<squiche::Connection, EstablishError> {
    let scid = generate_connection_id();
    let local_addr = socket
        .local_addr()
        .socket_addr()
        .ok_or(EstablishError::InvalidAddress)?;
    let remote_addr = remote.socket_addr().ok_or(EstablishError::InvalidAddress)?;

    let mut conn = squiche::connect(server_name, &scid, local_addr, remote_addr, config)
        .map_err(EstablishError::Quic)?;

    let mut send_buf = Box::new([0u8; 65535]);
    let mut recv_buf = Box::new([0u8; 65535]);

    loop {
        // Flush everything the connection has queued (handshake packets,
        // retransmissions, ACKs).
        loop {
            match conn.send(send_buf.as_mut()) {
                Ok((n, info)) => {
                    let to = ScionSocketAddr::from_std(remote.isd_asn(), info.to);
                    socket
                        .send_to(&send_buf[..n], to)
                        .await
                        .map_err(EstablishError::Io)?;
                }
                Err(squiche::Error::Done) => break,
                Err(err) => return Err(EstablishError::Quic(err)),
            }
        }

        if conn.is_established() {
            return Ok(conn);
        }
        if conn.is_closed() {
            return Err(EstablishError::Handshake);
        }

        // Wait for an inbound packet or the connection's timeout.
        let sleep = conn.timeout().unwrap_or(Duration::from_secs(1));
        tokio::select! {
            res = socket.recv_from(recv_buf.as_mut()) => {
                let (len, from) = res.map_err(EstablishError::Io)?;
                if let (Some(from), Some(to)) =
                    (from.socket_addr(), socket.local_addr().socket_addr())
                {
                    let recv_info = squiche::RecvInfo { from, to };
                    if let Err(err) = conn.recv(&mut recv_buf[..len], recv_info) {
                        tracing::warn!(?err, "client handshake: error feeding inbound packet");
                    }
                }
            }
            _ = tokio::time::sleep(sleep) => {
                conn.on_timeout();
            }
        }
    }
}

/// Generates a random QUIC source connection ID.
fn generate_connection_id() -> squiche::ConnectionId<'static> {
    let mut scid = [0u8; squiche::MAX_CONN_ID_LEN];
    // `fill` only fails for unsupported lengths; a fixed-size array never does.
    SystemRandom::new()
        .fill(&mut scid)
        .expect("system RNG fill");
    squiche::ConnectionId::from_vec(scid.to_vec())
}
