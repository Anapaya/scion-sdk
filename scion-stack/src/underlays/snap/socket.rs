// Copyright 2025 Anapaya Systems
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
//! SNAP underlay socket.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use anyhow::Context as _;
use bytes::Bytes;
use futures::future::BoxFuture;
use scion_proto::{
    address::SocketAddr,
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
    path::Path,
    wire_encoding::WireEncodeVec,
};
use tokio::sync::mpsc;

use crate::{
    allocation::PortGuard,
    scionstack::{
        AsyncUdpUnderlaySocket, ScionSocketReceiveError, ScionSocketSendError, UnderlaySocket,
        udp_polling::UdpPoller,
    },
    snap_tunnel::SnapTunnelSender,
};

/// A SNAP underlay socket.
pub struct SnapUnderlaySocket {
    pub(crate) tunnel: SnapTunnelSender,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) _port_allocation: Arc<PortGuard>,
    pub(crate) receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<ScionPacketRaw>>>,
}

impl SnapUnderlaySocket {
    /// Creates a new SNAP underlay socket.
    pub fn new(
        tunnel: SnapTunnelSender,
        bind_addr: SocketAddr,
        port_allocation: PortGuard,
        receiver: mpsc::Receiver<ScionPacketRaw>,
    ) -> Self {
        Self {
            tunnel,
            bind_addr,
            _port_allocation: Arc::new(port_allocation),
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }
}

impl UnderlaySocket for SnapUnderlaySocket {
    fn send<'a>(
        &'a self,
        packet: ScionPacketRaw,
    ) -> BoxFuture<'a, Result<(), crate::scionstack::ScionSocketSendError>> {
        Box::pin(async move {
            let packet = packet.encode_to_bytes_vec().concat().into();
            self.tunnel.send_datagram_wait(packet).await.map_err(|e| {
                match e {
                    quinn::SendDatagramError::TooLarge => {
                        ScionSocketSendError::InvalidPacket("Packet too large".into())
                    }
                    quinn::SendDatagramError::ConnectionLost(_) => {
                        ScionSocketSendError::NetworkUnreachable(
                            crate::scionstack::NetworkError::DestinationUnreachable(
                                "Connection lost, reconnecting".into(),
                            ),
                        )
                    }
                    quinn::SendDatagramError::Disabled
                    | quinn::SendDatagramError::UnsupportedByPeer => {
                        ScionSocketSendError::IoError(std::io::Error::other(format!(
                            "unexpected error from SNAP tunnel: {e:?}"
                        )))
                    }
                }
            })?;
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ScionPacketRaw, crate::scionstack::ScionSocketReceiveError>> {
        Box::pin(async move {
            let packet = match self.receiver.lock().await.recv().await {
                Some(packet) => packet,
                None => {
                    return Err(ScionSocketReceiveError::IoError(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Connection closed",
                    )));
                }
            };
            Ok(packet)
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

pub(crate) struct SnapAsyncUdpSocket {
    tunnel: SnapTunnelSender,
    bind_addr: SocketAddr,
    receiver: Mutex<mpsc::Receiver<ScionPacketRaw>>,
    _port_allocation: PortGuard,
}

impl SnapAsyncUdpSocket {
    pub fn new(
        tunnel: SnapTunnelSender,
        bind_addr: SocketAddr,
        receiver: mpsc::Receiver<ScionPacketRaw>,
        port_allocation: PortGuard,
    ) -> Self {
        Self {
            tunnel,
            bind_addr,
            receiver: Mutex::new(receiver),
            _port_allocation: port_allocation,
        }
    }
}

#[derive(Debug)]
struct AlwaysReadyUdpPoller;

impl UdpPoller for AlwaysReadyUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpUnderlaySocket for SnapAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysReadyUdpPoller)
    }

    fn try_send(&self, raw_packet: ScionPacketRaw) -> Result<(), std::io::Error> {
        match self
            .tunnel
            .send_datagram(raw_packet.encode_to_bytes_vec().concat().into())
        {
            Ok(_) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => Ok(()),
            Err(quinn::SendDatagramError::ConnectionLost(_)) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "Connection lost, reconnecting",
                ))
            }
            e => Err(std::io::Error::other(format!("Send error: {e:?}"))),
        }
    }

    fn poll_recv_from_with_path(
        &self,
        cx: &mut Context,
    ) -> Poll<std::io::Result<(SocketAddr, Bytes, Path)>> {
        match ready!(self.receiver.lock().unwrap().poll_recv(cx)) {
            Some(packet) => {
                let fallible = || {
                    let src = packet
                        .headers
                        .address
                        .source()
                        .context("no source address")?;
                    let dst = packet
                        .headers
                        .address
                        .destination()
                        .context("no destination address")?;

                    let path = Path::new(
                        packet.headers.path.clone(),
                        ByEndpoint {
                            source: src.isd_asn(),
                            destination: dst.isd_asn(),
                        },
                        None,
                    );

                    let packet: ScionPacketUdp = packet.try_into().context("invalid UDP packet")?;

                    anyhow::Ok((
                        SocketAddr::new(src, packet.src_port()),
                        packet.datagram.payload,
                        path,
                    ))
                };

                match fallible() {
                    Ok(result) => Poll::Ready(Ok(result)),
                    Err(e) => {
                        // Ignore errors, we just return pending.
                        tracing::error!("Error receiving packet: {}", e);
                        Poll::Pending
                    }
                }
            }
            None => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                )))
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}
