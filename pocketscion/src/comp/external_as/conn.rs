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

//! Connection to an External AS.

use std::{io, net::SocketAddr, sync::Arc};

use sciparse::{
    core::view::View,
    identifier::isd_asn::IsdAsn,
    packet::view::{ScionPacketView, ScionRawPacketView},
};
use tokio::net::UdpSocket;

/// Actual IO connection to the External AS, responsible for sending and receiving packets
/// to/from the peer
#[derive(Debug, Clone)]
pub struct ExternalAsConnection {
    isd_as: IsdAsn,
    /// Socket for sending and receiving packets to/from the peer
    socket: Arc<UdpSocket>,
    /// The address of the peer we expect to receive packets from and send packets to
    ///
    /// Received packets from other ip addresses will be discarded, port is ignored on recv
    peer_addr: SocketAddr,
}

impl ExternalAsConnection {
    pub fn new(
        isd_as: IsdAsn,
        socket: UdpSocket,
        upstream_addr: SocketAddr,
    ) -> ExternalAsConnection {
        ExternalAsConnection {
            isd_as,
            socket: Arc::new(socket),
            peer_addr: upstream_addr,
        }
    }

    /// Sends a packet to the External AS peer address.
    #[expect(unused)]
    pub async fn send(&self, send_msg: &ScionRawPacketView) -> io::Result<usize> {
        self.socket
            .send_to(send_msg.as_slice(), self.peer_addr)
            .await
    }

    /// Attempts to send a packet to the External AS peer address, returning an error if the
    /// send buffer is full or if another socket error occurs.
    pub fn try_send(&self, send_msg: &ScionRawPacketView) -> io::Result<usize> {
        self.socket.try_send_to(send_msg.as_slice(), self.peer_addr)
    }

    fn check_recv<'buf>(
        &self,
        buf: &'buf mut [u8],
        recv_addr: SocketAddr,
    ) -> io::Result<&'buf mut ScionPacketView> {
        let recv_ip = recv_addr.ip();
        let peer_ip = self.peer_addr.ip();

        // Message must come from the same IP as the configured upstream address
        if recv_ip != peer_ip {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Received packet from unexpected IP address {}, expected {}",
                    recv_ip, peer_ip
                ),
            ));
        }

        // We ignore extra bytes in the packet
        let (packet, _rest) = ScionPacketView::from_mut_slice(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(packet)
    }

    /// Receives a packet from the External AS, validating that it comes from the expected peer
    /// address and returns the decoded packet, otherwise continues to wait for the next packet.
    pub async fn recv<'buf>(&self, buf: &'buf mut [u8]) -> io::Result<&'buf mut ScionPacketView> {
        let size = loop {
            let (size, recv_addr) = self.socket.recv_from(buf).await?;

            match self.check_recv(&mut buf[..size], recv_addr) {
                Ok(pkt) => break pkt.as_slice().len(),
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Received invalid packet from External Interface {}, ignoring packet and continuing to receive",
                        self.isd_as
                    );
                }
            }
        };

        // Sadly required because of conditional borrowing in the loop above

        // SAFETY: We just verified that the buffer contains a valid packet, so it's safe to create
        // a view over it without checking again.
        let view = unsafe { ScionPacketView::from_mut_slice_unchecked(&mut buf[..size]) };

        Ok(view)
    }

    /// Attempts to receive a packet from the External AS, returning an error if the recv buffer
    /// is empty, or if another socket error occurs or if the received packet was
    /// invalid.
    #[expect(unused)]
    pub fn try_recv<'buf>(&self, buf: &'buf mut [u8]) -> io::Result<&'buf mut ScionPacketView> {
        let (size, recv_addr) = self.socket.try_recv_from(buf)?;
        self.check_recv(&mut buf[..size], recv_addr)
    }

    /// Returns the peer address configured for this connection
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the local socket address of this connection
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
