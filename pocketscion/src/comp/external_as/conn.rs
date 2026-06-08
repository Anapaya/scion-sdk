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

use scion_proto::{
    address::IsdAsn,
    packet::ScionPacketRaw,
    wire_encoding::{WireDecode, WireEncodeVec},
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
    pub async fn send(&self, send_msg: ScionPacketRaw) -> io::Result<usize> {
        let bytes: Vec<u8> = send_msg.encode_to_bytes_vec().concat();

        self.socket.send_to(&bytes, self.peer_addr).await
    }

    /// Attempts to send a packet to the External AS peer address, returning an error if the
    /// send buffer is full or if another socket error occurs.
    pub fn try_send(&self, send_msg: ScionPacketRaw) -> io::Result<usize> {
        let bytes: Vec<u8> = send_msg.encode_to_bytes_vec().concat();

        self.socket.try_send_to(&bytes, self.peer_addr)
    }

    fn check_recv(&self, buf: &[u8], recv_addr: SocketAddr) -> io::Result<ScionPacketRaw> {
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

        let packet = ScionPacketRaw::decode(&mut &buf[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(packet)
    }

    /// Receives a packet from the External AS, validating that it comes from the expected peer
    /// address and returns the decoded packet, otherwise continues to wait for the next packet.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<ScionPacketRaw> {
        loop {
            let (size, recv_addr) = self.socket.recv_from(buf).await?;
            match self.check_recv(&buf[..size], recv_addr) {
                Ok(pkt) => return Ok(pkt),
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Received invalid packet from External Interface {}, ignoring packet and continuing to receive",
                        self.isd_as
                    );
                }
            }
        }
    }

    /// Attempts to receive a packet from the External AS, returning an error if the recv buffer
    /// is empty, or if another socket error occurs or if the received packet was
    /// invalid.
    #[expect(unused)]
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<ScionPacketRaw> {
        let (size, recv_addr) = self.socket.try_recv_from(buf)?;
        self.check_recv(&buf[..size], recv_addr)
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
