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

//! Shared test utilities.

use std::{io, net::Ipv4Addr};

use scion_proto::address::{ScionAddr, SocketAddr};
use scion_sdk_quic_scion::{
    quic::config::QuicConfig,
    socket::{BoxedSocketError, GenericScionUdpSocket},
};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, mpsc};

/// Setup a client and server socket in two different ASes in the pocket SCION topology.
pub fn setup_sockets() -> (MockScionSocket, MockScionSocket) {
    let ia132 = "1-32".parse().unwrap();
    let client_addr = ScionAddr::new(ia132, Ipv4Addr::new(10, 1, 1, 0).into());
    let client_addr = SocketAddr::new(client_addr, 0);

    let ia212 = "2-12".parse().unwrap();
    let server_addr = ScionAddr::new(ia212, Ipv4Addr::new(10, 2, 1, 0).into());
    let server_addr = SocketAddr::new(server_addr, 0);

    MockScionSocket::pair(1024, client_addr, server_addr)
}

/// Generates a self-signed certificate and corresponding private key for testing purposes.
pub fn generate_server_config() -> (squiche::Config, NamedTempFile, NamedTempFile) {
    let config = QuicConfig::builder().verify_peer(false).build();

    let mut config = config.to_quiche_config().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    let mut key_file = tempfile::NamedTempFile::new().unwrap();

    use std::io::Write;
    cert_file
        .as_file_mut()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    key_file
        .as_file_mut()
        .write_all(key_pem.as_bytes())
        .unwrap();

    config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .unwrap();

    (config, cert_file, key_file)
}

struct MockDatagram {
    data: Vec<u8>,
    src: SocketAddr,
    dst: SocketAddr,
}

/// Simple in-memory mock implementation of a `GenericScionUdpSocket`
pub struct MockScionSocket {
    recv_channel: Mutex<mpsc::Receiver<MockDatagram>>,
    send_channel: mpsc::Sender<MockDatagram>,
    local_addr: scion_proto::address::SocketAddr,
}

impl MockScionSocket {
    /// Creates a pair of connected `MockScionSocket`s
    pub fn pair(
        queue_size: usize,
        sockaddr_a: SocketAddr,
        sockaddr_b: SocketAddr,
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
    /// Asynchronously sends a Datagram to the specified destination address.
    async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
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

    /// Asynchronously receives a Datagram, writing it into the provided buffer, and returns the
    /// number of bytes read and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), BoxedSocketError> {
        loop {
            let datagram = self.recv_channel.lock().await.recv().await.ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Channel closed",
                )) as BoxedSocketError
            })?;

            if datagram.dst != self.local_addr {
                continue; // Ignore datagrams not addressed to this socket
            }
            let data = datagram.data;
            let src = datagram.src;

            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            return Ok((len, src));
        }
    }

    /// Returns the local socket address of this socket.
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}
