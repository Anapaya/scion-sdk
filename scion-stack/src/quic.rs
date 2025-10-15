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
//! SCION stack QUIC connection.

use std::future::Future;

use bytes::Bytes;

/// Abstract over different types of Quinn-connections that differ only in the
/// type of address that is used for the local and remote address.
pub trait QuinnConn: Clone + Send + Sync {
    /// The type used to represent the local address.
    type AddrType: std::fmt::Debug;
    /// The type used to represent the remote socket address.
    type SockAddrType: std::fmt::Debug;
    /// Opens a new bidirectional stream.
    fn open_bi(&self) -> quinn::OpenBi<'_>;
    /// Accepts a new incoming bidirectional stream.
    fn accept_bi(&self) -> quinn::AcceptBi<'_>;
    /// Reads a datagram, if one is available.
    fn read_datagram(&self) -> quinn::ReadDatagram<'_>;
    /// Sends a datagram.
    fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError>;
    /// Sends a datagram and wait for it to be sent.
    fn send_datagram_wait(&self, data: Bytes) -> quinn::SendDatagram<'_>;
    /// Waits for the connection to be closed.
    fn closed(&self) -> impl Future<Output = quinn::ConnectionError> + Send;
    /// Returns the reason why the connection was closed, if it was closed.
    fn close_reason(&self) -> Option<quinn::ConnectionError>;
    /// Closes the connection with the given error code and reason.
    fn close(&self, error_code: quinn::VarInt, reason: &[u8]);
    /// Returns the maximum datagram size that can be sent on this connection.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Returns the amount of buffer space available for sending datagrams.
    fn datagram_send_buffer_space(&self) -> usize;
    /// Returns the remote socket address type.
    fn remote_address(&self) -> Self::SockAddrType;
    /// Returns the local address type.
    fn local_ip(&self) -> Option<Self::AddrType>;
    /// Returns a stable connection identifier.
    fn stable_id(&self) -> usize;
    /// Returns connection statistics.
    fn stats(&self) -> quinn::ConnectionStats;
}

/// SCION quinn connection.
#[derive(Clone)]
pub struct ScionQuinnConn {
    pub(crate) inner: quinn::Connection,
    /// The local SCION address of the connection.
    pub(crate) local_addr: Option<scion_proto::address::ScionAddr>,
    /// The remote SCION socket address of the connection.
    pub(crate) remote_addr: scion_proto::address::SocketAddr,
}

impl QuinnConn for ScionQuinnConn {
    type AddrType = scion_proto::address::ScionAddr;

    type SockAddrType = scion_proto::address::SocketAddr;

    fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.inner.open_bi()
    }

    fn accept_bi(&self) -> quinn::AcceptBi<'_> {
        self.inner.accept_bi()
    }

    fn read_datagram(&self) -> quinn::ReadDatagram<'_> {
        self.inner.read_datagram()
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.inner.send_datagram(data)
    }

    fn send_datagram_wait(&self, data: Bytes) -> quinn::SendDatagram<'_> {
        self.inner.send_datagram_wait(data)
    }

    async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }

    fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.inner.close_reason()
    }

    fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    fn datagram_send_buffer_space(&self) -> usize {
        self.inner.datagram_send_buffer_space()
    }

    fn remote_address(&self) -> Self::SockAddrType {
        self.remote_addr
    }

    fn local_ip(&self) -> Option<Self::AddrType> {
        self.local_addr
    }

    fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }
    fn stats(&self) -> quinn::ConnectionStats {
        self.inner.stats()
    }
}

impl QuinnConn for quinn::Connection {
    type AddrType = std::net::IpAddr;

    type SockAddrType = std::net::SocketAddr;

    fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.open_bi()
    }

    fn accept_bi(&self) -> quinn::AcceptBi<'_> {
        self.accept_bi()
    }

    fn read_datagram(&self) -> quinn::ReadDatagram<'_> {
        self.read_datagram()
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.send_datagram(data)
    }

    fn send_datagram_wait(&self, data: Bytes) -> quinn::SendDatagram<'_> {
        self.send_datagram_wait(data)
    }

    fn closed(&self) -> impl Future<Output = quinn::ConnectionError> + Send {
        self.closed()
    }

    fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.close_reason()
    }

    fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.close(error_code, reason);
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.max_datagram_size()
    }

    fn datagram_send_buffer_space(&self) -> usize {
        self.datagram_send_buffer_space()
    }

    fn remote_address(&self) -> Self::SockAddrType {
        self.remote_address()
    }

    fn local_ip(&self) -> Option<Self::AddrType> {
        self.local_ip()
    }

    fn stable_id(&self) -> usize {
        self.stable_id()
    }
    fn stats(&self) -> quinn::ConnectionStats {
        self.stats()
    }
}
