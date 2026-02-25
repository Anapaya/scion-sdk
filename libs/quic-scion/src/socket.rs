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

//! Generic SCION UDP socket abstraction for QUIC and HTTP/3 implementations.

use scion_proto::address::SocketAddr;

/// Generic trait for a SCION UDP socket that can be used by the QUIC and HTTP/3 implementations.
#[async_trait::async_trait]
pub trait GenericScionUdpSocket: Send + Sync + 'static {
    /// Asynchronously sends a Datagram to the specified destination address.
    async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), BoxedSocketError>;

    /// Asynchronously receives a Datagram, writing it into the provided buffer, and returns the
    /// number of bytes read and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), BoxedSocketError>;

    /// Returns the local socket address of this socket.
    fn local_addr(&self) -> SocketAddr;
}

/// Trait for errors that can occur when using a `GenericScionUdpSocket`.
pub trait SocketError: std::error::Error + Send + Sync + 'static {}
impl<T: std::error::Error + Send + Sync + 'static> SocketError for T {}

/// Boxed error type for socket errors.
pub type BoxedSocketError = Box<dyn SocketError>;
