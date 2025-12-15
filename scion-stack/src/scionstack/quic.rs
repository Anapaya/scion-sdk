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
//! SCION stack QUICK endpoint.

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    hash::{BuildHasher, Hash as _, Hasher as _},
    io::ErrorKind,
    net::{IpAddr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Poll, ready},
    time::{Duration, Instant},
};

use bytes::BufMut as _;
use chrono::Utc;
use foldhash::fast::FixedState;
use quinn::{AsyncUdpSocket, udp::RecvMeta};
use scion_proto::{
    address::SocketAddr,
    packet::{ByEndpoint, ScionPacketUdp},
};

use super::{AsyncUdpUnderlaySocket, udp_polling::UdpPoller};
use crate::{
    path::manager::{PathPrefetcher, SyncPathManager},
    quic::ScionQuinnConn,
};

/// Log at most 1 IO error every 3 seconds.
const IO_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(3);

/// A wrapper around a quinn::Endpoint that translates between SCION and ip:port addresses.
///
/// This is necessary because quinn expects a std::net::SocketAddr, but SCION uses
/// scion_proto::address::SocketAddr.
///
/// Addresses are mapped by the provided ScionAsyncUdpSocket.
pub struct Endpoint {
    inner: quinn::Endpoint,
    path_prefetcher: Arc<dyn PathPrefetcher + Send + Sync>,
    address_translator: Arc<AddressTranslator>,
    local_scion_addr: scion_proto::address::SocketAddr,
}

impl Endpoint {
    /// Creates a new endpoint.
    pub fn new_with_abstract_socket(
        config: quinn::EndpointConfig,
        server_config: Option<quinn::ServerConfig>,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        local_scion_addr: scion_proto::address::SocketAddr,
        runtime: Arc<dyn quinn::Runtime>,
        pather: Arc<dyn PathPrefetcher + Send + Sync>,
        address_translator: Arc<AddressTranslator>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: quinn::Endpoint::new_with_abstract_socket(
                config,
                server_config,
                socket,
                runtime,
            )?,
            path_prefetcher: pather,
            address_translator,
            local_scion_addr,
        })
    }

    /// Connect to the address.
    pub fn connect(
        &self,
        addr: scion_proto::address::SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connecting, quinn::ConnectError> {
        let mapped_addr = self
            .address_translator
            .register_scion_address(addr.scion_address());
        let local_addr = self
            .address_translator
            .lookup_scion_address(self.inner.local_addr().unwrap().ip())
            .unwrap();
        self.path_prefetcher
            .prefetch_path(local_addr.isd_asn(), addr.isd_asn());
        self.inner.connect(
            std::net::SocketAddr::new(mapped_addr, addr.port()),
            server_name,
        )
    }

    /// Accepts a new incoming connection.
    pub async fn accept(&self) -> Result<Option<ScionQuinnConn>, quinn::ConnectionError> {
        let incoming = self.inner.accept().await;
        if let Some(incoming) = incoming {
            let remote_socket_addr = incoming.remote_address();
            let local_scion_addr = incoming
                .local_ip()
                .and_then(|ip| self.address_translator.lookup_scion_address(ip));
            let conn = ScionQuinnConn {
                inner: incoming.await?,
                // XXX(uniquefine): For now the ScionAsyncUdpSocket does not have access to a
                // packets destination address, so we cannot lookup the local SCION
                // address.
                local_addr: local_scion_addr,
                remote_addr: scion_proto::address::SocketAddr::new(
                    self.address_translator
                        .lookup_scion_address(remote_socket_addr.ip())
                        .or_else(|| {
                            panic!(
                                "no scion address mapped for ip, this should never happen: {}",
                                remote_socket_addr.ip(),
                            );
                        })
                        .unwrap(),
                    remote_socket_addr.port(),
                ),
            };
            Ok(Some(conn))
        } else {
            Ok(None)
        }
    }

    /// Set the default QUIC client configuration.
    pub fn set_default_client_config(&mut self, config: quinn::ClientConfig) {
        self.inner.set_default_client_config(config);
    }

    /// Wait until all connections on the endpoint cleanly shut down.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }

    /// Returns the local socket address of the endpoint.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the local SCION address of the endpoint.
    pub fn local_scion_addr(&self) -> scion_proto::address::SocketAddr {
        self.local_scion_addr
    }
}

/// Type that can translate between SCION and IP addresses.
// TODO(uniquefine): Expiration or cleanup of translated addresses
pub struct AddressTranslator {
    build_hasher: FixedState,
    addr_map: Mutex<HashMap<std::net::Ipv6Addr, scion_proto::address::ScionAddr>>,
}

impl Debug for AddressTranslator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressTranslatorImpl {{ {} }}",
            self.addr_map
                .lock()
                .unwrap()
                .iter()
                .map(|(ip, addr)| format!("{ip} -> {addr}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl AddressTranslator {
    /// Creates a new address translator.
    pub fn new(build_hasher: FixedState) -> Self {
        Self {
            build_hasher,
            addr_map: Mutex::new(HashMap::new()),
        }
    }

    fn hash_scion_address(&self, addr: scion_proto::address::ScionAddr) -> std::net::Ipv6Addr {
        let mut hasher = self.build_hasher.build_hasher();
        hasher.write_u64(addr.isd_asn().to_u64());
        addr.local_address().hash(&mut hasher);
        Ipv6Addr::from(hasher.finish() as u128)
    }

    /// Registers the SCION address and returns the corresponding IP address.
    pub fn register_scion_address(
        &self,
        addr: scion_proto::address::ScionAddr,
    ) -> std::net::IpAddr {
        let ip = self.hash_scion_address(addr);
        let mut addr_map = self.addr_map.lock().unwrap();
        addr_map.entry(ip).or_insert(addr);
        IpAddr::V6(ip)
    }

    /// Looks up the SCION address for the given IP address.
    pub fn lookup_scion_address(
        &self,
        ip: std::net::IpAddr,
    ) -> Option<scion_proto::address::ScionAddr> {
        let ip = match ip {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => return None,
        };
        self.addr_map.lock().unwrap().get(&ip).cloned()
    }
}

impl Default for AddressTranslator {
    fn default() -> Self {
        Self {
            build_hasher: FixedState::with_seed(42),
            addr_map: Mutex::new(HashMap::new()),
        }
    }
}

/// A path-aware UDP socket that implements the [quinn::AsyncUdpSocket] trait.
///
/// The socket translates the SCION addresses of incoming packets to IP addresses that
/// are used by quinn.
/// To connect to a SCION destination, the destination SCION address must first be registered
/// with the [AddressTranslator].
pub(crate) struct ScionAsyncUdpSocket {
    socket: Arc<dyn AsyncUdpUnderlaySocket>,
    path_manager: Arc<dyn SyncPathManager + Send + Sync>,
    address_translator: Arc<AddressTranslator>,
    /// The last time a poll_recv error was logged.
    last_recv_error: Mutex<Instant>,
    /// The last time a try_send error was logged.
    last_send_error: Mutex<Instant>,
}

impl ScionAsyncUdpSocket {
    pub fn new(
        socket: Arc<dyn AsyncUdpUnderlaySocket>,
        path_manager: Arc<dyn SyncPathManager + Send + Sync>,
        address_translator: Arc<AddressTranslator>,
    ) -> Self {
        let now = Instant::now();
        let instant = now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now);
        Self {
            socket,
            path_manager,
            address_translator,
            last_recv_error: Mutex::new(instant),
            last_send_error: Mutex::new(instant),
        }
    }
}

impl std::fmt::Debug for ScionAsyncUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ScionAsyncUdpSocket({})",
            match self.local_addr() {
                Ok(addr) => addr.to_string(),
                Err(e) => e.to_string(),
            }
        ))
    }
}

/// A wrapper that implements quinn::UdpPoller by delegating to scionstack::UdpPoller
/// This allows scionstack to remain decoupled from the quinn crate
struct QuinnUdpPollerWrapper(Pin<Box<dyn UdpPoller>>);

impl std::fmt::Debug for QuinnUdpPollerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl QuinnUdpPollerWrapper {
    fn new(inner: Pin<Box<dyn UdpPoller>>) -> Self {
        Self(inner)
    }
}

impl quinn::UdpPoller for QuinnUdpPollerWrapper {
    fn poll_writable(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for ScionAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        let socket = self.socket.clone();
        let inner_poller = socket.create_io_poller();
        let wrapper = QuinnUdpPollerWrapper::new(inner_poller);
        Box::pin(wrapper)
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let buf = bytes::Bytes::copy_from_slice(transmit.contents);
        let remote_scion_addr = SocketAddr::new(
            self.address_translator
                .lookup_scion_address(transmit.destination.ip())
                .ok_or(std::io::Error::other(format!(
                    "no scion address mapped for ip, this should never happen: {}",
                    transmit.destination.ip(),
                )))?,
            transmit.destination.port(),
        );
        let path = self.path_manager.try_cached_path(
            self.socket.local_addr().isd_asn(),
            remote_scion_addr.isd_asn(),
            Utc::now(),
        )?;

        let path = match path {
            Some(path) => path,
            None => return Ok(()),
        };

        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: self.socket.local_addr(),
                destination: remote_scion_addr,
            },
            path.data_plane_path.to_bytes_path(),
            buf,
        )
        .map_err(|_| std::io::Error::other("failed to encode packet"))?;

        match self.socket.try_send(packet.into()) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                // XXX: We only log the error such that the quinn connection driver doesn't quit.
                debounced_warn(
                    &self.last_send_error,
                    "Failed to send on the underlying socket",
                    e,
                );
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match ready!(self.socket.poll_recv_from_with_path(cx)) {
            Ok((remote, bytes, path)) => {
                match path.to_reversed() {
                    Ok(path) => {
                        // Register the path for later reuse
                        self.path_manager.register_path(
                            remote.isd_asn(),
                            self.socket.local_addr().isd_asn(),
                            Utc::now(),
                            path,
                        );
                    }
                    Err(e) => {
                        tracing::trace!("Failed to reverse path for registration: {}", e)
                    }
                }

                let remote_ip = self
                    .address_translator
                    .register_scion_address(remote.scion_address());

                meta[0] = RecvMeta {
                    addr: std::net::SocketAddr::new(remote_ip, remote.port()),
                    len: bytes.len(),
                    ecn: None,
                    stride: bytes.len(),
                    dst_ip: self.socket.local_addr().local_address().map(|s| s.ip()),
                };
                bufs[0].as_mut().put_slice(&bytes);

                Poll::Ready(Ok(1))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Poll::Ready(Err(e)),
            Err(e) => {
                // XXX: We only log the error such that the endpoint driver doesn't quit.
                debounced_warn(
                    &self.last_recv_error,
                    "Failed to receive on the underlying socket",
                    e,
                );

                Poll::Pending
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(
            self.address_translator
                .register_scion_address(self.socket.local_addr().scion_address()),
            self.socket.local_addr().port(),
        ))
    }
}

/// Logs a warning message when an error occurs.
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
// Inspired by quinn's `log_sendmsg_error`.
fn debounced_warn(last_send_error: &Mutex<Instant>, msg: &str, err: impl core::fmt::Debug) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisoned lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        tracing::warn!(?err, "{msg}");
    }
}
