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
    io, net,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};

use anyhow::Context as _;
use arc_swap::{ArcSwap, Guard};
use bytes::Bytes;
use quinn::{ClientConfig, EndpointConfig, TransportConfig, crypto::rustls::QuicClientConfig};
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    datagram::UdpMessage,
    packet::{ByEndpoint, ScionPacketRaw, ScionPacketUdp},
    path::Path,
    scmp::SCMP_PROTOCOL_NUMBER,
    wire_encoding::{WireDecode as _, WireEncodeVec as _},
};
use scion_sdk_reqwest_connect_rpc::token_source::TokenSource;
use scion_sdk_utils::backoff::ExponentialBackoff;
use snap_control::client::{ControlPlaneApi as _, CrpcSnapControlClient};
use snap_tun::client::{AutoSessionRenewal, ClientBuilder};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{sync::futures::OwnedNotified, task::JoinHandle};
use url::Url;

use crate::{
    scionstack::{
        AsyncUdpUnderlaySocket, ScionSocketReceiveError, ScionSocketSendError, UnderlaySocket,
        udp_polling::UdpPoller,
    },
    underlays::v2::discovery::{UnderlayDiscovery, UnderlayInfo},
};

/// A handle to the background task that runs the SNAP underlay socket task.
/// Cancels the task when dropped.
struct SnapUnderlaySocketTaskHandle(JoinHandle<()>);

impl Drop for SnapUnderlaySocketTaskHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
pub(crate) struct SnapUnderlaySocket {
    pub inner: Arc<SnapUnderlaySocketInner>,
    _task: Arc<SnapUnderlaySocketTaskHandle>,
}

fn map_quinn_endpoint_error(
    e: std::io::Error,
    addr: net::SocketAddr,
    isd_asn: IsdAsn,
) -> crate::scionstack::ScionSocketBindError {
    use crate::scionstack::ScionSocketBindError;
    match e.kind() {
        std::io::ErrorKind::AddrInUse => ScionSocketBindError::PortAlreadyInUse(addr.port()),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::InvalidInput => {
            ScionSocketBindError::InvalidBindAddress(
                SocketAddr::new(ScionAddr::new(isd_asn, addr.ip().into()), addr.port()),
                format!("failed to bind quinn endpoint: {e:#}"),
            )
        }
        #[cfg(windows)]
        // On windows, if a port is already in use the error returned is sometimes
        // code 10013 WSAEACCES.
        // see https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
        std::io::ErrorKind::PermissionDenied => ScionSocketBindError::PortAlreadyInUse(addr.port()),
        _ => ScionSocketBindError::Other(Box::new(e)),
    }
}

impl SnapUnderlaySocket {
    pub async fn new(
        isd_asn: IsdAsn,
        bind_addr: Option<net::SocketAddr>,
        snap_cp: Url,
        data_plane_server_name: String,
        underlay_discovery: Arc<dyn UnderlayDiscovery>,
        snap_token_source: Arc<dyn TokenSource>,
        renewal_wait_threshold: Duration,
        backoff: ExponentialBackoff,
    ) -> Result<Self, crate::scionstack::ScionSocketBindError> {
        // Establish the initial tunnel.
        let mut snap_cp_client = CrpcSnapControlClient::new(&snap_cp).map_err(|e| {
            crate::scionstack::ScionSocketBindError::DataplaneError(
                format!("failed to create SNAP control plane client: {e:#}").into(),
            )
        })?;
        snap_cp_client.use_token_source(snap_token_source.clone());

        let session_grants = snap_cp_client
            .create_data_plane_sessions()
            .await
            .map_err(|e| {
                crate::scionstack::ScionSocketBindError::DataplaneError(
                    format!("failed to discover SNAP data planes: {e:#}").into(),
                )
            })?;

        let data_plane_addr = session_grants
            .first()
            .ok_or_else(|| {
                crate::scionstack::ScionSocketBindError::DataplaneError(
                    "no SNAP data plane found".into(),
                )
            })?
            .address;

        // Bind to the provided bind address or fall back to 0.0.0.0:0.
        let endpoint_bind_addr: net::SocketAddr =
            bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let mut endpoint = quinn_client_endpoint(endpoint_bind_addr)
            .map_err(|e| map_quinn_endpoint_error(e, endpoint_bind_addr, isd_asn))?;
        endpoint.set_default_client_config(default_client_config());

        let tunnel = new_snaptun(
            &endpoint,
            snap_token_source.clone(),
            renewal_wait_threshold,
            data_plane_addr,
            data_plane_server_name.clone(),
        )
        .await
        .map_err(|e| {
            crate::scionstack::ScionSocketBindError::DataplaneError(
                format!("failed to establish SNAP tunnel: {e:#}").into(),
            )
        })?;

        // Construct the inner socket.
        let assigned_addr = tunnel.ctrl.assigned_sock_addr().ok_or_else(|| {
            crate::scionstack::ScionSocketBindError::Internal(
                "SNAP tunnel connected but no address assigned".to_string(),
            )
        })?;

        // If the bind address is specified but does not match the assigned address, return an
        // error.
        if let Some(bind_addr) = bind_addr
            // IP mismatch
            && ((!bind_addr.ip().is_unspecified() && assigned_addr.ip() != bind_addr.ip())
            // Port mismatch
                || (bind_addr.port() != 0 && assigned_addr.port() != bind_addr.port()))
        {
            return Err(crate::scionstack::ScionSocketBindError::InvalidBindAddress(
                SocketAddr::new(
                    ScionAddr::new(isd_asn, bind_addr.ip().into()),
                    bind_addr.port(),
                ),
                format!(
                    "assigned address ({assigned_addr}) does not match requested address ({bind_addr}), likely due to NAT",
                ),
            ));
        }

        let socket_addr = SocketAddr::new(
            ScionAddr::new(isd_asn, assigned_addr.ip().into()),
            assigned_addr.port(),
        );
        let tunnel = VersionedArcSwap::new(tunnel);
        let inner = Arc::new(SnapUnderlaySocketInner {
            assigned_addr: socket_addr,
            connection: tunnel,
            endpoint,
        });

        // Start the background task.
        let task = SnapUnderlaySocketTask {
            underlay_discovery: underlay_discovery.clone(),
            snap_token_source: snap_token_source.clone(),
            backoff,
            snap_cp_client: (snap_cp.clone(), snap_cp_client),
            inner: inner.clone(),
            renewal_wait_threshold,
            data_plane_server_name,
        };
        let task = tokio::spawn(task.run());

        Ok(Self {
            inner,
            _task: Arc::new(SnapUnderlaySocketTaskHandle(task)),
        })
    }
}

impl UnderlaySocket for SnapUnderlaySocket {
    fn send<'a>(
        &'a self,
        packet: scion_proto::packet::ScionPacketRaw,
    ) -> futures::future::BoxFuture<'a, Result<(), crate::scionstack::ScionSocketSendError>> {
        Box::pin(async move {
            let packet = packet.encode_to_bytes_vec().concat().into();
            self.inner
                .connection
                .load_full()
                .1
                .sender
                .send_datagram_wait(packet)
                .await
                .map_err(|e| {
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
    ) -> futures::future::BoxFuture<'a, Result<ScionPacketRaw, ScionSocketReceiveError>> {
        Box::pin(async move {
            loop {
                let arc = self.inner.connection.load_full();
                let version = arc.0;
                let mut raw = match arc.1.receiver.read_datagram().await {
                    Ok(raw) => raw,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::Reset) => {
                        tracing::debug!("Connection closed, reconnecting");
                        // Wait for a new connection to be established.
                        self.inner.connection.wait_for_version(version + 1).await;
                        continue;
                    }
                    Err(e) => {
                        return Err(ScionSocketReceiveError::IoError(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            e,
                        )));
                    }
                };
                let packet = match ScionPacketRaw::decode(&mut raw) {
                    Ok(packet) => packet,
                    Err(e) => {
                        tracing::debug!(error = %e, "Failed to decode SCION packet, skipping");
                        continue;
                    }
                };
                match packet.headers.common.next_header {
                    UdpMessage::PROTOCOL_NUMBER => {
                        return Ok(packet);
                    }
                    SCMP_PROTOCOL_NUMBER => {
                        tracing::debug!("SCMP packet received, skipping");
                        continue;
                    }
                    _ => {
                        tracing::debug!(next_header = %packet.headers.common.next_header, "Unknown packet type, skipping");
                        continue;
                    }
                }
            }
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.assigned_addr
    }
}

pub(crate) struct SnapUnderlaySocketInner {
    /// Assigned socket address.
    assigned_addr: SocketAddr,
    /// The current connection.
    connection: VersionedArcSwap<SnapTunConnection>,
    /// The endpoint used to create new connections.
    endpoint: quinn::Endpoint,
}

/// The background task that runs the SNAP underlay socket
/// and handles reconnecting the SNAP tunnel.
struct SnapUnderlaySocketTask {
    pub underlay_discovery: Arc<dyn UnderlayDiscovery>,
    pub snap_token_source: Arc<dyn TokenSource>,
    pub backoff: ExponentialBackoff,
    pub snap_cp_client: (url::Url, CrpcSnapControlClient),
    pub inner: Arc<SnapUnderlaySocketInner>,
    pub renewal_wait_threshold: Duration,
    pub data_plane_server_name: String,
}

impl SnapUnderlaySocketTask {
    async fn run(mut self) {
        loop {
            // Wait for the current connection to be closed.
            let guard = self.inner.connection.load_full();
            guard.1.ctrl.inner_conn().closed().await;
            tracing::debug!("current connection closed, reconnecting");
            // Create a new connection.
            //
            // XXX(uniquefine): We are now reusing the same endpoint for the new connection.
            // This means the local socket doesn't need to be rebound, we trivially keep the
            // same local bind address.
            // Theoretically we could get a snap control plane URL that is only reachable from
            // a different local address.
            // But this is unlikely since we can only reconnect within the same SNAP cluster,
            // so this is fine.
            let mut failed_attempts = 0;
            loop {
                let new_connection: Result<SnapTunConnection, anyhow::Error> = async {
                    // Resolve underlay and find the data plane address.
                    let underlays = self
                        .underlay_discovery
                        .underlays(self.inner.assigned_addr.isd_asn())
                        .clone()
                        .into_iter()
                        .filter_map(|(_, underlay)| {
                            match underlay {
                                UnderlayInfo::Snap(url) => Some(url),
                                _ => None,
                            }
                        })
                        .collect::<Vec<_>>();

                    // If the control plane address has changed, we need to create a new control
                    // plane client. Otherwise, we reuse the existing control plane client.
                    if !underlays.contains(&self.snap_cp_client.0) {
                        let cp_url = underlays
                            .first()
                            .ok_or(anyhow::anyhow!("no snap control plane address found"))?;
                        tracing::debug!(before=%self.snap_cp_client.0, after=%cp_url, "using new snap control plane");
                        self.snap_cp_client = (cp_url.clone(), CrpcSnapControlClient::new(cp_url)?);
                        self.snap_cp_client
                            .1
                            .use_token_source(self.snap_token_source.clone());
                    }

                    let session_grants = self.snap_cp_client.1.create_data_plane_sessions().await?;
                    let data_plane_addr = session_grants
                        .first()
                        .context("no data plane found")?
                        .address;

                    let new_connection = new_snaptun(
                        &self.inner.endpoint,
                        self.snap_token_source.clone(),
                        self.renewal_wait_threshold,
                        data_plane_addr,
                        self.data_plane_server_name.clone(),
                    )
                    .await?;

                    // Make sure the assigned address matches the expected address.
                    let addr: net::SocketAddr = self.inner.assigned_addr.local_address().ok_or(anyhow::anyhow!("no local address on socket, this should not happen"))?;
                    let new_addr = new_connection.ctrl.assigned_sock_addr().ok_or(anyhow::anyhow!("no assigned address on new connection, this should not happen"))?;
                    if new_addr != addr {
                        // There is not much we can do here, close the connection and try again.
                        new_connection.ctrl.inner_conn().close(quinn::VarInt::from(0u16), b"assigned address mismatch");
                        return Err(anyhow::anyhow!("new snaptun connection assigned address does not match socket address, expected: {addr}, got: {new_addr}"));
                    }

                    Ok(new_connection)
                }
                .await;
                match new_connection {
                    Ok(new_connection) => {
                        tracing::debug!("new snaptun connection established");
                        self.inner.connection.store_new(new_connection);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(addr=%self.inner.assigned_addr, error=%e, %failed_attempts, next_try_in_secs=%self.backoff.duration(failed_attempts).as_secs(), "failed to reconnect snaptun");
                        failed_attempts += 1;
                        tokio::time::sleep(self.backoff.duration(failed_attempts)).await;
                    }
                }
            }
        }
    }
}

struct SnapTunConnection {
    sender: snap_tun::client::Sender,
    receiver: snap_tun::client::Receiver,
    ctrl: snap_tun::client::Control,
}

async fn new_snaptun(
    endpoint: &quinn::Endpoint,
    token_source: Arc<dyn TokenSource>,
    renewal_wait_threshold: Duration,
    data_plane_addr: net::SocketAddr,
    data_plane_server_name: String,
) -> anyhow::Result<SnapTunConnection> {
    let conn = endpoint
        .connect(data_plane_addr, &data_plane_server_name)?
        .await?;
    let token = token_source
        .get_token()
        .await
        .map_err(|e| anyhow::anyhow!("failed to get token: {e:?}"))?;
    let client_builder = ClientBuilder::new(token)
        .with_auto_session_renewal(AutoSessionRenewal::new(
            renewal_wait_threshold,
            Arc::new(move || {
                let token_source = token_source.clone();
                Box::pin(async move { token_source.get_token().await })
            }),
        ))
        .with_sock_addr_assignment();

    let (sender, receiver, ctrl) = client_builder.connect(conn).await?;
    Ok(SnapTunConnection {
        sender,
        receiver,
        ctrl,
    })
}

fn default_client_config() -> ClientConfig {
    let (cert_der, _config) = scion_sdk_utils::test::generate_cert(
        [42u8; 32],
        vec!["localhost".into()],
        vec![b"snaptun".to_vec()],
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"snaptun".to_vec()];

    let mut transport_config = TransportConfig::default();
    // 5 secs == 1/6 default idle timeout
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    // XXX: on windows, GSO is known to cause trouble depending on the
    // combination of network drivers, configuration, etc.
    #[cfg(target_os = "windows")]
    transport_config.enable_segmentation_offload(false);

    let transport_config_arc = Arc::new(transport_config);
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config_arc);
    client_config
}

pub(crate) struct SnapAsyncUdpSocket {
    socket: SnapUnderlaySocket,
    recv_fut: Mutex<
        Option<
            futures::future::BoxFuture<'static, Result<ScionPacketRaw, ScionSocketReceiveError>>,
        >,
    >,
}

impl SnapAsyncUdpSocket {
    pub fn new(socket: SnapUnderlaySocket) -> Self {
        Self {
            socket,
            recv_fut: Mutex::new(None),
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
            .socket
            .inner
            .connection
            .load()
            .1
            .sender
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
        loop {
            // Ensure we have a recv future
            let res = {
                let mut guard = self.recv_fut.lock().unwrap();
                if guard.is_none() {
                    let socket = self.socket.clone();
                    *guard = Some(Box::pin(async move { socket.recv().await }));
                }

                // If pending, keep the future stored and return
                let res = ready!(guard.as_mut().unwrap().as_mut().poll(cx));
                // Clear the cached future
                *guard = None;
                res
            };

            // Handle result
            match res {
                Ok(packet) => {
                    let fallible = || {
                        let src = packet
                            .headers
                            .address
                            .source()
                            .context("reading source address")?;
                        let dst = packet
                            .headers
                            .address
                            .destination()
                            .context("reading destination address")?;

                        let path = Path::new(
                            packet.headers.path.clone(),
                            ByEndpoint {
                                source: src.isd_asn(),
                                destination: dst.isd_asn(),
                            },
                            None,
                        );

                        let packet: ScionPacketUdp =
                            packet.try_into().context("parsing UDP packet")?;

                        anyhow::Ok((
                            SocketAddr::new(src, packet.src_port()),
                            packet.datagram.payload,
                            path,
                        ))
                    };

                    match fallible() {
                        Ok(result) => return Poll::Ready(Ok(result)),
                        Err(e) => {
                            tracing::warn!(error = %e, "Received invalid packet, skipping");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        e,
                    )));
                }
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket.inner.assigned_addr
    }
}

/// A wrapper around ArcSwap and a mutex protected notify to allow
/// awaiting a specific version of the inner value.
struct VersionedArcSwap<T> {
    inner: ArcSwap<(usize, T)>,
    version: std::sync::Mutex<(usize, Arc<tokio::sync::Notify>)>,
}

impl<T> VersionedArcSwap<T> {
    fn new(initial: T) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new((0, initial))),
            version: std::sync::Mutex::new((0, Arc::new(tokio::sync::Notify::new()))),
        }
    }

    fn store_new(&self, inner: T) {
        let mut guard = self.version.lock().unwrap();
        let new_version = guard.0 + 1;
        self.inner.store(Arc::new((new_version, inner)));
        guard.0 = new_version;
        guard.1.notify_waiters();
    }

    fn load(&self) -> Guard<Arc<(usize, T)>> {
        self.inner.load()
    }

    fn load_full(&self) -> Arc<(usize, T)> {
        self.inner.load_full()
    }

    /// Wait for the inner value to be at least the expected version.
    async fn wait_for_version(&self, expected_version: usize) {
        while let Some(notify) = self.create_notify(expected_version) {
            notify.await;
        }
    }

    fn create_notify(&self, expected_version: usize) -> Option<OwnedNotified> {
        // If inner is already at the expected version, return it.
        let inner = self.inner.load();
        if inner.0 >= expected_version {
            return None;
        }
        // If not, we wait for the next version.
        let guard = self.version.lock().unwrap();
        let owned_notified = if guard.0 >= expected_version {
            // Version has already been incremented. The next load should return the new
            // version.
            return None;
        } else {
            // Create the notified while still holding the lock. Quote from the tokio docs:
            //
            // > The Notified future is guaranteed to receive wakeups from notify_waiters()
            // > as soon as it has been created, even if it has not yet been polled.
            //
            // This guarantees that we will receive a wakeup as soon as the version is
            // incremented.
            guard.1.clone().notified_owned()
        };
        Some(owned_notified)
    }
}

#[cfg(windows)]
fn set_exclusive_addr_use(sock: &Socket, enable: bool) -> io::Result<()> {
    use std::{mem, os::windows::io::AsRawSocket};

    use windows_sys::Win32::Networking::WinSock;

    // Winsock expects an int/bool-ish value passed by pointer.
    let val: u32 = if enable { 1 } else { 0 };

    let rc = unsafe {
        WinSock::setsockopt(
            sock.as_raw_socket() as usize,
            WinSock::SOL_SOCKET,
            WinSock::SO_EXCLUSIVEADDRUSE,
            &val as *const _ as *const _,
            mem::size_of_val(&val) as _,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// This is equivalent to quinn::Endpoint::client(addr) but with the exclusive address use set to
/// true on windows.
/// This is because on windows, by default multiple endpoints can bind to the same address:port
/// if one binds to wildcard address.
fn quinn_client_endpoint(addr: net::SocketAddr) -> io::Result<quinn::Endpoint> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(false)
    {
        tracing::debug!(%e, "unable to make socket dual-stack");
    }

    // XXX(uniquefine): on windows, we need to set the exclusive address use to true to
    // prevent multiple endpoints from binding to the same address.
    #[cfg(windows)]
    set_exclusive_addr_use(&socket, true)?;

    socket.bind(&addr.into())?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    quinn::Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        runtime.wrap_udp_socket(socket.into())?,
        runtime,
    )
}
