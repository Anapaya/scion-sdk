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

#![allow(dead_code)]

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use async_trait::async_trait;
use chacha20::{ChaCha8Rng, rand_core::Rng};
use prometheus::IntGauge;
use scion_sdk_quic_scion::{
    quic::{
        config::QuicConfig,
        connection::ConnectionHandle,
        server_endpoint::{Metrics, QuicScionEndpointDriver, QuicScionServerEndpoint},
    },
    socket::{BoxedSocketError, GenericScionUdpSocket},
};
use sciparse::{address::ip_socket_addr::ScionSocketIpAddr, identifier::isd_asn::IsdAsn};
use tempfile::NamedTempFile;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_quiche::{
    ClientH3Controller, ClientH3Driver, ConnectionParams, QuicConnection, QuicResult,
    http3::settings::Http3Settings,
    quic::connect_with_config,
    settings::{Hooks, QuicSettings},
    socket::Socket,
};
use tokio_util::sync::CancellationToken;

/// Setup a client and server socket in two different ASes in the pocket SCION topology.
pub fn setup_sockets() -> (MockScionSocket, MockScionSocket) {
    let ia132 = "1-32".parse().unwrap();
    let client_addr = ScionSocketIpAddr::new(ia132, Ipv4Addr::new(10, 1, 1, 0).into(), 0);

    let ia212 = "2-12".parse().unwrap();
    let server_addr = ScionSocketIpAddr::new(ia212, Ipv4Addr::new(10, 2, 1, 0).into(), 0);

    MockScionSocket::pair(1024, client_addr, server_addr)
}

/// Generates a self-signed certificate and corresponding private key for testing purposes.
///
/// The returned [`NamedTempFile`]s back the certificate chain and private key
/// loaded into the config. They must be kept alive for as long as the config
/// (or any connection created from it) is in use.
pub fn generate_server_config() -> (squiche::Config, NamedTempFile, NamedTempFile) {
    build_server_config(QuicConfig::builder().verify_peer(false).build())
}

/// Like [`generate_server_config`], but overrides the idle timeout.
///
/// This is handy for timeout-driven tests that don't want to wait for the
/// default idle timeout to elapse.
pub fn generate_server_config_with_idle_timeout(
    idle_timeout: Duration,
) -> (squiche::Config, NamedTempFile, NamedTempFile) {
    build_server_config(
        QuicConfig::builder()
            .verify_peer(false)
            .idle_timeout(idle_timeout)
            .build(),
    )
}

/// Generates a self-signed certificate/key for the given [`QuicConfig`] and
/// loads them into the resulting `squiche::Config`.
fn build_server_config(quic_config: QuicConfig) -> (squiche::Config, NamedTempFile, NamedTempFile) {
    let mut config = quic_config.to_quiche_config().unwrap();

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
    src: ScionSocketIpAddr,
    dst: ScionSocketIpAddr,
}

/// Simple in-memory mock implementation of a [`GenericScionUdpSocket`].
pub struct MockScionSocket {
    recv_channel: Mutex<mpsc::Receiver<MockDatagram>>,
    send_channel: mpsc::Sender<MockDatagram>,
    local_addr: ScionSocketIpAddr,
}

impl MockScionSocket {
    /// Creates a pair of connected `MockScionSocket`s
    pub fn pair(
        queue_size: usize,
        sockaddr_a: ScionSocketIpAddr,
        sockaddr_b: ScionSocketIpAddr,
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
        destination: ScionSocketIpAddr,
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
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketIpAddr), BoxedSocketError> {
        loop {
            let datagram = self.recv_channel.lock().await.recv().await.ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Channel closed",
                )) as BoxedSocketError
            })?;

            // Route by the standard socket address only, ignoring the ISD-AS:
            // the endpoint-based QUIC stack tags outgoing packets with the
            // *local* ISD-AS rather than the peer's, so an ISD-AS-sensitive
            // comparison would drop legitimate server->client replies. Test
            // peers always have distinct socket addresses, so this still routes
            // unambiguously.
            if datagram.dst.socket_addr() != self.local_addr.socket_addr() {
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
    fn local_addr(&self) -> ScionSocketIpAddr {
        self.local_addr
    }
}

/// Direction of traffic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// Incoming
    Incoming,
    /// Outgoing
    Outgoing,
}

/// A traffic gate is a stateful structure that controls the behavior of a
/// communication channel. It can drop, manipulate and/or repeat packets.
pub trait TrafficGate: Send + Sync {
    /// Manipulate a packet that is being passed through a gated socket.
    ///
    /// ## Parameters
    ///
    /// * `dir` the direction of the packet.
    /// * `peer` the address of the peer: the destination for outgoing packets, the source for
    ///   incoming packets.
    /// * `packet` the packet.
    ///
    /// ## Return value
    ///
    /// The return value indicates how many times the (manipulated) packet
    /// should be repeated in the given direction.
    ///
    /// For example, a `TrafficGate` that simply passess through all traffic
    /// simply return `1` for all input. Conversely, a `TrafficGate` that drops
    /// everything simply returns `0` for all inputs.
    fn manipulate(&self, dir: Direction, peer: ScionSocketIpAddr, packet: &mut [u8]) -> usize;
}

/// Pass all gate has no effect on a communication channel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PassAll;

impl TrafficGate for PassAll {
    fn manipulate(&self, _dir: Direction, _peer: ScionSocketIpAddr, _packet: &mut [u8]) -> usize {
        1
    }
}

/// A lossy gate applies a drop rate to a communication channel.
#[derive(Debug, Clone)]
pub struct LossyGate {
    drop_rate: f64,
    rng_state: Arc<StdMutex<ChaCha8Rng>>,
}

impl TrafficGate for LossyGate {
    fn manipulate(&self, _dir: Direction, _peer: ScionSocketIpAddr, _packet: &mut [u8]) -> usize {
        let r_value = self.rng_state.lock().unwrap().next_u32() as f64;
        let p = r_value / u32::MAX as f64;
        if p > self.drop_rate {
            return 1;
        }
        0
    }
}

/// A [`TrafficGate`] that rate-limits *incoming* packets per peer address.
///
/// Peers are ranked by the order in which they are first observed in the
/// incoming direction. The i-th distinct peer is allowed `limits[i]` packets;
/// every subsequent packet from that peer is dropped. Peers observed after the
/// `limits` list is exhausted are unrestricted. Outgoing traffic always passes.
///
/// This is useful to simulate connections that stall at different stages of the
/// handshake (e.g. the client's retry token or its handshake completion being
/// lost).
pub struct IncomingPerPeerLimitGate {
    limits: Vec<usize>,
    state: StdMutex<PerPeerLimitState>,
}

#[derive(Default)]
struct PerPeerLimitState {
    /// Number of distinct peers observed so far.
    seen: usize,
    /// Per-peer packet count and assigned limit (`None` means unlimited).
    peers: HashMap<SocketAddr, (usize, Option<usize>)>,
}

impl IncomingPerPeerLimitGate {
    /// Creates a new gate with the given per-peer packet limits, applied in
    /// order of first observation.
    pub fn new(limits: impl Into<Vec<usize>>) -> Self {
        Self {
            limits: limits.into(),
            state: StdMutex::new(PerPeerLimitState::default()),
        }
    }
}

impl TrafficGate for IncomingPerPeerLimitGate {
    fn manipulate(&self, dir: Direction, peer: ScionSocketIpAddr, _packet: &mut [u8]) -> usize {
        if dir == Direction::Outgoing {
            return 1;
        }

        let key = peer.socket_addr();

        let mut state = self.state.lock().unwrap();
        if !state.peers.contains_key(&key) {
            let rank = state.seen;
            state.seen += 1;
            let limit = self.limits.get(rank).copied();
            state.peers.insert(key, (0, limit));
        }

        let (count, limit) = state.peers.get_mut(&key).unwrap();
        *count += 1;
        match limit {
            Some(limit) => usize::from(*count <= *limit),
            None => 1,
        }
    }
}

/// A [`TrafficGate`] that rate-limits *incoming* packets per peer, where each
/// peer declares its own budget in-band.
///
/// The first incoming packet from a previously unseen peer is interpreted as a
/// *config packet*: its payload is a big-endian [`u64`] budget (see
/// [`encode_packet_budget`]). The config packet itself is always dropped (never
/// forwarded to the server). The budget *counts that config packet*, so:
///
/// * `budget == 0` — the peer is unrestricted; every later packet passes.
/// * `budget == 1` — no further packet passes after the config packet.
/// * `budget == n` (`n >= 1`) — the next `n - 1` packets pass, the rest are dropped.
///
/// Because the budget travels in-band rather than being assigned by observation
/// order, connections no longer need to be driven sequentially: they can run
/// concurrently and still be reasoned about by their declared budget. This is
/// the concurrent counterpart to [`IncomingPerPeerLimitGate`].
pub struct ConfiguredPerPeerLimitGate {
    /// Per-peer remaining budget, established from the peer's config packet.
    state: StdMutex<HashMap<SocketAddr, PeerPacketBudget>>,
}

/// The remaining incoming-packet budget for a single peer.
enum PeerPacketBudget {
    /// At most this many further (post-config) packets may pass.
    Limited(usize),
    /// Every further packet passes.
    Unlimited,
}

impl ConfiguredPerPeerLimitGate {
    /// Creates a new gate. Peers are unknown until they send their config
    /// packet.
    pub fn new() -> Self {
        Self {
            state: StdMutex::new(HashMap::new()),
        }
    }
}

impl Default for ConfiguredPerPeerLimitGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a packet budget into the config-packet payload consumed by
/// [`ConfiguredPerPeerLimitGate`].
pub fn encode_packet_budget(budget: u64) -> [u8; 8] {
    budget.to_be_bytes()
}

impl TrafficGate for ConfiguredPerPeerLimitGate {
    fn manipulate(&self, dir: Direction, peer: ScionSocketIpAddr, packet: &mut [u8]) -> usize {
        if dir == Direction::Outgoing {
            return 1;
        }

        let key = peer.socket_addr();

        let mut state = self.state.lock().unwrap();
        match state.get_mut(&key) {
            None => {
                // First packet from this peer: its config packet. Parse the
                // declared budget, record the remaining post-config budget, and
                // drop the config packet itself.
                let budget = packet
                    .get(..8)
                    .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                let remaining = if budget == 0 {
                    PeerPacketBudget::Unlimited
                } else {
                    // The config packet counts towards the budget.
                    PeerPacketBudget::Limited((budget - 1) as usize)
                };
                state.insert(key, remaining);
                0
            }
            Some(PeerPacketBudget::Unlimited) => 1,
            Some(PeerPacketBudget::Limited(0)) => 0,
            Some(PeerPacketBudget::Limited(remaining)) => {
                *remaining -= 1;
                1
            }
        }
    }
}

/// A [`GenericScionUdpSocket`] backed by a real tokio [`UdpSocket`].
///
/// It is used to test a standard (non-SCION) QUIC implementation, such as
/// `tokio-quiche`, against the QUIC/SCION server. Every packet is passed
/// through the configured [`TrafficGate`], which may drop or duplicate it.
/// SCION addresses are synthesised from the standard socket addresses using
/// ISD-ASN `0`.
pub struct GatedTestScionSocket<F> {
    socket: UdpSocket,
    incoming_queue: Mutex<VecDeque<(Vec<u8>, ScionSocketIpAddr)>>,
    gate: F,
}

impl<F> GatedTestScionSocket<F>
where
    F: TrafficGate,
{
    /// Wraps `socket`, routing all traffic through `gate`.
    ///
    /// ## Parameters
    ///
    /// * `gate` controls which packets are forwarded, dropped, or duplicated.
    /// * `socket` the underlying tokio UDP socket.
    pub fn new(gate: F, socket: UdpSocket) -> Self {
        Self {
            socket,
            gate,
            incoming_queue: Default::default(),
        }
    }
}

#[async_trait]
impl<F> GenericScionUdpSocket for GatedTestScionSocket<F>
where
    F: TrafficGate + 'static,
{
    async fn send_to(
        &self,
        payload: &[u8],
        destination: ScionSocketIpAddr,
    ) -> Result<(), BoxedSocketError> {
        let dest_addr: SocketAddr = destination.socket_addr();

        let mut buf = payload.to_vec();
        let n = self
            .gate
            .manipulate(Direction::Outgoing, destination, &mut buf);
        for _ in 0..n {
            let res = self.socket.send_to::<SocketAddr>(&buf, dest_addr).await;

            // xxx: for whatever reason type inference did not work otherwise
            if let Err(err) = res {
                return Err(Box::new(err) as BoxedSocketError);
            }
        }
        Ok(())
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, ScionSocketIpAddr), BoxedSocketError> {
        let mut q = self.incoming_queue.lock().await;
        let mut tmp_buf = [0u8; 65536];
        {
            // dequeue duplicated packets first
            if let Some((p, t)) = q.pop_front() {
                let len = buf.len().min(p.len());
                buf[..len].copy_from_slice(&p);
                return Ok((len, t));
            }
        }
        loop {
            let res = self.socket.recv_from(&mut tmp_buf).await;
            // xxx: for whatever reason type inference did not work otherwise
            let (mut p, from) = match res {
                Ok((n, from)) => (tmp_buf[..n].to_vec(), from),
                Err(e) => return Err(Box::new(e) as BoxedSocketError),
            };
            let from = ScionSocketIpAddr::new(IsdAsn::from(0), from.ip(), from.port());
            let reps = self
                .gate
                .manipulate(Direction::Incoming, from, p.as_mut_slice());
            if reps > 0 {
                let len = buf.len().min(p.len());
                buf[..len].copy_from_slice(&p);

                for _ in 1..reps {
                    q.push_back((p.clone(), from));
                }
                return Ok((len, from));
            }
        }
    }

    fn local_addr(&self) -> ScionSocketIpAddr {
        let sockaddr = self.socket.local_addr().unwrap();
        ScionSocketIpAddr::new(IsdAsn::from(0), sockaddr.ip(), sockaddr.port())
    }
}

/// Constructs a fresh set of endpoint [`Metrics`].
///
/// The gauges are standalone (not registered with any prometheus registry), so
/// tests can read their values directly via [`IntGauge::get`].
pub fn test_metrics() -> Metrics {
    Metrics {
        establishing_connections_gauge: IntGauge::new(
            "test_establishing_connections",
            "Number of connections currently being established.",
        )
        .unwrap(),
        routed_source_cids_gauge: IntGauge::new(
            "test_registered_connections",
            "Number of currently registered connections.",
        )
        .unwrap(),
    }
}

/// Binds a tokio [`UdpSocket`] to an ephemeral port on `127.0.0.1`.
pub async fn bind_localhost_udp() -> UdpSocket {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    UdpSocket::bind(addr).await.unwrap()
}

/// A running QUIC/SCION server endpoint, wired up for tests.
///
/// The endpoint is driven by a spawned [`QuicScionEndpointDriver`] backed by a
/// [`GatedTestScionSocket`] over a real localhost UDP socket. Use
/// [`TestServer::local_addr`] as the connection target for a client.
///
/// Dropping the [`TestServer`] cancels and aborts the driver task.
pub struct TestServer {
    /// The standard UDP socket address the server is listening on. Use this as
    /// the connection target for a client (e.g. a `tokio-quiche` client).
    pub local_addr: SocketAddr,
    /// The SCION socket address of the server (ISD-ASN `0`).
    pub scion_addr: ScionSocketIpAddr,
    /// A clone of the endpoint metrics. The gauges share state with the running
    /// endpoint, so up-to-date values can be read directly.
    pub metrics: Metrics,
    /// Receives a [`ConnectionHandle`] for every connection the endpoint
    /// reports as established (via the driver's `established_conn` callback).
    pub established: mpsc::Receiver<ConnectionHandle>,
    cancel: CancellationToken,
    driver: JoinHandle<Result<(), BoxedSocketError>>,
    // Keeps the certificate/key temp files alive for the server's lifetime.
    _keep_alive: (NamedTempFile, NamedTempFile),
}

impl TestServer {
    /// Spawns a server endpoint driver using [`generate_server_config`] and the
    /// provided [`TrafficGate`].
    pub async fn spawn<G: TrafficGate + 'static>(gate: G) -> Self {
        let (config, cert, key) = generate_server_config();
        Self::spawn_with_config(gate, config, (cert, key)).await
    }

    /// Like [`TestServer::spawn`], but lets the caller provide a custom
    /// `squiche::Config` (for example one with a short idle timeout obtained
    /// from [`generate_server_config_with_idle_timeout`]).
    ///
    /// `keep_alive` holds the certificate/key temp files backing the config;
    /// they are kept alive for the lifetime of the server.
    pub async fn spawn_with_config<G: TrafficGate + 'static>(
        gate: G,
        config: squiche::Config,
        keep_alive: (NamedTempFile, NamedTempFile),
    ) -> Self {
        let udp = bind_localhost_udp().await;
        let local_addr = udp.local_addr().unwrap();

        let socket: Arc<dyn GenericScionUdpSocket> = Arc::new(GatedTestScionSocket::new(gate, udp));
        let scion_addr = socket.local_addr();

        let metrics = test_metrics();
        let endpoint = QuicScionServerEndpoint::new([0u8; 32], config, scion_addr, metrics.clone());

        let (established_tx, established) = mpsc::channel(1024);
        let driver = QuicScionEndpointDriver::new(endpoint, socket, move |handle| {
            // Best effort: the receiver may have been dropped by the test, or
            // the (generously sized) buffer may be full.
            let _ = established_tx.try_send(handle);
        });

        let cancel = CancellationToken::new();
        let driver = tokio::spawn(driver.run(cancel.clone()));

        Self {
            local_addr,
            scion_addr,
            metrics,
            established,
            cancel,
            driver,
            _keep_alive: keep_alive,
        }
    }

    /// The current value of the "establishing connections" gauge.
    pub fn establishing_count(&self) -> i64 {
        self.metrics.establishing_connections_gauge.get()
    }

    /// The current value of the "registered connections" gauge.
    pub fn registered_count(&self) -> i64 {
        self.metrics.routed_source_cids_gauge.get()
    }

    /// Waits for the next established connection reported by the driver.
    ///
    /// Returns `None` if the driver has stopped and no more connections will be
    /// reported.
    pub async fn next_established(&mut self) -> Option<ConnectionHandle> {
        self.established.recv().await
    }

    /// Signals the driver to stop. The driver task is also aborted on drop.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.driver.abort();
    }
}

/// Translates the SDK's [`QuicConfig`] into `tokio-quiche`'s [`QuicSettings`].
///
/// `squiche` (used by the server) and `quiche` (used by `tokio-quiche`) are
/// structurally similar forks but nominally distinct, so the relevant settings
/// are copied over field by field rather than reusing the `squiche::Config`.
fn quic_settings_from(config: &QuicConfig) -> QuicSettings {
    // `QuicSettings` is `#[non_exhaustive]`, so start from the defaults and
    // override the fields that have a counterpart in `QuicConfig`.
    let mut settings = QuicSettings::default();
    settings.alpn = config.application_protos.clone();
    settings.max_idle_timeout = Some(config.idle_timeout);
    settings.handshake_timeout = Some(config.handshake_timeout);
    settings.verify_peer = config.verify_peer;
    settings.max_recv_udp_payload_size = config.max_udp_payload_size;
    settings.max_send_udp_payload_size = config.max_udp_payload_size;
    settings.initial_max_data = config.initial_max_data;
    settings.initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local;
    settings.initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
    settings.initial_max_stream_data_uni = config.initial_max_stream_data_uni;
    settings.initial_max_streams_bidi = config.initial_max_streams_bidi;
    settings.initial_max_streams_uni = config.initial_max_streams_uni;
    settings
}

/// A connected `tokio-quiche` test client.
///
/// Returned by [`connect_test_client`]. Holds the established
/// [`QuicConnection`] (metadata handle) and the [`ClientH3Controller`] used to
/// drive HTTP/3 on the connection. Both should be kept alive for as long as the
/// connection should stay open — dropping the controller tears the connection
/// down.
pub struct TestClient {
    /// Metadata handle for the established QUIC connection.
    pub conn: QuicConnection,
    /// Controller to interact with (and close) the HTTP/3 connection.
    pub controller: ClientH3Controller,
}

/// Connects a `tokio-quiche` client to `server_addr` using a default test
/// configuration that matches [`generate_server_config`] (ALPN `h3`, peer
/// verification disabled).
///
/// The returned future resolves once the QUIC handshake has completed.
pub async fn connect_test_client(server_addr: SocketAddr) -> QuicResult<TestClient> {
    let config = QuicConfig::builder().verify_peer(false).build();
    connect_test_client_with_config(server_addr, &config).await
}

/// Like [`connect_test_client`], but derives the client configuration from the
/// provided [`QuicConfig`] (the same config type consumed by
/// [`generate_server_config`]).
///
/// Note that no client certificate is configured; the test setup relies on
/// `verify_peer = false`, so the self-signed server certificate is accepted
/// without a CA. mTLS is not wired up here.
pub async fn connect_test_client_with_config(
    server_addr: SocketAddr,
    config: &QuicConfig,
) -> QuicResult<TestClient> {
    // Bind an ephemeral localhost socket and connect it to the server so it can
    // be turned into a `tokio_quiche::socket::Socket`.
    let udp = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    udp.connect(server_addr).await?;
    let socket = Socket::try_from(udp)?;

    let params = ConnectionParams::new_client(quic_settings_from(config), None, Hooks::default());

    // The server endpoint negotiates HTTP/3 (ALPN `h3`), so drive the client
    // with the ready-made H3 application.
    let (h3_driver, controller) = ClientH3Driver::new(Http3Settings::default());
    let conn = connect_with_config(socket, Some("localhost"), &params, h3_driver).await?;

    Ok(TestClient { conn, controller })
}

/// Like [`connect_test_client_with_config`], but first sends a raw "config"
/// datagram declaring this connection's incoming-packet `budget` before the
/// QUIC handshake begins.
///
/// The config packet is sent from the same socket (hence the same source
/// address) that subsequently carries the QUIC traffic, so a
/// [`ConfiguredPerPeerLimitGate`] on the server can associate the budget with
/// this peer. The send is awaited before the handshake starts, and UDP
/// preserves per-flow ordering on localhost, so the gate observes the config
/// packet first. See [`ConfiguredPerPeerLimitGate`] for the budget semantics
/// (the config packet counts towards the budget).
pub async fn connect_test_client_with_budget(
    server_addr: SocketAddr,
    config: &QuicConfig,
    budget: u64,
) -> QuicResult<TestClient> {
    let udp = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    udp.connect(server_addr).await?;

    // Declare the budget before any QUIC packet leaves this socket.
    udp.send(&encode_packet_budget(budget)).await?;

    let socket = Socket::try_from(udp)?;

    let params = ConnectionParams::new_client(quic_settings_from(config), None, Hooks::default());
    let (h3_driver, controller) = ClientH3Driver::new(Http3Settings::default());
    let conn = connect_with_config(socket, Some("localhost"), &params, h3_driver).await?;

    Ok(TestClient { conn, controller })
}
