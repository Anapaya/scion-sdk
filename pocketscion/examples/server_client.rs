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
//! Simple end-to-end example using PocketScion and a ScionStack
//!
//! ## Overview
//!
//! 1. Starts a Pocket SCION runtime using topology defined in [example_topology].
//! 2. Creates a Server, which uses the ScionStack to listen for incoming connections.
//! 3. Creates a Client, which uses the ScionStack to connect to the Server.
//!
//! ------------------------
#![doc = include_str!("server_client.drawio.svg")]
//! ------------------------
//!
//! The ScionStack is a virtual network Stack, providing Scion enabled UDP sockets.
//! See: [scion_stack::scionstack::quic::ScionAsyncUdpSocket].
//!
//! A ScionAsyncUdpSocket can send/receive unreliable packets through a SCION network.
//! The [scion_stack::scionstack::quic::Endpoint] is a QUIC endpoint which uses this socket as its
//! transport.
//!
//! [PocketScionRuntime] is used to simulate a full SCION network. It provides:
//! - 1-n SCION Network Access Points (SNAPs) - allowing clients from the public internet to
//!   securely connect to the SCION network.
//! - A SCION Network Topology, which defines Autonomous Systems (ASes) and how they are connected.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::Context;
use bytes::Bytes;
use derive_more::Deref;
use ipnet::IpNet;
use pocketscion::{
    addr_to_http_url, io_config,
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::{PocketScionRuntime, PocketScionRuntimeBuilder},
    state::SharedPocketScionState,
};
use quinn::{EndpointConfig, crypto::rustls::QuicClientConfig, rustls::RootCertStore};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::{IsdAsn, ScionAddr, SocketAddr};
use scion_sdk_utils::test::install_rustls_crypto_provider;
use scion_stack::{
    quic::{QuinnConn, ScionQuinnConn},
    scionstack::ScionStackBuilder,
};
use serde::{Deserialize, Serialize};
use snap_tokens::snap_token::dummy_snap_token;
use tokio::{select, time::interval, try_join};
use tracing::{Instrument, info_span, level_filters::LevelFilter};
use url::Url;

const MESSAGE_PADDING: usize = 1000;

const LOG_INTERVAL_MS: u64 = 1000;
const SEND_INTERVAL_US: u64 = 1; // in microseconds

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    test_log::tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    let stat_tracker = Stats::default();

    install_rustls_crypto_provider();

    // Config
    let cfg = ExampleConfig {
        pocket_scion: PocketScionConfig {
            topology: example_topology()?,
            scion_access_points: vec![
                SnapConfig {
                    name: "server_snap".to_string(),
                    listening_addr: "127.0.0.1:10001".parse()?,
                    data_planes: vec![DataPlaneConfig {
                        listening_addr: "127.0.0.1:10002".parse()?,
                        isd_as: "2-2".parse()?,
                        address_range: vec!["10.1.0.0/24".parse()?],
                    }],
                },
                SnapConfig {
                    name: "client_snap".to_string(),
                    listening_addr: "127.0.0.1:10003".parse()?,
                    data_planes: vec![DataPlaneConfig {
                        listening_addr: "127.0.0.1:10004".parse()?,
                        isd_as: "2-1".parse()?,
                        address_range: vec!["10.2.0.0/24".parse()?],
                    }],
                },
            ],
        },
        server: ServerConfig {
            bind_port: 20001,
            use_snap: "server_snap".to_string(),
        },
        client: ClientConfig {
            use_snap: "client_snap".to_string(),
        },
    };

    //##############################################
    // Start Pocket SCION

    let _pocket_scion_runtime = {
        tracing::info!("Starting Pocket SCION runtime...");

        // Pocket SCIONs state is separated from IO Configuration to allow sharing the state
        // between multiple runtimes/machines/systems e.g. for testing purposes.
        let mut system_state = SharedPocketScionState::new(SystemTime::now());
        let io_config = io_config::SharedPocketScionIoConfig::new();

        // Set the topology
        system_state.set_topology(cfg.pocket_scion.topology.clone());

        // Create SCION Network Access Points (SNAPs)
        for snap in &cfg.pocket_scion.scion_access_points {
            // Add a new SNAP to the system state
            let snap_id = system_state.add_snap();

            // Then add an IO config to declare how this control plane can be reached
            io_config.set_snap_control_addr(snap_id, snap.listening_addr);

            for data_plane in &snap.data_planes {
                // Add the SNAP data plane to the system state
                let dataplane_id = system_state.add_snap_data_plane(
                    snap_id,
                    data_plane.isd_as,
                    data_plane.address_range.clone(),
                    ChaCha8Rng::seed_from_u64(10),
                );

                // Add an IO config
                io_config.set_snap_data_plane_addr(dataplane_id, data_plane.listening_addr);
            }
        }

        // Finally we create the PocketScionRuntime
        let rt: PocketScionRuntime = PocketScionRuntimeBuilder::new()
            .with_system_state(system_state.into_state())
            .with_io_config(io_config.into_state())
            .with_mgmt_listen_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 8082)))
            .start()
            .await
            .context("error starting Pocket SCION runtime")?;

        tracing::info!("Pocket SCION runtime started");

        rt
    };

    //##############################################
    // Setup the Server

    let (server_task, server_address, server_certificate) = async {
        // Create our SCION network stack - using the SNAP for the server as the Underlay
        let server_network_stack =
            ScionStackBuilder::new(cfg.get_snap_control_plane_host(&cfg.server.use_snap)?)
                .with_auth_token(dummy_snap_token())
                .build()
                .in_current_span()
                .await
                .context("error building server SCION stack")?;

        // Generate simple QUICK server config
        let (server_certificate, server_config) =
            scion_sdk_utils::test::generate_cert([42u8; 32], vec!["localhost".into()], vec![]);

        // Create a QUIC endpoint on top of the SCION network stack
        let server_quick_endpoint: scion_stack::scionstack::quic::Endpoint = server_network_stack
            .quic_endpoint(
                Some(SocketAddr::new(
                    ScionAddr::new(IsdAsn::WILDCARD, Ipv4Addr::UNSPECIFIED.into()),
                    cfg.server.bind_port,
                )),
                EndpointConfig::default(),
                Some(server_config),
                None,
            )
            .in_current_span()
            .await
            .context("error creating SCION QUIC endpoint")?;

        // Since we did not request a specific address, the SNAP will assign one
        let server_address = server_quick_endpoint.local_scion_addr();

        // The given Endpoint is a normal Quic endpoint
        let server_task = tokio::spawn(
            server_loop(server_quick_endpoint, stat_tracker.clone()).in_current_span(),
        );

        tracing::info!("Server listening on: {}", server_address);

        anyhow::Ok((server_task, server_address, server_certificate))
    }
    .instrument(info_span!("server"))
    .await?;

    //##############################################
    // Setup the Client

    let client_task = async {
        // Create the SCION network stack - using the SNAP for the client as the underlay
        let client_network_stack =
            ScionStackBuilder::new(cfg.get_snap_control_plane_host(&cfg.client.use_snap)?)
                .with_auth_token(dummy_snap_token())
                .build()
                .in_current_span()
                .await
                .context("error building client SCION stack")?;

        let addr = client_network_stack.bind(None).await?.local_addr();
        tracing::info!("Client address: {}", addr);

        // Create a QUIC endpoint on top of the SCION network stack
        let mut client_socket = client_network_stack
            .quic_endpoint(None, EndpointConfig::default(), None, None)
            .in_current_span()
            .await
            .context("error creating SCION QUIC endpoint")?;

        // Create a quic config
        let mut roots = RootCertStore::empty();
        roots
            .add(server_certificate)
            .context("error adding server certificate to root store")?;

        let client_crypto = quinn::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));

        client_socket.set_default_client_config(client_config);

        tracing::info!(
            "Client {} connecting to server at: {}",
            addr,
            server_address
        );

        // Connect to the server
        let connected_client_socket: quinn::Connection = client_socket
            .connect(server_address, "localhost")
            .context("error creating QUIC configuration")?
            .in_current_span()
            .await
            .context("error establishing connection with server")?;

        tracing::info!("Client connected to server");
        anyhow::Ok(tokio::task::spawn(
            client_loop(connected_client_socket, stat_tracker.clone()).in_current_span(),
        ))
    }
    .instrument(info_span!("client"))
    .await?;

    //##############################################
    // Logging

    let mut log_interval = interval(Duration::from_millis(LOG_INTERVAL_MS));
    let log_task = tokio::spawn(async move {
        loop {
            log_interval.tick().await;
            stat_tracker.print_stats();
        }
    });

    match try_join!(client_task, server_task, log_task) {
        Ok(_) => {
            unreachable!("Exited all loop tasks")
        }
        Err(e) => {
            tracing::error!("Some task failed: {:?}", e);
        }
    }

    Ok(())
}

async fn server_loop(server_quick_endpoint: scion_stack::scionstack::quic::Endpoint, stats: Stats) {
    // In the server, both the endpoint and connections can be used like a normal QUIC endpoint.
    loop {
        tracing::info!("Waiting for new client connection...");
        let client = match server_quick_endpoint.accept().await {
            Ok(Some(incoming)) => incoming,
            Ok(None) => {
                tracing::warn!("Socket closed, stopping server");
                break;
            }
            Err(e) => {
                tracing::error!("Error accepting connection: {:?}", e);
                continue;
            }
        };

        let addr = client.remote_address();
        tracing::info!("New client connected: {}", addr);

        let stats_c = stats.clone();
        tokio::task::spawn(async move {
            server_session_loop(client, stats_c)
                .instrument(info_span!("server"))
                .await
        });
    }

    async fn server_session_loop(conn: ScionQuinnConn, stats: Stats) {
        let mut send_interval =
            tokio::time::interval(std::time::Duration::from_micros(SEND_INTERVAL_US));

        loop {
            select! {
                _ = send_interval.tick() => {

                    let buf = PingPong {
                        timestamp_server: epoch_now(),
                        timestamp_client: None,
                    }.to_slice();

                    // Don't write if send would block
                    if conn.datagram_send_buffer_space() < buf.len() {
                        continue;
                    }


                    match conn.send_datagram(Bytes::copy_from_slice(&buf)) {
                        Ok(_) => {
                            stats.server_tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
                            stats.server_tx_packets.fetch_add(1, Ordering::Relaxed);

                            tracing::debug!("Sent ping to client");
                        },
                        Err(e) => {
                            tracing::error!("Failed to send ping to client: {:?}", e);
                            return;
                        }
                    }
                },
                recv = conn.read_datagram() => {
                    match recv {
                        Ok(data) => {
                            let now = epoch_now();

                            stats.server_rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                            stats.server_rx_packets.fetch_add(1, Ordering::Relaxed);

                            let msg = PingPong::from_slice(&data[0..PingPong::PACKET_SIZE]);

                            stats
                                .server_latency_sum
                                .fetch_add(now - msg.timestamp_client.expect("Must be set"), Ordering::Relaxed);
                        },
                        Err(e) => {
                            tracing::error!("Error receiving data, closing client: {:?}", e);
                            return;
                        }
                    }
                }

            }
        }
    }
}

async fn client_loop(conn: quinn::Connection, stats: Stats) {
    tracing::info!("Opening bidirectional stream to server...");

    loop {
        match conn.read_datagram().await {
            Ok(data) => {
                assert_eq!(
                    data.len(),
                    PingPong::PACKET_SIZE,
                    "Received unexpected data size"
                );
                let now = epoch_now();

                let mut message = PingPong::from_slice(&data[0..PingPong::PACKET_SIZE]);
                message.timestamp_client = Some(now);

                stats
                    .client_rx_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                stats.client_rx_packets.fetch_add(1, Ordering::Relaxed);
                stats
                    .client_latency_sum
                    .fetch_add(now - message.timestamp_server, Ordering::Relaxed);

                let message = message.to_slice();

                // Don't answer if it would block
                if conn.datagram_send_buffer_space() < message.len() {
                    continue;
                }

                match conn.send_datagram(Bytes::copy_from_slice(&message)) {
                    Ok(_) => {
                        stats.client_tx_packets.fetch_add(1, Ordering::Relaxed);
                        stats
                            .client_tx_bytes
                            .fetch_add(message.len() as u64, Ordering::Relaxed);

                        tracing::debug!("Sent pong");
                    }
                    Err(e) => {
                        tracing::error!("Failed to send pong: {:?}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error receiving data: {:?}", e);
                break;
            }
        }
    }
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PingPong {
    timestamp_server: u64,
    timestamp_client: Option<u64>,
}
impl PingPong {
    const HEADER_LENGTH: usize = size_of::<u64>() * 2;
    const PACKET_SIZE: usize = Self::HEADER_LENGTH + MESSAGE_PADDING;

    fn to_slice(&self) -> [u8; Self::PACKET_SIZE] {
        let mut buffer = [0x77; Self::PACKET_SIZE];
        buffer[..8].copy_from_slice(&self.timestamp_server.to_le_bytes());
        buffer[8..16].copy_from_slice(&self.timestamp_client.unwrap_or(0).to_le_bytes());

        buffer
    }

    fn from_slice(bytes: &[u8]) -> Self {
        let timestamp_ping = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let timestamp_pong = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        Self {
            timestamp_server: timestamp_ping,
            timestamp_client: Some(timestamp_pong),
        }
    }
}

#[derive(Debug)]
struct StatsInner {
    pub server_tx_packets: AtomicU64,
    pub server_tx_bytes: AtomicU64,
    pub server_rx_packets: AtomicU64,
    pub server_rx_bytes: AtomicU64,

    pub client_tx_packets: AtomicU64,
    pub client_tx_bytes: AtomicU64,
    pub client_rx_packets: AtomicU64,
    pub client_rx_bytes: AtomicU64,

    pub client_latency_sum: AtomicU64,
    pub server_latency_sum: AtomicU64,

    pub start_time: Instant,
}

impl Default for StatsInner {
    fn default() -> Self {
        Self {
            server_tx_packets: Default::default(),
            server_tx_bytes: Default::default(),
            server_rx_packets: Default::default(),
            server_rx_bytes: Default::default(),

            client_tx_packets: Default::default(),
            client_tx_bytes: Default::default(),
            client_rx_packets: Default::default(),
            client_rx_bytes: Default::default(),

            client_latency_sum: Default::default(),
            server_latency_sum: Default::default(),

            start_time: Instant::now(),
        }
    }
}

#[derive(Clone, Debug, Default, Deref)]
#[deref(forward)]
struct Stats(Arc<StatsInner>);

impl Stats {
    fn print_stats(&self) {
        let server_tx_packets = self.server_tx_packets.swap(0, Ordering::Relaxed);
        let server_tx_bytes = self.server_tx_bytes.swap(0, Ordering::Relaxed);
        let client_tx_packets = self.client_tx_packets.swap(0, Ordering::Relaxed);
        let client_tx_bytes = self.client_tx_bytes.swap(0, Ordering::Relaxed);

        let server_rx_packets = self.server_rx_packets.swap(0, Ordering::Relaxed);
        let server_rx_bytes = self.server_rx_bytes.swap(0, Ordering::Relaxed);
        let client_rx_packets = self.client_rx_packets.swap(0, Ordering::Relaxed);
        let client_rx_bytes = self.client_rx_bytes.swap(0, Ordering::Relaxed);

        let client_latency_sum = self.client_latency_sum.swap(0, Ordering::Relaxed);
        let client_latency_avg = client_latency_sum / client_rx_packets.max(1);

        let server_latency_sum = self.server_latency_sum.swap(0, Ordering::Relaxed);
        let server_latency_avg = server_latency_sum / server_rx_packets.max(1);

        let elapsed = self.start_time.elapsed().as_secs();
        tracing::info!(
            "{:<3}s | SRV | TX: {:>6} {:>9} | RX: {:>6} {:>9} | Ø OWD {:>11}",
            elapsed,
            server_tx_packets,
            print_bytes(server_tx_bytes),
            server_rx_packets,
            print_bytes(server_rx_bytes),
            micros_to_string(server_latency_avg)
        );
        tracing::info!(
            "     | CLI | TX: {:>6} {:>9} | RX: {:>6} {:>9} | Ø OWD {:>11}",
            client_tx_packets,
            print_bytes(client_tx_bytes),
            client_rx_packets,
            print_bytes(client_rx_bytes),
            micros_to_string(client_latency_avg)
        );

        // TX: {packets} {bytes} || Ø BUF SOCK {} TUNNEL {}  || Ø AVG {latency}
        // RX: {packets} {bytes} || Ø BUF SOCK {} TUNNEL {}
    }
}

fn print_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn micros_to_string(micros: u64) -> String {
    if micros < 1_000 {
        format!("{micros} us")
    } else if micros < 1_000_000 {
        format!("{:.3} ms", micros as f64 / 1_000.0)
    } else {
        let secs = micros / 1_000_000;
        let rem_micros = micros % 1_000_000;
        format!("{secs}.{rem_micros:06} s")
    }
}

/// Defines a Network Topology to be simulated through Pocket SCION.
pub fn example_topology() -> anyhow::Result<ScionTopology> {
    let mut topo = ScionTopology::new();

    topo.add_as(ScionAs::new_core("1-1".parse()?))?
        .add_as(ScionAs::new("1-2".parse()?))?
        .add_as(ScionAs::new("1-3".parse()?))?
        .add_as(ScionAs::new("1-4".parse()?))?
        .add_as(ScionAs::new_core("1-11".parse()?))?
        .add_as(ScionAs::new("1-12".parse()?))?
        .add_as(ScionAs::new_core("1-21".parse()?))?
        .add_as(ScionAs::new_core("2-1".parse()?))?
        .add_as(ScionAs::new("2-2".parse()?))?
        .add_as(ScionAs::new("2-3".parse()?))?
        .add_as(ScionAs::new("2-4".parse()?))?;

    // Core links
    topo.add_link("1-1#5 core 1-11#6".parse()?)?
        .add_link("1-1#32 core 1-21#17".parse()?)?
        .add_link("1-11#15 core 1-21#22".parse()?)?
        .add_link("1-21#23 core 2-1#24".parse()?)?
        .add_link("1-11#23 core 2-1#1".parse()?)?;

    // Single digit as links
    topo.add_link("1-1#1 down_to 1-2#2".parse()?)?
        .add_link("1-2#3 down_to 1-3#4".parse()?)?
        .add_link("1-3#15 down_to 1-4#16".parse()?)?
        .add_link("1-2#17 down_to 1-4#18".parse()?)?;

    // Double digit as links
    topo.add_link("1-11#7 down_to 1-12#8".parse()?)?
        .add_link("1-12#9 down_to 1-3#10".parse()?)?
        .add_link("1-12#19 down_to 1-4#20".parse()?)?
        .add_link("1-12#12 down_to 1-2#11 ".parse()?)?;

    // ISD2 links
    topo.add_link("2-1#2 down_to 2-2#3".parse()?)?
        .add_link("2-2#4 down_to 2-3#5".parse()?)?
        .add_link("2-3#6 down_to 2-4#7".parse()?)?;

    Ok(topo)
}

/// Configuration
struct ExampleConfig {
    pocket_scion: PocketScionConfig,

    server: ServerConfig,
    client: ClientConfig,
}
impl ExampleConfig {
    /// Gets the named config for a SNAP
    fn get_snap_control_plane_host(&self, snap_name: &str) -> anyhow::Result<Url> {
        self.pocket_scion
            .scion_access_points
            .iter()
            .find(|snap| snap.name == snap_name)
            .map(|snap| addr_to_http_url(snap.listening_addr))
            .with_context(|| format!("snap: '{snap_name}' was not declared in the ExampleConfig"))
    }
}

struct PocketScionConfig {
    /// The SCION network topology being simulated
    topology: ScionTopology,
    /// SCION Network Access Points (SNAP) for the server and client
    scion_access_points: Vec<SnapConfig>,
}

struct ServerConfig {
    /// The port on the SCION Network Stack the server should bind to
    bind_port: u16,
    /// The name of the SNAP this server should use
    use_snap: String,
}

/// SCION Network Access Point (SNAP) configuration
struct SnapConfig {
    /// Example internal name of the SNAP
    name: String,
    /// Listening address for the SNAP's control plane
    listening_addr: std::net::SocketAddr,
    /// This SNAP's data planes
    data_planes: Vec<DataPlaneConfig>,
}

struct ClientConfig {
    /// The name of the SNAP this client should use
    use_snap: String,
}

struct DataPlaneConfig {
    isd_as: IsdAsn,
    /// The LAN address this data plane should listen on
    listening_addr: std::net::SocketAddr,
    /// The (virtual) IP addresses this data plane can assign to its clients
    address_range: Vec<IpNet>,
}
