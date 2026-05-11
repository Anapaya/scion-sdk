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

//! In-memory network stack for the Network Simulator, allowing binding to a specific AS and IP
//! address, and sending and receiving SCION packets to and from the Network Simulator.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    packet::{ByEndpoint, NextHeader, ScionPacketRaw, ScionPacketUdp},
    path::DataPlanePath,
};
use scion_sdk_quic_scion::socket::{BoxedSocketError, GenericScionUdpSocket};
use tokio::sync::{Mutex, mpsc};

use crate::{
    network::{local::receivers::Receiver, scion::routing::ScionNetworkTime},
    state::SharedPocketScionState,
};

/// A in-memory network stack, allowing binding to a specific AS and IP address, and sending and
/// receiving SCION packets to and from the
#[derive(Clone)]
pub struct NetSimStack(Arc<NetSimStackInner>);

struct NetSimStackInner {
    state: SharedPocketScionState,

    udp_receivers: RwLock<HashMap<u16, mpsc::Sender<ScionPacketUdp>>>,
    raw_recevers: RwLock<Vec<mpsc::Sender<ScionPacketRaw>>>,

    local_as: IsdAsn,
    bind_addr: IpAddr,

    /// The size of the receive queues per socket.
    rx_queue_size: usize,
}

impl NetSimStack {
    /// Creates a new Network Simulator IP Stack with the given topology and bind address.
    ///
    /// The Stack is automatically as a receiver for the Network Simulator, and will receive packets
    /// sent to the given AS and IP address.
    ///
    /// If a receiver for the given AS and IP address already exists, an error is returned.
    pub fn bind(
        state: SharedPocketScionState,
        local_as: IsdAsn,
        bind_addr: IpAddr,
        queue_size: usize,
    ) -> anyhow::Result<Self> {
        let this = Self(Arc::new(NetSimStackInner {
            state: state.clone(),
            udp_receivers: RwLock::new(HashMap::new()),
            raw_recevers: RwLock::new(Vec::new()),
            local_as,
            bind_addr,
            rx_queue_size: queue_size,
        }));

        state.add_sim_receiver(local_as, bind_addr.into(), this.0.clone())?;

        Ok(this)
    }

    /// Binds a UDP socket to the stack on the given port, allowing sending and receiving SCION UDP
    /// packets. If port is 0, a random available port will be chosen. If the specified port is
    /// already in use, an error is returned.
    ///
    /// The socket will receive packets sent to the stack's AS and IP address with the matching
    /// destination port.
    pub fn bind_udp(&self, mut port: u16) -> anyhow::Result<NetSimUdpSocket> {
        let mut udp_receivers = self.0.udp_receivers.write().unwrap();

        if port == 0 {
            for check_port in 1024..65535 {
                if !udp_receivers.contains_key(&check_port) {
                    port = check_port;
                    break;
                }
            }

            if port == 0 {
                anyhow::bail!("No available ports");
            }
        }

        if udp_receivers.contains_key(&port) {
            anyhow::bail!("Port {} already in use", port);
        }

        let (socket, receiver) = NetSimUdpSocket::new(self.clone(), self.0.rx_queue_size, port);
        udp_receivers.insert(port, receiver);

        Ok(socket)
    }

    /// Binds a raw socket to the stack, allowing sending and receiving raw SCION packets. The
    /// socket will receive all packets sent to the stack's AS and IP address, regardless of
    /// port.
    pub fn bind_raw(&self) -> NetSimRawSocket {
        let mut raw_receivers = self.0.raw_recevers.write().unwrap();
        let (socket, receiver) = NetSimRawSocket::new(self.clone(), self.0.rx_queue_size);
        raw_receivers.push(receiver);

        socket
    }

    /// Cleans up all disconnected sockets from the stack
    pub fn clean(&self) {
        let mut udp_receivers = self.0.udp_receivers.write().unwrap();
        udp_receivers.retain(|_, rx| !rx.is_closed());

        let mut raw_receivers = self.0.raw_recevers.write().unwrap();
        raw_receivers.retain(|rx| !rx.is_closed());
    }

    /// Dispatches a packet to the network simulator, with the given timestamp. The packet will be
    /// sent from the local AS.
    fn send(&self, packet: ScionPacketRaw, timestamp: ScionNetworkTime) {
        self.0
            .state
            .dispatch_to_network_sim(self.0.local_as, 0, timestamp, packet);
    }
}

impl Receiver for NetSimStackInner {
    fn receive_packet(&self, packet: ScionPacketRaw) {
        // Check IP addr
        let dest_addr = packet.headers.address.destination();
        if !dest_addr
            .iter()
            .flat_map(|addr| addr.local_address())
            .any(|addr| addr == self.bind_addr)
        {
            tracing::warn!(
                packet_destination = ?dest_addr,
                local_address = ?self.bind_addr,
                "Received packet with destination address that does not match socket's bind address, dropping packet"
            );
            return;
        }

        let mut forwarded_once = false;
        // Always forward to raw receivers
        {
            let raw_recv = self.raw_recevers.read().unwrap();
            for raw_rx in raw_recv.iter() {
                match raw_rx.try_reserve() {
                    Ok(permit) => {
                        permit.send(packet.clone());
                        forwarded_once = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "Raw socket receiver is full, dropping packet for this receiver"
                        );
                    }
                }
            }
        }

        // Check packet type
        if packet.headers.common.next_header == NextHeader::UDP {
            // Forward to UDP receivers based on destination port.
            let pkt = match ScionPacketUdp::try_from(packet.clone()) {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "Failed to parse received packet as SCION UDP, not forwarding to UDP receivers"
                    );
                    return;
                }
            };
            let udp_receivers = self.udp_receivers.read().unwrap();

            let Some(udp) = udp_receivers.get(&pkt.dst_port()) else {
                if !forwarded_once {
                    tracing::warn!(
                        port = pkt.dst_port(),
                        "Received UDP packet for port that has no receiver, and no raw receivers to forward to, dropping packet"
                    );
                }
                return;
            };

            match udp.try_reserve() {
                Ok(permit) => permit.send(pkt),
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        port = pkt.dst_port(),
                        "UDP socket receiver is full, dropping packet for this receiver"
                    );
                }
            }
        }
    }
}

/// A bound UDP socket using the Network Simulator Stack
///
/// To create a socket, call [NetSimStack::bind_udp()].
pub struct NetSimUdpSocket {
    stack: NetSimStack,
    rx_queue: Mutex<mpsc::Receiver<ScionPacketUdp>>,
    port: u16,
}

impl NetSimUdpSocket {
    fn new(
        stack: NetSimStack,
        rx_queue_size: usize,
        port: u16,
    ) -> (Self, mpsc::Sender<ScionPacketUdp>) {
        let (rx_queue_sender, rx_queue) = mpsc::channel(rx_queue_size);
        (
            Self {
                stack,
                rx_queue: Mutex::new(rx_queue),
                port,
            },
            rx_queue_sender,
        )
    }

    /// Converts this socket into a path-aware socket using the given path provider.
    pub fn into_path_aware<P: NetSimPathProvider>(
        self,
        path_provider: P,
    ) -> PathAwareNetSimUdpSocket<P> {
        PathAwareNetSimUdpSocket::new(self, path_provider)
    }

    /// Sends a raw SCION packet through the socket to the network simulator.
    pub fn try_send(
        &self,
        dst: scion_proto::address::SocketAddr,
        path: DataPlanePath<Bytes>,
        payload: Bytes,
        timestamp: ScionNetworkTime,
    ) -> io::Result<()> {
        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::new(
                    ScionAddr::new(self.stack.0.local_as, self.stack.0.bind_addr.into()),
                    self.port,
                ),
                destination: dst,
            },
            path,
            payload,
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to construct SCION packet: {e}"),
            )
        })?;

        self.stack.send(packet.into(), timestamp);

        Ok(())
    }

    /// Tries to receive a packet from the socket's receive queue, returning an error if the queue
    /// is empty or if the socket has been disconnected.
    pub fn try_recv(&self) -> io::Result<ScionPacketUdp> {
        match self
            .rx_queue
            .try_lock()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Failed to acquire lock"))?
            .try_recv()
        {
            Ok(p) => Ok(p),
            Err(err) => {
                match err {
                    mpsc::error::TryRecvError::Empty => {
                        Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "No packet available",
                        ))
                    }
                    mpsc::error::TryRecvError::Disconnected => {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "Socket receiver disconnected",
                        ))
                    }
                }
            }
        }
    }

    /// Asynchronously receives a packet from the socket's receive queue, returning an error if the
    /// socket has been disconnected.
    pub async fn recv(&self) -> io::Result<ScionPacketUdp> {
        match self.rx_queue.lock().await.recv().await {
            Some(p) => Ok(p),
            None => {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Socket receiver disconnected",
                ))
            }
        }
    }

    /// Returns the local socket address of this socket.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(
            ScionAddr::new(self.stack.0.local_as, self.stack.0.bind_addr.into()),
            self.port,
        )
    }
}

/// A raw socket using the Network Simulator Stack, allowing sending and receiving raw SCION
/// packets.
///
/// To create a socket, call [NetSimStack::bind_raw()].
pub struct NetSimRawSocket {
    stack: NetSimStack,
    rx_queue: Mutex<mpsc::Receiver<ScionPacketRaw>>,
}

impl NetSimRawSocket {
    fn new(stack: NetSimStack, rx_queue_size: usize) -> (Self, mpsc::Sender<ScionPacketRaw>) {
        let (rx_queue_sender, rx_queue) = mpsc::channel(rx_queue_size);
        (
            Self {
                stack,
                rx_queue: Mutex::new(rx_queue),
            },
            rx_queue_sender,
        )
    }

    /// Sends a raw SCION packet through the socket to the network simulator.
    pub fn try_send(&self, packet: ScionPacketRaw, timestamp: ScionNetworkTime) -> io::Result<()> {
        self.stack.send(packet, timestamp);
        Ok(())
    }

    /// Tries to receive a packet from the socket's receive queue, returning an error if the queue
    /// is empty or if the socket has been disconnected.
    pub fn try_recv(&self) -> io::Result<ScionPacketRaw> {
        match self
            .rx_queue
            .try_lock()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Failed to acquire lock"))?
            .try_recv()
        {
            Ok(p) => Ok(p),
            Err(err) => {
                match err {
                    mpsc::error::TryRecvError::Empty => {
                        Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "No packet available",
                        ))
                    }
                    mpsc::error::TryRecvError::Disconnected => {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "Socket receiver disconnected",
                        ))
                    }
                }
            }
        }
    }

    /// Asynchronously receives a packet from the socket's receive queue, returning an error if the
    /// socket has been disconnected.
    pub async fn recv(&self) -> io::Result<ScionPacketRaw> {
        match self.rx_queue.lock().await.recv().await {
            Some(p) => Ok(p),
            None => {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Socket receiver disconnected",
                ))
            }
        }
    }

    /// Returns the local SCION address of this socket, consisting of the stack's AS and IP
    pub fn scion_addr(&self) -> ScionAddr {
        ScionAddr::new(self.stack.0.local_as, self.stack.0.bind_addr.into())
    }
}

/// Provider of paths for the Network Simulator Socket.
///
/// get_path will be called for every packet sent through the Network Simulator Socket.
pub trait NetSimPathProvider: Send + Sync + 'static {
    /// Returns a path from the given source AS to the given destination AS, if one exists.
    fn get_path(&self, src_as: IsdAsn, dst_as: IsdAsn) -> Option<DataPlanePath>;
}

/// A path-aware UDP socket using the Network Simulator Stack using provided paths from a
/// [NetSimPathProvider], allowing sending and receiving SCION packets without needing to specify
/// the path for each packet.
pub struct PathAwareNetSimUdpSocket<P: NetSimPathProvider> {
    socket: NetSimUdpSocket,
    /// The path provider for this socket, used to obtain paths for sending packets.
    pub path_provider: P,
}

impl<P: NetSimPathProvider> PathAwareNetSimUdpSocket<P> {
    /// Creates a new path-aware UDP socket
    pub fn new(socket: NetSimUdpSocket, path_provider: P) -> Self {
        Self {
            socket,
            path_provider,
        }
    }

    /// Sends a packet to the given destination address, using the path provider to obtain a path
    /// from the local AS to the destination AS. Returns an error if no path is found or if sending
    /// fails for any reason.
    pub fn try_send(
        &self,
        dst: scion_proto::address::SocketAddr,
        payload: Bytes,
    ) -> io::Result<()> {
        let path = self
            .path_provider
            .get_path(self.socket.stack.0.local_as, dst.isd_asn())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "No path found from AS {} to destination AS {}",
                        self.socket.stack.0.local_as,
                        dst.isd_asn()
                    ),
                )
            })?;

        self.socket
            .try_send(dst, path, payload, ScionNetworkTime::now())
    }

    /// Attempts to receive a packet from the socket's receive queue, returning an error if no
    /// packet is available or if the socket has been disconnected.
    pub fn try_recv(&mut self) -> io::Result<ScionPacketUdp> {
        self.socket.try_recv()
    }

    /// Asynchronously receives a packet from the socket's receive queue, returning an error if the
    /// socket has been disconnected.
    pub async fn recv(&self) -> io::Result<ScionPacketUdp> {
        self.socket.recv().await
    }
}

#[async_trait::async_trait]
impl<P: NetSimPathProvider> GenericScionUdpSocket for PathAwareNetSimUdpSocket<P> {
    /// Asynchronously sends a Datagram to the specified destination address.
    async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> Result<(), BoxedSocketError> {
        self.try_send(destination, Bytes::copy_from_slice(payload))
            .map_err(|e| Box::new(e) as BoxedSocketError)?;
        Ok(())
    }

    /// Asynchronously receives a Datagram, writing it into the provided buffer, and returns the
    /// number of bytes read and the source address.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), BoxedSocketError> {
        let (pkt, src_addr) = loop {
            let pkt = self
                .recv()
                .await
                .map_err(|e| Box::new(e) as BoxedSocketError)?;

            let sci_addr = match pkt.headers.address.source() {
                Some(addr) => addr,
                None => {
                    tracing::warn!("Received packet with unknown source address, dropping packet");
                    continue;
                }
            };

            let port = pkt.src_port();

            break (pkt, SocketAddr::new(sci_addr, port));
        };

        let payload = pkt.payload();

        // Copy the payload into the provided buffer, truncating if necessary.
        let payload_len = std::cmp::min(buf.len(), payload.len());
        buf[..payload_len].copy_from_slice(&payload[..payload_len]);

        Ok((payload_len, src_addr))
    }

    /// Returns the local socket address of this socket.
    fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(
            ScionAddr::new(
                self.socket.stack.0.local_as,
                self.socket.stack.0.bind_addr.into(),
            ),
            self.socket.port,
        )
    }
}

impl SharedPocketScionState {
    /// Creates a new Network Simulator Stack bound to the given AS and IP address, with the given
    /// receive queue size.
    ///
    /// The Socket is automatically registered as a receiver for the Network Simulator, and will
    /// receive packets sent to the given AS and IP address. If a receiver for the given AS and IP
    /// address already exists, an error is returned.
    pub fn bind_sim_network_stack(
        &self,
        local_as: IsdAsn,
        bind_addr: IpAddr,
        queue_size: usize,
    ) -> anyhow::Result<NetSimStack> {
        NetSimStack::bind(self.clone(), local_as, bind_addr, queue_size)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::SystemTime};

    use bytes::Bytes;
    use scion_proto::{
        address::{IsdAsn, ScionAddr, SocketAddr},
        packet::{ByEndpoint, ScionPacketUdp},
        path::DataPlanePath,
    };
    use tokio::time::{Duration, timeout};

    use crate::{
        network::scion::{
            routing::ScionNetworkTime,
            topology::{ScionAs, ScionTopology},
        },
        state::SharedPocketScionState,
    };

    fn setup_state(isd_as: IsdAsn) -> SharedPocketScionState {
        let mut state = SharedPocketScionState::new(SystemTime::now());
        let mut topology = ScionTopology::new();
        topology
            .add_as(ScionAs::new_core(isd_as))
            .expect("failed to add AS");
        state.set_topology(topology);
        state
    }

    #[tokio::test]
    async fn should_deliver_udp_to_port_and_raw_receiver() {
        let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
        let bind_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let queue_size = 8;

        let state = setup_state(local_as);
        let stack = state
            .bind_sim_network_stack(local_as, bind_ip, queue_size)
            .expect("bind sim stack");
        let udp_socket = stack.bind_udp(40000).expect("bind udp socket");
        let raw_socket = stack.bind_raw();

        let src_ip: IpAddr = "10.0.0.9".parse().unwrap();
        let src = SocketAddr::new(ScionAddr::new(local_as, src_ip.into()), 50000);
        let dst = SocketAddr::new(ScionAddr::new(local_as, bind_ip.into()), 40000);
        let payload = Bytes::from_static(b"hello");
        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: src,
                destination: dst,
            },
            DataPlanePath::EmptyPath,
            payload.clone(),
        )
        .expect("build packet");

        state.dispatch_to_network_sim(local_as, 0, ScionNetworkTime::now(), packet.clone().into());

        let recv_udp = timeout(Duration::from_secs(2), udp_socket.recv())
            .await
            .expect("udp recv timeout")
            .expect("udp recv packet");
        assert_eq!(recv_udp.payload(), &payload); // UDP socket receives payload

        let recv_raw = timeout(Duration::from_secs(2), raw_socket.recv())
            .await
            .expect("raw recv timeout")
            .expect("raw recv packet");
        let recv_raw_udp: ScionPacketUdp = recv_raw.try_into().expect("raw packet as UDP");
        assert_eq!(recv_raw_udp.payload(), &payload); // raw socket receives same payload
    }

    #[tokio::test]
    async fn should_send_udp_between_stacks() {
        let local_as: IsdAsn = "1-ff00:0:110".parse().unwrap();
        let sender_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let receiver_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let queue_size = 8;

        let state = setup_state(local_as);
        let sender_stack = state
            .bind_sim_network_stack(local_as, sender_ip, queue_size)
            .expect("bind sender stack");
        let receiver_stack = state
            .bind_sim_network_stack(local_as, receiver_ip, queue_size)
            .expect("bind receiver stack");

        let sender_socket = sender_stack.bind_udp(0).expect("bind sender udp");
        let receiver_socket = receiver_stack.bind_udp(41000).expect("bind receiver udp");

        let dst = SocketAddr::new(ScionAddr::new(local_as, receiver_ip.into()), 41000);
        let payload = Bytes::from_static(b"cross-stack");
        sender_socket
            .try_send(
                dst,
                DataPlanePath::EmptyPath,
                payload.clone(),
                ScionNetworkTime::now(),
            )
            .expect("send packet");

        let recv = timeout(Duration::from_secs(2), receiver_socket.recv())
            .await
            .expect("recv timeout")
            .expect("recv packet");

        assert_eq!(recv.payload(), &payload); // receiver gets payload
        assert_eq!(
            recv.source().expect("source addr"),
            sender_socket.socket_addr()
        );
    }
}
