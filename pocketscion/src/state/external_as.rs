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

//! External AS allows clients to discover Endhost APIs available to them

use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use scion_proto::{address::IsdAsn, packet::ScionPacketRaw};
use serde::{Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    task::{self},
};
use utoipa::ToSchema;

use crate::{
    io_config::SharedPocketScionIoConfig,
    network::{
        local::external_as_handler::ExternalAsHandler,
        scion::{routing::ScionNetworkTime, topology::ScionGlobalInterfaceId},
    },
    state::{SharedPocketScionState, external_as::conn::ExternalAsConnection},
    util::{BtreeMapError, map_btree, map_btree_fallible},
};

/// Represents multiple connections to an External AS in Pocket SCION
///
/// M Simulated ASes with M Interfaces which connect to 1 External AS
///
/// - Manages the Connections to the External AS and receiving packets from it
/// - Manages tasks associated with the External AS
pub struct ExternalAsService {
    /// IsdAsn of the External AS.
    #[expect(unused)]
    isd_as: IsdAsn,
    /// Map of as interfaces which connect to the External AS, keyed by IsdAsn and interface ID
    as_interfaces: HashMap<IsdAsn, HashMap<u16, ExternalAsInterface>>,
    #[expect(unused)]
    app_state: SharedPocketScionState,
    #[expect(unused)]
    task_set: task::JoinSet<()>,
}

impl ExternalAsService {
    /// Starts the External AS service for the given ISD-ASN, if it exists in the state.
    ///
    /// Will return after the server has stopped (e.g. due to an error).
    ///
    /// To start the External AS service:
    /// 1. A Topology containing an AS with the given ISD-ASN must be present in the system state,
    ///    and that AS must be marked as external.
    /// 2. The External AS must be added to the system state using
    ///    [SharedPocketScionState::add_external_as] with the same ISD-ASN.
    /// 3. For each link defined in the topology, an interface with the corresponding interface ID
    ///    must be present in the External AS state.
    /// 4. For each interface defined in the External AS state, a corresponding link with the same
    ///    interface ID must be present in the topology.
    pub async fn start(
        ext_isd_as: IsdAsn,
        app_state: SharedPocketScionState,
        io_config: SharedPocketScionIoConfig,
    ) -> anyhow::Result<Arc<ExternalAsService>> {
        let external_as = app_state
            .external_as(ext_isd_as)
            .context("No External AS API configured with the given ID")?;

        // Map of (external_if, internal_if)
        let mut link_map = HashMap::new();
        // Validate that the topology and External AS state are consistent with each other.
        {
            let state_guard = app_state.system_state.read().unwrap();
            let link_iter = state_guard
                .topology
                .as_ref()
                .context(
                    "To start External AS Service, a topology must be present in the system state",
                )?
                .iter_scion_links_by_as(&ext_isd_as);

            for link in link_iter {
                let link = link
                    .get_directed_from(&ext_isd_as)
                    .context("AS link is not connected to the expected AS, topology is inconsistent with External AS state")?;
                let ext = link.from;
                let intern = link.to;

                // Check that the interface is present in the External AS state
                let Some(_) = external_as.interfaces.get(&ext.if_id) else {
                    anyhow::bail!(
                        "Interface {} for External AS {} is missing from External AS state",
                        ext.if_id,
                        ext_isd_as
                    );
                };

                link_map.insert(ext.if_id, (ext, intern));
            }
        }

        let mut interfaces = HashMap::new();
        let mut task_set = task::JoinSet::new();
        // For each interface, prepare IO and spawn recv task
        // Note: These copy the system state, so they will not react to runtime changes in the
        // system state.
        {
            for (ext_iface_id, iface_state) in external_as.interfaces.iter() {
                let (external_if, internal_if) = *link_map.get(ext_iface_id).context(format!(
                    "Topology is missing link with interface {}#{}",
                    ext_isd_as, ext_iface_id,
                ))?;

                let target_addr = iface_state.target_addr;
                let listen_addr = match io_config
                    .external_as_interface_addr(ext_isd_as, *ext_iface_id)
                {
                    Some(addr) => addr,
                    None => {
                        // If no address is configured, let the OS assign one and update the config
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)
                    }
                };

                let socket = UdpSocket::bind(listen_addr)
                    .await
                    .context("error binding udp listener for External AS API")?;

                // Update IoConfig with the actual address
                io_config.set_external_as_interface_addr(
                    ext_isd_as,
                    *ext_iface_id,
                    socket.local_addr()?,
                );

                // Create connection and spawn recv task
                let iface = ExternalAsInterface {
                    external_if,
                    internal_if,
                    conn: ExternalAsConnection::new(ext_isd_as, socket, target_addr),
                    state: app_state.clone(),
                };

                // Spawn recv task for this interface
                task_set.spawn(iface.clone().recv_loop());

                // Insert interface into map
                interfaces
                    .entry(internal_if.isd_as)
                    .or_insert_with(HashMap::new)
                    .insert(*ext_iface_id, iface);

                tracing::info!(
                    %target_addr,
                    %listen_addr,
                    ?ext_isd_as,
                    "Started External AS interface {}",
                    internal_if,
                );
            }
        }

        Ok(Arc::new(ExternalAsService {
            isd_as: ext_isd_as,
            app_state,
            as_interfaces: interfaces,
            task_set,
        }))
    }
}

impl ExternalAsHandler for ExternalAsService {
    fn handle_incoming_packet(
        &self,
        from: ScionGlobalInterfaceId,
        to: ScionGlobalInterfaceId,
        packet: &mut ScionPacketRaw,
    ) {
        let Some(iface) = self
            .as_interfaces
            .get(&from.isd_as)
            .and_then(|iface_map| iface_map.get(&to.if_id))
        else {
            // Simulation should not send incorrect packets
            tracing::warn!(
                "Received packet from AS {from}, to AS {to}, no matching interface found. Dropping packet.",
            );
            return;
        };

        iface.handle_incoming_packet(from, to, packet);
    }
}

/// Represents a SCION-link between an internal and external AS, responsible
/// for sending and receiving packets to/from the External AS on that interface and dispatching
/// received packets to the network simulation.
#[derive(Clone)]
struct ExternalAsInterface {
    /// The External AS interface ID
    external_if: ScionGlobalInterfaceId,
    /// The internal interface ID
    internal_if: ScionGlobalInterfaceId,
    conn: ExternalAsConnection,
    state: SharedPocketScionState,
}

impl ExternalAsInterface {
    /// Continuously receives packets from the External AS connection and dispatches them to the
    /// network simulation until an error occurs.
    pub async fn recv_loop(self) {
        let mut recv_buf = Box::new([0u8; 65535]);
        loop {
            match self.conn.recv(&mut *recv_buf).await {
                Ok(pkt) => {
                    self.state.dispatch_to_network_sim(
                        self.internal_if.isd_as,
                        self.internal_if.if_id,
                        ScionNetworkTime::now(),
                        pkt,
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = ?e,
                        "Error receiving packet from External Interface {}, stopping recv task",
                        self.external_if
                    );
                    break;
                }
            }
        }
    }

    /// Handles an incoming packet from the network simulation by sending it to the External AS if
    /// it matches the expected from and to AS and interface IDs for this interface, otherwise drops
    fn handle_incoming_packet(
        &self,
        from: ScionGlobalInterfaceId,
        to: ScionGlobalInterfaceId,
        packet: &mut ScionPacketRaw,
    ) {
        if from != self.internal_if {
            // Simulation should not send incorrect packets
            tracing::warn!(
                "Received packet from AS {}, but handler expects packets from AS {}. Dropping packet.",
                from,
                self.internal_if.isd_as,
            );
            return;
        }

        if to != self.external_if {
            // Simulation should not send incorrect packets
            tracing::warn!(
                "Received packet for Interface {}, but handler only accepts packets for Interface {}. Dropping packet.",
                to,
                self.external_if
            );
            return;
        }

        match self.conn.try_send(packet.clone()) {
            Ok(_) => {}
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        tracing::warn!(
                            "Dropping packet to External AS {} because the send buffer is full.",
                            self.external_if
                        );
                    }
                    _ => {
                        tracing::error!(
                            error = ?e,
                            "Socket error when sending packet to External AS {}",
                            self.external_if
                        );
                    }
                }
            }
        }
    }
}

/// Serializable State for an External AS stored in PocketScionState
#[derive(Debug, Clone)]
pub struct ExternalAsState {
    interfaces: BTreeMap<u16, ExternalAsInterfaceState>,
}

/// Serializable State for an External AS interface stored in ExternalAsState
#[derive(Debug, Clone)]
pub struct ExternalAsInterfaceState {
    /// ID of the interface described
    interface_id: u16,
    /// Address to where this interface connects, used for sending packets to the External AS and
    /// validating received packets
    target_addr: SocketAddr,
}

/// Serialized state for ExternalAsState
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExternalAsStateDto {
    interfaces: BTreeMap<u16, ExternalAsInterfaceDto>,
}

impl From<ExternalAsState> for ExternalAsStateDto {
    fn from(value: ExternalAsState) -> Self {
        ExternalAsStateDto {
            interfaces: map_btree(value.interfaces, |iface_state| iface_state.into()),
        }
    }
}

impl TryFrom<ExternalAsStateDto> for ExternalAsState {
    type Error = BtreeMapError<u16, std::net::AddrParseError>;

    fn try_from(value: ExternalAsStateDto) -> Result<Self, Self::Error> {
        Ok(ExternalAsState {
            interfaces: map_btree_fallible(value.interfaces, |iface_state| iface_state.try_into())?,
        })
    }
}

/// Serialized state for ExternalAsInterfaceState
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExternalAsInterfaceDto {
    /// ID of the interface described
    interface_id: u16,
    /// Address to where this interface connects, used for sending packets to the External AS and
    /// validating received packets
    target_addr: String,
}

impl From<ExternalAsInterfaceState> for ExternalAsInterfaceDto {
    fn from(value: ExternalAsInterfaceState) -> Self {
        ExternalAsInterfaceDto {
            interface_id: value.interface_id,
            target_addr: value.target_addr.to_string(),
        }
    }
}

impl TryFrom<ExternalAsInterfaceDto> for ExternalAsInterfaceState {
    type Error = std::net::AddrParseError;

    fn try_from(value: ExternalAsInterfaceDto) -> Result<Self, Self::Error> {
        Ok(ExternalAsInterfaceState {
            interface_id: value.interface_id,
            target_addr: value.target_addr.parse()?,
        })
    }
}

impl SharedPocketScionState {
    /// Adds a new External AS to the System state with the given IAs
    pub fn add_external_as(&mut self, isd_asn: IsdAsn) -> anyhow::Result<()> {
        let mut sstate = self.system_state.write().unwrap();
        let is_external = sstate
            .topology
            .as_ref()
            .context("To add an External AS, a topology must be present")?
            .as_map
            .get(&isd_asn)
            .context(
                "No AS with the given ISD-ASN found in topology, cannot be added as External AS",
            )?
            .is_external();

        if !is_external {
            anyhow::bail!(
                "AS with the given ISD-ASN is not marked as external in the topology, cannot be added as External AS"
            );
        }

        if sstate.external_ases.contains_key(&isd_asn) {
            anyhow::bail!("External AS with the given ISD-ASN already exists");
        }

        sstate.external_ases.insert(
            isd_asn,
            ExternalAsState {
                interfaces: BTreeMap::new(),
            },
        );

        Ok(())
    }

    /// Adds a new interface to an existing External AS in the System state with the given interface
    /// ID and target address.
    pub fn add_external_as_interface(
        &mut self,
        isd_asn: IsdAsn,
        interface_id: u16,
        target_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let mut sstate = self.system_state.write().unwrap();
        let ext_as = sstate
            .external_ases
            .get_mut(&isd_asn)
            .context("External AS with the given ISD-ASN does not exist")?;

        if ext_as.interfaces.contains_key(&interface_id) {
            anyhow::bail!(
                "Interface with the given ID already exists for External AS {}, cannot add interface",
                isd_asn
            );
        }

        ext_as.interfaces.insert(
            interface_id,
            ExternalAsInterfaceState {
                interface_id,
                target_addr,
            },
        );

        Ok(())
    }

    /// Returns a map of all External AS APIs in the system state.
    pub(crate) fn external_ases(&self) -> BTreeMap<IsdAsn, ExternalAsState> {
        self.system_state.read().unwrap().external_ases.clone()
    }

    /// Returns the state of the External AS API with the given id, if it exists.
    pub(crate) fn external_as(&self, id: IsdAsn) -> Option<ExternalAsState> {
        self.system_state
            .read()
            .unwrap()
            .external_ases
            .get(&id)
            .cloned()
    }

    /// Registers a handler for the External AS with the given ISD-ASN, which will be used to send
    /// and receive packets.
    ///
    /// Fails if a handler for the given ISD-ASN is already registered.
    pub(crate) fn register_external_as_handler(
        &self,
        isd_asn: IsdAsn,
        handler: Arc<dyn ExternalAsHandler>,
    ) -> anyhow::Result<()> {
        let mut sstate = self.system_state.write().unwrap();

        if sstate.extern_as_handlers.contains_key(&isd_asn) {
            anyhow::bail!(
                "External AS handler for AS {} already exists, cannot register handler",
                isd_asn
            );
        }

        sstate
            .extern_as_handlers
            .register_external_as(isd_asn, handler);

        Ok(())
    }
}

mod conn {
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
    }
}
