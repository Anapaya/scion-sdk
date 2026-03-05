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

//! Control Service for PocketSCION

use std::{
    collections::HashMap,
    net::Ipv6Addr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use ipnet::Ipv6Net;
use scion_proto::{
    address::{IsdAsn, ScionAddr, ServiceAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketUdp},
    path::DataPlanePath,
};
use scion_protobuf::control_plane::v1::{
    BeaconRequest, BeaconResponse, ServiceResolutionRequest, ServiceResolutionResponse,
};
use scion_sdk_quic_scion::{quic::config::QuicConfig, socket::GenericScionUdpSocket};
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient};
use sciparse::{core::encode::WireEncode, path::onehop::model::OneHopPath};
use serde::{Deserialize, Serialize};
use tokio::{task, time::timeout};
use tracing::instrument;
use utoipa::ToSchema;

use crate::{
    addr_to_http_url,
    network::scion::{
        routing::ScionNetworkTime,
        segment::registry::SegmentRegistry,
        topology::{ScionGlobalInterfaceId, ScionTopology},
        trust_store::StoreCertificateDer,
    },
    state::{
        SharedPocketScionState,
        control_service::beaconing::InterfaceBeaconState,
        network_sim_socket::{NetSimPathProvider, NetSimRawSocket},
    },
};

pub mod beaconing;

/// Control Service Runtime
pub struct ControlService {
    /// The ISD-AS of the Control Service
    isd_asn: IsdAsn,
    /// Shared state of the PocketSCION instance
    app_state: SharedPocketScionState,
    /// Socket to send and receive messages to the network simulator
    net_sim_socket: Arc<NetSimRawSocket<ManualPathProvider>>,
    /// Since the CRPC client requires certificates to be stored in files, we need to create temp
    /// files for all certs used
    certificate_temp_dir: Mutex<CertificateTempDir>,
}

impl ControlService {
    /// Starts the Control Service for the given ISD-AS, by creating a Network Simulator Socket for
    /// communication with the network simulator, and starting the beaconing task.
    ///
    /// ## Parameters
    /// - `isd_asn`: The ISD-AS for which to start the Control Service. A state for the Control
    ///   Service must exist for this ISD-AS in the shared state before calling this function.
    /// - `app_state`: The shared state of the PocketSCION instance.
    ///
    /// ## State Requirements
    /// 1. A Topology must be present
    /// 2. A Control Service state must be present for the given ISD-AS
    /// 3. The AS this Control Service is running in must be a simulated AS
    /// 4. No Listener must be set up on `fd3a:9b6c:1f20:0002::/64` for the given ISD-AS
    pub fn start(
        isd_asn: IsdAsn,
        app_state: SharedPocketScionState,
    ) -> anyhow::Result<Arc<ControlService>> {
        // Note: We are currently just hardcoding a address and port for the socket
        let ip = Ipv6Addr::from_str("fd3a:9b6c:1f20:0002::")
            .expect("Failed to parse hardcoded Control Service IP address");
        let sockaddr = SocketAddr::new(ScionAddr::new(isd_asn, ip.into()), 12345);

        let (sock, receiver) =
            NetSimRawSocket::new(app_state.clone(), sockaddr, ManualPathProvider::default())?;

        app_state.add_sim_receiver(isd_asn, Ipv6Net::from(ip).into(), Arc::new(receiver)).with_context(|| {
            format!(
                "Failed to add Control Service receiver for ISD-AS {} and address {} to shared state",
                isd_asn, ip
            )
        })?;

        tracing::info!(
            isd_asn = %isd_asn,
            virt_addr = %sock.local_addr(),
            "Control Service started",
        );

        let svc = Arc::new(ControlService {
            isd_asn,
            app_state,
            net_sim_socket: Arc::new(sock),
            certificate_temp_dir: Mutex::new(CertificateTempDir::new()?),
        });

        task::spawn(svc.clone().start_beaconing());

        Ok(svc)
    }

    /// Main loop for beaconing task of the Control Service
    #[instrument(name = "cs_beaconing", skip(self), fields(isd_asn = %self.isd_asn))]
    pub async fn start_beaconing(self: Arc<Self>) {
        loop {
            let action = {
                let now = SystemTime::now();
                let state_guard = self.app_state.system_state.read().unwrap();

                let segment_registry = state_guard
                    .segment_registry
                    .as_ref()
                    .expect("Segment registry must be available in system state for beaconing");
                let topology = state_guard
                    .topology
                    .as_ref()
                    .expect("Topology must be available in system state for beaconing");
                self.app_state
                    .get_control_service_state(self.isd_asn)
                    .expect("Control Service state must exist for own ISD-AS")
                    .tick(now, segment_registry, topology)
                    .expect("Control Service state tick should not fail")
            };

            match action {
                ControlServiceAction::SendBeacons { beacons } => {
                    for (our_interface, beacon_reqs) in beacons {
                        let peer_as = self
                            .app_state
                            .system_state()
                            .topology
                            .as_ref()
                            .expect("Topology must be available in system state for beaconing")
                            .scion_link(&our_interface.isd_as, our_interface.if_id)
                            .expect("Interface should exist in topology")
                            .get_directed_from(&our_interface.isd_as)
                            .expect("Interface should have a direction from its AS in topology")
                            .to;

                        let (peer_as, svc_addr, path) = match self
                            .resolve_svc_addr(our_interface, ServiceAddr::CONTROL)
                            .await
                        {
                            Ok(res) => res,
                            Err(e) => {
                                tracing::warn!(
                                    interface = %our_interface,
                                    peer_as = %peer_as,
                                    error = ?e,
                                    "Failed to resolve control service address for peer AS, skipping sending beacons on this interface",
                                );

                                self.app_state
                                    .get_control_service_state(self.isd_asn)
                                    .expect("Control Service state must exist for own ISD-AS")
                                    .mark_send_result(&our_interface, false, SystemTime::now());

                                continue;
                            }
                        };

                        let mut all_successes = true;
                        let num_beacons = beacon_reqs.len();
                        tracing::debug!(
                            interface = %our_interface,
                            num_beacons,
                            "Sending beacons on interface",
                        );

                        for beacon_req in beacon_reqs {
                            // XXX(ake): As long as we allocate the port of the socket on creation,
                            // we can not parallelize any request
                            match self
                                .send_beacon(peer_as, svc_addr, path.clone(), beacon_req)
                                .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        interface = %our_interface,
                                        error = ?e,
                                        "Failed to send beacon on interface",
                                    );

                                    all_successes = false;
                                }
                            }
                        }

                        tracing::info!(
                            interface = %our_interface,
                            peer_as = %peer_as,
                            num_beacons,
                            all_succeeded = all_successes,
                            "Finished sending beacons on interface",
                        );

                        // Mark the result of sending beacons for this interface in the Control
                        // Service state
                        self.app_state
                            .mutate_control_service_state(self.isd_asn, |state| {
                                state.mark_send_result(
                                    &our_interface,
                                    all_successes,
                                    SystemTime::now(),
                                );
                                Ok(())
                            })
                            .expect(
                                "Failed to update Control Service state with beacon send result",
                            );
                    }
                }
                ControlServiceAction::Wait(next_time) => {
                    let duration = next_time
                        .duration_since(SystemTime::now())
                        .unwrap_or_else(|_| Duration::from_secs(0));
                    tracing::debug!(
                        wait_duration = ?duration,
                        "No beacons to send, waiting until next scheduled send time",
                    );

                    tokio::time::sleep(duration).await;
                }
            }
        }
    }

    /// Resolves an Address of the given service in the given ISD-AS
    ///
    /// Returns the socket address to send requests to for the service, and a dataplane path to
    /// reach the service through the network simulator
    pub async fn resolve_svc_addr(
        &self,
        egress_interface: ScionGlobalInterfaceId,
        svc_addr: ServiceAddr,
    ) -> anyhow::Result<(IsdAsn, std::net::SocketAddr, DataPlanePath)> {
        // Service Address is resolved through a UDP Packet with the Service Resolution Request in
        // the payload.

        let (this_as, peer_as_if) = {
            let state_guard = self.app_state.system_state.read().unwrap();
            let topo = state_guard
                .topology
                .as_ref()
                .expect("Topology must be available in system state for service resolution");

            let this_as = topo
                .as_map
                .get(&egress_interface.isd_as)
                .expect("AS of egress interface should exist in topology")
                .clone();

            let peer_as_if = topo
                .scion_link(&egress_interface.isd_as, egress_interface.if_id)
                .expect("Egress interface should exist in topology")
                .get_directed_from(&egress_interface.isd_as)
                .expect("Egress interface should have a direction from its AS in topology")
                .to;
            (this_as, peer_as_if)
        };

        let payload = ServiceResolutionRequest {};
        let path = OneHopPath::new(
            egress_interface.if_id,
            // We just use the if id for the segment id, in Reality, should be random
            egress_interface.if_id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as u32,
            this_as
                .forwarding_key()
                .expect("AS should have a forwarding key for path construction")
                .into(),
            255,
        );

        let mut path_buf = vec![0u8; path.required_size()];
        path.encode(&mut path_buf)?;

        let path = DataPlanePath::Unsupported {
            path_type: scion_proto::path::PathType::OneHop,
            bytes: Bytes::from_owner(path_buf),
        };

        let destination = SocketAddr::new(
            ScionAddr::new(peer_as_if.isd_as, svc_addr.into()),
            0, // Port is not relevant for service resolution request
        );

        let pkt = ScionPacketUdp::new(
            ByEndpoint {
                source: self.net_sim_socket.local_addr(),
                destination,
            },
            path,
            Bytes::from_owner(prost::Message::encode_to_vec(&payload)),
        )
        .context("Failed to construct service resolution request packet")?;

        tracing::debug!(
            out_if = %egress_interface,
            peer_as = %peer_as_if.isd_as,
            svc_addr = %svc_addr,
            "Sending service resolution request",
        );

        self.net_sim_socket
            .send(pkt.into(), ScionNetworkTime::now());

        // Wait for response and parse it as Service Resolution Response

        let res_pkt: ScionPacketUdp = timeout(Duration::from_secs(10), self.net_sim_socket.recv())
            .await
            .context("Failed to receive service resolution response from network simulator")??
            .try_into()
            .context("Failed to parse received packet as SCION UDP packet")?;

        let res: ServiceResolutionResponse = prost::Message::decode(&res_pkt.payload()[..])
            .context("Failed to decode service resolution response payload")?;

        tracing::debug!(
            peer_as = %peer_as_if.isd_as,
            svc_addr = %svc_addr,
            response = ?res,
            "Received service resolution response",
        );

        // Get the address of the service from the response
        let svc_sock_addr: std::net::SocketAddr = res
            .transports
            .get("QUIC")
            .context("No QUIC transport found in service resolution response")
            .and_then(|transport| {
                transport
                    .address
                    .parse()
                    .context("Failed to parse interface from service resolution response")
            })?;

        // Note: in the response, we expect the path to have been converted to a standard path
        // Reverse the path
        let path = res_pkt
            .headers
            .path
            .to_reversed()
            .context("Failed to reverse response path")?;

        tracing::debug!(
            peer_as = %peer_as_if.isd_as,
            service_addr = %svc_sock_addr,
            path = ?path,
            "Resolved service address",
        );

        Ok((peer_as_if.isd_as, svc_sock_addr, path))
    }

    /// Sends a beacon request to the control service in the External AS through the network
    /// simulator, using the given dataplane path to reach the service.
    pub async fn send_beacon(
        &self,
        dst_ia: IsdAsn,
        service_addr: std::net::SocketAddr,
        path: DataPlanePath,
        beacon_req: BeaconRequest,
    ) -> anyhow::Result<()> {
        let dst_cert_chain: Vec<StoreCertificateDer> = self
            .app_state
            .system_state()
            .topology
            .as_ref()
            .expect("must be available")
            .trust_store
            .ca_certs(&dst_ia.isd())
            .context("Failed to get CA certificate for destination ISD from topology trust store")?
            .values()
            .flat_map(|ca| vec![ca.root.cert.clone(), ca.intermediary.cert.clone()])
            .collect();

        let cert_chain_path = self
            .certificate_temp_dir
            .lock()
            .unwrap()
            .get_cert_dir(dst_ia, dst_cert_chain)
            .context("Failed to get certificate path for destination ISD-AS")?;

        let quic_config = QuicConfig {
            // Peer validation is disabled in general
            verify_peer: false,
            ca_certs_path: Some(
                cert_chain_path
                    .to_str()
                    .context("Certificate path should be valid UTF-8 string")?
                    .to_string(),
            ),
            ..Default::default()
        };

        // Set the path to be used in the packet
        self.net_sim_socket.path_provider().set_path(path);

        let crpc_client = CrpcClient::with_quic_config(
            SocketAddr::new(
                ScionAddr::new(dst_ia, service_addr.ip().into()),
                service_addr.port(),
            ),
            self.net_sim_socket.clone(),
            None, // XXX: Peer validation is disabled
            None,
            quic_config,
        )
        .await?;

        const BEACON_SERVICE_PATH: &str = "/proto.control_plane.v1.SegmentCreationService/Beacon";

        let mut url = addr_to_http_url(service_addr);
        url.set_path(BEACON_SERVICE_PATH);

        crpc_client
            .unary_request::<BeaconRequest, BeaconResponse>(http::Method::POST, url, beacon_req)
            .await?;

        Ok(())
    }
}

struct CertificateTempDir {
    existing: HashMap<IsdAsn, PathBuf>,
    temp_dir: tempfile::TempDir,
}
impl CertificateTempDir {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            existing: HashMap::new(),
            temp_dir: tempfile::tempdir()
                .context("Failed to create temporary directory for certificates")?,
        })
    }

    pub fn get_cert_dir(
        &mut self,
        isd_asn: IsdAsn,
        cert_chain: Vec<StoreCertificateDer>,
    ) -> anyhow::Result<PathBuf> {
        if let Some(path) = self.existing.get(&isd_asn) {
            Ok(path.clone())
        } else {
            let path =
                self.temp_dir
                    .path()
                    .join(format!("ISD{}-AS{}.crt", isd_asn.isd(), isd_asn.asn()));

            let cert_chain = cert_chain
                .into_iter()
                .map(|cert| cert.to_pem())
                .collect::<Vec<_>>()
                .join("\n");

            std::fs::write(&path, cert_chain)?;
            self.existing.insert(isd_asn, path.clone());

            Ok(path)
        }
    }
}

/// Serializable PocketScion State for the control service

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ControlServiceState {
    beaconing_interfaces: HashMap<ScionGlobalInterfaceId, beaconing::InterfaceBeaconState>,
}
impl ControlServiceState {
    /// Creates a new Control Service state with default values for all fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an interface to the control service state for beaconing, with the given initial
    /// beaconing state.
    pub fn add_beaconing_interface(&mut self, state: InterfaceBeaconState) -> anyhow::Result<()> {
        match self.beaconing_interfaces.entry(state.interface) {
            std::collections::hash_map::Entry::Occupied(_) => {
                bail!("Given interface already exists")
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(state);
                Ok(())
            }
        }
    }
}

impl ControlServiceState {
    /// Ticks the control service state to determine whether beacons should be sent on any of the
    fn tick(
        &mut self,
        now: SystemTime,
        segment_registry: &SegmentRegistry,
        topology: &ScionTopology,
    ) -> anyhow::Result<ControlServiceAction> {
        let mut beacons_to_send = Vec::new();
        let mut next_send_times = Vec::new();

        let mut shortest_wait = SystemTime::now() + Duration::from_secs(24 * 3600); // Default to waiting for 24 hours if no interfaces are configured

        for (interface, beacon_state) in &mut self.beaconing_interfaces {
            match beacon_state.tick(now, segment_registry, topology)? {
                beaconing::InterfaceBeaconAction::SendBeacons(beacons) => {
                    beacons_to_send.push((*interface, beacons));
                }
                beaconing::InterfaceBeaconAction::Wait(next_time) => {
                    next_send_times.push(next_time);
                    if next_time < shortest_wait {
                        shortest_wait = shortest_wait.min(next_time);
                    }
                }
            }
        }

        if !beacons_to_send.is_empty() {
            return Ok(ControlServiceAction::SendBeacons {
                beacons: beacons_to_send,
            });
        };

        Ok(ControlServiceAction::Wait(shortest_wait))
    }

    /// Report the result of sending beacons on the given interface, to update the beaconing state
    /// for that interface and schedule the next send time based on whether sending was successful
    /// or not.
    pub fn mark_send_result(
        &mut self,
        interface: &ScionGlobalInterfaceId,
        success: bool,
        current_time: SystemTime,
    ) {
        if let Some(beacon_state) = self.beaconing_interfaces.get_mut(interface) {
            match success {
                true => beacon_state.mark_success(current_time),
                false => beacon_state.mark_failure(current_time),
            }
        } else {
            tracing::warn!(
                interface = %interface,
                "Received send result for unknown interface, ignoring",
            );
        }
    }
}

#[derive(Debug, Default)]
struct ManualPathProvider {
    pub path: Mutex<Option<DataPlanePath>>,
}

impl ManualPathProvider {
    /// Sets the path to be returned by this path provider.
    pub fn set_path(&self, path: DataPlanePath) {
        self.path.lock().unwrap().replace(path);
    }
}

impl NetSimPathProvider for ManualPathProvider {
    fn get_path(
        &self,
        _src_as: IsdAsn,
        _dst_as: IsdAsn,
    ) -> Option<scion_proto::path::DataPlanePath> {
        self.path.lock().unwrap().clone()
    }
}

/// Action to be taken by the Control Service after ticking the state of all beaconing interfaces.
pub enum ControlServiceAction {
    /// Send the given beacons to the External AS, and mark the given interfaces as having sent
    /// beacons successfully or unsuccessfully based on whether sending was successful or not.
    SendBeacons {
        /// Interface and corresponding beacon requests for which to send beacons through the
        /// network simulator to
        beacons: Vec<(ScionGlobalInterfaceId, Vec<BeaconRequest>)>,
    },
    /// Wait until the given time and tick again to check if beacons should be sent
    Wait(SystemTime),
}

impl SharedPocketScionState {
    /// Adds a Control Service state for the given ISD-AS to the shared state, returning an error if
    /// a state for the ISD-AS already exists.
    pub fn add_control_service(
        &self,
        isd_asn: IsdAsn,
        state: ControlServiceState,
    ) -> anyhow::Result<()> {
        let mut system_state = self.system_state.write().unwrap();

        if system_state.control_service_states.contains_key(&isd_asn) {
            bail!(
                "Control Service state for ISD-AS {} already exists",
                isd_asn
            );
        }

        system_state.control_service_states.insert(isd_asn, state);
        Ok(())
    }

    /// Gets the ISD-AS and Control Service state for all Control Services in the shared state.
    pub fn get_control_services(&self) -> Vec<(IsdAsn, ControlServiceState)> {
        let state = self.system_state.read().unwrap();
        state
            .control_service_states
            .iter()
            .map(|(isd_asn, cs_state)| (*isd_asn, cs_state.clone()))
            .collect()
    }

    /// Gets the Control Service state for the given ISD-AS, if it exists.
    pub fn get_control_service_state(&self, isd_asn: IsdAsn) -> Option<ControlServiceState> {
        let state = self.system_state.read().unwrap();
        state.control_service_states.get(&isd_asn).cloned()
    }

    /// Mutates the Control Service state for the given ISD-AS, returning an error if no state for
    /// the
    fn mutate_control_service_state<F>(&self, isd_asn: IsdAsn, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut ControlServiceState) -> anyhow::Result<()>,
    {
        let mut state = self.system_state.write().unwrap();
        let control_service_state = state
            .control_service_states
            .get_mut(&isd_asn)
            .context("Control Service state for ISD-AS not found")?;

        f(control_service_state)
    }
}
