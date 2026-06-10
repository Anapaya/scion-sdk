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
    hash::{DefaultHasher, Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use scion_proto::{
    address::{IsdAsn, ScionAddr, ServiceAddr, SocketAddr},
    packet::ScionPacketUdp,
    path::DataPlanePath,
};
use scion_protobuf::control_plane::v1::{ServiceResolutionRequest, ServiceResolutionResponse};
use scion_sdk_quic_scion::quic::config::QuicConfig;
use sciparse::{core::encode::WireEncode, dataplane_path::onehop::model::OneHopPath};
use serde::{Deserialize, Serialize};
use tokio::{task, time::timeout};
use utoipa::ToSchema;

use crate::{
    comp::{
        control_service::{
            beaconing::{BeaconingService, InterfaceBeaconState},
            crpc::{AxumH3Server, MirroringPathProvider},
        },
        sim_network_stack::NetSimStack,
    },
    network::scion::{
        routing::ScionNetworkTime,
        topology::ScionGlobalInterfaceId,
        trust_store::{StoreCertificateDer, StoreKeyDer},
    },
    state::PocketScionState,
};

mod crpc;

pub mod beaconing;
pub mod segment_lookup;

pub use crpc::ManualPathProvider;

/// Control Service Runtime
pub struct ControlService {
    /// The ISD-AS of the Control Service
    isd_asn: IsdAsn,
    /// Shared state of the PocketSCION instance
    app_state: PocketScionState,
    /// Network Simulator Socket for communication with the network simulator
    net_stack: NetSimStack,
    /// Since the CRPC client requires certificates to be stored in files, we need to create temp
    /// files for all certs used
    certificate_temp_dir: CertificateTempDir,
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
        app_state: PocketScionState,
    ) -> anyhow::Result<Arc<ControlService>> {
        let self_state = app_state
            .get_control_service_state(isd_asn)
            .context("Control Service state for ISD-AS must be set in shared state before starting Control Service")?;
        let addr = self_state.virtual_addr();

        let stack = NetSimStack::bind(app_state.clone(), isd_asn, addr.ip(), 100)?;

        // Add CS svc address mapping
        app_state
            .add_svc_mapping(isd_asn, ServiceAddr::CONTROL, "QUIC".to_string(), addr)
            .context("Failed to add Control Service address mapping to shared state")?;

        let cert_temp_dir =
            CertificateTempDir::new().context("Failed to create certificate temp directory")?;

        let svc = Arc::new(ControlService {
            isd_asn,
            app_state,
            net_stack: stack.clone(),
            certificate_temp_dir: cert_temp_dir.clone(),
        });

        let app = axum::Router::new();

        let beaconing_svc = Arc::new(BeaconingService::new(svc.clone()));
        task::spawn(beaconing_svc.start_beaconing());

        let segment_lookup_svc =
            segment_lookup::PsSegmentLookupService::new(isd_asn, svc.app_state.clone());
        let app = segment_lookup::nest_api(app, segment_lookup_svc);

        // Start the server
        let sock = stack
            .bind_udp(addr.port())?
            .into_path_aware(MirroringPathProvider::default());

        let key_pair = {
            let read = svc.app_state.read();
            read.topology
                .trust_store
                .as_key_pair(&isd_asn)
                .context("Failed to get key pair for Control Service from topology trust store")?
                .clone()
        };

        let server_key = cert_temp_dir
            .get_or_create_key_file(&key_pair.key)
            .context("Failed to get or create key file for Control Service")?;
        let server_cert = cert_temp_dir
            .get_or_create_cert_file(&[key_pair.cert])
            .context("Failed to get or create cert file for Control Service")?;

        let conf = QuicConfig {
            verify_peer: false,
            ..Default::default()
        };

        let mut quiche_conf = conf.to_quiche_config()?;
        quiche_conf.load_cert_chain_from_pem_file(server_cert.to_str().unwrap())?;
        quiche_conf.load_priv_key_from_pem_file(server_key.to_str().unwrap())?;

        let server = AxumH3Server::serve(Arc::new(sock), app, quiche_conf);
        task::spawn(server);

        tracing::info!(
            %isd_asn,
            %addr,
            "Control Service started",
        );

        Ok(svc)
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
        let sock = self
            .net_stack
            .bind_udp(0)
            .context("Failed to bind UDP socket for service resolution")?;

        let (this_as, peer_as_if) = {
            let state_guard = self.app_state.read();
            let topo = &state_guard.topology;

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
                .expect("AS should have a forwarding key for path construction"),
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

        tracing::debug!(
            out_if = %egress_interface,
            peer_as = %peer_as_if.isd_as,
            svc_addr = %svc_addr,
            "Sending service resolution request",
        );

        let payload = Bytes::from_owner(prost::Message::encode_to_vec(&payload));

        match sock.try_send(destination, path, payload, ScionNetworkTime::now()) {
            Ok(_) => {}
            Err(e) => {
                bail!("Failed to send service resolution request packet: {e}");
            }
        }

        // Wait for response and parse it as Service Resolution Response

        let res_pkt: ScionPacketUdp = timeout(Duration::from_secs(10), sock.recv())
            .await
            .context("Failed to receive service resolution response from network simulator")??;

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

        drop(sock);
        self.net_stack.clean();

        Ok((peer_as_if.isd_as, svc_sock_addr, path))
    }
}

#[derive(Debug, Clone)]
struct CertificateTempDir {
    existing: Arc<Mutex<HashMap<u64, PathBuf>>>,
    temp_dir: Arc<tempfile::TempDir>,
}
impl CertificateTempDir {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            existing: Arc::new(Mutex::new(HashMap::new())),
            temp_dir: Arc::new(
                tempfile::tempdir()
                    .context("Failed to create temporary directory for certificates")?,
            ),
        })
    }

    // Creates or gets a temporary file for the given certificate chain, returning the path to the
    // file. The file is created in a temporary directory that is deleted when the
    // CertificateTempDir is dropped. If a file for the given certificate chain already exists, the
    // existing path is returned.
    pub fn get_or_create_cert_file(
        &self,
        cert_chain: &[StoreCertificateDer],
    ) -> anyhow::Result<PathBuf> {
        let mut hasher = DefaultHasher::new();
        cert_chain.hash(&mut hasher);
        let hash = hasher.finish();

        let mut existing_guard = self.existing.lock().unwrap();
        if let Some(path) = existing_guard.get(&hash) {
            Ok(path.clone())
        } else {
            let path = self.temp_dir.path().join(format!("chain-{}.crt", hash));

            let cert_chain = cert_chain
                .iter()
                .map(|cert| cert.to_pem())
                .collect::<Vec<_>>()
                .join("\n");

            std::fs::write(&path, cert_chain)?;
            existing_guard.insert(hash, path.clone());

            Ok(path)
        }
    }

    pub fn get_or_create_key_file(&self, key: &StoreKeyDer) -> anyhow::Result<PathBuf> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        let mut existing_guard = self.existing.lock().unwrap();
        if let Some(path) = existing_guard.get(&hash) {
            Ok(path.clone())
        } else {
            let path = self.temp_dir.path().join(format!("key-{}.key", hash));

            std::fs::write(&path, key.to_pem())?;
            existing_guard.insert(hash, path.clone());

            Ok(path)
        }
    }
}

// -----------------------------------------
// PocketSCION State Management

/// Serializable PocketScion State for the control service

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ControlServiceState {
    beaconing_interfaces: HashMap<ScionGlobalInterfaceId, beaconing::InterfaceBeaconState>,
    // The virtual IP address that the control service listens on for incoming requests.
    #[schema(value_type = String, example = "[fd3a:9b6c:1f20:0002::]:3000")]
    virtual_socket_addr: std::net::SocketAddr,
}
impl Default for ControlServiceState {
    fn default() -> Self {
        Self {
            beaconing_interfaces: HashMap::new(),
            virtual_socket_addr: std::net::SocketAddr::from_str("[fd3a:9b6c:1f20:0002::]:3000")
                .expect("Failed to parse hardcoded Control Service IP address"),
        }
    }
}

impl ControlServiceState {
    /// Creates a new Control Service state with default values for all fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the virtual socket address that the control service listens on for incoming requests.
    pub fn set_virtual_addr(&mut self, addr: std::net::SocketAddr) {
        self.virtual_socket_addr = addr;
    }

    /// Gets the virtual socket address that the control service listens on for incoming requests.
    pub fn virtual_addr(&self) -> std::net::SocketAddr {
        self.virtual_socket_addr
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

impl PocketScionState {
    /// Adds a Control Service state for the given ISD-AS to the shared state, returning an error if
    /// a state for the ISD-AS already exists.
    pub fn add_control_service(
        &self,
        isd_asn: IsdAsn,
        state: ControlServiceState,
    ) -> anyhow::Result<()> {
        let mut system_state = self.write();

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
        let state = self.read();
        state
            .control_service_states
            .iter()
            .map(|(isd_asn, cs_state)| (*isd_asn, cs_state.clone()))
            .collect()
    }

    /// Gets the Control Service state for the given ISD-AS, if it exists.
    pub fn get_control_service_state(&self, isd_asn: IsdAsn) -> Option<ControlServiceState> {
        let state = self.read();
        state.control_service_states.get(&isd_asn).cloned()
    }

    /// Mutates the Control Service state for the given ISD-AS, returning an error if no state for
    /// the
    fn mutate_control_service_state<F>(&self, isd_asn: IsdAsn, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut ControlServiceState) -> anyhow::Result<()>,
    {
        let mut state = self.write();
        let control_service_state = state
            .control_service_states
            .get_mut(&isd_asn)
            .context("Control Service state for ISD-AS not found")?;

        f(control_service_state)
    }
}
