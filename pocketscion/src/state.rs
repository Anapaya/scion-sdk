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
//! PocketSCION state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZero,
    str::FromStr,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{Duration, SystemTime},
};

use anyhow::Context as _;
use derive_more::Display;
use ipnet::IpNet;
use pem::Pem;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::IsdAsn;
use scion_sdk_address_manager::manager::{AddressManager, AddressRegistrationError};
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use snap_control::{
    crpc_api::api_service::model::SessionGrant,
    model::{CreateSessionError, SessionGranter, SnapUnderlay, UdpUnderlay, UnderlayDiscovery},
};
use snap_dataplane::{
    session::{
        manager::TokenIssuer,
        state::{SessionManagerState, SessionTokenIssuerState, insecure_const_ed25519_signing_key},
    },
    state::{DataPlaneState, Hostname, Id},
    tunnel_gateway::state::SharedTunnelGatewayState,
};
use snap_tokens::snap_token::SnapTokenClaims;
use utoipa::ToSchema;

use crate::{
    authorization_server::{
        api::{TokenRequest, TokenResponse},
        token_exchanger::{
            TokenExchange, TokenExchangeConfig, TokenExchangeError, TokenExchangeImpl,
        },
    },
    dto::{AuthServerStateDto, RouterStateDto, SnapStateDto, SystemStateDto},
    endhost_api::{EndhostApiId, EndhostApiState},
    io_config::SharedPocketScionIoConfig,
    network::{
        local::{receiver_registry::NetworkReceiverRegistry, receivers::Receiver},
        scion::{
            segment::registry::SegmentRegistry,
            topology::{FastTopologyLookup, ScionTopology},
        },
    },
};

pub mod endhost_segment_lister;
pub mod simulation_dispatcher;

/// The internal state of PocketScion.
#[derive(Clone)]
pub struct SharedPocketScionState {
    system_state: Arc<RwLock<SystemState>>,
}
// General
impl SharedPocketScionState {
    /// Creates a new default [SharedPocketScionState] with the given start time.
    pub fn new(start_time: SystemTime) -> Self {
        Self {
            system_state: Arc::new(RwLock::new(SystemState::default_from_start_time(
                start_time,
            ))),
        }
    }

    /// Creates a new [SharedPocketScionState] from the given [SystemState].
    // todo(dsd): these constructors need cleanup
    pub fn from_system_state(system_state: SystemState) -> Self {
        Self {
            system_state: Arc::new(RwLock::new(system_state)),
        }
    }

    /// Tries to take the inner Arc and return the System state
    pub fn into_state(self) -> SystemState {
        Arc::into_inner(self.system_state)
            .expect("Arc is used")
            .into_inner()
            .expect("no fail")
    }

    /// Returns a Read Guard for the contained [SystemState]
    pub fn system_state(&self) -> RwLockReadGuard<'_, SystemState> {
        self.system_state.read().unwrap()
    }

    pub(crate) fn to_dto(&self) -> SystemStateDto {
        self.system_state().as_ref().into()
    }

    #[allow(unused)]
    pub(crate) fn from_dto(
        start_time: SystemTime,
        system_state: SystemStateDto,
    ) -> Result<Self, anyhow::Error> {
        let mut system_state = SystemState::try_from(system_state)?;
        system_state.start_time = start_time;

        Ok(Self {
            system_state: Arc::new(RwLock::new(system_state)),
        })
    }
}
// Auth
impl SharedPocketScionState {
    /// Adds an authorization server to the pocket SCION.
    pub fn set_auth_server(&mut self, snap_token_private_pem: Pem) {
        let mut system_state = self.system_state.write().unwrap();
        system_state.auth_server = Some(AuthServerState {
            token_exchanger: TokenExchangeImpl::new(TokenExchangeConfig::new(
                snap_token_private_pem,
                Duration::from_secs(3600),
            )),
        });
    }

    pub(crate) fn auth_server(&self) -> AuthorizationServerHandle {
        AuthorizationServerHandle {
            system_state: self.system_state.clone(),
        }
    }

    pub(crate) fn has_auth_server(&self) -> bool {
        self.system_state.read().unwrap().auth_server.is_some()
    }
}
// Snaps
impl SharedPocketScionState {
    pub(crate) fn snap_token_public_key(&self) -> Pem {
        let sstate = self.system_state.read().unwrap();
        sstate.snap_token_public_pem.clone()
    }

    /// Set the public key used to verify SNAP tokens.
    pub fn set_snap_token_public_pem(&mut self, pem: Pem) {
        let mut system_state = self.system_state.write().unwrap();
        system_state.snap_token_public_pem = pem;
    }

    /// Adds a new SNAP to the system state and returns its id.
    pub fn add_snap(&mut self) -> SnapId {
        self.add_snap_with_session_manager(SessionManagerState::default())
    }

    /// Adds a new SNAP with a specific session manager state to the system state and returns its
    /// id.
    pub fn add_snap_with_session_manager(
        &mut self,
        session_manager: SessionManagerState,
    ) -> SnapId {
        let mut system_state = self.system_state.write().unwrap();
        let snap_id = SnapId::from_usize(system_state.snaps.len());
        let session_encoding_key = insecure_const_ed25519_signing_key(snap_id.as_usize());

        system_state.snaps.insert(
            snap_id,
            SnapState {
                session_manager,
                session_issuer: SessionTokenIssuerState::new(session_encoding_key.into()),
                data_planes: Default::default(),
            },
        );
        snap_id
    }

    /// Returns a map of all Snaps
    pub fn snaps(&self) -> BTreeMap<SnapId, SnapState> {
        let sstate = self.system_state.read().unwrap();
        sstate.snaps.clone()
    }

    /// Returns a vector of all existing SnapIds
    pub fn snaps_ids(&self) -> Vec<SnapId> {
        let sstate = self.system_state.read().unwrap();
        sstate.snaps.keys().cloned().collect()
    }

    /// Returns all local IsdAses of a snap
    pub fn snap_isd_ases(&self, id: SnapId) -> Option<BTreeSet<IsdAsn>> {
        self.system_state
            .read()
            .unwrap()
            .snaps
            .get(&id)
            .map(|s| s.isd_ases())
    }

    /// Get the [SnapDataPlaneDiscoveryHandle] of a specific snap
    pub(crate) fn snap_data_plane_discovery(
        &self,
        snap_id: SnapId,
        io_config: SharedPocketScionIoConfig,
    ) -> SnapDataPlaneDiscoveryHandle {
        SnapDataPlaneDiscoveryHandle {
            snap_id,
            system_state: self.system_state.clone(),
            io_config,
        }
    }

    /// Get the [SessionManagerHandle] of a specific snap
    pub(crate) fn snap_session_manager(
        &self,
        snap_id: SnapId,
        io_config: SharedPocketScionIoConfig,
    ) -> SessionManagerHandle {
        SessionManagerHandle {
            snap_id,
            system_state: self.system_state.clone(),
            io_config,
        }
    }

    /// Adds a new data plane for the given SNAP to the system state and returns its id.
    pub fn add_snap_data_plane(
        &mut self,
        snap_id: SnapId,
        isd_as: IsdAsn,
        prefixes: Vec<IpNet>,
        rng: ChaCha8Rng,
    ) -> SnapDataPlaneId {
        let mut system_state = self.system_state.write().unwrap();

        let snap = system_state
            .snaps
            .get_mut(&snap_id)
            .expect("SNAP not found");

        let hostname: Hostname = format!("host-{}", snap.data_planes.len())
            .try_into()
            .expect("valid hostname");
        let snap_dp_id = SnapDataPlaneId::new(snap_id, hostname.clone());

        let mgr = AddressManager::new(isd_as, prefixes, rng).unwrap();
        let mut dp_state = DataPlaneState::default();
        dp_state.address_registries.insert(mgr.id(), mgr);

        snap.data_planes.insert(hostname, dp_state);

        snap_dp_id
    }

    pub(crate) fn snap_data_planes(&self, snap_id: SnapId) -> Vec<SnapDataPlaneId> {
        let sstate = self.system_state.read().unwrap();
        let snap = sstate.snaps.get(&snap_id).expect("SNAP not found");
        snap.data_planes
            .keys()
            .map(|hostname| SnapDataPlaneId::new(snap_id, hostname.clone()))
            .collect()
    }

    pub(crate) fn snap_data_plane_ases(
        &self,
        snap_data_plane_id: SnapDataPlaneId,
    ) -> anyhow::Result<Vec<IsdAsn>> {
        let state_guard = self.system_state.read().unwrap();
        let state = state_guard
            .snaps
            .get(&snap_data_plane_id.snap_id)
            .and_then(|snap| {
                snap.data_planes
                    .get(&snap_data_plane_id.data_plane_hostname)
            })
            .context("SNAP data plane not found")?;
        Ok(state
            .address_registries
            .values()
            .map(|registry| registry.isd_asn())
            .collect::<Vec<_>>())
    }
}
// Endhost API
impl SharedPocketScionState {
    /// Adds a new endhost api to PocketSCION
    pub fn add_endhost_api(
        &mut self,
        local_ases: impl IntoIterator<Item = IsdAsn>,
    ) -> EndhostApiId {
        let mut sstate = self.system_state.write().unwrap();
        let id = sstate.endhost_apis.len().into();

        sstate.endhost_apis.insert(
            id,
            EndhostApiState {
                local_ases: local_ases.into_iter().collect(),
            },
        );

        id
    }

    /// Returns the cloned state of given endhost api
    pub(crate) fn endhost_api(&self, id: EndhostApiId) -> Option<EndhostApiState> {
        self.system_state
            .read()
            .unwrap()
            .endhost_apis
            .get(&id)
            .cloned()
    }

    pub(crate) fn endhost_apis(&self) -> BTreeMap<EndhostApiId, EndhostApiState> {
        self.system_state.read().unwrap().endhost_apis.clone()
    }
}
// Router Mode
impl SharedPocketScionState {
    /// Adds a new router.
    pub fn add_router(
        &mut self,
        isd_as: IsdAsn,
        if_ids: Vec<NonZero<u16>>,
        snap_data_plane_excludes: Vec<IpNet>,
        snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
    ) -> RouterId {
        let mut sstate = self.system_state.write().unwrap();
        let router_id = RouterId::from_usize(sstate.routers.len());

        sstate.routers.insert(
            router_id,
            RouterState {
                isd_as,
                if_ids,
                snap_data_plane_excludes,
                snap_data_plane_interfaces,
            },
        );
        router_id
    }

    /// Returns a map of all Routers
    pub(crate) fn routers(&self) -> BTreeMap<RouterId, RouterState> {
        let sstate = self.system_state.read().unwrap();
        sstate.routers.clone()
    }

    /// Returns the cloned state of the given router
    pub(crate) fn router(&self, router_id: RouterId) -> Option<RouterState> {
        self.system_state
            .read()
            .unwrap()
            .routers
            .get(&router_id)
            .cloned()
    }

    /// Returns a vec of all RouterIds
    pub(crate) fn router_ids(&self) -> Vec<RouterId> {
        let sstate = self.system_state.read().unwrap();
        sstate.routers.keys().cloned().collect()
    }
}
// Network Sim
impl SharedPocketScionState {
    /// Applies the given topology to the system state.
    /// If a topology is applied, pocket SCION will simulate the routing of packets.
    pub fn set_topology(&mut self, topology: ScionTopology) {
        let segment_store = SegmentRegistry::new(&FastTopologyLookup::new(&topology));
        let mut state_write_guard = self.system_state.write().unwrap();

        state_write_guard.topology = Some(topology);
        state_write_guard.topology_segments = Some(segment_store);
    }

    /// Sets the state of a link in the topology.
    /// If no topology is set, or the link does not exist, None is returned.
    pub fn set_link_state(&self, isd_asn: IsdAsn, link_id: u16, up: bool) -> Option<bool> {
        let mut state_write_guard = self.system_state.write().unwrap();
        if let Some(topology) = &mut state_write_guard.topology {
            topology.mut_scion_link(&isd_asn, link_id).map(|link| {
                link.set_is_up(up);
                up
            })
        } else {
            None
        }
    }

    /// Returns true if a topology is set.
    pub fn has_topology(&self) -> bool {
        self.system_state.read().unwrap().topology.is_some()
    }

    /// Adds a wildcard receiver for the given ISD-AS to the network simulation.
    pub fn add_wildcard_sim_receiver(
        &self,
        ias: IsdAsn,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let mut state = self.system_state.write().unwrap();
        state
            .sim_receivers
            .add_wildcard_receiver(ias, receiver)
            .context("error adding wildcard receiver")?;

        Ok(())
    }

    /// Adds a receiver bound to the given ISD-AS and IpNet to the network simulation.
    pub fn add_sim_receiver(
        &self,
        ias: IsdAsn,
        ipnet: IpNet,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let mut state = self.system_state.write().unwrap();
        state
            .sim_receivers
            .add_receiver(ias, ipnet, receiver)
            .context("error adding receiver")?;

        Ok(())
    }
}

/// Pocket SCION system state.
#[derive(Debug, Clone)]
pub struct SystemState {
    start_time: SystemTime,
    snap_token_public_pem: Pem,
    snaps: BTreeMap<SnapId, SnapState>,
    auth_server: Option<AuthServerState>,
    routers: BTreeMap<RouterId, RouterState>,
    endhost_apis: BTreeMap<EndhostApiId, EndhostApiState>,
    topology: Option<ScionTopology>,
    topology_segments: Option<SegmentRegistry>,
    sim_receivers: NetworkReceiverRegistry,
}

impl SystemState {
    /// Creates a new [SystemState] with the given start time.
    pub fn default_from_start_time(start_time: SystemTime) -> Self {
        Self {
            start_time,
            snap_token_public_pem: insecure_const_ed25519_key_pair_pem().1,
            snaps: Default::default(),
            routers: Default::default(),
            auth_server: Default::default(),
            topology: Default::default(),
            topology_segments: Default::default(),
            sim_receivers: Default::default(),
            endhost_apis: Default::default(),
        }
    }

    /// Creates a new [SystemState] with the current time as start time.
    pub fn default_from_now() -> Self {
        Self::default_from_start_time(SystemTime::now())
    }

    /// Returns all SNAPs defined in the system state.
    pub fn snaps(&self) -> &BTreeMap<SnapId, SnapState> {
        &self.snaps
    }
}

impl PartialEq for SystemState {
    fn eq(&self, other: &Self) -> bool {
        self.snaps == other.snaps
    }
}

impl From<&SystemState> for SystemStateDto {
    fn from(system_state: &SystemState) -> Self {
        Self {
            auth_server_state: system_state
                .auth_server
                .as_ref()
                .map(|auth_server| auth_server.into()),
            snap_token_public_key: system_state.snap_token_public_pem.to_string(),
            snaps: system_state
                .snaps
                .iter()
                .map(|(snap_id, snap_state)| (*snap_id, snap_state.into()))
                .collect(),
            routers: system_state
                .routers
                .iter()
                .map(|(router_socket_id, router_state)| (*router_socket_id, router_state.into()))
                .collect(),
            topology: system_state
                .topology
                .clone()
                .map(|topology| topology.into()),
            endhost_apis: system_state.endhost_apis.clone(),
        }
    }
}

impl TryFrom<SystemStateDto> for SystemState {
    type Error = anyhow::Error;

    fn try_from(dto: SystemStateDto) -> Result<Self, Self::Error> {
        let snaps = dto
            .snaps
            .into_iter()
            .map(|(snap_id, snap_state)| {
                Ok((
                    snap_id,
                    snap_state.try_into().context("invalid SNAP state")?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;
        let auth_server = match dto.auth_server_state {
            Some(auth_server_state) => {
                Some(
                    auth_server_state
                        .try_into()
                        .context("invalid auth server state")?,
                )
            }
            None => None,
        };
        let snap_token_public_pem = Pem::from_str(&dto.snap_token_public_key)
            .context("invalid PEM format for SNAP token public key")?;

        let router_sockets = dto
            .routers
            .into_iter()
            .map(|(router_socket_id, router_state)| {
                Ok((
                    router_socket_id,
                    router_state.try_into().context("invalid router state")?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        let topology = dto
            .topology
            .map(|topology_dto| topology_dto.try_into())
            .transpose()
            .context("invalid topology state")?;

        let topology_segments = topology
            .as_ref()
            .map(|topology| SegmentRegistry::new(&FastTopologyLookup::new(topology)));

        let sim_receivers = NetworkReceiverRegistry::default();

        Ok(SystemState {
            start_time: SystemTime::now(),
            auth_server,
            snap_token_public_pem,
            snaps,
            routers: router_sockets,
            topology,
            topology_segments,
            sim_receivers,
            endhost_apis: dto.endhost_apis,
        })
    }
}

impl AsRef<SystemState> for RwLockReadGuard<'_, SystemState> {
    fn as_ref(&self) -> &SystemState {
        self
    }
}

/// Pocket SCION SNAP state.
#[derive(Debug, PartialEq, Clone)]
pub struct SnapState {
    pub(crate) session_manager: SessionManagerState,
    pub(crate) session_issuer: SessionTokenIssuerState,
    // XXX(bunert): SNAP should contain a single data plane state.
    pub(crate) data_planes: BTreeMap<Hostname, DataPlaneState>,
}

impl SnapState {
    // List all ases this snap is connected to
    pub(crate) fn isd_ases(&self) -> BTreeSet<IsdAsn> {
        self.data_planes
            .iter()
            .flat_map(|dp| dp.1.address_registries.iter())
            .map(|ar| ar.1.isd_asn())
            .collect()
    }
}

impl From<&SnapState> for SnapStateDto {
    fn from(value: &SnapState) -> Self {
        Self {
            session_manager: (&value.session_manager).into(),
            session_issuer: (&value.session_issuer).into(),
            data_planes: value
                .data_planes
                .iter()
                .map(|(hostname, state)| (hostname.clone(), state.into()))
                .collect(),
        }
    }
}

impl TryFrom<SnapStateDto> for SnapState {
    type Error = anyhow::Error;

    fn try_from(value: SnapStateDto) -> Result<Self, Self::Error> {
        let data_planes = value
            .data_planes
            .into_iter()
            .map(|(hostname, state)| {
                Ok((
                    hostname.clone(),
                    state
                        .try_into()
                        .with_context(|| format!("invalid data plane state ({hostname})"))?,
                ))
            })
            .collect::<Result<_, Self::Error>>()?;

        let session_manager = value.session_manager.try_into()?;
        let session_issuer = value.session_issuer.try_into()?;

        Ok(Self {
            session_issuer,
            data_planes,
            session_manager,
        })
    }
}

/// The state of a SCION router emulated by PocketScion.
#[derive(Debug, Clone)]
pub struct RouterState {
    /// The ISD-AS of the router.
    pub isd_as: IsdAsn,
    /// The SCION interface IDs of the router.
    pub if_ids: Vec<NonZero<u16>>,
    /// The SNAP data planes that are connected to the router.
    /// Data plane ID -> udp underlay address
    pub snap_data_plane_interfaces: BTreeMap<String, SocketAddr>,
    /// Networks towards which SCION traffic will not be routed through
    /// the available SNAPs.
    pub snap_data_plane_excludes: Vec<IpNet>,
}

impl From<&RouterState> for RouterStateDto {
    fn from(value: &RouterState) -> Self {
        Self {
            isd_as: value.isd_as,
            if_ids: value.if_ids.iter().map(|if_id| if_id.get()).collect(),
            snap_data_plane_excludes: value
                .snap_data_plane_excludes
                .iter()
                .map(|network| network.to_string())
                .collect(),
            snap_data_plane_interfaces: value
                .snap_data_plane_interfaces
                .iter()
                .map(|(id, addr)| (id.clone(), addr.to_string()))
                .collect(),
        }
    }
}

impl TryFrom<RouterStateDto> for RouterState {
    type Error = anyhow::Error;

    fn try_from(value: RouterStateDto) -> Result<Self, Self::Error> {
        let isd_as = value.isd_as;
        let if_ids = value
            .if_ids
            .into_iter()
            .map(|if_id| {
                NonZero::new(if_id).ok_or_else(|| anyhow::anyhow!("Invalid interface ID: {if_id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut snap_data_plane_interfaces = BTreeMap::new();
        for (dp_id, addr) in value.snap_data_plane_interfaces.into_iter() {
            snap_data_plane_interfaces.insert(
                dp_id,
                addr.parse::<SocketAddr>().context("invalid address")?,
            );
        }

        Ok(Self {
            isd_as,
            if_ids,
            snap_data_plane_excludes: value
                .snap_data_plane_excludes
                .into_iter()
                .map(|network| network.parse::<IpNet>().context("invalid IP network"))
                .collect::<Result<Vec<_>, _>>()?,
            snap_data_plane_interfaces,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct AuthServerState {
    token_exchanger: TokenExchangeImpl,
}

impl From<&AuthServerState> for AuthServerStateDto {
    fn from(state: &AuthServerState) -> Self {
        Self {
            token_exchanger: (&state.token_exchanger).into(),
        }
    }
}

impl TryFrom<AuthServerStateDto> for AuthServerState {
    type Error = anyhow::Error;

    fn try_from(state: AuthServerStateDto) -> Result<Self, Self::Error> {
        let token_exchanger = state.token_exchanger.try_into()?;
        Ok(Self { token_exchanger })
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizationServerHandle {
    system_state: Arc<RwLock<SystemState>>,
}

impl TokenExchange for AuthorizationServerHandle {
    fn exchange(&mut self, req: TokenRequest) -> Result<TokenResponse, TokenExchangeError> {
        let mut sstate = self.system_state.write().unwrap();
        sstate
            .auth_server
            .as_mut()
            .expect("Auth server not found")
            .token_exchanger
            .exchange(req)
    }
}

#[derive(Debug, thiserror::Error)]
enum AllocationError {
    #[error("registration error: {0}")]
    RegistrationError(#[from] AddressRegistrationError),
}

impl From<AllocationError> for snap_tun::AddressAllocationError {
    fn from(error: AllocationError) -> Self {
        match error {
            AllocationError::RegistrationError(e) => {
                // XXX(ake): moved here since snap-tun should not depend on address-manager and
                // vice versa
                match e {
                    AddressRegistrationError::AddressAlreadyRegistered(addr) => {
                        snap_tun::AddressAllocationError::AddressAlreadyRegistered(addr)
                    }
                    AddressRegistrationError::IaNotInAllocationRange(requested_ia, ia) => {
                        snap_tun::AddressAllocationError::IaNotInAllocationRange(requested_ia, ia)
                    }
                    AddressRegistrationError::AddressAllocatorError(
                        scion_sdk_address_manager::allocator::AddressAllocatorError::NoAddressesAvailable,
                    ) => snap_tun::AddressAllocationError::NoAddressesAvailable,
                    AddressRegistrationError::AddressAllocatorError(
                        scion_sdk_address_manager::allocator::AddressAllocatorError::AddressNotInPrefix(addr),
                    ) => snap_tun::AddressAllocationError::AddressNotInAllocationRange(addr),
                    _ => snap_tun::AddressAllocationError::AddressAllocationRejected,
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct SnapDataPlaneDiscoveryHandle {
    snap_id: SnapId,
    system_state: Arc<RwLock<SystemState>>,
    io_config: SharedPocketScionIoConfig,
}

impl UnderlayDiscovery for SnapDataPlaneDiscoveryHandle {
    fn list_snap_underlays(&self) -> Vec<SnapUnderlay> {
        let sstate = self.system_state.read().unwrap();
        let snap = sstate.snaps.get(&self.snap_id).expect("SNAP not found");

        snap.data_planes
            .iter()
            .filter_map(|(hostname, dp_state)| {
                let isd_ases: Vec<IsdAsn> = dp_state
                    .address_registries
                    .values()
                    .map(|ar| ar.isd_asn())
                    .collect();

                self.io_config
                    .snap_data_plane_addr(SnapDataPlaneId::new(self.snap_id, hostname.clone()))
                    .map(|address| SnapUnderlay { address, isd_ases })
            })
            .collect()
    }

    fn list_udp_underlays(&self) -> Vec<UdpUnderlay> {
        vec![] // XXX(ake): Currently no mixed mode with both UDP and SNAP data planes is supported
    }
}

pub(crate) struct SessionManagerHandle {
    #[allow(unused)]
    snap_id: SnapId,
    #[allow(unused)]
    system_state: Arc<RwLock<SystemState>>,
    #[allow(unused)]
    io_config: SharedPocketScionIoConfig,
}

impl SessionGranter for SessionManagerHandle {
    // Issue a grant for _every_ available data plane for which a socket address
    // is configured in the io layer of pocket scion.
    fn create_sessions(
        &self,
        // In the case of PocketSCION, the endhost ip addr is ignored.
        _endhost_ip_addr: IpAddr,
        snap_token: SnapTokenClaims,
    ) -> Result<Vec<SessionGrant>, CreateSessionError> {
        let mut sstate = self.system_state.write().unwrap();
        self.io_config
            .list_snap_data_planes(self.snap_id)
            .into_iter()
            .filter_map(|(dp_id, addr)| addr.map(move |a| (dp_id, a)))
            .map(|(dp_id, address)| {
                let snap = sstate.snaps.get_mut(&self.snap_id).expect("SNAP not found");

                // open a data plane session
                let session_grant = snap
                    .session_manager
                    .open(snap_token.pssid.clone(), dp_id.data_plane())?;

                // issue a session token
                let token = snap.session_issuer.issue(
                    snap_token.pssid.clone(),
                    dp_id.data_plane(),
                    session_grant,
                )?;

                Ok(SessionGrant { address, token })
            })
            .collect()
    }
}

/// The SNAP identifier.
#[derive(
    Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(transparent)]
pub struct SnapId(usize);

impl TryFrom<String> for SnapId {
    type Error = <usize as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(SnapId::from_usize(s.parse()?))
    }
}

impl Id for SnapId {
    fn as_usize(&self) -> usize {
        self.0
    }

    fn from_usize(val: usize) -> Self {
        Self(val)
    }
}

/// SNAP data plane identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ToSchema)]
pub struct SnapDataPlaneId {
    snap_id: SnapId,
    data_plane_hostname: Hostname,
}

impl SnapDataPlaneId {
    pub(crate) fn new(snap_id: SnapId, hostname: Hostname) -> Self {
        Self {
            snap_id,
            data_plane_hostname: hostname,
        }
    }

    pub(crate) fn snap(&self) -> SnapId {
        self.snap_id
    }

    pub(crate) fn data_plane(&self) -> Hostname {
        self.data_plane_hostname.clone()
    }
}

impl Serialize for SnapDataPlaneId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}-{}", self.snap_id.0, self.data_plane_hostname);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SnapDataPlaneId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(Error::custom("invalid SnapDataPlaneId format"));
        }
        let snap = parts[0]
            .parse::<usize>()
            .map_err(|_| Error::custom("invalid SnapId part"))?;
        let hostname = parts[1]
            .try_into()
            .map_err(|e| Error::custom(format!("invalid hostname: {}", e)))?;
        Ok(SnapDataPlaneId {
            snap_id: SnapId(snap),
            data_plane_hostname: hostname,
        })
    }
}

impl fmt::Display for SnapDataPlaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.snap_id, self.data_plane_hostname)
    }
}

/// The router identifier.
#[derive(
    Debug,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(transparent)]
pub struct RouterId(usize);

impl RouterId {
    /// Creates a new `RouterId` from a `usize`.
    pub fn new(val: usize) -> Self {
        Self(val)
    }
}

impl Id for RouterId {
    fn as_usize(&self) -> usize {
        self.0
    }

    fn from_usize(val: usize) -> Self {
        Self(val)
    }
}

/// Map of all tunnel gateway states indexed by SNAP ID and SNAP data plane ID.
pub type TunnelGatewayStates =
    BTreeMap<SnapId, BTreeMap<SnapDataPlaneId, SharedTunnelGatewayState<SnapTokenClaims>>>;

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use rand::SeedableRng;
    use test_log::test;

    use super::*;

    #[test]
    fn should_convert_to_dto_and_back_without_data_loss() {
        let mut pstate = SharedPocketScionState::new(SystemTime::now());
        let isd_as = "1-ff00:0:110".parse().unwrap();
        let snap_id = pstate.add_snap();
        let _dp_id = pstate.add_snap_data_plane(
            snap_id,
            isd_as,
            vec!["10.0.0.0/16".parse().unwrap()],
            ChaCha8Rng::seed_from_u64(42),
        );
        let _router_id = pstate.add_router(
            isd_as,
            vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
            vec!["192.168.0.0/16".parse().unwrap()],
            BTreeMap::from([(
                "test-snap-data-plane".to_string(),
                "127.0.0.1:0".parse().unwrap(),
            )]),
        );
        let before = pstate.system_state.read().unwrap().clone();

        let dto_sstate = pstate.to_dto();
        let start_time = pstate.system_state().start_time;
        let after = SharedPocketScionState::from_dto(start_time, dto_sstate)
            .expect("failed to convert")
            .system_state()
            .clone();

        assert_eq!(before, after);
    }
}
