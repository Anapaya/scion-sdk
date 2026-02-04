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
    collections::BTreeMap,
    net::SocketAddr,
    num::NonZero,
    str::FromStr,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{Duration, SystemTime},
};

use anyhow::Context as _;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use derive_more::Display;
use dhsd::DhsdSecret;
use ipnet::IpNet;
use pem::Pem;
use scion_proto::address::IsdAsn;
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;
use serde::{Deserialize, Serialize};
use snap_dataplane::state::Id;
use utoipa::ToSchema;

use crate::{
    authorization_server::{
        api::{TokenRequest, TokenResponse},
        token_exchanger::{
            TokenExchange, TokenExchangeConfig, TokenExchangeError, TokenExchangeImpl,
        },
    },
    dto::{AuthServerStateDto, RouterStateDto, SystemStateDto},
    endhost_api::{EndhostApiId, EndhostApiState},
    network::{
        local::{receiver_registry::NetworkReceiverRegistry, receivers::Receiver},
        scion::{
            segment::registry::SegmentRegistry,
            topology::{FastTopologyLookup, ScionTopology},
        },
    },
    state::snap::{SnapId, SnapState},
};

pub mod endhost_segment_lister;
pub mod simulation_dispatcher;
pub mod snap;

/// The default keepalive interval for the SNAPtun connection(s).
pub const DEFAULT_SNAPTUN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// The default root secret for PocketSCION.
pub const DEFAULT_POCKET_SCION_ROOT_SECRET: [u8; 32] = [67u8; 32];

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
// SNAPtun
impl SharedPocketScionState {
    /// Returns the keepalive interval for the SNAPtun connection(s).
    pub fn snaptun_keepalive_interval(&self) -> Duration {
        self.system_state.read().unwrap().snaptun_keepalive_interval
    }
    /// Sets the keepalive interval for the SNAPtun connection(s).
    pub fn set_snaptun_keepalive_interval(&mut self, interval: Duration) {
        let mut state = self.system_state.write().unwrap();
        state.snaptun_keepalive_interval = interval;
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
    root_secret: DhsdSecret,
    start_time: SystemTime,
    snap_token_public_pem: Pem,
    snaptun_keepalive_interval: Duration,
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
            root_secret: DhsdSecret::from_root_secret([67u8; 32]),
            start_time,
            snap_token_public_pem: insecure_const_ed25519_key_pair_pem().1,
            snaps: Default::default(),
            snaptun_keepalive_interval: DEFAULT_SNAPTUN_KEEPALIVE_INTERVAL,
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

    /// Returns the root secret of the system state.
    pub fn root_secret(&self) -> DhsdSecret {
        self.root_secret.clone()
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
            root_secret: Some(BASE64_STANDARD.encode(system_state.root_secret.as_array())),
            auth_server_state: system_state
                .auth_server
                .as_ref()
                .map(|auth_server| auth_server.into()),
            snap_token_public_key: system_state.snap_token_public_pem.to_string(),
            snaptun_keepalive_interval: system_state.snaptun_keepalive_interval,
            snaps: system_state
                .snaps
                .iter()
                .map(|(snap_id, snap_state)| (*snap_id, snap_state.clone().into()))
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
        let root_secret = DhsdSecret::from_root_secret(
            dto.root_secret
                .map(|root_secret| {
                    let bytes: [u8; 32] = BASE64_STANDARD
                        .decode(root_secret)
                        .context("invalid base64 encoded root secret")?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("root secret is not 32 bytes"))?;
                    anyhow::Ok(bytes)
                })
                .transpose()?
                .unwrap_or(DEFAULT_POCKET_SCION_ROOT_SECRET),
        );
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
            root_secret,
            start_time: SystemTime::now(),
            snaptun_keepalive_interval: dto.snaptun_keepalive_interval,
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use test_log::test;

    use super::*;

    #[test]
    fn should_convert_to_dto_and_back_without_data_loss() {
        let mut pstate = SharedPocketScionState::new(SystemTime::now());
        let isd_as = "1-ff00:0:110".parse().unwrap();

        pstate.add_snap(isd_as).unwrap();

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
