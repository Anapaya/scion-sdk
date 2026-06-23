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
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};

use chrono::{DateTime, Utc};
use dhsd::DhsdSecret;
use pem::Pem;
use scion_proto::address::{IsdAsn, ScionAddr};
use scion_sdk_token_validator::validator::insecure_const_ed25519_key_pair_pem;

use crate::{
    comp::{
        authorization_server::AuthServerState,
        control_service::{ControlServiceState, segment_lookup::SegmentListingCache},
        daemon::DaemonServiceState,
        endhost_api::{EndhostApiId, EndhostApiState},
        endhost_api_discovery::{EndhostApiDiscoveryApiId, EndhostApiDiscoveryState},
        external_as::ExternalAsState,
        network_forwarder::NetworkForwarderState,
        router::{RouterId, RouterState},
        snap::{SnapId, SnapState},
    },
    network::{
        local::{
            external_as_registry::ExternalAsRegistry, receiver_registry::NetworkReceiverRegistry,
        },
        scion::{
            segment::registry::SegmentRegistry,
            topology::{
                FastTopologyLookup, ScionAs, ScionLink, ScionTopology, ScionTopologyBuilder,
            },
        },
    },
    util::cert_tmp_dir::CertificateTempDir,
};

/// The default keepalive interval for the SNAPtun connection(s).
pub const DEFAULT_SNAPTUN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// The default root secret for PocketSCION.
pub const DEFAULT_POCKET_SCION_ROOT_SECRET: [u8; 32] = [67u8; 32];

/// Inner state of PocketSCION, containing all runtime state (as far as possible) of the system.
///
/// See [PocketScionState] for usage.
#[derive(Debug, Clone)]
pub struct PocketScionStateInner {
    // Configuration
    // -------------------------------------------------
    /// The root secret used to derive the secrets for the SNAPs.
    pub root_secret: DhsdSecret,
    /// The time when PocketSCION was started, used to calculate uptime and for other time-based
    /// features.
    pub start_time: DateTime<Utc>,
    /// The public key to verify the SNAP tokens.
    pub snap_token_public_pem: Pem,
    /// The keepalive interval for the SNAPtun connection(s).
    pub snaptun_keepalive_interval: Duration,
    /// Whether to ignore MACs in the system.
    pub ignore_macs: bool,

    // Network State
    // -------------------------------------------------
    /// The SCION topology of the system.
    pub topology: ScionTopology,
    /// The segment registry of the system.
    pub segment_registry: SegmentRegistry,
    /// Network traffic receivers in the network simulation
    pub sim_receivers: NetworkReceiverRegistry,
    /// Special AS handlers for the network simulation, keyed by ISD-ASN.
    ///
    /// These handlers can be used to define custom behavior for specific ASes in the network
    /// simulation.
    pub extern_as_handlers: ExternalAsRegistry,

    // Component States
    // -------------------------------------------------
    /// The state of the authorization server.
    pub auth_server: Option<AuthServerState>,
    /// The list of SNAPs in the system.
    pub snaps: BTreeMap<SnapId, SnapState>,
    /// The state of the routers in the system.
    pub routers: BTreeMap<RouterId, RouterState>,
    /// The state of the daemon services in the system.
    pub daemon_services: BTreeMap<IsdAsn, DaemonServiceState>,
    /// The state of the endhost APIs in the system.
    pub endhost_apis: BTreeMap<EndhostApiId, EndhostApiState>,
    /// The state of the endhost API discovery APIs in the system.
    pub endhost_api_discovery_api: BTreeMap<EndhostApiDiscoveryApiId, EndhostApiDiscoveryState>,
    /// The external ASes in the system.
    pub external_ases: BTreeMap<IsdAsn, ExternalAsState>,
    /// The control service states in the system.
    pub control_service_states: BTreeMap<IsdAsn, ControlServiceState>,
    /// The network forwarders in the system.
    pub network_forwarders: BTreeMap<ScionAddr, NetworkForwarderState>,
    /// Optional global cache for segment listing results, used by the SegmentLookupService.
    pub segment_listing_cache: Option<SegmentListingCache>,
    /// Temporary directory for certificate files,
    pub cert_dir: CertificateTempDir,
}

impl PocketScionStateInner {
    /// Creates a new [SystemState] with the given start time.
    fn new_with_start_time(start_time: DateTime<Utc>) -> Self {
        Self {
            root_secret: DhsdSecret::from_root_secret([67u8; 32]),
            start_time,
            snap_token_public_pem: insecure_const_ed25519_key_pair_pem().1,
            snaps: Default::default(),
            snaptun_keepalive_interval: DEFAULT_SNAPTUN_KEEPALIVE_INTERVAL,
            routers: Default::default(),
            daemon_services: Default::default(),
            auth_server: Default::default(),
            topology: Self::default_topology(),
            segment_registry: SegmentRegistry::new(&FastTopologyLookup::new(
                &Self::default_topology(),
            )),
            sim_receivers: Default::default(),
            endhost_apis: Default::default(),
            endhost_api_discovery_api: Default::default(),
            external_ases: Default::default(),
            extern_as_handlers: Default::default(),
            network_forwarders: Default::default(),
            control_service_states: Default::default(),
            ignore_macs: false,
            segment_listing_cache: None,
            cert_dir: CertificateTempDir::new().expect("Failed to create temporary directory"),
        }
    }

    /// Returns a default topology
    fn default_topology() -> ScionTopology {
        let mut topo = ScionTopologyBuilder::new();
        topo.add_as(ScionAs::new_core("1-ff00:0:132".parse().unwrap()))
            .unwrap()
            .add_as(ScionAs::new_core("2-ff00:0:212".parse().unwrap()))
            .unwrap()
            .add_link(
                ScionLink::new(
                    "1-ff00:0:132".parse().unwrap(),
                    1,
                    crate::network::scion::topology::ScionLinkType::Core,
                    "2-ff00:0:212".parse().unwrap(),
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        topo.build().expect("building default topology")
    }
}

/// Shared state for PocketSCION, containing all runtime state (as far as possible) of the system.
///
/// It acts as:
/// - a snapshot of the current state of the system
/// - the configuration for the system
///
/// As a user of PocketSCION, you set up the initial state of the system by creating a
/// [PocketScionState] with the desired configuration and passing it to
/// [PocketScionRuntimeBuilder](crate::runtime::builder::PocketScionRuntimeBuilder).
///
/// As PocketSCION runs, the state is updated to reflect the current state of the system. You can
/// read the state at any time by calling `runtime.state().read()`.
#[derive(Clone)]
pub struct PocketScionState {
    system_state: Arc<RwLock<PocketScionStateInner>>,
}

impl Debug for PocketScionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.read().fmt(f)
    }
}

// General
impl PocketScionState {
    /// Creates a new default [PocketScionState] with the given start time.
    pub fn new(start_time: DateTime<Utc>) -> Self {
        Self {
            system_state: Arc::new(RwLock::new(PocketScionStateInner::new_with_start_time(
                start_time,
            ))),
        }
    }

    /// Locks and returns a read guard for the contained [PocketScionStateInner]
    pub fn read(&self) -> ReadGuard<'_> {
        ReadGuard {
            guard: self.system_state.read().unwrap(),
        }
    }

    /// Locks and returns a write guard for the contained [PocketScionStateInner]
    ///
    /// To avoid breaking the internal invariants of the system, this is not public.
    pub(crate) fn write(&self) -> WriteGuard<'_, PocketScionStateInner> {
        WriteGuard {
            guard: self.system_state.write().unwrap(),
        }
    }
}

/// Secret Management
impl PocketScionState {
    /// Returns the root secret for PocketSCION.
    pub fn root_secret(&self) -> DhsdSecret {
        self.read().root_secret.clone()
    }
}

/// Pocketscion Read Guard wrapper
pub struct ReadGuard<'a> {
    guard: RwLockReadGuard<'a, PocketScionStateInner>,
}
impl Deref for ReadGuard<'_> {
    type Target = PocketScionStateInner;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

/// Pocketscion Write Guard wrapper
pub struct WriteGuard<'a, T> {
    guard: std::sync::RwLockWriteGuard<'a, T>,
}
impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}
impl<T> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
