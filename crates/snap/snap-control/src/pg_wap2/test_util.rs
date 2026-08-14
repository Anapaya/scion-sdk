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

//! Fixtures shared by the tests of the individual primitives.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use endhost_api_models::SegmentsError;
use sciparse::{
    address::ip_socket_addr::ScionSocketIpAddr,
    dataplane_path::standard::types::HopFieldMac,
    identifier::isd_asn::IsdAsn,
    reexport::p256,
    segment::{
        AsEntry, HopEntry, SegmentHopField, Segments, SegmentsPage, SignedPathSegment,
        UnsignedPathSegment,
    },
};

use super::{
    auth::{AuthSegments, AuthService, GrantedSegmentId},
    paths::PathManager,
    segments::{SegmentManager, SegmentStoreId},
};
use crate::pg_wap2::sni::{CustomerDomainRef, WapSNI};

pub fn sni() -> WapSNI {
    WapSNI::new("id.wap.target.example.com".to_string()).unwrap()
}

pub fn other_sni() -> WapSNI {
    WapSNI::new("id.wap.other.example.com".to_string()).unwrap()
}

/// Interfaces of the up segment used by most tests.
pub const UP_IFS: (u16, u16) = (1, 2);
/// Interfaces of the core segment, which connects [`core_ia`] and [`other_core_ia`].
pub const CORE_IFS: (u16, u16) = (3, 4);
/// Interfaces of the down segment, which connects [`other_core_ia`] and [`other_leaf_ia`].
pub const DOWN_IFS: (u16, u16) = (5, 6);

pub fn client_ip() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))
}

/// A second client, for the cases where two IPs share something.
pub fn other_client_ip() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2))
}

/// A third client, for the cases where two clients already share something.
pub fn stranger_ip() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 3))
}

pub fn core_ia() -> IsdAsn {
    "1-ff00:0:110".parse().unwrap()
}

pub fn leaf_ia() -> IsdAsn {
    "1-ff00:0:111".parse().unwrap()
}

/// The core AS on the far side of the core segment.
pub fn other_core_ia() -> IsdAsn {
    "1-ff00:0:120".parse().unwrap()
}

/// The leaf AS below [`other_core_ia`], reachable from [`leaf_ia`] only over up, core and down.
pub fn other_leaf_ia() -> IsdAsn {
    "1-ff00:0:121".parse().unwrap()
}

pub fn wag(ia: IsdAsn) -> ScionSocketIpAddr {
    format!("[{ia},10.0.0.1]:443").parse().unwrap()
}

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

/// The point in time `secs` seconds after the UNIX epoch, which is where the tests start.
pub fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

pub fn secs_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One AS an artificial segment traverses, and the interfaces it enters and leaves it on.
pub struct Hop {
    pub ia: IsdAsn,
    pub ingress: u16,
    pub egress: u16,
}

/// Builds a signed segment whose fingerprint is determined by `hops`, and whose expiry is
/// determined by `timestamp` and `expiration_units`.
///
/// The signatures and MACs are not verifiable; nothing in the control plane checks them.
pub fn segment(timestamp: u32, expiration_units: u8, hops: &[Hop]) -> SignedPathSegment {
    let as_entries = hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            AsEntry {
                local: hop.ia,
                next: hops.get(i + 1).map_or(IsdAsn(0), |next| next.ia),
                mtu: 1500,
                hop_entry: HopEntry {
                    ingress_mtu: 1500,
                    hop_field: SegmentHopField {
                        expiration_units,
                        cons_ingress: hop.ingress,
                        cons_egress: hop.egress,
                        mac: HopFieldMac([0; 6]),
                    },
                },
                peer_entries: Vec::new(),
                extensions: Vec::new(),
                unsigned_extensions: Vec::new(),
            }
        })
        .collect();

    let key = p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap();

    UnsignedPathSegment::new(timestamp, 42, as_entries)
        .try_into_signed_segment(|_| Some((key.clone(), None)), timestamp)
        .expect("test segment can be signed")
}

/// An up segment from the core AS down to the leaf AS, i.e. a path from leaf to core.
pub fn up_segment(timestamp: u32) -> SignedPathSegment {
    segment(
        timestamp,
        u8::MAX,
        &[
            Hop {
                ia: core_ia(),
                ingress: 0,
                egress: UP_IFS.0,
            },
            Hop {
                ia: leaf_ia(),
                ingress: UP_IFS.1,
                egress: 0,
            },
        ],
    )
}

/// The up segment of [`up_segment`], but with hop fields that live `expiration_units` + 1 units
/// of [`sciparse::dataplane_path::standard::types::EXP_TIME_UNIT`] instead of the maximum.
pub fn short_lived_up_segment(timestamp: u32, expiration_units: u8) -> SignedPathSegment {
    segment(
        timestamp,
        expiration_units,
        &[
            Hop {
                ia: core_ia(),
                ingress: 0,
                egress: UP_IFS.0,
            },
            Hop {
                ia: leaf_ia(),
                ingress: UP_IFS.1,
                egress: 0,
            },
        ],
    )
}

/// A second up segment, over different interfaces, so it has a different fingerprint.
pub fn other_up_segment(timestamp: u32) -> SignedPathSegment {
    segment(
        timestamp,
        u8::MAX,
        &[
            Hop {
                ia: core_ia(),
                ingress: 0,
                egress: UP_IFS.0 + 10,
            },
            Hop {
                ia: leaf_ia(),
                ingress: UP_IFS.1 + 10,
                egress: 0,
            },
        ],
    )
}

/// A core segment between the two core ASes, the middle of the up-core-down path.
pub fn core_segment(timestamp: u32) -> SignedPathSegment {
    segment(
        timestamp,
        u8::MAX,
        &[
            Hop {
                ia: other_core_ia(),
                ingress: 0,
                egress: CORE_IFS.0,
            },
            Hop {
                ia: core_ia(),
                ingress: CORE_IFS.1,
                egress: 0,
            },
        ],
    )
}

/// A down segment from the far core AS to the far leaf AS, the end of the up-core-down path.
pub fn down_segment(timestamp: u32) -> SignedPathSegment {
    segment(
        timestamp,
        u8::MAX,
        &[
            Hop {
                ia: other_core_ia(),
                ingress: 0,
                egress: DOWN_IFS.0,
            },
            Hop {
                ia: other_leaf_ia(),
                ingress: DOWN_IFS.1,
                egress: 0,
            },
        ],
    )
}

/// A [`SegmentsDiscovery`] returning whatever it was last told to return.
pub struct MockFetcher {
    segments: Mutex<Segments>,
    calls: AtomicUsize,
    /// While set, every fetch fails instead of returning `segments`.
    failing: AtomicBool,
}

impl MockFetcher {
    pub fn new(segments: Segments) -> Arc<Self> {
        Arc::new(Self {
            segments: Mutex::new(segments),
            calls: AtomicUsize::new(0),
            failing: AtomicBool::new(false),
        })
    }

    pub fn empty() -> Arc<Self> {
        Self::new(Segments::default())
    }

    pub fn with_up_segments(segments: Vec<SignedPathSegment>) -> Arc<Self> {
        Self::new(Segments {
            up_segments: segments,
            ..Segments::default()
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    /// Changes what the next fetch returns.
    pub fn set_segments(&self, segments: Segments) {
        *self.segments.lock().unwrap() = segments;
    }

    /// Makes every fetch fail, or stops doing so.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl endhost_api_models::SegmentsDiscovery for MockFetcher {
    async fn list_segments(
        &self,
        _src: IsdAsn,
        _dst: IsdAsn,
        _page_size: i32,
        _page_token: String,
    ) -> Result<SegmentsPage, SegmentsError> {
        self.calls.fetch_add(1, Ordering::Relaxed);

        if self.failing.load(Ordering::Relaxed) {
            return Err(SegmentsError::InternalError(
                "fetching is set to fail".into(),
            ));
        }

        Ok(SegmentsPage {
            segments: self.segments.lock().unwrap().clone(),
            next_page_token: String::new(),
        })
    }
}

/// Longest the [`Fixture`]'s [`SegmentManager`] leaves a pair unfetched.
pub const MAX_FETCH_INTERVAL: Duration = Duration::from_secs(3600);
/// Shortest the [`Fixture`]'s [`SegmentManager`] waits between two fetches of one pair.
pub const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(10);
/// How long an unheld pair survives without being used in the [`Fixture`].
pub const IDLE_EVICTION_TIME: Duration = Duration::from_secs(60);
/// Least a segment must have left to be kept by the [`Fixture`]'s [`SegmentManager`].
pub const MIN_SEGMENT_LIFETIME: Duration = Duration::from_secs(60);
/// How long before a segment expires the [`Fixture`] wants its replacement fetched.
pub const SEGMENT_LIFETIME_BUFFER: Duration = Duration::from_secs(300);

pub struct Fixture {
    pub auth: AuthService,
    pub fetcher: Arc<MockFetcher>,
    pub segments: SegmentManager,
    pub paths: PathManager,
}

impl Fixture {
    /// Builds the primitives with generous timeouts, so nothing expires unless a test hands one
    /// of them a later point in time.
    pub fn new(fetcher: Arc<MockFetcher>, auth_duration: Duration) -> Self {
        // The clean interval bounds only matter for `AuthService::run`, which the tests drive by
        // calling `clean` directly.
        let auth = AuthService::new(
            auth_duration,
            Duration::from_millis(30),
            Duration::from_secs(120),
        );
        let segments = SegmentManager::new(
            MAX_FETCH_INTERVAL,
            MIN_FETCH_INTERVAL,
            IDLE_EVICTION_TIME,
            MIN_SEGMENT_LIFETIME,
            SEGMENT_LIFETIME_BUFFER,
            Box::new(fetcher.clone()),
        );
        let paths = PathManager::new(segments.clone(), auth.clone());

        Self {
            auth,
            fetcher,
            segments,
            paths,
        }
    }

    /// Grants `segments` to the test client for the test SNI.
    pub fn grant_non_core(&self, segments: Vec<SignedPathSegment>, now: SystemTime) {
        self.auth.authorize(
            client_ip(),
            HashMap::from([(
                sni().customer_domain().into(),
                AuthSegments::new(Vec::new(), segments),
            )]),
            now,
        );
    }

    /// Grants `ip` access to `dst`, without any private segments.
    pub fn grant_target(&self, ip: IpAddr, dst: CustomerDomainRef<'_>, now: SystemTime) {
        self.auth.authorize(
            ip,
            HashMap::from([(dst.into(), AuthSegments::default())]),
            now,
        );
    }

    /// Grants `segments` to `ip` for the test SNI.
    pub fn grant_non_core_to(&self, ip: IpAddr, segments: Vec<SignedPathSegment>, now: SystemTime) {
        self.auth.authorize(
            ip,
            HashMap::from([(
                sni().customer_domain().into(),
                AuthSegments::new(Vec::new(), segments),
            )]),
            now,
        );
    }

    /// Grants `ip` access to `dst` over `core` and `non_core`.
    pub fn grant_for(
        &self,
        ip: IpAddr,
        dst: CustomerDomainRef<'_>,
        core: Vec<SignedPathSegment>,
        non_core: Vec<SignedPathSegment>,
        now: SystemTime,
    ) {
        self.auth.authorize(
            ip,
            HashMap::from([(dst.into(), AuthSegments::new(core, non_core))]),
            now,
        );
    }
}

pub fn granted_id(segment: &SignedPathSegment) -> GrantedSegmentId {
    GrantedSegmentId::NonCore(segment.fingerprint())
}

pub fn granted_core_id(segment: &SignedPathSegment) -> GrantedSegmentId {
    GrantedSegmentId::Core(segment.fingerprint())
}

pub fn store_id(segment: &SignedPathSegment) -> SegmentStoreId {
    non_core_store_id(segment, leaf_ia(), core_ia())
}

/// The id an up or down segment fetched for the (`src`, `dst`) pair is stored under.
pub fn non_core_store_id(segment: &SignedPathSegment, src: IsdAsn, dst: IsdAsn) -> SegmentStoreId {
    SegmentStoreId::NonCore {
        src,
        dst,
        fp: segment.fingerprint(),
    }
}

/// The id a core segment fetched for the (`src`, `dst`) pair is stored under.
pub fn core_store_id(segment: &SignedPathSegment, src: IsdAsn, dst: IsdAsn) -> SegmentStoreId {
    SegmentStoreId::Core {
        src,
        dst,
        fp: segment.fingerprint(),
    }
}
