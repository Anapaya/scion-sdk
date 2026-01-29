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

use std::{
    borrow::Cow,
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
    net,
    time::{Duration, SystemTime},
};

use scion_proto::{
    address::{HostAddr, IsdAsn},
    packet::ScionPacketRaw,
    path::{DataPlanePathFingerprint, Path},
    scmp::{DestinationUnreachableCode, ScmpErrorMessage},
    wire_encoding::WireDecode,
};

use crate::{
    path::{manager::algo::exponential_decay, types::Score},
    scionstack::ScionSocketSendError,
};

/// Marker for a path issue
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueMarker {
    pub target: IssueMarkerTarget,
    pub timestamp: SystemTime,
    pub penalty: Score,
}

impl IssueMarker {
    const SYSTEM_HALF_LIFE: Duration = Duration::from_secs(30);

    /// Returns the decayed penalty score of the issue.
    pub fn decayed_penalty(&self, now: SystemTime) -> Score {
        let elapsed = now
            .duration_since(self.timestamp)
            .unwrap_or(Duration::from_secs(0));

        let decayed = exponential_decay(self.penalty.value(), elapsed, Self::SYSTEM_HALF_LIFE);

        Score::new_clamped(decayed)
    }
}

/// The Path type that the issue marker targets.
///
/// This is global and only applies to SCION paths, and is not specific to any specific endhost.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum IssueMarkerTarget {
    FullPath {
        fingerprint: DataPlanePathFingerprint,
    },
    Interface {
        isd_asn: IsdAsn,
        /// Optionally only applies when arriving on this ingress interface
        ingress_filter: Option<u16>,
        /// Applies when leaving on this egress interface
        egress_filter: u16,
    },
    FirstHop {
        isd_asn: IsdAsn,
        egress_interface: u16,
    },
    LastHop {
        isd_asn: IsdAsn,
        ingress_interface: u16,
    },
    // XXX(ake) : These DestinationNetwork errors are not handled in the PathManager
    DestinationNetwork {
        isd_asn: IsdAsn,
        ingress_interface: u16,
        dst_host: HostAddr,
    },
}

impl IssueMarkerTarget {
    /// Checks if the issue marker target matches the given path.
    ///
    /// If the path does not contain metadata, hop based targets cannot be matched.
    ///
    /// If it's possible to optimize path matching, use `matches_path_checked` instead.
    pub fn matches_path(&self, path: &Path, fingerprint: &DataPlanePathFingerprint) -> bool {
        self.matches_path_checked(path, fingerprint, |_, _| true)
    }

    /// Checks if the issue marker target matches the given path.
    ///
    /// `might_include_check` is a closure allowing optimizations to skip paths that definitely
    /// won't match, called before any detailed matching is done.
    ///
    /// If the path does not contain metadata, hop based targets cannot be matched.
    pub fn matches_path_checked<F>(
        &self,
        path: &Path,
        fingerprint: &DataPlanePathFingerprint,
        might_include_check: F,
    ) -> bool
    where
        F: Fn(&IssueMarkerTarget, &Path) -> bool,
    {
        match self {
            // Check per fingerprint
            Self::FullPath {
                fingerprint: target_fingerprint,
            } => fingerprint == target_fingerprint,
            // Just need to check first interface
            Self::FirstHop {
                isd_asn,
                egress_interface,
            } => {
                path.first_hop_egress_interface()
                    .is_some_and(|intf| intf.isd_asn == *isd_asn && intf.id == *egress_interface)
            }
            // Just need to check last interface
            Self::DestinationNetwork {
                isd_asn,
                ingress_interface,
                ..
            }
            | Self::LastHop {
                isd_asn,
                ingress_interface,
            } => {
                path.last_hop_ingress_interface()
                    .is_some_and(|intf| intf.isd_asn == *isd_asn && intf.id == *ingress_interface)
            }
            // Check all interfaces for matching ingress/egress pair
            Self::Interface {
                isd_asn,
                egress_filter,
                ingress_filter,
            } => {
                // Quick check if path might include the targeted AS
                if !might_include_check(self, path) {
                    return false;
                }

                let interfaces = match path
                    .metadata
                    .as_ref()
                    .and_then(|meta| meta.interfaces.as_ref())
                {
                    Some(interfaces) => interfaces,
                    None => return false, // No metadata, cannot match
                };

                // We start in the source AS, so first interface is always source egress
                if path.source() == *isd_asn {
                    return match ingress_filter {
                        Some(_) => false, /* we are in src, but an ingress filter is set, */
                        // cannot match
                        None => {
                            interfaces
                                .first()
                                .is_some_and(|iface| &iface.id == egress_filter)
                        }
                    };
                }

                let mut iter = interfaces.iter();

                // Check every ingress interface if it's in the target AS
                while let Some(interface) = iter.nth(1) {
                    if interface.isd_asn != *isd_asn {
                        continue;
                    }

                    // Check ingress filter
                    if let Some(ingress) = ingress_filter
                        && interface.id != *ingress
                    {
                        return false;
                    }

                    // Next interface is egress
                    return iter
                        .next()
                        .is_some_and(|egress| &egress.id == egress_filter);
                }

                false
            }
        }
    }

    /// Returns how many entries this issue marker can apply to.
    pub fn applies_to_multiple_paths(&self) -> bool {
        match self {
            IssueMarkerTarget::Interface { .. }
            | IssueMarkerTarget::FirstHop { .. }
            | IssueMarkerTarget::LastHop { .. }
            | IssueMarkerTarget::DestinationNetwork { .. } => true,
            IssueMarkerTarget::FullPath { .. } => false,
        }
    }

    /// Checks if the issue marker can apply to a path between the given src and dst ISD-ASNs.
    pub fn applies_to_path(&self, src: IsdAsn, dst: IsdAsn) -> bool {
        match self {
            // Applies to all src-dst pairs
            IssueMarkerTarget::FullPath { .. } | IssueMarkerTarget::Interface { .. } => true,
            // Applies to specific src
            IssueMarkerTarget::FirstHop { isd_asn, .. } => src == *isd_asn,
            // Applies to specific dst
            IssueMarkerTarget::LastHop { isd_asn, .. }
            | IssueMarkerTarget::DestinationNetwork { isd_asn, .. } => dst == *isd_asn,
        }
    }
}

/// Marks a specific issue experienced on a path
///
/// Issue markers serve as a hard indicator of health and mostly immediately downgrade path
/// usability
#[derive(Debug, Clone)]
pub enum IssueKind {
    /// Path received SCMP error
    Scmp { error: ScmpErrorMessage },
    /// ICMP error
    Icmp {/* icmp error details */}, //TODO: details
    /// Socket error
    Socket { err: SendError },
}
impl Display for IssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueKind::Scmp { error } => write!(f, "SCMP Error: {}", error),
            IssueKind::Icmp { .. } => write!(f, "ICMP Error"),
            IssueKind::Socket { err } => write!(f, "Socket Error: {:?}", err),
        }
    }
}
impl IssueKind {
    /// Returns a hash for deduplication of issues.
    pub fn dedup_id(&self, marker: &IssueMarkerTarget) -> u64 {
        let mut hasher = DefaultHasher::new();

        // Deduplicate based on target
        marker.hash(&mut hasher);
        // And issue kind
        // TODO: Took shortcut here, need to properly implement
        let error_str = format!("{}", self);
        error_str.hash(&mut hasher);

        hasher.finish()
    }

    /// Returns the target type the issue applies to, if any.
    pub fn target_type(&self, path: Option<&Path>) -> Option<IssueMarkerTarget> {
        match self {
            IssueKind::Scmp { error } => {
                if path.is_none() {
                    debug_assert!(false, "Path must be provided on SCMP errors");
                    return None;
                };

                match error {
                    ScmpErrorMessage::DestinationUnreachable(scmp_destination_unreachable) => {
                        // XXX(ake): Destination Unreachable depend on the destination host,
                        // thus they can't be applied globally
                        use scion_proto::scmp::DestinationUnreachableCode::*;
                        match scmp_destination_unreachable.code {
                            NoRouteToDestination
                            | AddressUnreachable
                            | BeyondScopeOfSourceAddress
                            | CommunicationAdministrativelyDenied
                            | SourceAddressFailedIngressEgressPolicy
                            | RejectRouteToDestination => {
                                let mut offending =
                                    scmp_destination_unreachable.get_offending_packet();
                                let pkt = ScionPacketRaw::decode(&mut offending).ok()?;
                                let dst = pkt.headers.path().last_hop_ingress_interface()?;
                                let dst_host = pkt.headers.address.destination()?.host();

                                Some(IssueMarkerTarget::DestinationNetwork {
                                    isd_asn: dst.isd_asn,
                                    ingress_interface: dst.id,
                                    dst_host,
                                })
                            }
                            // Filter out unspecific
                            Unassigned(_) | PortUnreachable | _ => None,
                        }
                    }
                    ScmpErrorMessage::ExternalInterfaceDown(msg) => {
                        Some(IssueMarkerTarget::Interface {
                            isd_asn: msg.isd_asn,
                            ingress_filter: None,
                            // TODO: docs on field say something about the value being encoded
                            // in the LSB of this field. Figure out what was done there and how
                            // to decode it.
                            egress_filter: msg.interface_id as u16,
                        })
                    }
                    ScmpErrorMessage::InternalConnectivityDown(msg) => {
                        Some(IssueMarkerTarget::Interface {
                            isd_asn: msg.isd_asn,
                            ingress_filter: Some(msg.ingress_interface_id as u16),
                            egress_filter: msg.egress_interface_id as u16,
                        })
                    }

                    ScmpErrorMessage::Unknown(_) => None,
                    ScmpErrorMessage::PacketTooBig(_) => None,
                    ScmpErrorMessage::ParameterProblem(_) => None,
                }
            }
            IssueKind::Icmp { .. } => None,
            IssueKind::Socket { err } => {
                if path.is_none() {
                    debug_assert!(false, "Path must be provided on Socket errors");
                    return None;
                };

                match err {
                    SendError::FirstHopUnreachable {
                        isd_asn,
                        interface_id,
                        ..
                    } => {
                        Some(IssueMarkerTarget::FirstHop {
                            isd_asn: *isd_asn,
                            egress_interface: *interface_id,
                        })
                    }
                }
            }
        }
    }

    /// Calculates the penalty based on the severity of the issue.
    /// Returns a negative score (penalty).
    pub fn penalty(&self) -> Score {
        let magnitude = match self {
            IssueKind::Scmp { error } => {
                match error {
                    // LINK FAILURES (Max penalty)
                    // Interface down means the link is physically/logically broken.
                    // With 30s half-life, it takes ~3 mins to recover to > -0.01
                    ScmpErrorMessage::ExternalInterfaceDown(_)
                    | ScmpErrorMessage::InternalConnectivityDown(_) => -1.0,

                    // ROUTING ISSUES (High)
                    // Dst AS can't route the packet internally
                    ScmpErrorMessage::DestinationUnreachable(err) => {
                        // XXX(ake): Destination Errors are not handled in the Path Manager
                        match err.code {
                            // Can't forward packet to dst ip
                            DestinationUnreachableCode::NoRouteToDestination
                            | DestinationUnreachableCode::AddressUnreachable => -0.8,
                            // Admin denied might be policy, treated as severe
                            DestinationUnreachableCode::CommunicationAdministrativelyDenied => -0.9,

                            // Unreachable Port is beyond routing
                            DestinationUnreachableCode::PortUnreachable => 0.0,
                            _ => -0.5,
                        }
                    }
                    // Unspecific
                    ScmpErrorMessage::Unknown(_) => -0.2,
                    // Irrelevant
                    ScmpErrorMessage::PacketTooBig(_) | ScmpErrorMessage::ParameterProblem(_) => {
                        0.0
                    }
                }
            }

            // SOCKET / TRANSIENT (Medium)
            // Often temporary congestion or local buffer issues.
            // Penalty: -0.4.
            // Recovers quickly (within ~45 seconds).
            IssueKind::Socket { err } => {
                match err {
                    SendError::FirstHopUnreachable { .. } => -0.4,
                }
            }

            // Unhandled as of now
            IssueKind::Icmp { .. } => 0.0,
        };

        Score::new_clamped(magnitude)
    }
}

/// Classification of a ScionSocketSendError send error that includes the necessary
/// information for the path manager to handle the error.
/// This type is necessary because ScionSocketSendError is not Clone.
#[derive(Debug, Clone)]
pub enum SendError {
    FirstHopUnreachable {
        isd_asn: IsdAsn,
        interface_id: u16,
        address: Option<net::SocketAddr>,
        msg: Cow<'static, str>,
    },
}

impl SendError {
    pub fn from_socket_send_error(error: &ScionSocketSendError) -> Option<Self> {
        match error {
            ScionSocketSendError::UnderlayNextHopUnreachable {
                isd_as,
                interface_id,
                address,
                msg,
            } => {
                Some(Self::FirstHopUnreachable {
                    isd_asn: *isd_as,
                    interface_id: *interface_id,
                    address: *address,
                    msg: msg.clone().into(),
                })
            }
            _ => None,
        }
    }
}
