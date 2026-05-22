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

//! SCION control plane paths and related functionality.
//!
//! These paths are usually obtained from the SCION daemon.
//! They contain the encoded dataplane path and optional metadata about the path, such as expiration
//! time, MTU, and interfaces used by the path.

use std::net::SocketAddr;

use crate::{
    core::view::View,
    dataplane_path::{
        standard::view::StandardPathView,
        types::PathReverseError,
        view::{ScionDpPathView, ScionDpPathViewExt, ScionDpPathViewExtMut},
    },
    identifier::isd_asn::IsdAsn,
    path::metadata::{geo::GeoCoordinates, link::LinkMeta, path_interface::PathInterface},
    rpc::FromRpcError,
};

pub mod combinator;
pub mod fingerprint;
pub mod metadata;
pub mod policy;

/// A Control Plane Path, which can be of different types (e.g., standard, one-hop).
///
/// This contains a [ScionDpPathView], which is the encoded dataplane path as returned by the
/// SCION daemon, and optional metadata about the path, such as expiration time, MTU, and interfaces
/// used by the path
#[derive(Debug, Clone)]
pub struct ScionPath {
    /// The ISD-AS of the path's source.
    src_ia: IsdAsn,
    /// The ISD-AS of the path's destination.
    dst_ia: IsdAsn,
    /// The encoded dataplane path as returned by the SCION daemon.
    dp_path: ScionDpPathView,
    /// Metadata about the path
    metadata: Option<metadata::PathMetadata>,
    /// The address of the SCION router which is used to exit the local AS on this path.
    next_hop: Option<SocketAddr>,

    // Computed fields
    /// Computed fingerprint of the path based on control plane data
    _cp_fingerprint: Option<fingerprint::control_plane::PathFingerprint>,
    /// Computed fingerprint of the path based on the dataplane path data
    _fingerprint: fingerprint::data_plane::DpPathFingerprint,
    /// Computed Unix epoch in seconds after which the path is considered expired.
    ///
    /// None if the paths expiration time could not be obtained from the dataplane path (e.g.,
    /// unsupported path types).
    _expiration: Option<u32>,
}
impl ScionPath {
    /// Creates a new [ScionPath] with the given dataplane path and metadata.
    pub fn new(
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
        dp_path: ScionDpPathView,
        metadata: Option<metadata::PathMetadata>,
        next_hop: Option<SocketAddr>,
    ) -> Self {
        let dp_fingerprint = fingerprint::data_plane::DpPathFingerprint::from_dp_path(
            dp_path.as_ref(),
            src_ia,
            dst_ia,
        );

        let expiration = dp_path.expiration();

        let mut this = Self {
            dp_path,
            metadata,
            src_ia,
            dst_ia,
            next_hop,
            _cp_fingerprint: None,
            _fingerprint: dp_fingerprint,
            _expiration: expiration,
        };

        // Try to set the path fingerprint if possible
        this._cp_fingerprint =
            fingerprint::control_plane::PathFingerprint::from_scion_path(&this).ok();
        this
    }

    /// Creates a new [ScionPath] for a local path, sending packets within the same AS.
    ///
    /// Returns None if the AS is a wildcard.
    pub fn local(local_as: IsdAsn) -> Option<Self> {
        if local_as.is_wildcard() {
            None
        } else {
            Some(Self::new(
                local_as,
                local_as,
                ScionDpPathView::Empty,
                None,
                None,
            ))
        }
    }
}
// utility
impl ScionPath {
    /// Returns the egress interface of the first hop of the path.
    pub fn first_egress_interface(&self) -> Option<PathInterface> {
        // Try from dataplane path first
        if let Some(if_id) = self.dp_path.first_egress_interface() {
            return Some(PathInterface {
                isd_asn: self.src_ia,
                id: if_id,
            });
        }

        // Then try from metadata
        if let Some(meta_if) = self
            .metadata
            .as_ref()
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|interfaces| interfaces.first())
            .map(|meta| meta.interface)
        {
            return Some(meta_if);
        }

        None
    }

    /// Returns the ingress interface of the last hop of the path, if metadata is available.
    pub fn last_ingress_interface(&self) -> Option<PathInterface> {
        // Try from dataplane path first
        if let Some(if_id) = self.dp_path.last_ingress_interface() {
            return Some(PathInterface {
                isd_asn: self.dst_ia,
                id: if_id,
            });
        }

        // Then try from metadata
        if let Some(meta_if) = self
            .metadata
            .as_ref()
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|interfaces| interfaces.last())
            .map(|meta| meta.interface)
        {
            return Some(meta_if);
        }

        None
    }

    /// Attempts to reverse the path by reversing the dataplane path and swapping the source and
    /// destination ISD-AS.
    ///
    /// If the dataplane path type does not support reversal, returns an error.
    pub fn try_reverse(&mut self) -> Result<(), PathReverseError> {
        self.dp_path.try_reverse()?;
        std::mem::swap(&mut self.src_ia, &mut self.dst_ia);

        // Next hop is not valid after reversal.
        self.next_hop = None;

        if let Some(metadata) = self.metadata.as_mut() {
            if let Some(interfaces) = metadata.interfaces.as_mut() {
                interfaces.reverse();
            }

            if let Some(notes) = metadata.notes.as_mut() {
                notes.reverse();
            }

            let cp_fingerprint =
                fingerprint::control_plane::PathFingerprint::from_scion_path(self).ok();
            self._cp_fingerprint = cp_fingerprint;
        }

        self._fingerprint = fingerprint::data_plane::DpPathFingerprint::from_dp_path(
            self.dp_path.as_ref(),
            self.src_ia,
            self.dst_ia,
        );

        Ok(())
    }
}
// accessors
impl ScionPath {
    /// Returns the encoded dataplane path as returned by the SCION daemon.
    pub fn dp_path(&self) -> &ScionDpPathView {
        &self.dp_path
    }
    /// Returns metadata about the path, if available.
    pub fn metadata(&self) -> Option<&metadata::PathMetadata> {
        self.metadata.as_ref()
    }

    /// Returns the ISD-AS of the path's source.
    pub fn src_ia(&self) -> IsdAsn {
        self.src_ia
    }

    /// Returns the ISD-AS of the path's destination.
    pub fn dst_ia(&self) -> IsdAsn {
        self.dst_ia
    }

    /// Returns the address of the SCION router which is used to exit the local AS on this path, if
    /// available.
    pub fn next_hop(&self) -> Option<SocketAddr> {
        self.next_hop
    }

    /// Sets the address of the SCION router which is used to exit the local AS on this path.
    pub fn set_next_hop(&mut self, next_hop: Option<SocketAddr>) {
        self.next_hop = next_hop;
    }

    /// Returns a fingerprint for this path, uniquely identifying the route taken by the path.
    ///
    /// Usually [Self::fingerprint] is prefferable, this method is only useful if the control plane
    /// fingerprint is needed.
    ///
    /// See [PathFingerprint](fingerprint::control_plane::PathFingerprint) for details.
    pub fn cp_fingerprint(&self) -> Option<fingerprint::control_plane::PathFingerprint> {
        self._cp_fingerprint
    }

    /// Returns the fingerprint for this path based on the dataplane path data, uniquely identifying
    /// the route taken by the path.
    ///
    /// See [DpPathFingerprint](fingerprint::data_plane::DpPathFingerprint) for details
    pub fn fingerprint(&self) -> fingerprint::data_plane::DpPathFingerprint {
        self._fingerprint
    }

    /// Returns the expiration time of the path in seconds since the UNIX epoch, if available.
    ///
    /// This is obtained from the dataplane path if possible, and falls back to the control plane
    /// metadata if not.
    ///
    /// Returns None if the expiration time could not be obtained from either source.
    pub fn expiration(&self) -> Option<u32> {
        self._expiration.or_else(|| {
            self.metadata
                .as_ref()
                .map(|metadata| metadata.expiration as u32)
        })
    }
}
// rpc
impl ScionPath {
    /// Creates a new [ScionPath] from the given RPC path.
    ///
    /// ### Parameters
    /// - `rpc_path`: The RPC path as returned by the SCION daemon.
    /// - `src_ia`: The ISD-AS of the path's source.
    /// - `dst_ia`: The ISD-AS of the path's destination.
    pub fn from_rpc(
        rpc_path: scion_protobuf::daemon::v1::Path,
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
    ) -> Result<Self, FromRpcError> {
        if rpc_path.raw.is_empty() {
            if src_ia.is_wildcard() && dst_ia.is_wildcard() {
                // Todo(ake): Scion Proto creates a `empty` path here. Does this make sense?
                return Err(
                    "cannot create empty path with wildcard source and destination IA".into(),
                );
            } else if src_ia == dst_ia {
                // Local path, create an empty dataplane path
                return Ok(Self::local(src_ia).expect("check above ensures src_ia is not wildcard"));
            } else {
                return Err("RPC payload had an empty path".into());
            }
        }

        // Parse the path
        let (view, rest) = StandardPathView::from_slice(&rpc_path.raw).map_err(|err| {
            FromRpcError::new(format!("failed to parse standard path from RPC: {err}"))
        })?;

        if !rest.is_empty() {
            return Err("RPC payload had extra data after parsing standard path".into());
        }

        let next_hop = rpc_path
            .interface
            .and_then(|intf| intf.address)
            .map(|addr| addr.address.parse())
            .transpose()
            .map_err(|err| {
                FromRpcError::new(format!("failed to parse next hop address from RPC: {err}"))
            })?;

        let path_meta = {
            let interface_count = rpc_path.interfaces.len();
            if interface_count == 0 || !interface_count.is_multiple_of(2) {
                return Err(format!(
                    "RPC payload had invalid number of interfaces: expected an even number greater than 0, got {interface_count}"
                ).into());
            }

            let mut interface_meta = rpc_path
                .interfaces
                .into_iter()
                .map(|intf| {
                    Ok(metadata::InterfaceMetadata {
                        interface: intf.try_into()?,
                        geo_info: None,
                        latency: None,
                        bandwidth: None,
                        link: None,
                    })
                })
                .collect::<Result<Vec<_>, FromRpcError>>()?;

            let expected_count_ases = interface_count / 2 + 1;
            let expected_count_links = interface_count - 1;
            let expected_count_links_intra = interface_count / 2 - 1;
            let expected_count_links_inter = interface_count / 2;

            let expiration: u64 = rpc_path
                .expiration
                .map(|ts| ts.seconds)
                .ok_or("RPC payload missing expiration timestamp")?
                .try_into()
                .map_err(|_| "RPC timestamp does not fit in u64")?;

            let mtu: u16 = rpc_path
                .mtu
                .try_into()
                .map_err(|_| "RPC MTU does not fit in u16")?;

            // Collect latencies if available, one per link (total_interfaces - 1) leaving out the
            // last interface which is the destination
            if rpc_path.latency.len() == expected_count_links {
                for (meta, latency) in interface_meta.iter_mut().zip(rpc_path.latency.into_iter()) {
                    meta.latency = Some(
                        latency
                            .try_into()
                            .map_err(|_| "Failed to convert latency")?,
                    );
                }
            }

            // Collect bandwidths if available, one per link (total_interfaces - 1) leaving out the
            // last interface which is the destination
            if rpc_path.bandwidth.len() == expected_count_links {
                for (meta, bandwidth) in interface_meta
                    .iter_mut()
                    .zip(rpc_path.bandwidth.into_iter())
                {
                    meta.bandwidth = Some(bandwidth);
                }
            }

            // Collect geo info if available, one per interface
            if rpc_path.geo.len() == interface_count {
                for (meta, geo_info) in interface_meta.iter_mut().zip(rpc_path.geo.into_iter()) {
                    meta.geo_info = Some(GeoCoordinates::from_rpc(geo_info));
                }
            }

            // Link Types
            // The path switches between intra-AS and inter-AS links every interface.
            // The first is always a inter-AS link, the second an intra-AS link, and so on.
            // We need to weave the rpc_path.link_type and rpc_path.interfaces together to assign
            // the correct link type to each interface.

            {
                // Inter-AS links are at the even indices (0, 2, 4, ...) of the interfaces
                let egress_iter = interface_meta.iter_mut().step_by(2);
                if rpc_path.link_type.len() == expected_count_links_inter {
                    for (egress_meta, link_type) in egress_iter.zip(rpc_path.link_type.into_iter())
                    {
                        egress_meta.link = Some(LinkMeta::Egress(link_type.into()));
                    }
                }
            }

            {
                // Intra-AS links are at the odd indices (1, 3, 5, ...) of the interfaces
                let ingress_iter = interface_meta.iter_mut().skip(1).step_by(2);
                if rpc_path.internal_hops.len() == expected_count_links_intra {
                    for (ingress_meta, internal_hops) in
                        ingress_iter.zip(rpc_path.internal_hops.into_iter())
                    {
                        ingress_meta.link = Some(LinkMeta::Ingress {
                            internal_hop_count: internal_hops,
                        });
                    }
                }
            }

            // collect notes if available, one per AS (total_interfaces / 2 + 1) leaving out the
            // links
            let notes = if rpc_path.notes.len() == expected_count_ases {
                Some(rpc_path.notes)
            } else {
                None
            };

            metadata::PathMetadata {
                expiration,
                mtu,
                interfaces: Some(interface_meta),
                epic_auth: None,
                notes,
            }
        };

        Ok(Self::new(
            src_ia,
            dst_ia,
            view.to_boxed().into(),
            Some(path_meta),
            next_hop,
        ))
    }
}
