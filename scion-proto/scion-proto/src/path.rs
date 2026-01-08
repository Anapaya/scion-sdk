// Copyright 2025 Mysten Labs
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

//! SCION path types.
//!
//! This module contains types for SCION paths and metadata as well as encoding and decoding
//! functions.
//!
//! # Organisation
//!
//! - [`Path`] is the primary path type used with SCION sockets and applications. It encapsulates a
//!   [datplane path][DataPlanePath] along with optional metadata about that path, such as its
//!   source and destination ASes, next hop on the SCION underlay, expiry time, and interface hops.
//!
//! - [`Metadata`] is metadata about a SCION [`Path`] that is communicated during beaconing or
//!   parsed from the path.
//!
//! - [`DataPlanePath`] represents the various SCION paths that be placed within a SCION packet, and
//!   sent on the network. Currently, only the empty and standard SCION datplane path types are
//!   supported (see [`standard`]).
//!
//! - [`StandardPath`] is a structure representation of a SCION path that can be used to create or
//!   modify SCION paths.

use std::{net::SocketAddr, ops::Deref};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use scion_protobuf::daemon::v1 as daemon_grpc;
use tracing::warn;

use crate::{address::IsdAsn, packet::ByEndpoint, wire_encoding::WireDecode};

mod error;
pub use error::{DataPlanePathErrorKind, PathParseError, PathParseErrorKind};

mod data_plane;
pub use data_plane::{DataPlanePath, PathType, UnsupportedPathType};

pub mod standard;
pub use standard::*;

pub mod segment;
pub use segment::*;

pub mod encoded;
pub use encoded::*;

pub mod convert;

pub mod epic;
pub use epic::EpicAuths;

pub mod combinator;
pub mod policy;

mod fingerprint;
pub use fingerprint::{FingerprintError, PathFingerprint};

mod dataplane_fingerprint;
pub use dataplane_fingerprint::DataPlanePathFingerprint;

mod metadata;
pub use metadata::{GeoCoordinates, LinkType, Metadata, PathInterface};

mod meta_header;
pub use meta_header::{HopFieldIndex, InfoFieldIndex, MetaHeader, MetaReserved, SegmentLength};

pub mod crypto;
pub mod test_builder;

/// Minimum MTU along any path or within any AS.
pub const PATH_MIN_MTU: u16 = 1280;

/// A SCION end-to-end path with optional metadata.
///
/// `Path`s are generic over the underlying representation used by the [`DataPlanePath`]. By
/// default, this is a [`Bytes`] object which allows relatively cheap copying of the overall path
/// as the Path data can then be shared across several `Path` instances.
#[derive(Clone)]
pub struct Path<T = Bytes> {
    /// The raw bytes to be added as the path header to SCION data plane packets.
    pub data_plane_path: DataPlanePath<T>,
    /// The underlay address (IP + port) of the next hop; i.e., the local border router.
    pub underlay_next_hop: Option<SocketAddr>,
    /// The ISD-ASN where the path starts and ends.
    pub isd_asn: ByEndpoint<IsdAsn>,
    /// Path metadata.
    pub metadata: Option<Metadata>,
}

impl<T> std::fmt::Debug for Path<T>
where
    T: Deref<Target = [u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.data_plane_path {
            DataPlanePath::EmptyPath => {
                write!(
                    f,
                    "EmptyPath: {} -> {}",
                    self.isd_asn.source, self.isd_asn.destination
                )
            }
            DataPlanePath::Unsupported { .. } => {
                write!(
                    f,
                    "UnsupportedPath: {} -> {}",
                    self.isd_asn.source, self.isd_asn.destination
                )
            }
            DataPlanePath::Standard(_) => {
                if let Some(metadata) = &self.metadata {
                    write!(f, "StandardPath Hops: ")?;
                    metadata.format_interfaces(f)?;
                    write!(f, " MTU: {}", metadata.mtu)
                } else {
                    write!(
                        f,
                        "StandardPath: {} -> {} (no metadata)",
                        self.isd_asn.source, self.isd_asn.destination
                    )
                }
            }
        }
    }
}

impl<T> Path<T>
where
    T: Deref<Target = [u8]>,
{
    /// Creates a new `Path` instance with the provided data plane path, its endpoints, and the
    /// next hop in the network underlay, but with no metadata.
    pub fn new(
        data_plane_path: DataPlanePath<T>,
        isd_asn: ByEndpoint<IsdAsn>,
        underlay_next_hop: Option<SocketAddr>,
    ) -> Self {
        Self {
            data_plane_path,
            underlay_next_hop,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns a path for sending packets within the specified AS.
    ///
    /// # Panics
    ///
    /// Panics if the AS is a wildcard AS.
    pub fn local(isd_asn: IsdAsn) -> Self {
        assert!(!isd_asn.is_wildcard(), "no local path for wildcard AS");

        Self {
            data_plane_path: DataPlanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn: ByEndpoint::with_cloned(isd_asn),
            metadata: Some(Metadata {
                expiration: DateTime::<Utc>::MAX_UTC,
                mtu: PATH_MIN_MTU,
                interfaces: None,
                ..Metadata::default()
            }),
        }
    }

    /// Returns the source of this path.
    pub const fn source(&self) -> IsdAsn {
        self.isd_asn.source
    }

    /// Returns the destination of this path.
    pub const fn destination(&self) -> IsdAsn {
        self.isd_asn.destination
    }

    /// Creates a new empty path with the provided source and destination ASes.
    ///
    /// For creating an empty, AS-local path see [`local()`][Self::local] instead.
    pub fn empty(isd_asn: ByEndpoint<IsdAsn>) -> Self {
        Self {
            data_plane_path: DataPlanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns true iff the data plane path is an empty path.
    pub fn is_empty(&self) -> bool {
        self.data_plane_path.is_empty()
    }

    /// Returns a fingerprint of the path.
    ///
    /// See [`PathFingerprint`] for more details.
    pub fn fingerprint(&self) -> Result<PathFingerprint, FingerprintError> {
        PathFingerprint::try_from(self)
    }

    /// Returns a fingerprint based on the dataplane path.
    ///
    /// Different from [`PathFingerprint`], this can be computed, even if
    /// no metadata is present.
    ///
    /// See [`DataPlanePathFingerprint`] for more details.
    pub fn data_plane_fingerprint(&self) -> DataPlanePathFingerprint {
        DataPlanePathFingerprint::new(self)
    }

    /// Returns the expiry time of the path if the path hop fields, otherwise None.
    pub fn expiry_time(&self) -> Option<DateTime<Utc>> {
        // First check the metadata, if it exists.
        if let Some(metadata) = &self.metadata {
            return Some(metadata.expiration);
        }
        // If no metadata exists, calculate it from the data plane path.
        match &self.data_plane_path {
            DataPlanePath::EmptyPath => None,
            DataPlanePath::Standard(path) => Some(path.expiry_time()),
            DataPlanePath::Unsupported { .. } => None,
        }
    }

    /// Returns true if the path contains an expiry time, and it is after now,
    /// false if the contained expiry time is at or before now, and None if the path
    /// does not contain an expiry time.
    pub fn is_expired(&self, now: DateTime<Utc>) -> Option<bool> {
        self.expiry_time().map(|t| t <= now)
    }

    /// Sets the expiry time of the path.
    pub fn set_expiration(&mut self, expiration: DateTime<Utc>) {
        self.metadata = Some(Metadata {
            expiration,
            ..self.metadata.take().unwrap_or_default()
        });
    }

    /// Returns the number of interfaces traversed by the path, if available. Otherwise None.
    pub fn interface_count(&self) -> Option<usize> {
        self.metadata
            .as_ref()
            .and_then(|i| i.interfaces.as_ref().map(|intfs| intfs.len()))
    }

    /// Returns the first hop egress interface of the path, if available.
    pub fn first_hop_egress_interface(&self) -> Option<PathInterface> {
        match self
            .metadata
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|intfs| intfs.first())
        {
            Some(intf) => Some(*intf),
            None => {
                // Extract from data plane path if possible
                match &self.data_plane_path {
                    DataPlanePath::Standard(path) => {
                        let info = path.info_fields().next()?;
                        let hf = path.hop_fields().next()?;
                        Some(PathInterface::new(
                            self.source(),
                            hf.egress_interface(info)?.into(),
                        ))
                    }
                    _ => None,
                }
            }
        }
    }

    /// Returns the last hop ingress interface of the path, if available.
    pub fn last_hop_ingress_interface(&self) -> Option<PathInterface> {
        match self
            .metadata
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|intfs| intfs.iter().next_back())
        {
            Some(intf) => Some(*intf),
            None => {
                // Extract from data plane path if possible
                match &self.data_plane_path {
                    DataPlanePath::Standard(path) => {
                        let info = path.info_fields().next_back()?;
                        let hf = path.hop_fields().next_back()?;
                        Some(PathInterface::new(
                            self.destination(),
                            hf.ingress_interface(info)?.into(),
                        ))
                    }
                    _ => None,
                }
            }
        }
    }
}

impl<T> Path<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns a new `Path` reversing `data_plane_path` and `isd_asn`
    /// using given `buf` as backing storage for the `data_plane_path`
    ///
    /// # Panics
    ///
    /// Panics if `buf` has insufficient length. This can be prevented by ensuring a buffer size
    /// of at least [`DataPlanePath::MAX_LEN`].
    pub fn reverse_to_slice(self, buf: &mut [u8]) -> Path<&mut [u8]> {
        let path_len = self.data_plane_path.raw().len();
        let data_plane_path = self.data_plane_path.reverse_to_slice(&mut buf[..path_len]);

        Path::new(
            data_plane_path,
            self.isd_asn.into_reversed(),
            self.underlay_next_hop,
        )
    }

    /// Returns a new `Path` reversing `data_plane_path` and `isd_asn`
    pub fn to_reversed(&self) -> Result<Path, UnsupportedPathType> {
        Ok(Path::new(
            self.data_plane_path.to_reversed()?,
            self.isd_asn.into_reversed(),
            self.underlay_next_hop,
        ))
    }
}

impl Path<Bytes> {
    /// Attempts to parse the GRPC representation of a path into a [`Path`].
    #[tracing::instrument]
    pub fn try_from_grpc(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let mut data_plane_path = Bytes::from(std::mem::take(&mut value.raw));
        if data_plane_path.is_empty() {
            return if isd_asn.are_equal() && isd_asn.destination.is_wildcard() {
                Ok(Path::empty(isd_asn))
            } else if isd_asn.are_equal() {
                Ok(Path::local(isd_asn.destination))
            } else {
                Err(PathParseErrorKind::EmptyRaw.into())
            };
        };
        let data_plane_path = encoded::EncodedStandardPath::decode(&mut data_plane_path)
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidRaw))?
            .into();

        let underlay_next_hop = match &value.interface {
            Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay { address }),
            }) => {
                address
                    .parse()
                    .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidInterface))?
            }
            // TODO: Determine if the daemon returns paths that are strictly on the host.
            // If so, this is only an error if the path is non-empty
            _ => return Err(PathParseErrorKind::NoInterface.into()),
        };
        let underlay_next_hop = Some(underlay_next_hop);

        let metadata = Metadata::try_from(value)
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        Ok(Self {
            data_plane_path,
            underlay_next_hop,
            isd_asn,
            metadata,
        })
    }

    /// Creates a new Path using the given path's bytes as backing storage
    pub fn to_slice_path(&self) -> Path<&[u8]> {
        Path {
            data_plane_path: self.data_plane_path.to_slice_path(),
            underlay_next_hop: self.underlay_next_hop,
            isd_asn: self.isd_asn,
            metadata: self.metadata.clone(),
        }
    }
}

impl<T: AsRef<[u8]>> Path<T> {
    /// Transforms the path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> Path<Bytes> {
        Path {
            data_plane_path: self.data_plane_path.to_bytes_path(),
            underlay_next_hop: self.underlay_next_hop,
            isd_asn: self.isd_asn,
            metadata: self.metadata.clone(),
        }
    }
}

impl<T> PartialEq for Path<T>
where
    T: Deref<Target = [u8]>,
{
    fn eq(&self, other: &Self) -> bool {
        self.data_plane_path == other.data_plane_path
            && self.underlay_next_hop == other.underlay_next_hop
            && self.isd_asn == other.isd_asn
            && self.metadata == other.metadata
    }
}

impl<T> std::fmt::Display for Path<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src:{}, dst:{}, next hop: {}, path: ",
            self.isd_asn.source,
            self.isd_asn.destination,
            self.underlay_next_hop
                .map_or_else(|| "none".to_string(), |a| a.to_string()),
        )?;

        match self.metadata.as_ref() {
            Some(meta) => meta.format_interfaces(f)?,
            None => write!(f, "<no metadata>")?,
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::path::metadata::{PathInterface, test_utils::*};

    #[test]
    fn successful_empty_path() {
        let path = Path::try_from_grpc(
            daemon_grpc::Path {
                raw: vec![],
                ..minimal_grpc_path()
            },
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert!(path.underlay_next_hop.is_none());
        assert!(path.metadata.is_none());
        assert!(path.data_plane_path.is_empty());
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
    }

    #[test]
    fn successful_conversion() {
        let path = Path::try_from_grpc(
            minimal_grpc_path(),
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert_eq!(
            path.underlay_next_hop.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 42)
        );
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
        assert_eq!(
            path.metadata,
            Some(Metadata {
                interfaces: Some(vec![
                    PathInterface {
                        isd_asn: IsdAsn::WILDCARD,
                        id: 0,
                    };
                    2
                ]),
                internal_hops: Some(vec![]),
                ..Default::default()
            })
        );
    }

    macro_rules! test_conversion_failure {
        ($name:ident; $($field:ident : $value:expr),* ; $error:expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Path::try_from_grpc(
                        daemon_grpc::Path {
                            $($field : $value,)*
                            ..minimal_grpc_path()
                        },
                        ByEndpoint {
                            source: "1-1".parse().unwrap(),
                            destination: "1-2".parse().unwrap(),
                        },
                    ),
                    Err($error)
                )
            }
        };
    }

    test_conversion_failure!(
        empty_raw_path_different_ases;
        raw: vec![];
        PathParseErrorKind::EmptyRaw.into()
    );
    test_conversion_failure!(no_interface; interface: None; PathParseErrorKind::NoInterface.into());
    test_conversion_failure!(
        invalid_interface;
        interface: Some(daemon_grpc::Interface {
            address: Some(daemon_grpc::Underlay {
                address: "invalid address".into(),
            }),
        });
        PathParseErrorKind::InvalidInterface.into()
    );
}
