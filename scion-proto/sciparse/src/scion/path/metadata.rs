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

//! SCION control plane path metadata

use std::time::Duration;

use crate::path::metadata::{link::LinkMeta, path_interface::PathInterface};

/// Metadata about a path, including expiration time, MTU, and optionally the interfaces used by
/// the path.
#[derive(Debug, Clone, PartialEq)]
pub struct PathMetadata {
    /// Unix epoch in seconds after which the path is considered expired. As supplied by the
    /// control plane
    pub expiration: u64,
    /// Maximum Transmission Unit of the path in bytes.
    pub mtu: u16,
    /// Metadata about the interfaces used by this path.
    pub interfaces: Option<Vec<InterfaceMetadata>>,
    /// EPIC path authentication info for the path.
    pub epic_auth: Option<epic::EpicAuths>,
    /// Optional notes added by ASes along the path. The i-th note corresponds to the i-th AS along
    /// the path.
    pub notes: Option<Vec<String>>,
}

impl PathMetadata {
    /// Creates a new [PathMetadata] instance without any optional metadata.
    ///
    /// # Parameters
    /// - `expiration`: Unix epoch in seconds after which the path is considered expired.
    /// - `mtu`: Maximum Transmission Unit of the path in bytes.
    /// - `interfaces`: List of interfaces used by this path.
    pub fn new_minimal(expiration: u64, mtu: u16, interfaces: Vec<PathInterface>) -> Self {
        Self {
            expiration,
            mtu,
            interfaces: Some(
                interfaces
                    .into_iter()
                    .map(InterfaceMetadata::new_without_metadata)
                    .collect(),
            ),
            epic_auth: None,
            notes: None,
        }
    }
}

/// Metadata about an interface used in a path.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceMetadata {
    /// Interface used by this path
    pub interface: PathInterface,
    /// Geographic information about the location of the interface.
    pub geo_info: Option<geo::GeoCoordinates>,
    /// Latency to the next interface.
    pub latency: Option<Duration>,
    /// Bandwidth to the next interface in kilobits per second.
    pub bandwidth: Option<u64>,
    /// Type of the link to the next interface.
    pub link: Option<LinkMeta>,
}

impl InterfaceMetadata {
    /// Creates a new [InterfaceMetadata] instance without any optional metadata.
    pub fn new_without_metadata(interface: PathInterface) -> Self {
        Self {
            interface,
            geo_info: None,
            latency: None,
            bandwidth: None,
            link: None,
        }
    }
}

/// EPIC authentication information for a path hop, including the penultimate and last hop
/// validation keys.
pub mod epic {
    use crate::core::macros::impl_from;

    /// EPIC authentication information for a path hop, including the penultimate and last hop
    /// validation keys.
    ///
    /// EPIC authentication is not yet supported by SciParse
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct EpicAuths {
        /// Key to compute the penultimate hop validation field
        pub phop_authenticator: Vec<u8>,
        /// Key to compute the last hop validation field
        pub lhop_authenticator: Vec<u8>,
    }

    impl EpicAuths {
        /// Creates a new [EpicAuths] instance.
        pub fn new(p_hop_validation_key: Vec<u8>, last_hop_validation_key: Vec<u8>) -> Self {
            Self {
                phop_authenticator: p_hop_validation_key,
                lhop_authenticator: last_hop_validation_key,
            }
        }

        /// Creates a new [EpicAuths] instance from a protobuf message.
        pub fn from_rpc(value: scion_protobuf::daemon::v1::EpicAuths) -> Self {
            Self {
                phop_authenticator: value.auth_phvf,
                lhop_authenticator: value.auth_lhvf,
            }
        }

        /// Converts this [EpicAuths] instance into a protobuf message.
        pub fn into_rpc(&self) -> scion_protobuf::daemon::v1::EpicAuths {
            scion_protobuf::daemon::v1::EpicAuths {
                auth_phvf: self.phop_authenticator.clone(),
                auth_lhvf: self.lhop_authenticator.clone(),
            }
        }
    }
    impl_from!(scion_protobuf::daemon::v1::EpicAuths, EpicAuths, |v| {
        EpicAuths::from_rpc(v)
    });
    impl_from!(EpicAuths, scion_protobuf::daemon::v1::EpicAuths, |v| {
        v.into_rpc()
    });
}

/// Geographic coordinates of a location, including latitude, longitude, and an optional
/// human-readable address.
pub mod geo {
    use crate::core::macros::impl_from;

    /// Geographic coordinates of a location, including latitude, longitude, and an optional
    /// human-readable address.
    #[derive(Debug, Clone, PartialEq)]
    pub struct GeoCoordinates {
        /// Latitude of the geographic coordinate, in the WGS 84 datum.
        pub latitude: f32,
        /// Longitude of the geographic coordinate, in the WGS 84 datum.
        pub longitude: f32,
        /// Human Readable address of the location, e.g., "Zurich, Switzerland"
        pub address: Option<String>,
    }
    impl GeoCoordinates {
        /// Creates a new [GeoCoordinates] instance.
        pub fn new(latitude: f32, longitude: f32, address: Option<String>) -> Self {
            Self {
                latitude,
                longitude,
                address,
            }
        }

        /// Creates a new [GeoCoordinates] instance from a protobuf message.
        pub fn from_rpc(value: scion_protobuf::daemon::v1::GeoCoordinates) -> Self {
            let address = match value.address.is_empty() {
                false => Some(value.address),
                true => None,
            };

            Self {
                latitude: value.latitude,
                longitude: value.longitude,
                address,
            }
        }

        /// Converts this [GeoCoordinates] instance into a protobuf message.
        pub fn into_rpc(&self) -> scion_protobuf::daemon::v1::GeoCoordinates {
            scion_protobuf::daemon::v1::GeoCoordinates {
                latitude: self.latitude,
                longitude: self.longitude,
                address: self.address.clone().unwrap_or_default(),
            }
        }
    }
    impl_from!(
        scion_protobuf::daemon::v1::GeoCoordinates,
        GeoCoordinates,
        |v| GeoCoordinates::from_rpc(v)
    );
    impl_from!(
        GeoCoordinates,
        scion_protobuf::daemon::v1::GeoCoordinates,
        |v| v.into_rpc()
    );
}

/// An interface used in a path, identified by owning ISD-AS and interfaces ID.
pub mod path_interface {
    use crate::{core::macros::impl_from, identifier::isd_asn::IsdAsn, rpc::FromRpcError};

    /// An interface used in a path, identified by owning ISD-AS and interfaces ID.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PathInterface {
        /// The ISD-AS of this interface.
        pub isd_asn: IsdAsn,
        /// The ID of the interface within the AS.
        pub id: u16,
    }
    impl PathInterface {
        /// Creates a new [PathInterface] instance.
        pub fn new(isd_asn: IsdAsn, interface_id: u16) -> Self {
            Self {
                isd_asn,
                id: interface_id,
            }
        }

        /// Creates a new [PathInterface] instance from a protobuf message.
        pub fn from_rpc(
            value: scion_protobuf::daemon::v1::PathInterface,
        ) -> Result<Self, FromRpcError> {
            Ok(Self {
                isd_asn: value.isd_as.into(),
                id: value
                    .id
                    .try_into()
                    .map_err(|_| "interface_id exceeds u16 range")?,
            })
        }

        /// Converts this [PathInterface] instance into a protobuf message.
        pub fn into_rpc(&self) -> scion_protobuf::daemon::v1::PathInterface {
            scion_protobuf::daemon::v1::PathInterface {
                isd_as: self.isd_asn.into(),
                id: self.id as u64,
            }
        }
    }
    impl_from!(
        PathInterface,
        scion_protobuf::daemon::v1::PathInterface,
        |v| v.into_rpc()
    );
    impl TryFrom<scion_protobuf::daemon::v1::PathInterface> for PathInterface {
        type Error = FromRpcError;

        fn try_from(value: scion_protobuf::daemon::v1::PathInterface) -> Result<Self, Self::Error> {
            Self::from_rpc(value)
        }
    }
}

/// The type of an inter-domain link based on the underlay connection.
pub mod link {
    use crate::core::macros::impl_from;

    /// Metadata about a link used in a path
    #[derive(Debug, Clone, PartialEq)]
    pub enum LinkMeta {
        /// The route to the next hop is internal to the AS
        Ingress {
            /// How many hops the route to the next hop takes within the AS. This is a hint about
            /// the "distance" to the next Interface.
            ///
            /// These hops are not visible in the dataplane path and are not relevant for
            /// forwarding, but can be used for path selection and performance estimation.
            internal_hop_count: u32,
        },
        /// The route to the next hop leaves the AS through an inter-domain link with the given
        /// type.
        Egress(LinkType),
    }

    /// The type of an inter-domain link based on the underlay connection.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
    #[repr(i32)]
    pub enum LinkType {
        /// Unspecified.
        #[default]
        Unset = 0,
        /// Direct physical connection.
        Direct = 1,
        /// Connection with local routing/switching.
        MultiHop = 2,
        /// Connection overlaid over publicly routed Internet.
        OpenNet = 3,
        /// Unknown link type.
        Unknown(u8),
    }
    impl LinkType {
        /// Creates a [LinkType] from an i32 value
        pub fn from_i32(value: i32) -> Self {
            match value {
                0 => Self::Unset,
                1 => Self::Direct,
                2 => Self::MultiHop,
                3 => Self::OpenNet,
                _ => Self::Unknown(value as u8),
            }
        }

        /// Converts the [LinkType] to an i32 value
        pub fn to_i32(&self) -> i32 {
            match self {
                Self::Unset => 0,
                Self::Direct => 1,
                Self::MultiHop => 2,
                Self::OpenNet => 3,
                Self::Unknown(v) => *v as i32,
            }
        }
    }
    impl_from!(i32, LinkType, |v| LinkType::from_i32(v));
    impl_from!(LinkType, i32, |v| v.to_i32());
}
