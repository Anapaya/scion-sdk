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

use std::num::NonZeroU64;

use chrono::{DateTime, Duration, Utc};
use scion_protobuf::daemon::v1 as daemon_grpc;
use tracing::warn;

use super::{EpicAuths, PathParseError};
use crate::path::error::PathParseErrorKind;

pub mod linktype;
pub use linktype::LinkType;

pub mod geo;
pub use geo::GeoCoordinates;

pub mod path_interface;
pub use path_interface::PathInterface;

/// Metadata of SCION end-to-end paths.
///
/// Fields are set to `None` if unset or trying to convert an invalid value.
/// For vectors, individual entries are `None` if trying to convert an invalid value.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Metadata {
    /// The point in time when this path expires.
    pub expiration: DateTime<Utc>,
    /// The maximum transmission unit (MTU) on the path in bytes.
    pub mtu: u16,
    /// The list of interfaces the path is composed of.
    pub interfaces: Option<Vec<PathInterface>>,
    /// Latencies between any two consecutive interfaces.
    /// Entry i describes the latency between interface i and i+1.
    /// Consequently, there are N-1 entries for N interfaces.
    pub latency: Option<Vec<Option<Duration>>>,
    /// The bandwidth between any two consecutive interfaces, in kbps.
    /// Entry i describes the bandwidth between interfaces i and i+1.
    pub bandwidth_kbps: Option<Vec<Option<NonZeroU64>>>,
    /// Geographical position of the border routers along the path.
    /// Entry i describes the position of the router for interface i.
    pub geo: Option<Vec<Option<GeoCoordinates>>>,
    /// LinkType contains the announced link type of inter-domain links.
    /// Entry i describes the link between interfaces 2*i and 2*i+1.
    pub link_type: Option<Vec<LinkType>>,
    /// Number of AS-internal hops for the ASes on path.
    /// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same
    /// AS.
    /// Consequently, there are no entries for the first and last ASes, as these
    /// are not traversed completely by the path.
    /// One cannot distinguish between unset values and an explicit 0.
    pub internal_hops: Option<Vec<u32>>,
    /// Notes added by ASes on the path, in the order of occurrence.
    /// Entry i is the note of AS i on the path.
    pub notes: Option<Vec<String>>,
    /// Optional EPIC-HP authenticators used to calculate the PHVF and LHVF.
    pub epic_auths: Option<EpicAuths>,
}

macro_rules! some_if_length_matches {
    ($input_vec:expr, $expected_length:expr, $result:expr) => {
        if $input_vec.len() == $expected_length {
            Some($result)
        } else {
            None
        }
    };
    (($input_vec:expr, $expected_length:expr) => $($method:ident ($($param:expr),*)).*) => {
        some_if_length_matches!($input_vec, $expected_length, $input_vec.$($method ($($param),*)).*)
    };
    ($input_vec:expr, $expected_length:expr) => {
        some_if_length_matches!($input_vec, $expected_length, $input_vec)
    };
}

impl Metadata {
    /// Formats the interfaces of the path for human consumption
    ///
    /// Example: `"1-ff00:0:111 2>2 1-ff00:0:110 5>10 1-ff00:0:200"`
    ///
    /// If no interface data is available, `<no interface data>` is written.
    pub fn format_interfaces(&self, writer: &mut dyn std::fmt::Write) -> std::fmt::Result {
        match &self.interfaces {
            Some(interfaces) => {
                if interfaces.is_empty() {
                    write!(writer, "<empty interfaces>")?;
                    return Ok(());
                }

                if interfaces.len() != 1 && interfaces.len() % 2 != 0 {
                    // This is not a valid path, but we handle it anyway.
                    write!(writer, "<invalid path> ")?;
                }

                // first interface
                let first = &interfaces[0]; // Safety: we know there is at least one interface
                write!(writer, "{} {}", first.isd_asn, first.id)?;

                if interfaces.len() <= 1 {
                    // in case there is only one interface we are done
                    return Ok(());
                }

                write!(writer, ">")?;

                let mut had_final = false;
                // following interfaces
                for chunk in interfaces[1..interfaces.len()].chunks(2) {
                    match chunk {
                        [trav_in, trav_out] => {
                            match trav_in.isd_asn == trav_out.isd_asn {
                                true => {
                                    write!(
                                        writer,
                                        "{} {} {}>",
                                        trav_in.id, trav_in.isd_asn, trav_out.id
                                    )?
                                }
                                false => {
                                    write!(
                                        writer,
                                        "{} <invalid hop> ({}/{}) {}>",
                                        trav_in.id, trav_in.isd_asn, trav_out.isd_asn, trav_out.id
                                    )?;
                                }
                            }
                        }
                        [final_if] => {
                            write!(writer, "{} {}", final_if.id, final_if.isd_asn)?;
                            had_final = true;
                        }
                        _ => {}
                    }
                }

                if !had_final {
                    writer.write_str(" missing final hop")?;
                }
            }
            None => {
                write!(writer, "<no interface data>")?;
            }
        };
        Ok(())
    }
}

impl TryFrom<daemon_grpc::Path> for Metadata {
    type Error = PathParseError;

    #[tracing::instrument]
    fn try_from(grpc_path: daemon_grpc::Path) -> Result<Self, Self::Error> {
        // We check that the metadata is itself consistent, including the lengths of various
        // metadata vectors. We *do not* check if it is consistent with the raw data plane path.
        let count_interfaces = grpc_path.interfaces.len();
        if count_interfaces == 0 || count_interfaces % 2 != 0 {
            return Err(PathParseErrorKind::InvalidNumberOfInterfaces.into());
        }
        let expected_count_ases = count_interfaces / 2 + 1;
        let expected_count_links = count_interfaces - 1;
        let expected_count_links_intra = count_interfaces / 2 - 1;
        let expected_count_links_inter = count_interfaces / 2;

        let expiration = grpc_path
            .expiration
            .and_then(|t| DateTime::from_timestamp(t.seconds, t.nanos.try_into().ok()?))
            .ok_or(PathParseError::from(PathParseErrorKind::InvalidExpiration))?;

        let mtu = grpc_path
            .mtu
            .try_into()
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidMtu))?;

        let interfaces = grpc_path
            .interfaces
            .into_iter()
            .map(|i| i.try_into().map_err(|e| warn!("{}", e)).ok())
            .collect();

        let latency = some_if_length_matches!(
            (grpc_path.latency, expected_count_links) =>
                into_iter()
                .map(|d| {
                    Duration::seconds(d.seconds)
                        .checked_add(&Duration::nanoseconds(d.nanos.into()))
                        .filter(|d| d >= &Duration::zero())
                })
                .collect()
        );

        let bandwidth_kbps = some_if_length_matches!(
            (grpc_path.bandwidth, expected_count_links) =>
                into_iter()
                .map(NonZeroU64::new)
                .collect()
        );

        let geo = some_if_length_matches!(
            (grpc_path.geo, count_interfaces) =>
                into_iter()
                .map(GeoCoordinates::from_grpc_or_none)
                .collect()
        );

        let link_type = some_if_length_matches!(
            (grpc_path.link_type, expected_count_links_inter) =>
                into_iter()
                .map(LinkType::from)
                .collect()
        );

        let internal_hops =
            some_if_length_matches!(grpc_path.internal_hops, expected_count_links_intra);

        let notes = some_if_length_matches!(grpc_path.notes, expected_count_ases);

        let epic_auths = grpc_path.epic_auths.map(EpicAuths::from);

        Ok(Self {
            expiration,
            mtu,
            interfaces,
            latency,
            bandwidth_kbps,
            geo,
            link_type,
            internal_hops,
            notes,
            epic_auths,
        })
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub const MINIMAL_RAW_PATH: [u8; 24] = [
        0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    pub fn minimal_grpc_path() -> daemon_grpc::Path {
        daemon_grpc::Path {
            raw: MINIMAL_RAW_PATH.into(),
            interface: Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay {
                    address: "0.0.0.0:42".into(),
                }),
            }),
            expiration: Some(prost_types::Timestamp::default()),
            mtu: 0,
            interfaces: vec![daemon_grpc::PathInterface { isd_as: 0, id: 0 }; 2],
            latency: vec![],
            bandwidth: vec![],
            geo: vec![],
            link_type: vec![],
            internal_hops: vec![],
            notes: vec![],
            epic_auths: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use prost_types::Timestamp;

    use super::{test_utils::*, *};
    use crate::address::{Asn, Isd, IsdAsn};

    #[test]
    fn valid_values() {
        assert_eq!(
            Metadata::try_from(daemon_grpc::Path {
                expiration: Some(prost_types::Timestamp::date(2023, 11, 22).expect("valid date")),
                mtu: 1472,
                interfaces: vec![
                    daemon_grpc::PathInterface {
                        isd_as: 281_474_976_710_698,
                        id: 42
                    },
                    daemon_grpc::PathInterface {
                        isd_as: 281_474_976_710_699,
                        id: 1
                    },
                    daemon_grpc::PathInterface {
                        isd_as: 281_474_976_710_699,
                        id: 2
                    },
                    daemon_grpc::PathInterface {
                        isd_as: 11_821_949_021_847_553,
                        id: 314
                    }
                ],
                latency: vec![
                    prost_types::Duration {
                        seconds: 3,
                        nanos: 14
                    },
                    prost_types::Duration {
                        seconds: 0,
                        nanos: 0
                    },
                    prost_types::Duration {
                        seconds: 0,
                        nanos: 42
                    }
                ],
                bandwidth: vec![1000, 2000, 3000],
                geo: vec![
                    daemon_grpc::GeoCoordinates {
                        latitude: 47.37,
                        longitude: 8.55,
                        address: "Zurich".into()
                    };
                    4
                ],
                link_type: vec![2, 1],
                internal_hops: vec![1],
                notes: vec!["AS1".into(), "AS2".into(), "AS3".into()],
                epic_auths: Some(daemon_grpc::EpicAuths {
                    auth_phvf: vec![0; 24],
                    auth_lhvf: vec![1; 24],
                }),
                ..minimal_grpc_path()
            }),
            Ok(Metadata {
                expiration: DateTime::<Utc>::from_str("2023-11-22T00:00:00Z").expect("valid date"),
                mtu: 1472,
                interfaces: Some(vec![
                    PathInterface {
                        isd_asn: IsdAsn::new(Isd::new(1), Asn::new(42)),
                        id: 42,
                    },
                    PathInterface {
                        isd_asn: IsdAsn::new(Isd::new(1), Asn::new(43)),
                        id: 1,
                    },
                    PathInterface {
                        isd_asn: IsdAsn::new(Isd::new(1), Asn::new(43)),
                        id: 2,
                    },
                    PathInterface {
                        isd_asn: IsdAsn::new(Isd::new(42), Asn::new(1)),
                        id: 314,
                    }
                ]),
                latency: Some(vec![
                    Some(
                        Duration::seconds(3)
                            .checked_add(&Duration::nanoseconds(14))
                            .expect("valid duration")
                    ),
                    Some(Duration::zero()),
                    Some(Duration::nanoseconds(42)),
                ]),
                bandwidth_kbps: Some(vec![
                    NonZeroU64::new(1000),
                    NonZeroU64::new(2000),
                    NonZeroU64::new(3000)
                ]),
                geo: Some(vec![
                    Some(GeoCoordinates {
                        lat: 47.37,
                        long: 8.55,
                        address: "Zurich".into()
                    });
                    4
                ]),
                link_type: Some(vec![LinkType::MultiHop, LinkType::Direct]),
                internal_hops: Some(vec![1]),
                notes: Some(vec!["AS1".into(), "AS2".into(), "AS3".into()]),
                epic_auths: Some(EpicAuths {
                    phvf: Bytes::from_static(&[0; 24]),
                    lhvf: Bytes::from_static(&[1; 24]),
                }),
            })
        )
    }

    #[test]
    fn unset_values() {
        assert_eq!(
            Metadata::try_from(daemon_grpc::Path {
                interfaces: vec![
                    daemon_grpc::PathInterface {
                        isd_as: 0,
                        id: u64::from(u16::MAX) + 1
                    };
                    4
                ],
                latency: vec![
                    prost_types::Duration {
                        seconds: 0,
                        nanos: -1
                    };
                    3
                ],
                bandwidth: vec![0; 3],
                geo: vec![daemon_grpc::GeoCoordinates::default(); 4],
                link_type: vec![0, -1],
                internal_hops: vec![0],
                ..minimal_grpc_path()
            }),
            Ok(Metadata {
                interfaces: None,
                latency: Some(vec![None; 3]),
                bandwidth_kbps: Some(vec![None; 3]),
                geo: Some(vec![None; 4]),
                link_type: Some(vec![LinkType::Unset, LinkType::Invalid]),
                internal_hops: Some(vec![0]),
                ..Metadata::default()
            })
        )
    }

    macro_rules! test_invalid_metadata {
        ($name:ident; $($field:ident : $value:expr),*; $error_type:expr) => {
            #[test]
            fn $name() {
                assert_eq!(Metadata::try_from(daemon_grpc::Path {
                    $($field : $value,)*
                    ..minimal_grpc_path()
                }), Err($error_type.into()))
            }
        };
    }

    test_invalid_metadata!(
        empty_interfaces;
        interfaces: vec![];
        PathParseErrorKind::InvalidNumberOfInterfaces
    );
    test_invalid_metadata!(
        single_interfaces;
        interfaces: vec![daemon_grpc::PathInterface{ isd_as: 0, id: 0 }];
        PathParseErrorKind::InvalidNumberOfInterfaces
    );
    test_invalid_metadata!(
        missing_mtu;
        mtu: u32::from(u16::MAX) + 1;
        PathParseErrorKind::InvalidMtu
    );
    test_invalid_metadata!(
        missing_expiration;
        expiration: None;
        PathParseErrorKind::InvalidExpiration
    );
    test_invalid_metadata!(
        negative_expiration_nanos;
        expiration: Some(Timestamp{ seconds: 0, nanos: -1 });
        PathParseErrorKind::InvalidExpiration
    );
    test_invalid_metadata!(
        invalid_expiration;
        expiration: Some(Timestamp{ seconds: i64::MAX, nanos: 0 });
        PathParseErrorKind::InvalidExpiration
    );

    mod macro_tests {
        #[test]
        fn correct_length_without_method() {
            assert_eq!(some_if_length_matches!(vec![0; 2], 2), Some(vec![0; 2]));
        }

        #[test]
        fn correct_length_with_method() {
            assert_eq!(
                some_if_length_matches!(
                    (vec![0; 2], 2) => into_iter().map(|x| x+1).collect()
                ),
                Some(vec![1; 2])
            );
        }

        #[test]
        fn incorrect_length() {
            assert!(some_if_length_matches!(vec![0; 2], 1).is_none());
        }

        #[test]
        fn incorrect_length_with_method() {
            assert!(
                some_if_length_matches!(
                    (vec![0; 2], 1) => into_iter()
                )
                .is_none()
            );
        }
    }

    mod format_test {
        use super::*;

        #[test]
        fn should_format_interfaces() {
            let cases = vec![
                (0, "<empty interfaces>"),
                (1, "0-0 10"),
                (2, "0-0 10>11 1-1"),
                (3, "<invalid path> 0-0 10>11 1-1 12> missing final hop"),
                (4, "0-0 10>11 1-1 12>13 2-2"),
                (6, "0-0 10>11 1-1 12>13 2-2 14>15 3-3"),
                (8, "0-0 10>11 1-1 12>13 2-2 14>15 3-3 16>17 4-4"),
            ];

            for (n, expected) in cases {
                let interfaces: Vec<_> = (0..n)
                    .map(|i| {
                        let offset_i = i + 1;
                        PathInterface {
                            isd_asn: IsdAsn::new(
                                Isd::new((offset_i / 2) as u16),
                                Asn::new((offset_i / 2) as u64),
                            ),
                            id: i as u16 + 10,
                        }
                    })
                    .collect();

                let mut output = String::new();
                let meta = Metadata {
                    interfaces: Some(interfaces),
                    ..Default::default()
                };

                meta.format_interfaces(&mut output).unwrap();
                assert_eq!(output, expected, "Unexpected format at test with n={n}");
            }
        }

        #[test]
        fn should_format_not_matching_as() {
            let interfaces = vec![
                PathInterface {
                    isd_asn: IsdAsn::new(Isd::new(1), Asn::new(42)),
                    id: 10,
                },
                PathInterface {
                    isd_asn: IsdAsn::new(Isd::new(1), Asn::new(43)),
                    id: 11,
                },
                // This hop is invalid, different ASes
                PathInterface {
                    isd_asn: IsdAsn::new(Isd::new(2), Asn::new(1)),
                    id: 12,
                },
                PathInterface {
                    isd_asn: IsdAsn::new(Isd::new(2), Asn::new(1)),
                    id: 13,
                },
            ];

            let mut output = String::new();
            let meta = Metadata {
                interfaces: Some(interfaces),
                ..Default::default()
            };

            meta.format_interfaces(&mut output).unwrap();
            assert_eq!(output, "1-42 10>11 <invalid hop> (1-43/2-1) 12>13 2-1");
        }
    }
}
