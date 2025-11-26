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

use std::str::FromStr;

use scion_protobuf::daemon::v1 as daemon_grpc;

use crate::{
    address::{AddressParseError, IsdAsn},
    path::{PathParseError, PathParseErrorKind},
};

/// SCION interface with the AS's ISD-ASN and the interface's ID.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct PathInterface {
    /// The ISD-ASN of the AS where the interface is located
    pub isd_asn: IsdAsn,
    /// The AS-local interface ID
    pub id: u16,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PathInterfaceParseError {
    #[error("invalid ISD-ASN")]
    IsdAsn(#[from] AddressParseError),
    #[error("invalid interface ID")]
    InterfaceId(#[from] std::num::ParseIntError),
    #[error("invalid delimiter, expected exactly one '#'")]
    Delimiter,
}

impl FromStr for PathInterface {
    type Err = PathInterfaceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (isd_asn, id) = s
            .split_once('#')
            .ok_or(PathInterfaceParseError::Delimiter)?;
        Ok(PathInterface {
            isd_asn: IsdAsn::try_from(isd_asn.to_string())?,
            id: id.parse()?,
        })
    }
}

impl TryFrom<daemon_grpc::PathInterface> for PathInterface {
    type Error = PathParseError;

    fn try_from(i: daemon_grpc::PathInterface) -> Result<Self, Self::Error> {
        u16::try_from(i.id)
            .map(|id| {
                PathInterface {
                    isd_asn: IsdAsn::from(i.isd_as),
                    id,
                }
            })
            .map_err(|_| PathParseErrorKind::InvalidPathInterface.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value() {
        assert_eq!(
            Ok(PathInterface {
                isd_asn: IsdAsn::WILDCARD,
                id: 0
            }),
            daemon_grpc::PathInterface { isd_as: 0, id: 0 }.try_into()
        );
    }

    #[test]
    fn id_out_of_range() {
        assert_eq!(
            PathInterface::try_from(daemon_grpc::PathInterface {
                isd_as: 0,
                id: u16::MAX as u64 + 1
            }),
            Err(PathParseError::from(
                PathParseErrorKind::InvalidPathInterface
            ))
        )
    }
}
