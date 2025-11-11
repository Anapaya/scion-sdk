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

use core::net;
use std::fmt::Display;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    address::{AddressKind, AddressParseError, IsdAsn, ScionAddr, ScionAddrV4, ScionAddrV6},
    packet::AddressInfo,
};

/// A SCION endhost address where the host address is either an IPv4 or IPv6
/// address. In particular, no service addresses are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum EndhostAddr {
    /// An IPv4 SCION host address
    V4(ScionAddrV4),
    /// An IPv6 SCION host address
    V6(ScionAddrV6),
}

impl Display for EndhostAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.isd_asn(), self.local_address())
    }
}

impl EndhostAddr {
    /// Creates a new SCION endhost address.
    pub const fn new(isd_asn: IsdAsn, host: net::IpAddr) -> Self {
        match host {
            net::IpAddr::V4(host) => Self::V4(ScionAddrV4::new(isd_asn, host)),
            net::IpAddr::V6(host) => Self::V6(ScionAddrV6::new(isd_asn, host)),
        }
    }

    /// Returns the local address.
    pub const fn local_address(&self) -> net::IpAddr {
        match self {
            Self::V4(addr) => net::IpAddr::V4(*addr.host()),
            Self::V6(addr) => net::IpAddr::V6(*addr.host()),
        }
    }

    /// Returns the ISD-AS number.
    pub const fn isd_asn(&self) -> IsdAsn {
        match self {
            Self::V4(addr) => addr.isd_asn(),
            Self::V6(addr) => addr.isd_asn(),
        }
    }

    /// Set the host address.
    pub fn set_host(&mut self, host: net::IpAddr) {
        *self = Self::new(self.isd_asn(), host);
    }

    /// Set the ISD-AS number.
    pub fn set_isd_asn(&mut self, isd_asn: IsdAsn) {
        match self {
            Self::V4(addr) => addr.set_isd_asn(isd_asn),
            Self::V6(addr) => addr.set_isd_asn(isd_asn),
        }
    }

    /// Extract the endhost [`AddressInfo`].
    pub const fn address_info(&self) -> AddressInfo {
        match self {
            Self::V4(_) => AddressInfo::IPV4,
            Self::V6(_) => AddressInfo::IPV6,
        }
    }
}

impl AsRef<IsdAsn> for EndhostAddr {
    fn as_ref(&self) -> &IsdAsn {
        match self {
            Self::V4(addr) => addr.as_ref(),
            Self::V6(addr) => addr.as_ref(),
        }
    }
}

impl From<EndhostAddr> for ScionAddr {
    fn from(addr: EndhostAddr) -> Self {
        match addr {
            EndhostAddr::V4(addr) => ScionAddr::V4(addr),
            EndhostAddr::V6(addr) => ScionAddr::V6(addr),
        }
    }
}

impl TryFrom<ScionAddr> for EndhostAddr {
    type Error = EndhostAddrError;

    fn try_from(addr: ScionAddr) -> Result<Self, Self::Error> {
        match addr {
            ScionAddr::V4(addr) => Ok(Self::V4(addr)),
            ScionAddr::V6(addr) => Ok(Self::V6(addr)),
            _ => Err(EndhostAddrError::ServiceAddressNotAllowed),
        }
    }
}

impl core::str::FromStr for EndhostAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = ScionAddrV4::from_str(s) {
            Ok(Self::V4(addr))
        } else if let Ok(addr) = ScionAddrV6::from_str(s) {
            Ok(Self::V6(addr))
        } else {
            Err(AddressKind::Scion.into())
        }
    }
}

/// Endhost address errors.
#[derive(Debug, Error)]
pub enum EndhostAddrError {
    /// Service addresses are not supported.
    #[error("cannot convert service address to endhost address")]
    ServiceAddressNotAllowed,
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn endhost_display_is_parse_inverse() {
        let cases = [
            EndhostAddr::new(
                IsdAsn(0x1_ff00_0000_0110),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            EndhostAddr::new(
                IsdAsn(0x2_ff00_0000_0200),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            ),
            EndhostAddr::new(
                IsdAsn(0x3_ff00_0000_0300),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ),
        ];

        for expected in cases {
            let encoded = expected.to_string();
            let parsed = encoded.parse::<EndhostAddr>().expect("failed to parse");
            assert_eq!(parsed, expected, "round trip mismatch for {encoded}");
        }
    }
}
