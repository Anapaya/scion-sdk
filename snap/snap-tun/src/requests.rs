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
//! SNAP tunnel control requests.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::SystemTime,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use scion_proto::address::{EndhostAddr, IsdAsn};

pub(crate) fn system_time_from_unix_epoch_secs(secs: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

pub(crate) fn unix_epoch_from_system_time(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Response to a token update request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenUpdateResponse {
    /// The unix epoch timestamp at which the token expires.
    #[prost(uint64, tag = "1")]
    pub valid_until: u64,
}

/// Represents a SCION endhost address range.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressRange {
    /// The ISD-AS of the requested address. Can include wildcards.
    #[prost(uint64, tag = "1")]
    pub isd_as: u64,
    /// Version MUST be either 4 or 6, indicating IPv4 or IPv6 respectively.
    #[prost(uint32, tag = "2")]
    pub ip_version: u32,
    /// The length of the network prefix. May not be larger than 32
    /// for version = 4, and may not be larger than 128 for version =
    /// 6.
    #[prost(uint32, tag = "3")]
    pub prefix_length: u32,
    /// The IP address in network byte order. The length of the address
    /// must be 4 for version = 4 and 16 for version = 16.
    #[prost(bytes = "vec", tag = "4")]
    pub address: Vec<u8>,
}

impl AddressRange {
    pub(crate) fn ipnet(&self) -> Result<IpNet, AddrError> {
        match self.ip_version {
            4 => {
                if self.prefix_length != 32 {
                    return Err(AddrError::InvalidPrefixLen {
                        actual: self.prefix_length as u8,
                        max: 32,
                    });
                }
                if self.address.len() != 4 {
                    return Err(AddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 4,
                    });
                }
                let mut bytes = [0u8; 4];
                bytes[..].copy_from_slice(&self.address[..]);
                Ok(Ipv4Net::new_assert(Ipv4Addr::from(bytes), self.prefix_length as u8).into())
            }
            6 => {
                if self.prefix_length != 128 {
                    return Err(AddrError::InvalidPrefixLen {
                        actual: self.prefix_length as u8,
                        max: 128,
                    });
                }
                if self.address.len() != 16 {
                    return Err(AddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 16,
                    });
                }
                let mut bytes = [0u8; 16];
                bytes[..].copy_from_slice(&self.address[..]);
                Ok(Ipv6Net::new_assert(Ipv6Addr::from(bytes), self.prefix_length as u8).into())
            }
            v => Err(AddrError::InvalidIPVersion(v)),
        }
    }
}

/// Represents a socket addr assignment request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SocketAddrAssignmentRequest {}

/// Represents a socket addr assignment response.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SocketAddrAssignmentResponse {
    /// Version MUST be either 4 or 6, indicating IPv4 or IPv6 respectively.
    #[prost(uint32, tag = "1")]
    pub ip_version: u32,
    /// The IP address in network byte order. The length of the address
    /// must be 4 for version = 4 and 16 for version = 6.
    #[prost(bytes = "vec", tag = "2")]
    pub address: Vec<u8>,
    /// The port of the endhost socket address.
    #[prost(uint32, tag = "3")]
    pub port: u32,
}

impl SocketAddrAssignmentResponse {
    /// Converts the response to a standard `std::net::SocketAddr`.
    pub fn socket_addr(&self) -> Result<SocketAddr, AddrError> {
        let port = self
            .port
            .try_into()
            .map_err(|_| AddrError::InvalidPort(self.port))?;

        match self.ip_version {
            4 => {
                if self.address.len() != 4 {
                    return Err(AddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 4,
                    });
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&self.address);
                let addr = Ipv4Addr::from(bytes);
                Ok(SocketAddr::new(addr.into(), port))
            }
            6 => {
                if self.address.len() != 16 {
                    return Err(AddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 16,
                    });
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&self.address);
                let addr = Ipv6Addr::from(bytes);
                Ok(SocketAddr::new(addr.into(), port))
            }
            v => Err(AddrError::InvalidIPVersion(v)),
        }
    }
}

impl From<SocketAddr> for SocketAddrAssignmentResponse {
    fn from(socket_addr: SocketAddr) -> Self {
        match socket_addr {
            SocketAddr::V4(addr) => {
                Self {
                    ip_version: 4,
                    address: addr.ip().octets().to_vec(),
                    port: addr.port() as u32,
                }
            }
            SocketAddr::V6(addr) => {
                Self {
                    ip_version: 6,
                    address: addr.ip().octets().to_vec(),
                    port: addr.port() as u32,
                }
            }
        }
    }
}

impl TryInto<EndhostAddr> for &AddressRange {
    type Error = AddrError;

    fn try_into(self) -> Result<EndhostAddr, Self::Error> {
        let addr: IpNet = self.ipnet()?;
        let isd_as = IsdAsn::from(self.isd_as);
        if isd_as.is_wildcard() {
            return Err(AddrError::InvalidIsdAs);
        }
        Ok(EndhostAddr::new(isd_as, addr.addr()))
    }
}

impl TryInto<(IsdAsn, IpNet)> for &AddressRange {
    type Error = AddrError;

    fn try_into(self) -> Result<(IsdAsn, IpNet), Self::Error> {
        let addr: IpNet = self.ipnet()?;
        let isd_as = IsdAsn::from(self.isd_as);
        if isd_as.is_wildcard() {
            return Err(AddrError::InvalidIsdAs);
        }
        Ok((isd_as, addr))
    }
}

impl From<&EndhostAddr> for AddressRange {
    fn from(addr: &EndhostAddr) -> Self {
        let isd_as = addr.isd_asn().to_u64();
        let (ip_version, prefix_length, address) = match addr.local_address() {
            IpAddr::V4(a) => (4, 32, a.octets().to_vec()),
            IpAddr::V6(a) => (6, 128, a.octets().to_vec()),
        };
        AddressRange {
            isd_as,
            ip_version,
            prefix_length,
            address,
        }
    }
}

/// SNAP tunnel address errors.
#[derive(Debug, thiserror::Error)]
pub enum AddrError {
    /// Unsupported IP version.
    #[error("unsupported IP version {0}")]
    InvalidIPVersion(u32),
    /// Invalid address length.
    #[error("invalid address length")]
    InvalidAddressLen {
        /// Provided length.
        actual: u8,
        /// Expected length.
        expected: u8,
    },
    /// Invalid prefix length.
    #[error("invalid prefix length")]
    InvalidPrefixLen {
        /// Provided length.
        actual: u8,
        /// Maximum allowed length.
        max: u8,
    },
    /// Wildcard ISD-AS is not allowed.
    #[error("wildcard ISD-AS is not allowed")]
    InvalidIsdAs,
    /// Provided port is outside of allowed range 1..65535.
    #[error("port outside of allowed range: {0}")]
    InvalidPort(u32),
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use assert_matches::assert_matches;
    use scion_proto::address::{Asn, Isd};

    use super::*;

    const TEST_ISD_AS: IsdAsn = IsdAsn::new(Isd(1), Asn::new(0xff00_0000_0110));

    #[test]
    fn try_into_endhost_addr_ipv4_success() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 4,
            prefix_length: 32,
            address: vec![192, 0, 2, 1],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        let endhost_addr = result.expect("conversion should succeed");

        let expected_addr = EndhostAddr::new(TEST_ISD_AS, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(endhost_addr, expected_addr);
    }

    #[test]
    fn try_into_endhost_addr_ipv6_success() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 6,
            prefix_length: 128,
            address: vec![
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34,
            ],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        let endhost_addr = result.expect("conversion should succeed");

        let expected_addr = EndhostAddr::new(
            TEST_ISD_AS,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0, 0, 0x8a2e, 0x0370, 0x7334,
            )),
        );
        assert_eq!(endhost_addr, expected_addr);
    }

    #[test]
    fn try_into_endhost_addr_invalid_ip_version() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 5, // Invalid version
            prefix_length: 32,
            address: vec![192, 0, 2, 1],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(result, Err(AddrError::InvalidIPVersion(5)));
    }

    #[test]
    fn try_into_endhost_addr_ipv4_invalid_prefix() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 4,
            prefix_length: 24, // Invalid prefix for endhost
            address: vec![192, 0, 2, 1],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(
            result,
            Err(AddrError::InvalidPrefixLen {
                actual: 24,
                max: 32
            })
        );
    }

    #[test]
    fn try_into_endhost_addr_ipv6_invalid_prefix() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 6,
            prefix_length: 64, // Invalid prefix for endhost
            address: vec![0; 16],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(
            result,
            Err(AddrError::InvalidPrefixLen {
                actual: 64,
                max: 128
            })
        );
    }

    #[test]
    fn try_into_endhost_addr_ipv4_invalid_addr_len() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 4,
            prefix_length: 32,
            address: vec![192, 0, 2], // Invalid length
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(
            result,
            Err(AddrError::InvalidAddressLen {
                actual: 3,
                expected: 4
            })
        );
    }

    #[test]
    fn try_into_endhost_addr_ipv6_invalid_addr_len() {
        let address_range = AddressRange {
            isd_as: TEST_ISD_AS.to_u64(),
            ip_version: 6,
            prefix_length: 128,
            address: vec![0; 15], // Invalid length
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(
            result,
            Err(AddrError::InvalidAddressLen {
                actual: 15,
                expected: 16
            })
        );
    }

    #[test]
    fn try_into_endhost_addr_wildcard_isd_as() {
        let address_range = AddressRange {
            isd_as: IsdAsn::WILDCARD.to_u64(), // Wildcard ISD-AS
            ip_version: 4,
            prefix_length: 32,
            address: vec![192, 0, 2, 1],
        };

        let result: Result<EndhostAddr, _> = (&address_range).try_into();
        assert_matches!(result, Err(AddrError::InvalidIsdAs));
    }
}
