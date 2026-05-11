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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::SystemTime,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;

/// Convert a Unix epoch seconds timestamp to a [`SystemTime`].
pub fn system_time_from_unix_epoch_secs(secs: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

/// Convert a [`SystemTime`] to a Unix epoch seconds timestamp.
pub fn unix_epoch_from_system_time(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Response to a session renewal request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionRenewalResponse {
    /// The unix epoch timestamp at which this session expires.
    #[prost(uint64, tag = "1")]
    pub valid_until: u64,
}

/// Represents an IP address range.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpAddressRange {
    /// Version MUST be either 4 or 6, indicating IPv4 or IPv6 respectively.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// The length of the network prefix. May not be larger than 32
    /// for version = 4, and may not be larger than 128 for version =
    /// 6.
    #[prost(uint32, tag = "2")]
    pub prefix_length: u32,
    /// The IP address in network format. The length of the address
    /// must be 4 for version = 4 and 16 for version = 16.
    #[prost(bytes = "vec", tag = "3")]
    pub address: Vec<u8>,
}

/// Represents an address assignment request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressAssignRequest {
    /// The requested IP address ranges.
    #[prost(message, repeated, tag = "1")]
    pub requested_addresses: Vec<IpAddressRange>,
}

/// Response to a address assign request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressAssignResponse {
    /// The assigned address ranges.
    #[prost(message, repeated, tag = "1")]
    pub assigned_addresses: Vec<IpAddressRange>,
}

/// Response to a route advertisement request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteAdvertisementResponse {
    /// The advertised IP routes.
    #[prost(message, repeated, tag = "1")]
    pub routes: Vec<IpAddressRange>,
}

impl TryInto<IpNet> for &IpAddressRange {
    type Error = IpAddrError;

    fn try_into(self) -> Result<IpNet, Self::Error> {
        match self.version {
            4 => {
                if self.address.len() != 4 {
                    return Err(IpAddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 4,
                    });
                }
                let prefix_len = self.prefix_length as u8;
                if self.prefix_length > 32 {
                    return Err(IpAddrError::InvalidPrefixLen {
                        actual: prefix_len,
                        max: 32,
                    });
                }
                let mut bytes = [0u8; 4];
                bytes[..].copy_from_slice(&self.address[..]);
                let addr = Ipv4Addr::from(bytes);

                Ok(Ipv4Net::new(addr, prefix_len)
                    .expect("already checked prefix len")
                    .into())
            }
            6 => {
                if self.address.len() != 16 {
                    return Err(IpAddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 16,
                    });
                }
                let prefix_len = self.prefix_length as u8;
                if self.prefix_length > 128 {
                    return Err(IpAddrError::InvalidPrefixLen {
                        actual: prefix_len,
                        max: 128,
                    });
                }
                let mut bytes = [0u8; 16];
                bytes[..].copy_from_slice(&self.address[..]);
                let addr = Ipv6Addr::from(bytes);

                Ok(Ipv6Net::new(addr, prefix_len)
                    .expect("already checked prefix len")
                    .into())
            }
            v => Err(IpAddrError::InvalidVersion(v)),
        }
    }
}

impl From<IpNet> for IpAddressRange {
    fn from(value: IpNet) -> Self {
        let version: u32;
        let address: Vec<u8>;
        let prefix_length: u32;
        match value {
            IpNet::V4(ipv4_net) => {
                version = 4;
                address = ipv4_net.addr().octets().to_vec();
                prefix_length = ipv4_net.prefix_len() as u32;
            }
            IpNet::V6(ipv6_net) => {
                version = 6;
                address = ipv6_net.addr().octets().to_vec();
                prefix_length = ipv6_net.prefix_len() as u32;
            }
        }

        IpAddressRange {
            version,
            prefix_length,
            address,
        }
    }
}

impl TryInto<IpAddr> for &IpAddressRange {
    type Error = IpAddrError;

    fn try_into(self) -> Result<IpAddr, Self::Error> {
        match self.version {
            4 => {
                if self.address.len() != 4 {
                    return Err(IpAddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 4,
                    });
                }
                if self.prefix_length != 32 {
                    return Err(IpAddrError::InvalidPrefixLen {
                        actual: self.prefix_length as u8,
                        max: 32,
                    });
                }
                let mut bytes = [0u8; 4];
                bytes[..].copy_from_slice(&self.address[..]);
                Ok(Ipv4Addr::from(bytes).into())
            }
            6 => {
                if self.address.len() != 16 {
                    return Err(IpAddrError::InvalidAddressLen {
                        actual: self.address.len() as u8,
                        expected: 16,
                    });
                }
                if self.prefix_length != 128 {
                    return Err(IpAddrError::InvalidPrefixLen {
                        actual: self.prefix_length as u8,
                        max: 128,
                    });
                }
                let mut bytes = [0u8; 16];
                bytes[..].copy_from_slice(&self.address[..]);
                Ok(Ipv6Addr::from(bytes).into())
            }
            v => Err(IpAddrError::InvalidVersion(v)),
        }
    }
}

impl From<IpAddr> for IpAddressRange {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(ipv4) => {
                IpAddressRange {
                    version: 4,
                    prefix_length: 32,
                    address: ipv4.octets().to_vec(),
                }
            }
            IpAddr::V6(ipv6) => {
                IpAddressRange {
                    version: 6,
                    prefix_length: 128,
                    address: ipv6.octets().to_vec(),
                }
            }
        }
    }
}

/// Error returned when an [`IpAddressRange`] cannot be converted to a standard IP type.
#[derive(Debug, Error)]
pub enum IpAddrError {
    /// The IP version field was not 4 or 6.
    #[error("Unsupported IP version {0}")]
    InvalidVersion(u32),
    /// The address bytes length does not match the expected length for the IP version.
    #[error("Invalid address length")]
    InvalidAddressLen {
        /// Actual length of the address bytes.
        actual: u8,
        /// Expected length for this IP version.
        expected: u8,
    },
    /// The prefix length exceeds the maximum for this IP version.
    #[error("Invalid prefix length")]
    InvalidPrefixLen {
        /// Actual prefix length.
        actual: u8,
        /// Maximum allowed prefix length for this IP version.
        max: u8,
    },
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    #[test]
    fn test_serialize_deserialize() {
        let req = AddressAssignRequest {
            requested_addresses: vec![IpAddressRange {
                version: 4,
                prefix_length: 4,
                address: vec![1, 2, 3, 4],
            }],
        };

        let b = req.encode_to_vec();
        let req_ = AddressAssignRequest::decode(&b[..]).unwrap();
        let a = &req.requested_addresses[0];
        let b = &req_.requested_addresses[0];
        assert_eq!(a.version, b.version);
        assert_eq!(a.prefix_length, b.prefix_length);
        assert_eq!(a.address, b.address);
    }
}
