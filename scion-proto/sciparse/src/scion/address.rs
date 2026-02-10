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

//! Network Addresses used in SCION
//!
//! [ScionHostAddr](host_addr::ScionHostAddr) is similar to an IP address, but includes SCION
//! specific address types such as service addresses.
//!
//! [ScionAddr](addr::ScionAddr) combines [IsdAsn](crate::identifier::isd_asn::IsdAsn) with a
//! [ScionHostAddr](host_addr::ScionHostAddr) to represent a full SCION network address.
//!
//! [ScionSocketAddr](socket_addr::ScionSocketAddr) is a socket address combining a
//! [ScionAddr](addr::ScionAddr) and a port number.

pub mod addr;
pub mod host_addr;
pub mod socket_addr;

/// An error which can be returned when parsing various SCION address formats.
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AddressParseError {
    #[error("invalid ISD format")]
    Isd,
    #[error("invalid AS number format")]
    Asn,
    #[error("invalid ISD-AS number format")]
    IsdAsn,
    #[error("invalid service address format")]
    Service,
    #[error("invalid host address format")]
    HostAddr,
    #[error("invalid SCION address format")]
    Scion,
    #[error("invalid SCION-IPv4 address format")]
    ScionV4,
    #[error("invalid SCION-IPv6 address format")]
    ScionV6,
    #[error("invalid SCION-service address format")]
    ScionSvc,
    #[error("invalid socket address format")]
    Socket,
    #[error("invalid SCION-IPv4 socket address format")]
    SocketV4,
    #[error("invalid SCION-IPv6 socket address format")]
    SocketV6,
    #[error("invalid service socket address format")]
    SocketSvc,
}
