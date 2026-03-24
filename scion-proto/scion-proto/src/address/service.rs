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

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use super::{AddressParseError, HostAddr, HostType, error::AddressKind};

/// A SCION service address.
///
/// A service address is a short identifier used to send anycast or multicast
/// messages to SCION services.
///
/// # Textual Representation
///
/// Service addresses can also be represented as strings, for example CS and CS_A
/// both represent the anycast service address ServiceAddr::CONTROL. The
/// corresponding multicast service address would be CS_M.
#[derive(Eq, PartialEq, Copy, Clone, Debug, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ServiceAddr(pub u16);

impl ServiceAddr {
    /// SCION daemon anycast service address (DS_A)
    pub const DAEMON: Self = Self(0x0001);
    /// SCION control-service anycast address (CS_A)
    pub const CONTROL: Self = Self(0x0002);
    /// Wildcard service address (Wildcard_A)
    pub const WILDCARD: Self = Self(0x0010);

    /// The encoded length of the address.
    pub(crate) const ENCODED_LENGTH: usize = 2;

    #[allow(unused)]
    /// Special none service address value.
    pub(crate) const NONE: Self = Self(0xffff);
    /// Flag bit indicating whether the address includes multicast
    const MULTICAST_FLAG: u16 = 0x8000;

    /// Returns true if the service address is multicast, false otherwise.
    pub fn is_multicast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == Self::MULTICAST_FLAG
    }

    /// Sets the service address to be multicast.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::ServiceAddr;
    /// assert!(!ServiceAddr::DAEMON.is_multicast());
    /// assert!(ServiceAddr::DAEMON.multicast().is_multicast());
    /// ```
    pub fn multicast(self) -> Self {
        Self(self.0 | Self::MULTICAST_FLAG)
    }

    /// Sets the service address to be anycast, disabling multicast
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::ServiceAddr;
    /// assert!(ServiceAddr::DAEMON.multicast().anycast().is_anycast());
    /// assert!(!ServiceAddr::DAEMON.multicast().anycast().is_multicast());
    /// ```
    pub fn anycast(self) -> Self {
        Self(self.0 & !Self::MULTICAST_FLAG)
    }

    /// Returns true if the service address is anycast, false otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scion_proto::address::ServiceAddr;
    /// assert!(ServiceAddr::DAEMON.is_anycast());
    /// assert!(!ServiceAddr::DAEMON.multicast().is_anycast());
    /// ```
    pub fn is_anycast(&self) -> bool {
        (self.0 & Self::MULTICAST_FLAG) == 0
    }
}

impl FromStr for ServiceAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (service, suffix) = s.split_once('_').unwrap_or((s, "A"));

        let address = match service {
            "CS" => ServiceAddr::CONTROL,
            "DS" => ServiceAddr::DAEMON,
            "Wildcard" => ServiceAddr::WILDCARD,
            _ => return Err(AddressKind::Service.into()),
        };
        match suffix {
            "A" => Ok(address),
            "M" => Ok(address.multicast()),
            _ => Err(AddressKind::Service.into()),
        }
    }
}

impl From<ServiceAddr> for u16 {
    fn from(value: ServiceAddr) -> Self {
        value.0
    }
}

impl From<ServiceAddr> for HostAddr {
    fn from(value: ServiceAddr) -> Self {
        HostAddr::Svc(value)
    }
}

impl From<ServiceAddr> for HostType {
    fn from(_: ServiceAddr) -> Self {
        HostType::Svc
    }
}

impl Display for ServiceAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.anycast() {
            ServiceAddr::DAEMON => write!(f, "DS")?,
            ServiceAddr::CONTROL => write!(f, "CS")?,
            ServiceAddr::WILDCARD => write!(f, "Wildcard")?,
            ServiceAddr(value) => write!(f, "<SVC:{value:#06x}>")?,
        }

        if self.is_multicast() {
            write!(f, "_M")?;
        }

        Ok(())
    }
}

impl Serialize for ServiceAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ServiceAddr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_multicast() {
        assert!(!ServiceAddr::DAEMON.is_multicast());
        assert!(ServiceAddr::DAEMON.multicast().is_multicast());
    }

    mod parse {
        use super::*;

        macro_rules! test_success {
            ($name:ident, $str:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(ServiceAddr::from_str($str).unwrap(), $expected);
                }
            };
        }

        test_success!(control, "CS_A", ServiceAddr::CONTROL);
        test_success!(control_shorthand, "CS", ServiceAddr::CONTROL);
        test_success!(daemon, "DS_A", ServiceAddr::DAEMON);
        test_success!(daemon_shorthand, "DS", ServiceAddr::DAEMON);
        test_success!(wildcard, "Wildcard_A", ServiceAddr::WILDCARD);
        test_success!(wildcard_shorthand, "Wildcard", ServiceAddr::WILDCARD);
        test_success!(control_multicast, "CS_M", ServiceAddr::CONTROL.multicast());
        test_success!(daemon_multicast, "DS_M", ServiceAddr::DAEMON.multicast());
        test_success!(
            wildcard_multicast,
            "Wildcard_M",
            ServiceAddr::WILDCARD.multicast()
        );

        macro_rules! test_error {
            ($name:ident, $str:expr) => {
                #[test]
                fn $name() {
                    assert_eq!(
                        ServiceAddr::from_str($str).unwrap_err(),
                        AddressParseError(AddressKind::Service)
                    );
                }
            };
        }

        test_error!(empty, "");
        test_error!(bad_value, "garbage");
        test_error!(invalid_suffix, "CS_Y");
        test_error!(lowercase_anycast, "cs_a");
        test_error!(lowercase_multicast, "cs_m");
        test_error!(trailing_space, "CS ");
        test_error!(leading_space, " CS ");
    }

    mod display {
        use super::*;

        macro_rules! test_display {
            ($name:ident, $addr:expr, $expected:expr) => {
                #[test]
                fn $name() {
                    assert_eq!($addr.to_string(), $expected);
                }
            };
        }

        test_display!(unknown, ServiceAddr(0xABC), "<SVC:0x0abc>");
        test_display!(control, ServiceAddr::CONTROL, "CS");
        test_display!(control_multicast, ServiceAddr::CONTROL.multicast(), "CS_M");
        test_display!(daemon, ServiceAddr::DAEMON, "DS");
        test_display!(daemon_multicast, ServiceAddr::DAEMON.multicast(), "DS_M");
        test_display!(wildcard, ServiceAddr::WILDCARD, "Wildcard");
        test_display!(
            wildcard_multicast,
            ServiceAddr::WILDCARD.multicast(),
            "Wildcard_M"
        );
    }
}
