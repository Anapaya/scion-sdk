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
use etherparse::{Ipv4Slice, Ipv6Slice};

/// Layout of an IP packet
#[derive(Debug)]
pub struct IpPacketValidator;

/// Error returned when an IP packet fails validation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParseError;

impl IpPacketValidator {
    /// Returns the IP version (4 or 6) encoded in the first nibble of `data`.
    #[inline]
    pub fn ip_version(data: &[u8]) -> u8 {
        data.first().unwrap_or(&0) >> 4
    }

    /// Validates that given data is a valid IP4 packet.
    pub fn check(data: &[u8]) -> Result<(), ParseError> {
        match Self::ip_version(data) {
            4 => {
                Ipv4Slice::from_slice(data).map_err(|_| ParseError)?;
            }
            6 => {
                Ipv6Slice::from_slice(data).map_err(|_| ParseError)?;
            }
            _ => return Err(ParseError),
        };
        Ok(())
    }
}
