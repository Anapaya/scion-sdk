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
//! SNAP token library.

pub mod snap_token;

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The pseudo SCION subscriber identity (PSSID).
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Pssid(pub Uuid);

impl Default for Pssid {
    fn default() -> Self {
        Self::new()
    }
}
impl Pssid {
    /// Generates a new random PSSID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl FromStr for Pssid {
    type Err = std::io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match Uuid::parse_str(value) {
            Ok(uuid) => Ok(Pssid(uuid)),
            Err(_) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid PSSID",
                ))
            }
        }
    }
}

impl From<Pssid> for String {
    fn from(pssid: Pssid) -> Self {
        pssid.0.to_string()
    }
}

impl Display for Pssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
