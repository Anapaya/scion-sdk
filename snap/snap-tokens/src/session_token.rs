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
//! SNAP dataplane session token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scion_sdk_token_validator::validator::Token;
use serde::{Deserialize, Serialize};

use crate::Pssid;

/// Represents the SNAP data plane session token claims contained in a JWT.
///
/// The claims include the data plane ID (`data_plane_id`) and the expiration time
/// (`exp`) of the JWT.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionTokenClaims {
    /// The pseudo SCION subscriber identity (PSSID) from the SNAP token.
    pub pssid: Pssid,
    /// The hostname of the data plane.
    pub hostname: String,
    /// The expiration time of the JWT, represented as a Unix timestamp.
    pub exp: u64,
}

impl Token for SessionTokenClaims {
    fn id(&self) -> String {
        self.pssid.to_string()
    }
    fn exp_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.exp)
    }
    fn required_claims() -> Vec<&'static str> {
        vec!["pssid", "data_plane_id", "exp"]
    }
}
