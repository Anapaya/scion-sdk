// Copyright 2026 Anapaya Systems
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
//! PathGuard WAP authentication service.

use std::{net::IpAddr, time::Instant};

/// Information about an authenticated IP address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthInfo {
    /// The authenticated IP address.
    pub ip: IpAddr,
    /// The time until which the authentication is valid. After this time, the client needs to
    /// reauthenticate.
    pub valid_until: Instant,
    /// The target domains a client is allowed to connect to.
    pub targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthService {
    auth_duration: std::time::Duration,
}

impl AuthService {
    pub fn new(auth_duration: std::time::Duration) -> Self {
        Self { auth_duration }
    }

    pub fn authenticate(&self, now: Instant, ip: IpAddr, targets: &[&str]) -> AuthInfo {
        let valid_until = now + self.auth_duration;
        AuthInfo {
            ip,
            targets: targets.iter().map(|s| s.to_string()).collect(),
            valid_until,
        }
    }
}
