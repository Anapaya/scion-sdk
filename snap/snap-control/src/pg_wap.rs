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
//! Pathguard WAP SNAP extension.

use std::net::IpAddr;

use crate::{
    api::http::model::{IpAuthInfo, PgWapSessionManager},
    pg_wap::{
        auth::{AuthInfo, AuthService},
        session_manager::WapSessionManager,
    },
};

mod auth;
pub mod session_manager;
pub mod tcp_session;

/// Handles Client control plane interactions
#[derive(Clone)]
pub struct ControlService {
    auth_service: AuthService,
    session_manager: WapSessionManager,
    encoded_local_ip: String,
}

impl ControlService {
    /// Creates a new control service.
    pub fn new(
        session_manager: WapSessionManager,
        auth_duration: std::time::Duration,
        local_ip: IpAddr,
    ) -> Self {
        let auth_service = AuthService::new(auth_duration);

        Self {
            session_manager,
            auth_service,
            encoded_local_ip: Self::encode_ap_id(local_ip),
        }
    }

    fn encode_ap_id(ip: IpAddr) -> String {
        let ip_bytes: &[u8] = match ip {
            IpAddr::V4(ip) => &ip.octets(),
            IpAddr::V6(ip) => &ip.octets(),
        };

        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, ip_bytes)
    }

    // Authenticates a Client IP address, allowing it to establish TCP sessions.
    //
    // Returns the APs DNS name derived from the local IP address, which the client can use to
    // establish TCP sessions.
    fn grant_ip_access(&self, auth_info: AuthInfo) {
        let client_ip = auth_info.ip;
        self.session_manager
            .add_session_authentication(auth_info.clone());

        let until = auth_info.valid_until;
        tracing::info!(%client_ip, %until, "Granted IP access");
    }

    fn ap_id(&self) -> &str {
        &self.encoded_local_ip
    }
}

impl PgWapSessionManager for ControlService {
    fn new_session(&self, client_ip: IpAddr) -> Result<IpAuthInfo, anyhow::Error> {
        let auth_info = self.auth_service.authenticate(client_ip);
        let ap_id = self.ap_id();
        self.grant_ip_access(auth_info.clone());

        Ok(IpAuthInfo {
            ip: auth_info.ip,
            ap_id: ap_id.to_string(),
            valid_until: auth_info.valid_until,
        })
    }
}
