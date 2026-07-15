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
//! PathGuard WAP SNAP extension.

use std::{net::IpAddr, time::Instant};

use anyhow::Context as _;

use crate::{
    api::http::model::{PgWapSessionManager, Session},
    pg_wap::{auth::AuthService, session_manager::WapSessionManager},
};

mod auth;
pub mod session_manager;

pub use auth::AuthInfo;

/// Encode the WAP IP address as base32 encoded WAP ID.
pub fn encode_ap_id(ip: IpAddr) -> String {
    let ip_bytes: &[u8] = match ip {
        IpAddr::V4(ip) => &ip.octets(),
        IpAddr::V6(ip) => &ip.octets(),
    };

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, ip_bytes)
}

/// Handles WAP control plane interactions
#[derive(Clone)]
pub struct WapControl {
    auth_service: AuthService,
    session_manager: WapSessionManager,
    data_plane_port: u16,
    encoded_local_ip: String,
}

impl WapControl {
    /// Creates a new control service.
    pub fn new(
        session_manager: WapSessionManager,
        auth_duration: std::time::Duration,
        local_ip: IpAddr,
        data_plane_port: u16,
    ) -> Self {
        let auth_service = AuthService::new(auth_duration);

        Self {
            session_manager,
            auth_service,
            encoded_local_ip: encode_ap_id(local_ip),
            data_plane_port,
        }
    }

    fn ap_id(&self) -> &str {
        &self.encoded_local_ip
    }
}

impl PgWapSessionManager for WapControl {
    fn new_session(
        &self,
        client_ip: IpAddr,
        target_domains: &[&str],
    ) -> Result<Session, anyhow::Error> {
        let now = Instant::now();
        let auth_info = self
            .auth_service
            .authenticate(now, client_ip, target_domains);
        self.session_manager
            .add_session_authentication(auth_info.clone());

        let valid_until = chrono::Utc::now()
            + chrono::Duration::from_std(auth_info.valid_until.saturating_duration_since(now))
                .context("auth service returned out of bounds duration")?;
        tracing::info!(%client_ip, %valid_until, ?target_domains, "Granted IP access");

        Ok(Session {
            ip: auth_info.ip,
            ap_id: self.ap_id().to_string(),
            data_plane_port: self.data_plane_port,
            target_domains: auth_info.targets,
            valid_until,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::*;

    fn control() -> WapControl {
        WapControl::new(
            WapSessionManager::new(),
            Duration::from_secs(60),
            IpAddr::from([127, 0, 0, 1]),
            8443,
        )
    }

    #[test]
    fn new_session_authenticates_for_requested_target_domains() {
        let control = control();
        let client_ip = IpAddr::from([10, 0, 0, 1]);

        let session = control
            .new_session(client_ip, &["a.example.com", "b.example.com"])
            .expect("new_session");

        // The response echoes exactly the requested target domains.
        assert_eq!(
            session.target_domains,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
        assert_eq!(session.ip, client_ip);
        assert_eq!(session.data_plane_port, 8443);

        // The session manager records an authentication covering exactly those domains.
        let authed = control
            .session_manager
            .authenticated_sessions_for_ip(client_ip);
        assert_eq!(authed.len(), 1);
        assert_eq!(
            authed[0].targets,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[test]
    fn authentication_is_scoped_to_supplied_domains() {
        let control = control();
        let client_ip = IpAddr::from([10, 0, 0, 2]);

        control
            .new_session(client_ip, &["a.example.com"])
            .expect("new_session");

        let authed = control
            .session_manager
            .authenticated_sessions_for_ip(client_ip);
        assert_eq!(authed.len(), 1);
        assert!(authed[0].targets.contains(&"a.example.com".to_string()));
        assert!(
            !authed[0]
                .targets
                .contains(&"not-requested.example.com".to_string())
        );
    }
}
