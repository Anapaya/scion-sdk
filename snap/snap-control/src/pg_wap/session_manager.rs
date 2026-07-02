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
//! Session manager for the PathGuard WAP API, responsible for managing client authentication and
//! TCP sessions.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::pg_wap::auth::AuthInfo;

/// Manages client authentication and TCP sessions.
#[derive(Clone)]
pub struct WapSessionManager {
    inner: Arc<Mutex<WapSessionManagerInner>>,
}

impl WapSessionManager {
    /// Authenticate an IP address to be able to open sessions.
    ///
    /// The authenticated session is appended to the set of authenticated sessions for the given IP
    /// address.
    pub fn add_session_authentication(&self, auth_info: AuthInfo) {
        let mut inner = self.inner.lock().unwrap();
        inner.add_session_authentication(auth_info);
    }

    /// Find the set of authenticated sessions for the given client IP address.
    pub fn authenticated_sessions_for_ip(&self, client_addr: IpAddr) -> Vec<AuthInfo> {
        let mut inner = self.inner.lock().unwrap();
        inner.authenticated_sessions_for_ip(Instant::now(), client_addr)
    }
}

/// Internal session manager state.
pub struct WapSessionManagerInner {
    sessions: HashMap<IpAddr, Vec<AuthInfo>>,
}

impl WapSessionManager {
    /// Create a new [WapSessionManager].
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(WapSessionManagerInner {
            sessions: HashMap::new(),
        }));

        Self { inner }
    }
}

impl Default for WapSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WapSessionManagerInner {
    /// Authenticate a IP to be able to open sessions.
    ///
    /// The authenticated session is appended to the set of authenticated sessions for the given IP
    /// address.
    pub fn add_session_authentication(&mut self, auth_info: AuthInfo) {
        // XXX(uniquefine): Currently the sessions map can grow unlimited e.g. due to a malicious
        // client. We should add a limit on the maximum number of entries in the
        // map/sessions in an auth_info.
        self.sessions
            .entry(auth_info.ip)
            .or_default()
            .push(auth_info);
    }

    /// Find the set of authenticated sessions for the given client IP address.
    pub fn authenticated_sessions_for_ip(
        &mut self,
        now: Instant,
        client_addr: IpAddr,
    ) -> Vec<AuthInfo> {
        let Some(auth_infos) = self.sessions.get_mut(&client_addr) else {
            return Vec::new();
        };

        // Remove expired auths and return the remaining ones.
        // XXX(uniquefine): We should consider adding an active cleanup of expired auths.
        auth_infos.retain(|auth| auth.valid_until > now);
        if auth_infos.is_empty() {
            self.sessions.remove(&client_addr);
            Vec::new()
        } else {
            auth_infos.clone()
        }
    }
}
