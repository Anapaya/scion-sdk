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
//! Session manager for the Pathguard WAP API, responsible for managing client authentication and
//! TCP sessions.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use thiserror::Error;
use tokio::task::JoinHandle;

use crate::pg_wap::{
    auth::AuthInfo,
    tcp_session::{TcpSessionHandle, TcpSessionSharedState},
};

const DEFAULT_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Manages client authentication and TCP sessions.
#[derive(Clone)]
pub struct WapSessionManager {
    inner: Arc<SessionManagerInner>,
    _cleanup_task: Arc<JoinHandle<()>>,
}

impl Deref for WapSessionManager {
    type Target = SessionManagerInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Internal session manager state.
pub struct SessionManagerInner {
    sessions: Mutex<HashMap<IpAddr, AuthenticatedSessions>>,
}

impl WapSessionManager {
    /// Create a new [WapSessionManager] and start the session cleanup task.
    ///
    /// The cleanup task will run every `DEFAULT_SESSION_CLEANUP_INTERVAL` and remove expired
    /// sessions from the session manager. This means sessions will be removed with a delay of
    /// up to `DEFAULT_SESSION_CLEANUP_INTERVAL` after they expire.
    pub fn new() -> Self {
        let inner = Arc::new(SessionManagerInner {
            sessions: Mutex::new(HashMap::new()),
        });

        let cleanup_task = Arc::new(SessionManagerInner::start_cleanup_task(
            Arc::downgrade(&inner),
            DEFAULT_SESSION_CLEANUP_INTERVAL,
        ));

        Self {
            inner,
            _cleanup_task: cleanup_task,
        }
    }
}

impl Default for WapSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur when trying to add a TCP session to the session manager.
#[derive(Debug, Error)]
pub enum AddTcpSessionError {
    /// No authentication for this client IP address exists.
    #[error("No authentication for this client IP address exists")]
    NotAuthenticated,
    /// The authentication for this client IP address has expired.
    #[error("Authentication for this client IP address has expired")]
    AuthenticationExpired,
    /// An open TCP session from this client address already exists.
    #[error("An open TCP session from this client address already exists")]
    OpenSessionAlreadyExists,
}

impl SessionManagerInner {
    /// Start the session cleanup task, which will run every `cleanup_interval` and remove expired
    /// sessions from the session manager. This means sessions will be removed with a delay of up to
    /// `cleanup_interval` after they expire.
    pub fn start_cleanup_task(this: Weak<Self>, cleanup_interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                tracing::trace!("Running session cleanup");

                let Some(inner) = this.upgrade() else {
                    // The SessionManager has been dropped, so we can stop the cleanup task
                    tracing::info!("SessionManager has been dropped, stopping cleanup task");
                    break;
                };

                inner.cleanup_expired_sessions();
            }
        })
    }

    /// Authenticate a IP to be able to open sessions.
    ///
    /// In case the IP is already authenticated, the authentication information is replaced if the
    /// new authentication has a longer lifetime than the current one.
    ///
    /// Returns the currently valid authentication information for the IP after the update.
    pub fn add_session_authentication(&self, auth_info: AuthInfo) -> AuthInfo {
        let mut sessions = self.sessions.lock().expect("no fail");

        let auth = sessions
            .entry(auth_info.ip)
            .or_insert_with(|| AuthenticatedSessions::new(auth_info.clone()));

        auth.maybe_replace_auth_info(auth_info);

        auth.latest_auth.clone()
    }

    /// Check if a clients sessions can be accepted
    pub fn can_accept_client_session(&self, client_addr: IpAddr) -> bool {
        let sessions = self.sessions.lock().expect("no fail");
        let auth = sessions.get(&client_addr);

        auth.map(|auth| !auth.auth_is_expired()).unwrap_or(false)
    }

    /// Try to add a TCP session to the session manager.
    ///
    /// If no open session exists for the TCP session, the session cannot be added and an
    /// error is returned.
    pub fn try_add_tcp_session(&self, session: TcpSessionHandle) -> Result<(), AddTcpSessionError> {
        let src_addr = session.src_addr;
        let mut sessions = self.sessions.lock().expect("no fail");
        tracing::info!(%src_addr, "Trying to add TCP session for client",);

        let client_sessions = sessions
            .get_mut(&src_addr.ip())
            .ok_or(AddTcpSessionError::NotAuthenticated)?;

        client_sessions.add_tcp_session(session)?;

        drop(sessions);
        Ok(())
    }

    /// Try to remove a TCP session from the session manager.
    ///
    /// If a session exists for the given source address, it is removed and closed within this
    /// method. Returns the removed session handle (already closed), or `None` if no session was
    /// found.
    pub fn try_remove_tcp_session(&self, src_addr: SocketAddr) -> Option<TcpSessionHandle> {
        let mut sessions = self.sessions.lock().expect("no fail");

        let client_sessions = sessions.get_mut(&src_addr.ip())?;
        let removed_handle = client_sessions.remove_tcp_session(src_addr);

        drop(sessions);

        if let Some(handle) = &removed_handle {
            tracing::info!(%src_addr, "Removed TCP session for client");
            handle.close("Session removed from session manager");
        }

        removed_handle
    }

    /// Remove expired sessions from the session manager.
    pub fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().expect("no fail");
        // Drop all expired sessions, this will also close all TCP sessions of the expired clients.
        sessions.retain(|_, auth_sessions| {
            if auth_sessions.auth_is_expired() {
                tracing::info!(ip = %auth_sessions.latest_auth.ip, "Authentication expired, removing sessions for client");
                {
                    let this = &mut *auth_sessions;
                    for session in this.tcp_sessions.values() {
                        session.close("Authentication expired");
                    }

                    this.tcp_sessions.clear();
                }

                false
            } else {
                true
            }
        });
    }
}

#[derive(Debug)]
struct AuthenticatedSessions {
    /// Information about the latest authentication for this IP address.
    ///
    /// TODO: In reality we will have multiple different auths here, which might e.g. allow just
    /// certain targets or supply Hidden Segments, for now we just store the latest auth for
    /// simplicity.
    latest_auth: AuthInfo,
    /// Active TCP sessions for this client, indexed by the socket address of the client.
    tcp_sessions: BTreeMap<SocketAddr, TcpSessionHandle>,
}

impl AuthenticatedSessions {
    fn new(auth_info: AuthInfo) -> Self {
        Self {
            latest_auth: auth_info,
            tcp_sessions: BTreeMap::new(),
        }
    }

    /// Maybe replace the authentication information for this client.
    /// The authentication information is replaced if the new authentication has a longer lifetime
    /// than the current one.
    fn maybe_replace_auth_info(&mut self, auth_info: AuthInfo) {
        if auth_info.valid_until > self.latest_auth.valid_until {
            self.latest_auth = auth_info;
        }
    }

    /// Check if the session should be removed from the session manager
    fn auth_is_expired(&self) -> bool {
        self.latest_auth.valid_until <= chrono::Utc::now()
    }

    // Attempt to add a TCP session. If an open session from the same client address already exists,
    // the session is not added and an error is returned.
    fn add_tcp_session(&mut self, session: TcpSessionHandle) -> Result<(), AddTcpSessionError> {
        if self.auth_is_expired() {
            return Err(AddTcpSessionError::AuthenticationExpired);
        }

        match self.tcp_sessions.entry(session.src_addr) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(session);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                // Session is closed but was not removed yet
                if matches!(
                    &*e.get().shared.borrow(),
                    TcpSessionSharedState::Closed { .. }
                ) {
                    e.insert(session);
                    Ok(())
                } else {
                    Err(AddTcpSessionError::OpenSessionAlreadyExists)
                }
            }
        }
    }

    /// Remove a TCP session and returns its handle.
    ///
    /// The caller should close the session after removing it from the session manager.
    fn remove_tcp_session(&mut self, src_addr: SocketAddr) -> Option<TcpSessionHandle> {
        self.tcp_sessions.remove(&src_addr)
    }
}
