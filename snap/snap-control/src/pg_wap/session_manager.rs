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
    sync::{Arc, Mutex},
};

use thiserror::Error;

use crate::pg_wap::{
    auth::AuthInfo,
    tcp_session::{TcpSessionHandle, TcpSessionSharedState},
};

/// Manages client authentication and TCP sessions.
#[derive(Clone)]
pub struct WapSessionManager {
    inner: Arc<SessionManagerInner>,
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
    /// Create a new [WapSessionManager].
    pub fn new() -> Self {
        let inner = Arc::new(SessionManagerInner {
            sessions: Mutex::new(HashMap::new()),
        });

        Self { inner }
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
    pub fn can_accept_client_session(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        client_addr: IpAddr,
    ) -> bool {
        let sessions = self.sessions.lock().expect("no fail");
        let auth = sessions.get(&client_addr);

        auth.map(|auth| !auth.auth_is_expired(now)).unwrap_or(false)
    }

    /// Try to add a TCP session to the session manager.
    ///
    /// If no open session exists for the TCP session, the session cannot be added and an
    /// error is returned. Returns the valid until timestamp for the session.
    pub fn try_add_tcp_session(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        session: TcpSessionHandle,
    ) -> Result<chrono::DateTime<chrono::Utc>, AddTcpSessionError> {
        let src_addr = session.src_addr;
        let mut sessions = self.sessions.lock().expect("no fail");
        tracing::info!(%src_addr, "Trying to add TCP session for client",);

        let client_sessions = sessions
            .get_mut(&src_addr.ip())
            .ok_or(AddTcpSessionError::NotAuthenticated)?;

        client_sessions.add_tcp_session(now, session)?;
        let valid_until = client_sessions.latest_auth.valid_until;

        drop(sessions);
        Ok(valid_until)
    }

    /// Try to remove a TCP session from the session manager.
    ///
    /// If a session exists for the given source address, it is removed and closed within this
    /// method. Returns the removed session handle (already closed), or `None` if no session was
    /// found.
    pub fn try_remove_tcp_session(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        src_addr: SocketAddr,
    ) -> Option<TcpSessionHandle> {
        let mut sessions = self.sessions.lock().expect("no fail");

        let removed_handle = match sessions.entry(src_addr.ip()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let handle = entry.get_mut().remove_tcp_session(src_addr);
                // If no more open session exists and the authentication is expired, remove the
                // client from the session manager.
                if entry.get().tcp_sessions.is_empty() && entry.get().auth_is_expired(now) {
                    entry.remove();
                }
                handle
            }
            std::collections::hash_map::Entry::Vacant(_) => None,
        };

        drop(sessions);

        if let Some(handle) = &removed_handle {
            tracing::info!(%src_addr, "Removed TCP session for client");
            handle.close("Session removed from session manager");
        }

        removed_handle
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
        if self.latest_auth.valid_until > auth_info.valid_until {
            return;
        }

        self.latest_auth = auth_info;
        // Broadcast to all active sessions to extend lifetime
        for session in self.tcp_sessions.values() {
            let _ = session.tx.try_send(
                crate::pg_wap::tcp_session::TcpSessionCommand::ExtendLifetime {
                    new_valid_until: self.latest_auth.valid_until,
                },
            );
        }
    }

    /// Check if the session should be removed from the session manager
    fn auth_is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.latest_auth.valid_until <= now
    }

    // Attempt to add a TCP session. If an open session from the same client address already exists,
    // the session is not added and an error is returned.
    fn add_tcp_session(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
        session: TcpSessionHandle,
    ) -> Result<(), AddTcpSessionError> {
        if self.auth_is_expired(now) {
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::pg_wap::{
        auth::AuthInfo,
        tcp_session::{TcpSessionCommand, TcpSessionHandle, TcpSessionSharedState},
    };

    fn now() -> chrono::DateTime<chrono::Utc> {
        // Fixed reference point so tests never race the wall clock.
        chrono::DateTime::from_timestamp(1_000_000, 0).unwrap()
    }

    fn secs(n: i64) -> chrono::Duration {
        chrono::Duration::seconds(n)
    }

    /// Build a `TcpSessionHandle` and return the raw ends so tests can assert
    /// commands sent to it and drive its shared-state.
    fn make_session(
        client_addr: SocketAddr,
    ) -> (
        TcpSessionHandle,
        tokio::sync::mpsc::Receiver<TcpSessionCommand>,
        tokio::sync::watch::Sender<TcpSessionSharedState>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (shared_tx, shared_rx) =
            tokio::sync::watch::channel(TcpSessionSharedState::WaitingForTlsHandshake);
        let handle = TcpSessionHandle {
            src_addr: client_addr,
            tx,
            shared: shared_rx,
        };
        (handle, rx, shared_tx)
    }

    #[test]
    fn accept_client_sessions() {
        let manager = WapSessionManager::new();
        let t = now();
        let ip = "10.0.0.1".parse().unwrap();

        // No auth yet, fail to accept.
        assert!(!manager.can_accept_client_session(t, ip));

        // Add auth, should be accepted.
        let valid_until = t + secs(60);
        manager.add_session_authentication(AuthInfo { ip, valid_until });
        assert!(manager.can_accept_client_session(t, ip));

        // Fail after expiry.
        assert!(!manager.can_accept_client_session(valid_until + secs(1), ip));
    }

    #[test]
    fn auth_is_only_extended() {
        let manager = WapSessionManager::new();
        let t = now();
        let ip = "10.0.0.1".parse().unwrap();

        // Add initial auth with 60s lifetime.
        let initial_expiry = t + secs(60);
        let auth_info = manager.add_session_authentication(AuthInfo {
            ip,
            valid_until: initial_expiry,
        });
        assert_eq!(auth_info.valid_until, initial_expiry);

        // Auth with longer lifetime should replace the current one.
        let longer_expiry = t + secs(300);
        let auth_info = manager.add_session_authentication(AuthInfo {
            ip,
            valid_until: longer_expiry,
        });
        assert_eq!(auth_info.valid_until, longer_expiry);

        // Auth with shorter lifetime should not replace the current one.
        let auth_info = manager.add_session_authentication(AuthInfo {
            ip,
            valid_until: t + secs(30),
        });
        assert_eq!(auth_info.valid_until, longer_expiry);
    }

    #[test]
    fn adding_sessions() {
        let manager = WapSessionManager::new();
        let t = now();
        let ip = "10.0.0.1".parse().unwrap();

        let (session_1, ..) = make_session(SocketAddr::new(ip, 1000));

        // Adding a session without authentication should fail.
        let err = manager.try_add_tcp_session(now(), session_1).unwrap_err();
        assert!(matches!(err, AddTcpSessionError::NotAuthenticated));

        // Authenticate client
        let valid_until = t + secs(60);
        manager.add_session_authentication(AuthInfo { ip, valid_until });

        // Adding a session should now succeed.
        let session2_socket_addr = SocketAddr::new(ip, 2000);
        let (session_2, _, session_2_shared_tx) = make_session(session2_socket_addr);
        let session_2_validity = manager
            .try_add_tcp_session(t, session_2)
            .expect("add session 2 should succeed");
        assert_eq!(session_2_validity, valid_until);

        // Adding another session from the same address should fail since the first one is still
        // open.
        let (session_2_1, ..) = make_session(session2_socket_addr);
        let err = manager.try_add_tcp_session(t, session_2_1).unwrap_err();
        assert!(matches!(err, AddTcpSessionError::OpenSessionAlreadyExists));

        // Closed session can be re-added.
        session_2_shared_tx.send_replace(TcpSessionSharedState::Closed {
            reason: "done".into(),
        });
        let (session_2_2, ..) = make_session(session2_socket_addr);
        assert!(manager.try_add_tcp_session(t, session_2_2).is_ok());

        // After the auth expires, adding a new session should fail.
        let (session_3, ..) = make_session(SocketAddr::new(ip, 3000));
        let err = manager
            .try_add_tcp_session(t + secs(300), session_3)
            .unwrap_err();
        assert!(matches!(err, AddTcpSessionError::AuthenticationExpired));
    }

    #[test]
    fn auth_expiry_broadcast() {
        let manager = WapSessionManager::new();
        let t = now();
        let ip = "10.0.0.1".parse().unwrap();

        // Authenticate client
        let valid_until = t + secs(60);
        manager.add_session_authentication(AuthInfo { ip, valid_until });

        // Add two sessions
        let (session_1, mut session_1_rx, _) = make_session(SocketAddr::new(ip, 1000));
        let session_1_validity = manager
            .try_add_tcp_session(t, session_1)
            .expect("add session 1 should succeed");
        assert_eq!(session_1_validity, valid_until);

        let (session_2, mut session_2_rx, _) = make_session(SocketAddr::new(ip, 2000));
        let session_2_validity = manager
            .try_add_tcp_session(t, session_2)
            .expect("add session 2 should succeed");
        assert_eq!(session_2_validity, valid_until);

        // A shorter-lived auth does not broadcast to existing sessions.
        manager.add_session_authentication(AuthInfo {
            ip,
            valid_until: t + secs(30),
        });
        assert!(
            session_1_rx.try_recv().is_err(),
            "no broadcast expected for shorter auth"
        );
        assert!(
            session_2_rx.try_recv().is_err(),
            "no broadcast expected for shorter auth"
        );

        // A longer-lived auth must broadcast to all open sessions.
        let new_until = t + secs(300);
        manager.add_session_authentication(AuthInfo {
            ip,
            valid_until: new_until,
        });

        assert!(matches!(
            session_1_rx.try_recv().expect("session 1 should receive the new expiry"),
            TcpSessionCommand::ExtendLifetime { new_valid_until } if new_valid_until == new_until
        ));
        assert!(matches!(
            session_2_rx.try_recv().expect("session 2 should receive the new expiry"),
            TcpSessionCommand::ExtendLifetime { new_valid_until } if new_valid_until == new_until
        ));
    }

    #[test]
    fn remove_sessions() {
        let manager = WapSessionManager::new();
        let t = now();
        let ip = "10.0.0.1".parse().unwrap();

        // Removing a non-existing session.
        let session_1_addr = SocketAddr::new(ip, 1000);
        assert!(manager.try_remove_tcp_session(t, session_1_addr).is_none());

        // Add auth and session
        let valid_until = t + secs(60);
        manager.add_session_authentication(AuthInfo { ip, valid_until });
        let (session_1, mut session_1_rx, _) = make_session(session_1_addr);
        manager
            .try_add_tcp_session(t, session_1)
            .expect("add session should succeed");

        // Removing an existing session should succeed and close the session.
        let still_valid = t + secs(30);
        let _ = manager
            .try_remove_tcp_session(still_valid, session_1_addr)
            .expect("remove session 1");
        assert!(matches!(
            session_1_rx
                .try_recv()
                .expect("session should receive termination command"),
            TcpSessionCommand::Terminate { .. },
        ));
        // Auth is still valid, so adding a new session should succeed.
        let session_2_addr = SocketAddr::new(ip, 2000);
        let (session_2, ..) = make_session(session_2_addr);
        assert!(manager.try_add_tcp_session(still_valid, session_2).is_ok());

        // Removing the last session when the auth is expired should clean up the auth entry.
        let _ = manager
            .try_remove_tcp_session(valid_until + secs(1), session_2_addr)
            .expect("remove session 2");
        let (session_3, ..) = make_session(SocketAddr::new(ip, 3000));
        let err = manager
            .try_add_tcp_session(valid_until + secs(1), session_3)
            .unwrap_err();
        assert!(matches!(err, AddTcpSessionError::NotAuthenticated));
    }
}
