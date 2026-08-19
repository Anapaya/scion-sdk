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

//! The authentication token, and how a new one reaches a running client.
//!
//! The stack's [`TokenSource`] is a push interface: `watch` is the only method an implementation
//! owes, and the `get_token` the endhost-API client calls per request is a default built on the
//! watch channel, returning the current value or awaiting the first one. So the token lives in a
//! channel here, and the caller replaces it through
//! [`set_auth_token`](crate::ScionHttp3Client::set_auth_token).

use std::sync::Arc;

use scion_http3::{TokenSource, TokenSourceError, TokenSourceWatch};
use tokio::sync::watch;

/// The token a client authenticates with, replaceable while the client runs.
///
/// Held by the client and handed to the configuration as a [`SharedToken`], so that a replacement
/// reaches connectivity that has already been built, and survives the rebuild that follows a
/// network change or a [`reset`](crate::ScionHttp3Client::reset).
pub(crate) struct AuthToken {
    sender: watch::Sender<Option<Result<String, TokenSourceError>>>,
}

impl AuthToken {
    /// Starts from `token`, which the endhost API and the SNAP control plane are given until it is
    /// replaced. Not a header on the requests the caller issues.
    pub(crate) fn new(token: String) -> Self {
        let (sender, _) = watch::channel(Some(Ok(token)));
        Self { sender }
    }

    /// Replaces the token. Requests already in flight keep the one they started with.
    ///
    /// Setting the token it already holds notifies nobody. That is not an optimisation: snap-tun
    /// re-registers this endpoint's identity with every control plane on each update it sees, so a
    /// caller that sets the token defensively, on every foreground or on every emission from its
    /// own token manager, would otherwise pay a registration round trip per call.
    pub(crate) fn set(&self, token: String) {
        self.sender.send_if_modified(|current| {
            match current {
                Some(Ok(existing)) if *existing == token => false,
                _ => {
                    *current = Some(Ok(token));
                    true
                }
            }
        });
    }

    /// A handle to give the stack, which takes its token source by value.
    pub(crate) fn shared(self: &Arc<Self>) -> SharedToken {
        SharedToken(Arc::clone(self))
    }
}

/// A handle to one [`AuthToken`], for the configuration to own.
///
/// [`Config::with_auth_token_source`](scion_http3::Config::with_auth_token_source) takes its source
/// by value, while the client keeps the token so it can replace it. This is what lets both hold the
/// same channel: the configuration is handed this, and every stack the configuration builds reads
/// through it, so a replacement reaches connectivity built before the call.
pub(crate) struct SharedToken(Arc<AuthToken>);

impl TokenSource for SharedToken {
    fn watch(&self) -> TokenSourceWatch {
        self.0.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_seed_token_is_what_requests_get() {
        let token = Arc::new(AuthToken::new("first".to_string()));

        assert_eq!(
            token.shared().get_token().await.expect("a token"),
            "first",
            "the token passed at construction was not the one handed out"
        );
    }

    #[tokio::test]
    async fn a_replacement_reaches_a_handle_taken_earlier() {
        let token = Arc::new(AuthToken::new("first".to_string()));
        // Taken before the replacement, as the configuration takes it before any request runs.
        let shared = token.shared();

        token.set("second".to_string());

        assert_eq!(
            shared.get_token().await.expect("a token"),
            "second",
            "a handle taken before the replacement still reported the old token"
        );
    }

    /// The invariant the deleted pull-based adapter also guarded: snap-tun re-registers this
    /// endpoint's identity with every control plane on each update it sees, so an unchanged token
    /// must not look like a new one.
    #[tokio::test]
    async fn setting_the_same_token_notifies_nobody() {
        let token = Arc::new(AuthToken::new("first".to_string()));
        let watch = token.shared().watch();

        token.set("first".to_string());

        assert!(
            watch.has_changed().is_ok_and(|changed| !changed),
            "re-setting the token it already held looked like a renewal"
        );
    }

    #[tokio::test]
    async fn a_subscriber_is_notified_of_a_replacement() {
        let token = Arc::new(AuthToken::new("first".to_string()));
        let mut watch = token.shared().watch();

        token.set("second".to_string());

        assert!(
            watch.changed().await.is_ok(),
            "replacing the token did not notify a subscriber"
        );
    }
}
