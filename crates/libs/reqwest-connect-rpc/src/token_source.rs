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
//! Token source trait for the connect RPC client.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;

pub mod mock;
pub mod refresh;
pub mod static_token;

/// The cause of a [`TokenSourceError`].
pub type TokenSourceCause = Arc<dyn std::error::Error + Sync + Send>;

/// Why a token source could not provide a token.
///
/// A source knows what it authenticates against, so it is the only place that can tell whether
/// asking again may work. The variant it picks is how it says so; callers read it back through
/// [`TokenSourceError::is_transient`] instead of interpreting the cause themselves.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TokenSourceError {
    /// No token right now, but a later call may produce one, e.g. because the request to the
    /// token service did not get through.
    #[error("token temporarily unavailable: {0}")]
    Unavailable(TokenSourceCause),
    /// The credential the source authenticates with was refused, or the answer it got back cannot
    /// be used as a token. Asking again yields the same answer.
    #[error("token rejected: {0}")]
    Rejected(TokenSourceCause),
    /// The source itself stopped working, e.g. the task that refreshes its token is gone, so it
    /// will not produce a token again.
    #[error("token source broken: {0}")]
    Broken(TokenSourceCause),
}

impl TokenSourceError {
    /// The token could not be obtained now, but a later call may succeed.
    pub fn unavailable(cause: impl Into<Box<dyn std::error::Error + Sync + Send>>) -> Self {
        Self::Unavailable(cause.into().into())
    }

    /// The token cannot be obtained, no matter how often it is asked for.
    pub fn rejected(cause: impl Into<Box<dyn std::error::Error + Sync + Send>>) -> Self {
        Self::Rejected(cause.into().into())
    }

    /// The source can no longer hand out tokens at all.
    pub fn broken(cause: impl Into<Box<dyn std::error::Error + Sync + Send>>) -> Self {
        Self::Broken(cause.into().into())
    }

    /// Returns whether the failure is transient, so that a retry may help.
    ///
    /// Prefer this over matching the variants: a new variant would silently fall into a caller's
    /// wildcard arm.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Unavailable(_) => true,
            Self::Rejected(_) | Self::Broken(_) => false,
        }
    }
}

/// A watch receiver for token source updates.
pub type TokenSourceWatch = watch::Receiver<Option<Result<String, TokenSourceError>>>;

/// A source for authentication tokens.
#[async_trait]
pub trait TokenSource: Send + Sync + 'static {
    /// Returns a watch receiver that always holds the latest valid token.
    ///
    /// The receiver allows both grabbing the current value immediately
    /// and awaiting updates.
    fn watch(&self) -> TokenSourceWatch;

    /// Gets a token, possibly refreshing it.
    ///
    /// If the token cannot be obtained, returns the [`TokenSourceError`] the source published,
    /// classification included, so the caller can tell a source that is momentarily out of reach
    /// from one that will not produce a token again.
    ///
    /// Prefer using `watch` if a subscription to token updates is needed.
    ///
    /// ### Implementation Note
    ///
    /// The default implementation uses the watch channel to get the latest token.
    ///``
    /// - Should be efficient to call multiple times.
    /// - Errors should be returned if no valid token can be obtained.
    /// - Should try to not return errors as long as a valid token is available.
    async fn get_token(&self) -> Result<String, TokenSourceError> {
        let mut watch = self.watch();

        // First, try to get the current value without waiting. and return immediately if available.
        // Cloning keeps the published classification; the cause is shared, not copied.
        match watch.borrow_and_update().as_ref() {
            Some(Ok(token)) => return Ok(token.clone()),
            Some(Err(e)) => return Err(e.clone()),
            None => {}
        }

        // If there is no current value, wait for an update.
        watch.changed().await.map_err(TokenSourceError::broken)?;

        // After being notified, get the updated value.
        match watch.borrow().as_ref() {
            Some(Ok(token)) => Ok(token.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => {
                Err(TokenSourceError::broken(
                    "token source watch channel has no value",
                ))
            }
        }
    }

    /// Formats the token for use in an `Authorization` header.
    ///
    /// The default implementation formats the token as a Bearer token.
    /// Override this method if a different format is required.
    fn format_header(&self, token: String) -> String {
        format!("Bearer {token}")
    }
}
