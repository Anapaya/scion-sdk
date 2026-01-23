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

use async_trait::async_trait;
use tokio::sync::watch;

pub mod mock;
pub mod refresh;
pub mod static_token;

/// The error type for token sources.
pub type TokenSourceError = Box<dyn std::error::Error + Sync + Send>;
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
    /// If the token cannot be obtained, returns a `TokenSourceError`.
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
        match watch.borrow_and_update().as_ref() {
            Some(Ok(token)) => return Ok(token.clone()),
            Some(Err(e)) => return Err(e.to_string().into()),
            None => {}
        }

        // If there is no current value, wait for an update.
        watch.changed().await.map_err(|_| {
            Box::<dyn std::error::Error + Sync + Send>::from("token source watch channel closed")
        })?;

        // After being notified, get the updated value.
        match watch.borrow().as_ref() {
            Some(Ok(token)) => Ok(token.clone()),
            Some(Err(e)) => Err(e.to_string().into()),
            None => {
                Err(Box::<dyn std::error::Error + Sync + Send>::from(
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
