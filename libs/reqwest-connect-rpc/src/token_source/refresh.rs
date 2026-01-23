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
//! [`RefreshTokenSource`] automatically refreshes tokens before expiry using a configurable
//! [`TokenRefresher`].
//!
//! Use the builder pattern to configure refresh intervals, timeouts, and minimum token lifetimes.
//! See [`RefreshTokenSourceBuilder`] for details.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::{sync::watch, task::JoinHandle};

use crate::token_source::{TokenSource, TokenSourceError};

const DEFAULT_REFRESH_RETRY_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_REFRESH_THRESHOLD: Duration = Duration::from_secs(60);
const DEFAULT_REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MIN_TOKEN_LIFETIME: Duration = Duration::from_secs(10);

/// Builder for a [RefreshTokenSource].
pub struct RefreshTokenSourceBuilder<T: TokenRefresher> {
    name: String,
    token_refresher: T,
    refresh_retry_delay: Duration,
    refresh_threshold: Duration,
    refresh_timeout: Duration,
    min_token_lifetime: Duration,
}
impl<T: TokenRefresher> RefreshTokenSourceBuilder<T> {
    /// Creates a new builder for a [RefreshTokenSource].
    ///
    /// # Arguments
    /// * `name` - Name of the token source, used for logging.
    /// * `token_refresher` - Ability to refresh the token.
    pub fn new(name: String, token_refresher: T) -> Self {
        Self {
            name,
            token_refresher,
            refresh_retry_delay: DEFAULT_REFRESH_RETRY_DELAY,
            refresh_threshold: DEFAULT_REFRESH_THRESHOLD,
            refresh_timeout: DEFAULT_REFRESH_TIMEOUT,
            min_token_lifetime: DEFAULT_MIN_TOKEN_LIFETIME,
        }
    }

    /// Minimum lifetime a token must have to be considered valid when returned by `get_token`.
    pub fn min_token_lifetime(mut self, duration: Duration) -> Self {
        self.min_token_lifetime = duration;
        self
    }

    /// The delay between retries if the refresh function fails.
    pub fn refresh_retry_delay(mut self, duration: Duration) -> Self {
        self.refresh_retry_delay = duration;
        self
    }

    /// The duration before the token's expiry when a refresh should be attempted.
    pub fn refresh_threshold(mut self, duration: Duration) -> Self {
        self.refresh_threshold = duration;
        self
    }

    /// The duration to wait for a refresh to complete when `get_token` is called before a timeout.
    pub fn refresh_timeout(mut self, duration: Duration) -> Self {
        self.refresh_timeout = duration;
        self
    }

    /// Build the [RefreshTokenSource]
    pub fn build(self) -> RefreshTokenSource {
        RefreshTokenSource::new(
            self.name,
            self.token_refresher,
            self.refresh_retry_delay,
            self.refresh_threshold,
            self.refresh_timeout,
        )
    }
}

// ################################
// RefreshTokenSource

/// A [TokenSource] automatically refreshing the token before it expires.
pub struct RefreshTokenSource {
    /// Shared state between the background refresh task and the token source.
    watch_rx: watch::Receiver<Option<Result<String, TokenSourceError>>>,
    // Handle to manage the background task, ensuring it is aborted when the `RefreshTokenSource`
    // is dropped.
    #[allow(unused)]
    task_handle: RefreshingTokenSourceTaskHandle,
}

impl RefreshTokenSource {
    /// Creates a builder for a `RefreshTokenSource`.
    pub fn builder<T: TokenRefresher>(
        name: impl Into<String>,
        token_refresher: T,
    ) -> RefreshTokenSourceBuilder<T> {
        RefreshTokenSourceBuilder::new(name.into(), token_refresher)
    }

    /// Creates a new `RefreshTokenSource`.
    ///
    /// # Arguments
    /// * `name` - Name of the token source, used for logging.
    /// * `refresh_function` - Function to refresh the token.
    /// * `refresh_retry_delay` - Delay between retries if the refresh function fails.
    /// * `refresh_threshold` - Duration before the token's expiry when a refresh should be
    ///   attempted.
    /// * `refresh_timeout` - Duration to wait for a refresh to complete when `get_token` is called.
    pub fn new(
        name: String,
        token_refresher: impl TokenRefresher,
        refresh_retry_delay: Duration,
        refresh_threshold: Duration,
        min_token_lifetime: Duration,
    ) -> Self {
        let (watch_tx, watch_rx) = tokio::sync::watch::channel(None);
        let inner = RefreshTokenSourceTask {
            name,
            watch_tx,
            refresh_retry_delay,
            refresh_threshold,
            min_token_lifetime,
            token_refresher: Box::new(token_refresher),
        };

        let task_handle = inner.run();

        Self {
            watch_rx,
            task_handle,
        }
    }
}

#[async_trait]
impl TokenSource for RefreshTokenSource {
    fn watch(&self) -> watch::Receiver<Option<Result<String, TokenSourceError>>> {
        self.watch_rx.clone()
    }
}

/// A token with its expiry time.
#[derive(Clone, Debug)]
pub struct TokenWithExpiry {
    /// JWT string.
    pub token: String,
    /// Token expiry.
    pub expires_at: Instant,
}

// ################################
// RefreshingTokenSourceTaskHandle

/// Handle to manage the background refresh task.
/// When dropped, the task is aborted.
struct RefreshingTokenSourceTaskHandle {
    handle: JoinHandle<()>,
}

impl Drop for RefreshingTokenSourceTaskHandle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct RefreshTokenSourceTask {
    name: String,
    watch_tx: watch::Sender<Option<Result<String, TokenSourceError>>>,
    refresh_retry_delay: Duration,
    refresh_threshold: Duration,
    #[allow(clippy::type_complexity)]
    token_refresher: Box<dyn TokenRefresher>,
    min_token_lifetime: Duration,
}

impl RefreshTokenSourceTask {
    fn run(self) -> RefreshingTokenSourceTaskHandle {
        let handle = tokio::spawn(async move {
            let mut fail_count = 0;
            let mut current_token: Option<TokenWithExpiry> = None;
            loop {
                // Determine when to next refresh the token.
                let token_expiry = match current_token {
                    Some(ref token) => token.expires_at,
                    // No token yet, or last refreshes failed, try to get a new token immediately.
                    _ => Instant::now(),
                };

                let refresh_deadline = token_expiry
                    .checked_sub(self.refresh_threshold)
                    .unwrap_or_else(Instant::now);

                tokio::time::sleep_until(refresh_deadline.into()).await;

                // Attempt to refresh the token.
                let new_token = self.token_refresher.refresh().await;

                match new_token {
                    // Got a new token, store it and notify waiters
                    Ok(token) => {
                        let token_ttl_secs = token
                            .expires_at
                            .saturating_duration_since(Instant::now())
                            .as_secs();

                        // Validate that token has a decent expiry time
                        if token.expires_at <= Instant::now() + self.min_token_lifetime {
                            tracing::error!(
                                name = %self.name,
                                token_ttl_secs,
                                "Refreshed token is already expired or too close to expiry, ignoring"
                            );
                            // XXX(ake): Not sure if we should abort here instead?

                            // Wait before trying again to avoid busy looping
                            tokio::time::sleep(self.refresh_retry_delay).await;
                            continue;
                        }

                        fail_count = 0;

                        tracing::info!(
                            name = %self.name,
                            token_ttl_secs,
                            "Refreshed token"
                        );

                        current_token = Some(token.clone());
                        self.watch_tx.send_replace(Some(Ok(token.token)));
                    }
                    // Failed to refresh the token, log the error and retry after a delay
                    Err(e) => {
                        fail_count += 1;

                        tracing::error!(
                            name = %self.name,
                            ttl_secs = token_expiry.saturating_duration_since(Instant::now()).as_secs(),
                            retry_secs = self.refresh_retry_delay.as_secs(),
                            fail_count,
                            error = %e,
                            "Failed to refresh token"
                        );

                        // If the current token is still valid, keep it, otherwise store the error
                        // and notify waiters
                        if token_expiry <= Instant::now() + self.min_token_lifetime {
                            current_token = None;
                            self.watch_tx.send_replace(Some(Err(e)));
                            continue;
                        }

                        tokio::time::sleep(self.refresh_retry_delay).await;
                        continue;
                    }
                }
            }
        });

        RefreshingTokenSourceTaskHandle { handle }
    }
}

// ################################
// TokenRefresher

/// Anything which allows to refresh a token.
///
/// Default implementations are provided for async functions and closures
#[async_trait]
pub trait TokenRefresher: Send + Sync + 'static {
    /// Refreshes the token and return the new token and its expiry time.
    async fn refresh(&self) -> Result<TokenWithExpiry, TokenSourceError>;
}

/// Allow any async function or closure matching the signature to be used as a TokenRefresher.
#[async_trait]
impl<AsyncFn, FnFuture> TokenRefresher for AsyncFn
where
    AsyncFn: Fn() -> FnFuture + Send + Sync + 'static,
    FnFuture: Future<Output = Result<TokenWithExpiry, TokenSourceError>> + Send,
{
    async fn refresh(&self) -> Result<TokenWithExpiry, TokenSourceError> {
        (self)().await
    }
}
