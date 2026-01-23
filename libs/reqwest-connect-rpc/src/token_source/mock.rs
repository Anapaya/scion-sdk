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

//! Simple in-memory mock token source for testing.

use async_trait::async_trait;

use crate::token_source::{TokenSource, TokenSourceError};

/// MockTokenSource is a simple in-memory implementation of TokenSource for testing.
#[derive(Clone)]
pub struct MockTokenSource {
    watch_tx: tokio::sync::watch::Sender<Option<Result<String, TokenSourceError>>>,
}

#[async_trait]
impl TokenSource for MockTokenSource {
    fn watch(&self) -> tokio::sync::watch::Receiver<Option<Result<String, TokenSourceError>>> {
        self.watch_tx.subscribe()
    }
}

impl MockTokenSource {
    /// Creates a new MockTokenSource with the given initial token.
    pub fn new(initial_token: String) -> Self {
        let (watch_tx, _watch_rx) = tokio::sync::watch::channel(Some(Ok(initial_token.clone())));
        Self { watch_tx }
    }

    /// Updates the token and notifies subscribers.
    pub fn update_token(&self, new_token: String) {
        let _ = self.watch_tx.send(Some(Ok(new_token)));
    }
}
