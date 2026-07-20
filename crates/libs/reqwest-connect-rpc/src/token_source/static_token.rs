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

//! Static token source implementation.
//!
//! Allows using a `String` or `&'static str` as a token source.

use async_trait::async_trait;
use tokio::sync::watch;

use crate::token_source::{TokenSource, TokenSourceError};

/// A static token source that always returns the same token.
/// Can be created from a `String` or `&'static str`.
pub struct StaticTokenSource {
    token: String,
    watch_tx: watch::Sender<Option<Result<String, TokenSourceError>>>,
}

impl From<String> for StaticTokenSource {
    fn from(token: String) -> Self {
        let (watch_tx, _watch_rx) = watch::channel(Some(Ok(token.clone())));
        StaticTokenSource { token, watch_tx }
    }
}

impl From<&'static str> for StaticTokenSource {
    fn from(token: &'static str) -> Self {
        let (watch_tx, _watch_rx) = watch::channel(Some(Ok(token.to_string())));
        StaticTokenSource {
            token: token.to_string(),
            watch_tx,
        }
    }
}

#[async_trait]
impl TokenSource for StaticTokenSource {
    async fn get_token(&self) -> Result<String, TokenSourceError> {
        Ok(self.token.clone())
    }

    fn watch(&self) -> watch::Receiver<Option<Result<String, TokenSourceError>>> {
        self.watch_tx.subscribe()
    }
}
