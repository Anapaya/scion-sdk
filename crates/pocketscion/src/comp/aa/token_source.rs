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

//! [`PocketScionAaTokenSource`] gets SNAP tokens from the PocketSCION AA.

use std::{
    fmt,
    time::{Duration, Instant},
};

use anyhow::Context;
use async_trait::async_trait;
use reqwest_connect_rpc::token_source::{
    TokenSource, TokenSourceError, TokenSourceWatch,
    refresh::{RefreshTokenSource, TokenWithExpiry},
};
use url::Url;

use crate::comp::aa::api::{SNAP_TOKEN_PATH, SnapTokenResponse};

const SOURCE_NAME: &str = "pocketscion-aa";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`TokenSource`] that gets SNAP tokens from the [PocketSCION AA](crate::comp::aa), and renews
/// the token.
///
/// On a real SCION network, use the token source of a production AA instead.
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use anyhow::Context;
/// use pocketscion::{
///     comp::aa::PocketScionAaTokenSource,
///     util::topologies::{UnderlayType, minimal::minimal_topology},
/// };
///
/// let ps = minimal_topology(UnderlayType::Snap).await;
/// let aa_url = ps.aa_url().context("no PocketSCION AA")?;
/// // Give the source to `ScionStackBuilder::with_auth_token_source`.
/// let source = PocketScionAaTokenSource::new(&aa_url)?;
/// # Ok(())
/// # }
/// ```
pub struct PocketScionAaTokenSource {
    source: RefreshTokenSource,
}

impl PocketScionAaTokenSource {
    /// Creates a source that gets tokens from the PocketSCION AA at `aa_url`. The first request
    /// starts at once, on the current Tokio runtime.
    pub fn new(aa_url: &Url) -> anyhow::Result<Self> {
        let url = aa_url
            .join(SNAP_TOKEN_PATH)
            .context("invalid PocketSCION AA URL")?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("cannot build the HTTP client for the PocketSCION AA")?;

        let refresher = move || {
            let client = client.clone();
            let url = url.clone();
            async move { request_token(&client, url).await }
        };
        Ok(Self {
            source: RefreshTokenSource::builder(SOURCE_NAME, refresher).build(),
        })
    }
}

async fn request_token(
    client: &reqwest::Client,
    url: Url,
) -> Result<TokenWithExpiry, TokenSourceError> {
    let sent_at = Instant::now();
    let response = client
        .post(url)
        .send()
        .await
        .map_err(TokenSourceError::unavailable)?
        .error_for_status()
        .map_err(TokenSourceError::rejected)?
        .json::<SnapTokenResponse>()
        .await
        .map_err(TokenSourceError::rejected)?;

    Ok(TokenWithExpiry {
        token: response.snap_token,
        expires_at: sent_at + Duration::from_secs(response.expires_in),
    })
}

#[async_trait]
impl TokenSource for PocketScionAaTokenSource {
    fn watch(&self) -> TokenSourceWatch {
        self.source.watch()
    }

    async fn get_token(&self) -> Result<String, TokenSourceError> {
        self.source.get_token().await
    }
}

impl fmt::Debug for PocketScionAaTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PocketScionAaTokenSource")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use test_log::test;

    use super::*;
    use crate::{
        comp::aa::AaConfig, runtime::builder::PocketScionRuntimeBuilder, state::PocketScionState,
        util::addr_to_http_url,
    };

    #[test(tokio::test)]
    async fn gets_a_token_from_the_aa() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let mut pstate = PocketScionState::new(Utc::now());
        pstate.set_aa(AaConfig::default()).unwrap();
        let runtime = PocketScionRuntimeBuilder::new()
            .with_system_state(pstate)
            .start()
            .await
            .unwrap();
        let aa_url = addr_to_http_url(runtime.aa_addr().unwrap());

        let source = PocketScionAaTokenSource::new(&aa_url).unwrap();
        let token = tokio::time::timeout(Duration::from_secs(30), source.get_token())
            .await
            .expect("the source answers")
            .unwrap();

        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_aa_is_transient() {
        scion_sdk_utils::rustls::select_ring_crypto_provider();
        let source = PocketScionAaTokenSource::new(&"http://127.0.0.1:1".parse().unwrap()).unwrap();

        let error = tokio::time::timeout(Duration::from_secs(30), source.get_token())
            .await
            .expect("the source answers")
            .expect_err("nothing listens on port 1");

        assert!(error.is_transient(), "{error}");
    }
}
