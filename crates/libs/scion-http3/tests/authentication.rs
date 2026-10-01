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

//! A token source that produces no token fails the request, and the failure
//! carries the retryability that the source gave its own error.

mod common;

use async_trait::async_trait;
use scion_http3::{Client, Error, TokenSource, TokenSourceError, TokenSourceWatch};
use test_log::test;
use tokio::sync::watch;

use crate::common::{SERVER_NAME, e2e_setup};

struct FailedTokenSource {
    error: TokenSourceError,
    _sender: watch::Sender<Option<Result<String, TokenSourceError>>>,
    receiver: TokenSourceWatch,
}

impl FailedTokenSource {
    fn new(error: TokenSourceError) -> Self {
        let (sender, receiver) = watch::channel(Some(Err(error.clone())));
        FailedTokenSource {
            error,
            _sender: sender,
            receiver,
        }
    }
}

#[async_trait]
impl TokenSource for FailedTokenSource {
    fn watch(&self) -> TokenSourceWatch {
        self.receiver.clone()
    }

    async fn get_token(&self) -> Result<String, TokenSourceError> {
        Err(self.error.clone())
    }
}

async fn first_request_error(source: FailedTokenSource) -> Error {
    let setup = e2e_setup().await;
    let client = Client::new(
        setup
            .client_config()
            .with_auth_token_source(source)
            .with_dns_override(SERVER_NAME, vec![setup.server_ip()]),
    );
    let error = client
        .get(setup.url("/hello"))
        .await
        .expect_err("no token, no request");
    client.close().await;
    error
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_a_refused_credential_fails_the_request_for_good() {
    let error = first_request_error(FailedTokenSource::new(TokenSourceError::rejected(
        "revoked",
    )))
    .await;
    assert!(
        matches!(
            error,
            Error::StackBuild {
                retryable: false,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!error.is_retryable());
}

#[test(tokio::test)]
#[ntest::timeout(120_000)]
async fn e2e_an_unreachable_token_service_is_worth_a_retry() {
    let error = first_request_error(FailedTokenSource::new(TokenSourceError::unavailable(
        "no route",
    )))
    .await;
    assert!(
        matches!(
            error,
            Error::StackBuild {
                retryable: true,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(error.is_retryable());
}
